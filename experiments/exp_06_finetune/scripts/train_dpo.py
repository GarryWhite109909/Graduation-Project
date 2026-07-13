"""
DPO（Direct Preference Optimization）训练脚本 —— 在 SFT 模型基础上减少偏见。

设计依据：docs/改进.md 第三节方案 A
  BiasDPO（2024, arXiv:2407.13928）已证明 DPO 能有效减少 LLM 偏见。
  DPO 的损失函数直接最大化 chosen（正确判断）的概率、最小化 rejected
  （错误判断）的概率，比 SFT 更直接地"惩罚"偏见。

  DPO 的优势：
    - 不需要额外的 reward model（对比 PPO）
    - 直接在偏好数据上优化策略
    - 比SFT 更有效地减少"顽固先验"（如 shell=True 偏见）

  DPO 的风险：
    - likelihood displacement：chosen 和 rejected 概率同时下降
      缓解：用较小学习率（5e-7）+ beta=0.1
    - 过拟合：偏好对较少，1 epoch 即可

显存安全（16GB AMD GPU，同时驱动显示器）：
  - precompute_ref_log_probs=True：先单独跑 reference model 前向，
    将 ref_log_probs 存到 CPU，训练时不再需要同时加载两个模型的 activation
  - max_length=1024：DPO 偏好对文本较短，1024 足够
  - batch_size=1 + gradient_checkpointing：最小化 activation 占用
  - set_per_process_memory_fraction(0.88)：限制 PyTorch 最多用 15GB VRAM，
    留 2GB 给桌面显示（SFT 实测峰值 11GB，DPO 双前向+反向约 12-13GB）
  - paged_adamw_8bit：与 SFT 一致，8bit 分页优化器已验证可行
  - AMD_SERIALIZE_KERNEL=3：序列化内核启动，规避 ROCm 异步竞态

数据：experiments/exp_06_finetune/data/dpo_preference_pairs.jsonl
基座：需先完成 SFT 训练（train_qlora.py），在 SFT adapter 基础上做 DPO
方法：4bit NF4 量化 + LoRA（r=8, alpha=16）+ DPO loss
硬件：AMD Radeon RX 9060 XT 16GB + ROCm 7.2

用法（在 AI conda 环境中运行，需 GPU）：
  # 先确保 SFT adapter 已训练完成
  # 然后在 SFT 模型基础上做 DPO
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_dpo.py \
      --sft-adapter experiments/exp_06_finetune/outputs/lora_r8_a16_e1_s42/best \
      --epochs 1 --beta 0.1 --lr 5e-7
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ROCm 多设备保护
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
# 减少显存碎片，避免 ROCm 分配器在大块分配时失败
os.environ.setdefault("PYTORCH_HIP_ALLOC_CONF",
                      "garbage_collection_threshold:0.6,max_split_size_mb:128")
# 序列化内核启动，帮助定位/规避 ROCm 异步内核竞态（hipErrorLaunchFailure）
os.environ.setdefault("AMD_SERIALIZE_KERNEL", "3")
os.environ.setdefault("AMD_SERIALIZE_COPY", "3")

# 避免临时缓存被系统清理（/tmp 可能被 systemd-tmpfiles 清空）
_cache_dir = Path(__file__).resolve().parents[1] / ".cache"
_cache_dir.mkdir(exist_ok=True)
os.environ.setdefault("HF_DATASETS_CACHE", str(_cache_dir))

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from trl import DPOConfig, DPOTrainer

# GPU 同时驱动显示器，必须留出显示缓冲区，否则 VRAM 溢出会导致花屏/系统挂死。
# 8bit 模式下 OOM 是优雅错误（不挂死 GPU），可以用更高比例。
# 4bit 模式下 bnb backward 有 ROCm bug 会挂死 GPU，已禁用。
_VRAM_FRACTION = 0.95  # 0.95: 16.2GB PyTorch + 0.9GB 显示（基本桌面足够）

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/dpo_preference_pairs.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"  # 与 SFT 训练一致


def load_dpo_dataset(path: Path) -> Dataset:
    """加载 DPO 偏好对 jsonl 为 HF Dataset。

    先保存到磁盘再加载，确保 cache_files 非空，
    避免 TRL 的 precompute_ref_logps 缓存到 /tmp 被系统清理。
    """
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    print(f"加载 {len(records)} 对偏好对")

    # 创建 dataset 并持久化到磁盘，使 cache_files 非空
    ds = Dataset.from_list(records)
    cache_path = _cache_dir / f"dpo_{path.stem}"
    ds.save_to_disk(str(cache_path))
    ds = Dataset.load_from_disk(str(cache_path))
    print(f"数据集已缓存到: {cache_path}")
    return ds


def main():
    parser = argparse.ArgumentParser(description="DPO 训练：在 SFT 模型基础上减少偏见")
    parser.add_argument("--sft-adapter", type=str, required=True,
                        help="SFT LoRA adapter 路径（DPO 在此基础上训练）")
    parser.add_argument("--epochs", type=int, default=1,
                        help="训练轮数（默认 1；DPO 数据少，多轮易过拟合）")
    parser.add_argument("--batch-size", type=int, default=1, help="每设备 batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="梯度累积步数")
    parser.add_argument("--lr", type=float, default=5e-7,
                        help="学习率（默认 5e-7；DPO 需要比 SFT 小得多的学习率，"
                             "避免 likelihood displacement）")
    parser.add_argument("--beta", type=float, default=0.1,
                        help="DPO beta 参数（默认 0.1；控制偏离参考模型的程度，"
                             "beta 越大越保守，越小越激进）")
    parser.add_argument("--lora-r", type=int, default=8, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=16, help="LoRA alpha")
    parser.add_argument("--max-length", type=int, default=1024,
                        help="最大序列长度（默认 1024；DPO 偏好对文本较短，"
                             "1024 足够且避免 16GB VRAM 爆满导致 GPU 挂死）")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--model-id", type=str, default=MODEL_ID, help="基座模型 ID")
    parser.add_argument("--no-4bit", action="store_true",
                        help="禁用 4bit 量化，用 fp16（3B 模型可用）")
    parser.add_argument("--use-8bit", action="store_true",
                        help="使用 8bit 量化（7B 模型，绕过 4bit backward bug）")
    parser.add_argument("--data-file", type=str, default=None,
                        help="DPO 数据 jsonl 路径（默认 data/dpo_preference_pairs.jsonl）")
    args = parser.parse_args()

    data_file = Path(args.data_file) if args.data_file else DATA_FILE
    sft_adapter = Path(args.sft_adapter)
    use_4bit = not args.no_4bit and not args.use_8bit
    use_8bit = args.use_8bit

    # 检查 GPU
    if not torch.cuda.is_available():
        print("错误：未检测到 CUDA/HIP GPU。请在有 GPU 的环境中运行。")
        sys.exit(1)
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    vram_total = torch.cuda.get_device_properties(0).total_memory / 1e9
    print(f"VRAM: {vram_total:.2f} GB")

    # 关键：限制 PyTorch 显存占用，留出空间给桌面显示
    # GPU 同时驱动显示器，若 PyTorch 占满 VRAM 会导致花屏/系统挂死
    torch.cuda.set_per_process_memory_fraction(_VRAM_FRACTION)
    vram_limit = vram_total * _VRAM_FRACTION
    print(f"PyTorch VRAM 限制: {vram_limit:.2f} GB ({_VRAM_FRACTION*100:.0f}%)，"
          f"留 {vram_total - vram_limit:.2f} GB 给显示")

    # 检查 SFT adapter 存在
    if not sft_adapter.exists():
        print(f"错误：SFT adapter 路径不存在: {sft_adapter}")
        print("请先运行 train_qlora.py 完成 SFT 训练")
        sys.exit(1)

    # 加载数据
    print(f"DPO 数据: {data_file}")
    dataset = load_dpo_dataset(data_file)

    # 加载 tokenizer
    print(f"加载 tokenizer: {args.model_id}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 量化配置：4bit / 8bit / fp16
    bnb_config = None
    if use_4bit:
        try:
            import bitsandbytes as bnb  # noqa: F401
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
            print(f"启用 4bit NF4 量化")
        except Exception as e:
            print(f"bitsandbytes 4bit 不可用: {e}")
            print("降级为 fp16")
            bnb_config = None
    elif use_8bit:
        try:
            import bitsandbytes as bnb  # noqa: F401
            bnb_config = BitsAndBytesConfig(load_in_8bit=True)
            print(f"启用 8bit 量化")
        except Exception as e:
            print(f"bitsandbytes 8bit 不可用: {e}")
            print("降级为 fp16")
            bnb_config = None

    # 加载基座模型
    quant_tag = "4bit" if use_4bit else ("8bit" if use_8bit else "fp16")
    print(f"加载基座模型: {args.model_id} ({quant_tag})")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        quantization_config=bnb_config,
        device_map={"": 0},
        trust_remote_code=True,
        torch_dtype=torch.float16,
        # eager 注意力最稳定；sdpa 在 ROCm 上是实验性的，
        # DPO 反向传播（chosen+rejected 双前向重计算）会触发 sdpa backward bug
        attn_implementation="eager",
    )
    model.config.use_cache = False

    # 准备 kbit 训练
    if bnb_config is not None:
        model = prepare_model_for_kbit_training(model)
    else:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()

    # 加载 SFT adapter（DPO 在 SFT 基础上训练）
    print(f"加载 SFT adapter: {sft_adapter}")
    from peft import PeftModel
    # 直接加载 SFT adapter 并设为可训练。DPO 会微调 SFT adapter 的权重，
    # 而非创建新的 LoRA。原因：
    #   1. TRL DPOTrainer 不支持嵌套 PeftModel（SFT adapter + 新 DPO LoRA），
    #      会报 "ModuleDict has no attribute 'ref'" 错误
    #   2. precompute_ref_log_probs=True 会在训练前用当前权重计算 reference
    #      logps，所以 reference 就是 SFT 模型本身，DPO 在此基础上优化
    #   3. 不创建新 LoRA 也省去了额外的参数和梯度显存
    model = PeftModel.from_pretrained(model, str(sft_adapter), is_trainable=True)
    model.print_trainable_parameters()
    print("SFT adapter 已加载为可训练（DPO 直接微调 SFT 权重）")

    # DPO 配置
    output_dir = OUTPUT_DIR / f"dpo_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_beta{args.beta}_s{args.seed}"
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    dpo_config = DPOConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        logging_steps=2,
        save_steps=50,
        save_total_limit=3,
        bf16=False,  # RDNA4 不支持 bf16
        fp16=bnb_config is None,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        # paged_adamw_8bit：SFT 训练已验证可行，8bit 分页节省优化器状态显存
        optim="paged_adamw_8bit" if bnb_config is not None else "adamw_torch",
        seed=args.seed,
        max_length=args.max_length,
        beta=args.beta,
        # 显存安全：预计算 reference log probs，训练时不需要同时保持
        # policy model 和 reference model 的 activation，节省约 4GB VRAM
        precompute_ref_log_probs=True,
        precompute_ref_batch_size=1,
        report_to="none",
        logging_dir=str(LOG_DIR),
    )

    # DPO Trainer
    trainer = DPOTrainer(
        model=model,
        args=dpo_config,
        train_dataset=dataset,
        processing_class=tokenizer,
    )

    # 训练前 VRAM 检查
    vram_alloc = torch.cuda.memory_allocated() / 1e9
    vram_reserved = torch.cuda.memory_reserved() / 1e9
    print(f"\nVRAM 状态: {vram_alloc:.1f}/{vram_limit:.1f} GB used (limit), "
          f"{vram_reserved:.1f} GB reserved")
    if vram_limit - vram_reserved < 2.0:
        print(f"警告: 可用 VRAM 不足 2GB ({vram_limit - vram_reserved:.1f} GB)，训练可能 OOM！")
        print("建议: 减小 --max-length 或确保无其他 GPU 进程")

    # 训练
    print(f"\n开始 DPO 训练: {args.epochs} epochs, lr={args.lr}, beta={args.beta}, seed={args.seed}")
    print(f"train={len(dataset)} 对偏好对")
    print(f"输出目录: {output_dir}")
    try:
        train_result = trainer.train()
    except RuntimeError as e:
        if "out of memory" in str(e).lower() or "CUDA" in str(e):
            print(f"\nGPU OOM 错误: {e}")
            print("尝试释放显存...")
            torch.cuda.empty_cache()
            raise SystemExit(1) from e
        raise

    # 保存模型
    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    print(f"\nDPO adapter 已保存到: {best_dir}")

    # 训练指标
    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # 打印训练日志
    if trainer.state.log_history:
        print("\n训练 loss 历史:")
        for entry in trainer.state.log_history:
            if "loss" in entry:
                print(f"  epoch={entry.get('epoch', '?'):.2f}  loss={entry['loss']:.4f}"
                      f"  rewards/accuracies={entry.get('rewards/accuracies', '?')}")

    # 保存训练日志
    log_file = LOG_DIR / f"dpo_log_r{args.lora_r}_e{args.epochs}_beta{args.beta}_s{args.seed}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": args.model_id,
                "quantization": "4bit" if bnb_config else "fp16",
                "train_samples": len(dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")


if __name__ == "__main__":
    main()
