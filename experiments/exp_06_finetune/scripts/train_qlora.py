"""
QLoRA 微调脚本 —— 支持 Qwen2.5-Coder-7B-Instruct（4bit）或 3B（fp16）。

数据：experiments/exp_06_finetune/data/train_chatml_v2.jsonl（760 条 ChatML 样本）
基座：Qwen/Qwen2.5-Coder-7B-Instruct（默认，4bit QLoRA）
      Qwen/Qwen2.5-Coder-3B-Instruct（--model-id 指定，fp16 LoRA）
方法：4bit NF4 量化 + LoRA（r=16, alpha=32）+ 梯度检查点
硬件：AMD Radeon RX 9060 XT 16GB + ROCm 7.2
      7B 4bit 实测：加载 6GB，LoRA 挂载 10.9GB，前向+反向峰值 11.0GB（余量 6GB）

防过拟合措施：
  - 从训练集分 15% 作 dev，按 dev loss 选 best checkpoint
  - EarlyStoppingCallback：dev loss 连续 patience 轮不降则停
  - load_best_model_at_end=True：训练结束自动回滚到 best checkpoint
  - 推荐 epochs=3, lr=1e-4

用法（在 AI conda 环境中运行，需 GPU 访问）：
  # 7B 4bit QLoRA（默认）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_qlora.py \
      --epochs 3 --batch-size 1 --grad-accum 8 --lr 1e-4

  # 3B fp16（用 --no-4bit + --model-id 切换）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_qlora.py \
      --model-id Qwen/Qwen2.5-Coder-3B-Instruct --no-4bit
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

# ROCm 可能报告多个 GPU 设备，在 import torch 前强制只用 GPU 0
# 防止 Trainer 自动启用 DataParallel 跨不存在设备导致 "invalid device ordinal"
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    EarlyStoppingCallback,
    TrainingArguments,
)
from trl import SFTConfig, SFTTrainer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/train_chatml_v2.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"  # 默认 7B，4bit QLoRA 实测可行


def load_chatml_dataset(path: Path) -> Dataset:
    """加载 ChatML jsonl 为 HF Dataset。"""
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    print(f"加载 {len(records)} 条样本")
    return Dataset.from_list(records)


def split_train_dev(dataset: Dataset, dev_ratio: float, seed: int = 42) -> tuple[Dataset, Dataset]:
    """按 dev_ratio 分拆训练集与验证集（P0 改造：避免过拟合，按 dev loss 选 best）。

    用 seed 固定随机性，保证多种子训练时 dev 集一致（仅训练种子不同）。
    返回 (train_dataset, dev_dataset)。
    """
    n = len(dataset)
    n_dev = max(1, int(n * dev_ratio))
    n_train = n - n_dev
    # 用 seed 打乱索引
    rng = random.Random(seed)
    indices = list(range(n))
    rng.shuffle(indices)
    dev_indices = set(indices[:n_dev])
    train_records = [dataset[i] for i in range(n) if i not in dev_indices]
    dev_records = [dataset[i] for i in range(n) if i in dev_indices]
    print(f"分拆：train={len(train_records)} dev={len(dev_records)}（dev_ratio={dev_ratio}）")
    return Dataset.from_list(train_records), Dataset.from_list(dev_records)


def try_4bit_quant(use_4bit: bool) -> BitsAndBytesConfig | None:
    """配置 4bit 量化。bitsandbytes 在 ROCm 上易段错误，默认禁用。"""
    if not use_4bit:
        print("禁用 4bit 量化（fp16 LoRA + 梯度检查点模式）")
        return None
    try:
        import bitsandbytes as bnb  # noqa: F401
        print(f"bitsandbytes {bnb.__version__} 可用，尝试 4bit 量化")
        return BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
    except Exception as e:
        print(f"bitsandbytes 4bit 不可用: {e}")
        print("降级为 fp16 LoRA + 梯度检查点")
        return None


def main():
    parser = argparse.ArgumentParser(description="QLoRA 微调 Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--epochs", type=int, default=2, help="训练轮数（默认 2，避免过拟合）")
    parser.add_argument("--batch-size", type=int, default=1, help="每设备 batch size")
    parser.add_argument("--grad-accum", type=int, default=8, help="梯度累积步数")
    parser.add_argument("--lr", type=float, default=5e-5, help="学习率（LoRA 推荐 1e-5 ~ 5e-5）")
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=32, help="LoRA alpha")
    parser.add_argument("--max-seq-length", type=int, default=2048, help="最大序列长度")
    parser.add_argument("--save-steps", type=int, default=50, help="每 N 步保存")
    parser.add_argument("--logging-steps", type=int, default=5, help="每 N 步记录日志")
    parser.add_argument("--warmup-ratio", type=float, default=0.05, help="warmup 比例")
    parser.add_argument("--seed", type=int, default=42, help="随机种子")
    parser.add_argument("--model-id", type=str, default=MODEL_ID,
                        help=f"基座模型 ID（默认 {MODEL_ID}）")
    parser.add_argument("--no-4bit", action="store_true",
                        help="禁用 4bit 量化，用 fp16（3B 模型可用；7B fp16 在 16GB 上 OOM）")
    parser.add_argument("--data-file", type=str, default=None,
                        help="训练数据 jsonl 路径（默认 data/train_chatml_v2.jsonl）")
    # P0 改造：验证集 + early stopping
    parser.add_argument("--dev-ratio", type=float, default=0.15,
                        help="验证集比例（默认 0.15，即 15%% 作 dev）")
    parser.add_argument("--early-stopping-patience", type=int, default=2,
                        help="EarlyStopping 耐心值：dev loss 连续 N 轮不降则停（默认 2）")
    parser.add_argument("--no-early-stopping", action="store_true",
                        help="禁用 early stopping（仍会分 dev 集评估，但不提前停）")
    args = parser.parse_args()

    # 解析数据文件路径
    data_file = Path(args.data_file) if args.data_file else DATA_FILE
    model_id = args.model_id
    use_4bit = not args.no_4bit

    # 检查 GPU
    if not torch.cuda.is_available():
        print("错误：未检测到 CUDA/HIP GPU。请在有 GPU 的环境中运行。")
        print("提示：若在 IDE 沙箱中，需在真实终端运行此脚本。")
        sys.exit(1)
    n_gpus = torch.cuda.device_count()
    print(f"检测到 GPU 数量: {n_gpus}")
    if n_gpus > 1:
        print(f"警告：检测到 {n_gpus} 个 GPU，但单卡训练模式只使用 GPU 0。")
        print("  设置 CUDA_VISIBLE_DEVICES=0 避免多 GPU DataParallel 报错。")
        os.environ["CUDA_VISIBLE_DEVICES"] = "0"
        os.environ["HIP_VISIBLE_DEVICES"] = "0"
        # 重新检查（环境变量需在 torch.cuda 初始化前设置才生效，
        # 若已初始化则只能警告，建议用户在运行脚本前设置）
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    # 加载数据并分拆 dev
    print(f"训练数据: {data_file}")
    full_dataset = load_chatml_dataset(data_file)
    train_dataset, dev_dataset = split_train_dev(full_dataset, args.dev_ratio, seed=42)

    # 加载 tokenizer
    print(f"加载 tokenizer: {model_id}")
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 加载模型（4bit 或 fp16）
    bnb_config = try_4bit_quant(use_4bit)
    print(f"加载模型: {model_id} ({'4bit' if bnb_config else 'fp16'})")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map={"": 0},  # ROCm 上 "auto" 易段错误，强制单 GPU
        trust_remote_code=True,
        torch_dtype=torch.float16,
        attn_implementation="sdpa",  # sdpa 比 eager 省显存（避免 OOM），ROCm 上已验证可用
    )
    model.config.use_cache = False  # 训练时关闭 KV cache

    # 准备 kbit 训练
    if bnb_config is not None:
        model = prepare_model_for_kbit_training(model)
    else:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()

    # LoRA 配置
    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.1,  # 增加 dropout 防止过拟合
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # SFT 配置（P0 改造：加 eval + load_best）
    output_dir = OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_s{args.seed}"
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        save_total_limit=3,
        bf16=False,  # RDNA4 不支持 bf16
        fp16=bnb_config is None,  # 4bit 模式下禁用 fp16 GradScaler（与 BFloat16 梯度冲突）
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="paged_adamw_8bit" if bnb_config is not None else "adamw_torch",
        seed=args.seed,
        max_length=args.max_seq_length,  # TRL 1.7+ 改名为 max_length
        packing=False,  # ROCm 上 packing 需 flash-attn，关闭避免 cross-contamination + 省 VRAM
        dataset_text_field=None,  # 使用 messages 字段
        assistant_only_loss=True,  # 只对 assistant 部分计算 loss
        report_to="none",
        logging_dir=str(LOG_DIR),
        # P0 改造：验证集评估 + best checkpoint
        eval_strategy="epoch",  # 每 epoch 评估 dev
        eval_steps=None,  # epoch 级别评估，不需 steps
        load_best_model_at_end=True,  # 训练结束回滚到 best checkpoint
        metric_for_best_model="eval_loss",  # 按 dev loss 选 best
        greater_is_better=False,  # loss 越小越好
        save_strategy="epoch",  # 与 eval 对齐，每 epoch 存
    )

    # EarlyStoppingCallback
    callbacks = []
    if not args.no_early_stopping:
        callbacks.append(EarlyStoppingCallback(
            early_stopping_patience=args.early_stopping_patience,
            early_stopping_threshold=0.001,  # dev loss 降幅 < 0.001 视为无改善
        ))
        print(f"启用 EarlyStopping：patience={args.early_stopping_patience}, threshold=0.001")
    else:
        print("禁用 EarlyStopping（仍会评估 dev 并存 best checkpoint）")

    # Trainer
    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=dev_dataset,  # P0 改造：传入 dev 集
        processing_class=tokenizer,
        callbacks=callbacks,
    )

    # 训练
    print(f"\n开始训练: {args.epochs} epochs, lr={args.lr}, batch={args.batch_size}x{args.grad_accum}, seed={args.seed}")
    print(f"train={len(train_dataset)} dev={len(dev_dataset)}")
    print(f"输出目录: {output_dir}")
    train_result = trainer.train()

    # 保存 best 模型（load_best_model_at_end=True 已把 best 加载回 model）
    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    print(f"\nBest LoRA adapter（按 dev_loss 选）已保存到: {best_dir}")

    # 也保存 final（训练结束时的状态，可能不是 best）
    final_dir = output_dir / "final"
    # 注意：load_best_model_at_end=True 时 model 已是 best，final 与 best 相同
    # 但 trainer_state 记录了完整训练过程
    print(f"（load_best_model_at_end=True，final 即 best）")

    # 训练指标
    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # 打印 dev 评估历史
    if trainer.state.log_history:
        print("\nDev loss 历史:")
        for entry in trainer.state.log_history:
            if "eval_loss" in entry:
                print(f"  epoch={entry.get('epoch', '?'):.2f}  eval_loss={entry['eval_loss']:.4f}")

    # 保存训练日志
    log_file = LOG_DIR / f"train_log_r{args.lora_r}_e{args.epochs}_s{args.seed}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": model_id,
                "quantization": "4bit" if bnb_config else "fp16",
                "train_samples": len(train_dataset),
                "dev_samples": len(dev_dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")


if __name__ == "__main__":
    main()
