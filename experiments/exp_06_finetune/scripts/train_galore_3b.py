"""
GaLore 全参数微调脚本（Phase 7 兜底方案）—— 3B 模型在 16GB 显存上的全参数训练。

对应 docs/方法.md §9 Phase 7，原理见 §8.2 GaLore。
论文：GaLore (Zhao et al. 2024, arXiv:2403.07404)

原理：
  GaLore 把梯度投影到低秩空间再优化，全参数训练但显存接近 LoRA。
  论文证明能在 24GB 显存上跑 7B 全参数微调，3B 模型在 16GB 上理论可行。

显存核算（3B fp16 全参数 + GaLore）：
  | 组成                  | 3B fp16  |
  |----------------------|----------|
  | 模型参数 (fp16)        | 6 GB     |
  | 梯度 (fp16)            | 6 GB     |
  | GaLore AdamW 状态 (低秩) | ~2-4 GB  |
  | 激活值 (梯度检查点后)     | ~2 GB    |
  | **总计**              | **~16 GB** |

  vs 标准 AdamW 全参数微调需要 ~62GB（详见 §4 L4），GaLore 节省 4x。

⚠️ ROCm 兼容性待验证：
  - GaLore 依赖 SVD 分解，ROCm 上 rocSOLVER 应支持，但未实测
  - bitsandbytes 的 GaLore 8bit 变体在 RDNA4 上可能有 paged_adamw_8bit 同类 bug（§12.2 P0）
  - 建议先用 galore_adamw（非 8bit）验证，再试 galore_adamw_8bit
  - 若 SVD 报错或 loss 异常，回退到 Phase 2 的 r=32 LoRA 方案

设计要点：
  - 全参数微调（不挂 LoRA），所有参数 trainable
  - 3B 模型 fp16（不量化，全参数需要 fp16）
  - GaLore 优化器：optim="galore_adamw"，rank=128 投影
  - 混入 20% 通用代码数据防遗忘（§4 L4 建议，可选）
  - assistant_only_loss=True（SFT，学漏洞检测技能）
  - 梯度检查点 + eval_accumulation_steps 省显存

数据：experiments/exp_06_finetune/data/train_chatml_v2.jsonl（823 条 ChatML 样本）
基座：Qwen/Qwen2.5-Coder-3B-Instruct（fp16，不量化）

用法（在 AI conda 环境中运行，需 GPU）：
  # 标准 GaLore（推荐，先验证兼容性）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_galore_3b.py \\
      --epochs 2 --lr 2e-5 --galore-rank 128

  # 8bit GaLore（更省显存，但有 bnb bug 风险）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_galore_3b.py \\
      --epochs 2 --lr 2e-5 --galore-rank 128 --galore-8bit

  # 测试模式（max_steps=5，验证脚本能跑通）
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_galore_3b.py --test

输出：
  outputs/galore_3b_r128_e2_lr2e-5/best/   - 全参数微调后的模型
  logs/train_log_galore_3b_*.json           - 训练日志
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

# ROCm 多设备保护
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    EarlyStoppingCallback,
    TrainingArguments,
)
from trl import SFTConfig, SFTTrainer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/train_chatml_v2.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
MODEL_ID = "Qwen/Qwen2.5-Coder-3B-Instruct"  # 3B fp16 全参数，16GB 可行

# GaLore 投影的目标模块（与 LoRA target_modules 一致，7 个 proj）
GALORE_TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
]


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
    """按 dev_ratio 分拆训练集与验证集（与 train_qlora.py 一致，保证 dev 集对齐）。"""
    n = len(dataset)
    n_dev = max(1, int(n * dev_ratio))
    rng = random.Random(seed)
    indices = list(range(n))
    rng.shuffle(indices)
    dev_indices = set(indices[:n_dev])
    train_records = [dataset[i] for i in range(n) if i not in dev_indices]
    dev_records = [dataset[i] for i in range(n) if i in dev_indices]
    print(f"分拆：train={len(train_records)} dev={len(dev_records)}（dev_ratio={dev_ratio}）")
    return Dataset.from_list(train_records), Dataset.from_list(dev_records)


def parse_args():
    p = argparse.ArgumentParser(description="GaLore 全参数微调 Qwen2.5-Coder-3B-Instruct")
    p.add_argument("--epochs", type=int, default=2,
                   help="训练轮数（默认 2；全参数微调比 LoRA 慢，不宜多轮）")
    p.add_argument("--batch-size", type=int, default=1, help="每设备 batch size")
    p.add_argument("--grad-accum", type=int, default=16,
                   help="梯度累积步数（默认 16，比 LoRA 的 8 大，弥补小 batch）")
    p.add_argument("--lr", type=float, default=2e-5,
                   help="学习率（默认 2e-5；全参数微调 lr 比 LoRA 低，LoRA 的 1e-5 对全参数太保守）")
    p.add_argument("--galore-rank", type=int, default=128,
                   help="GaLore 梯度投影 rank（默认 128；论文推荐 128-256）")
    p.add_argument("--galore-update-proj-gap", type=int, default=200,
                   help="GaLore 重新投影的间隔 step（默认 200）")
    p.add_argument("--galore-scale", type=float, default=0.25,
                   help="GaLore 梯度缩放因子（默认 0.25）")
    p.add_argument("--galore-8bit", action="store_true",
                   help="用 galore_adamw_8bit（更省显存，但有 bnb bug 风险，§12.2 P0）")
    p.add_argument("--max-seq-length", type=int, default=2048, help="最大序列长度")
    p.add_argument("--save-steps", type=int, default=50, help="每 N 步保存")
    p.add_argument("--logging-steps", type=int, default=5, help="每 N 步记录日志")
    p.add_argument("--warmup-ratio", type=float, default=0.05, help="warmup 比例")
    p.add_argument("--seed", type=int, default=42, help="随机种子")
    p.add_argument("--model-id", type=str, default=MODEL_ID,
                   help=f"基座模型 ID（默认 {MODEL_ID}，3B fp16 全参数）")
    p.add_argument("--data-file", type=str, default=None,
                   help="训练数据 jsonl 路径（默认 data/train_chatml_v2.jsonl）")
    p.add_argument("--dev-ratio", type=float, default=0.15,
                   help="验证集比例（默认 0.15）")
    p.add_argument("--early-stopping-patience", type=int, default=2,
                   help="EarlyStopping 耐心值（默认 2）")
    p.add_argument("--no-early-stopping", action="store_true",
                   help="禁用 early stopping")
    p.add_argument("--test", action="store_true",
                   help="测试模式：max_steps=5，验证脚本能跑通 + ROCm 兼容性")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 70)
    print("GaLore 全参数微调（Phase 7 兜底方案）")
    print("=" * 70)
    print(f"基座模型: {args.model_id} (fp16, 全参数)")
    print(f"GaLore: rank={args.galore_rank} update_proj_gap={args.galore_update_proj_gap}"
          f" scale={args.galore_scale} 8bit={args.galore_8bit}")
    print(f"训练: epochs={args.epochs} lr={args.lr} batch={args.batch_size}x{args.grad_accum}")
    print(f"⚠️ ROCm 兼容性待验证：若 SVD 报错或 loss NaN，回退到 Phase 2 r=32 LoRA")

    # 检查 GPU
    if not torch.cuda.is_available():
        print("\n❌ 未检测到 CUDA/HIP GPU")
        sys.exit(1)
    print(f"\nGPU: {torch.cuda.get_device_name(0)}")
    vram_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
    print(f"VRAM: {vram_gb:.2f} GB")
    if vram_gb < 15:
        print(f"⚠️ VRAM < 15GB，3B GaLore 全参数微调可能 OOM（需 ~16GB）")

    # 解析数据文件
    data_file = Path(args.data_file) if args.data_file else DATA_FILE

    # 加载数据
    print(f"\n训练数据: {data_file}")
    full_dataset = load_chatml_dataset(data_file)
    train_dataset, dev_dataset = split_train_dev(full_dataset, args.dev_ratio, seed=42)

    # 加载 tokenizer
    print(f"\n加载 tokenizer: {args.model_id}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 加载模型（fp16，不量化，全参数微调）
    print(f"\n加载模型: {args.model_id} (fp16, 全参数)")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        device_map={"": 0},  # 强制单 GPU
        trust_remote_code=True,
        torch_dtype=torch.float16,
        attn_implementation="sdpa",  # ROCm 上 sdpa 已验证可用
    )
    model.config.use_cache = False
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    model.enable_input_require_grads()  # 梯度检查点需要

    # 全参数微调：所有参数都 trainable
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"\n全参数微调：trainable={trainable/1e9:.2f}B / total={total/1e9:.2f}B (100%)")

    # GaLore 优化器配置
    # transformers 4.41+ 支持 optim="galore_adamw"，通过 optim_args 传 GaLore 参数
    # optim_target_modules 指定哪些模块做 GaLore 投影（其余模块用标准 AdamW）
    optim_name = "galore_adamw_8bit" if args.galore_8bit else "galore_adamw"
    optim_args = {
        "rank": args.galore_rank,
        "update_proj_gap": args.galore_update_proj_gap,
        "scale": args.galore_scale,
    }
    print(f"\n优化器: {optim_name}")
    print(f"  optim_args: {optim_args}")
    print(f"  target_modules: {GALORE_TARGET_MODULES}")
    if args.galore_8bit:
        print(f"  ⚠️ 8bit 模式有 bnb paged_adamw_8bit 同类 bug 风险（§12.2 P0），"
              f"建议先验证 galore_adamw（非 8bit）稳定后再试")

    # 输出目录
    bit_tag = "_8bit" if args.galore_8bit else ""
    output_subdir = f"galore_3b_r{args.galore_rank}_e{args.epochs}_lr{args.lr:g}{bit_tag}"
    output_dir = OUTPUT_DIR / output_subdir
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    print(f"输出目录: {output_dir}")

    # SFT 配置
    # 注意：GaLore 的 optim_args 和 optim_target_modules 是 transformers 4.41+ 参数
    # 若版本过低会报 TypeError，捕获后提示升级
    sft_config_kwargs = dict(
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
        fp16=True,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim=optim_name,
        seed=args.seed,
        max_length=args.max_seq_length,
        packing=False,
        dataset_text_field=None,
        assistant_only_loss=True,
        report_to="none",
        logging_dir=str(LOG_DIR),
        eval_strategy="epoch",
        eval_steps=None,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        save_strategy="epoch",
        per_device_eval_batch_size=1,
        eval_accumulation_steps=16,
        dataloader_pin_memory=False,
    )

    # 测试模式：限制 max_steps
    if args.test:
        sft_config_kwargs["max_steps"] = 5
        sft_config_kwargs["save_strategy"] = "no"
        sft_config_kwargs["load_best_model_at_end"] = False
        sft_config_kwargs["eval_strategy"] = "no"
        print("\n⚠️ 测试模式：max_steps=5，不存盘不评估，只验证脚本能跑通")

    # 尝试构建 SFTConfig（GaLore 参数可能因 transformers 版本不支持）
    try:
        sft_config = SFTConfig(**sft_config_kwargs)
    except TypeError as e:
        if "optim_args" in str(e) or "optim_target_modules" in str(e):
            print(f"\n❌ 当前 transformers 版本不支持 GaLore 集成参数：{e}")
            print(f"   需升级到 transformers >= 4.41：")
            print(f"   pip install -U 'transformers>=4.41'")
            print(f"   或改用 GaLore 原生优化器（from gallora import GaLoreOptim）")
            sys.exit(1)
        raise

    # EarlyStopping
    callbacks = []
    if not args.no_early_stopping and not args.test:
        callbacks.append(EarlyStoppingCallback(
            early_stopping_patience=args.early_stopping_patience,
            early_stopping_threshold=0.001,
        ))
        print(f"启用 EarlyStopping：patience={args.early_stopping_patience}")

    # Trainer
    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=dev_dataset if not args.test else None,
        processing_class=tokenizer,
        callbacks=callbacks,
    )

    # 训练
    print(f"\n开始 GaLore 全参数微调...")
    print(f"  监控点：前 5 step 若 loss=NaN 或 SVD 报错 → ROCm 不兼容，立即 Ctrl+C")
    try:
        train_result = trainer.train()
    except RuntimeError as e:
        if "svd" in str(e).lower() or "lusolver" in str(e).lower():
            print(f"\n❌ GaLore SVD 在 ROCm 上不兼容：{e}")
            print(f"   回退方案：bash experiments/exp_06_finetune/scripts/run_phase2_sft.sh")
            sys.exit(2)
        if "out of memory" in str(e).lower():
            print(f"\n❌ OOM：3B GaLore 全参数微调在 {vram_gb:.1f}GB 上显存不足")
            print(f"   尝试：--galore-8bit（省 ~2GB）或 --max-seq-length 1024（省激活值）")
            sys.exit(3)
        raise

    if args.test:
        print("\n✅ 测试模式通过：GaLore 在 ROCm 上可运行")
        print(f"   前 5 step loss 曲线：")
        for entry in trainer.state.log_history:
            if "loss" in entry:
                print(f"   step={entry.get('step', '?')} loss={entry['loss']:.4f}")
        return

    # 保存 best 模型（全参数，不是 adapter）
    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    print(f"\n✅ Best 全参数模型已保存到: {best_dir}")
    print(f"   注意：全参数模型 ~6GB（fp16），不是 LoRA adapter")

    # 训练指标
    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # dev loss 历史
    if trainer.state.log_history:
        print("\nDev loss 历史:")
        for entry in trainer.state.log_history:
            if "eval_loss" in entry:
                print(f"  epoch={entry.get('epoch', '?'):.2f}  eval_loss={entry['eval_loss']:.4f}")

    # 保存训练日志
    log_file = LOG_DIR / f"train_log_galore_3b_r{args.galore_rank}_e{args.epochs}_lr{args.lr:g}{bit_tag}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": args.model_id,
                "method": "galore_full_finetune",
                "train_samples": len(train_dataset),
                "dev_samples": len(dev_dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")

    print(f"\n下一步：评估")
    print(f"  ${AI_PYTHON:-python} {PROJECT_ROOT}/experiments/exp_06_finetune/scripts/evaluate.py \\")
    print(f"      --model {best_dir} --temperature 0.0")


if __name__ == "__main__":
    main()
