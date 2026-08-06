"""QLoRA 微调脚本 —— 云端版（A100/H100 80GB，fp16/bf16 原生训练，无需 4bit 量化）。

与本地版 train_qlora.py 的区别：
  - 去掉 ROCm 特性（HIP bug 规避、fp32 提升、eager attention 等）
  - 使用 bf16 原生混合精度（A100+ 支持，比 fp16 更稳，无 GradScaler，不会 NaN）
  - 不用 bitsandbytes 4bit 量化（本地 16GB 才需要；云端 80GB 直接跑 fp16）
  - max_seq_length 默认 4096：覆盖最终数据全部 7692 条（max=3895 tokens），无需压缩数据
  - batch_size 默认 4 + grad_accum 2 = 有效 batch 8，梯度更稳

方法：LoRA（默认 r=8, alpha=16, rsLoRA 默认开启）+ 梯度检查点
数据：experiments/exp_06_finetune/data/quality/final_train_chatml_quality_final.jsonl（最终 7692 条，归一化 CWE + 统一 prompt + 60 hard samples）

用法（云端已装 torch/torchvision/transformers/trl/peft/datasets）：


说明：
  - bf16 原生训练，数值稳定，不会出现本地 4bit 的 NaN/梯度爆炸
  - load_best_model_at_end=True 自动选 dev loss 最低的 checkpoint
  - 默认禁用 early stopping（和本地成功配方一致，让 cosine 走完）
  - 数据太大可选 --subset 限制条数做快速验证
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
)
from trl import SFTConfig, SFTTrainer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/quality/final_train_chatml_quality_final.jsonl"
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
MODEL_ID = "Qwen/Qwen3-8B"


def load_chatml_dataset(path: Path, subset: int | None = None) -> Dataset:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    if subset is not None:
        records = records[:subset]
    print(f"加载 {len(records)} 条样本")
    return Dataset.from_list(records)


def split_train_dev(dataset: Dataset, dev_ratio: float, seed: int = 42):
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


def main():
    parser = argparse.ArgumentParser(description="云端 QLoRA 微调 Qwen3-8B（bf16 原生）")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=4, help="每设备 batch size（云端 80GB，默认 4）")
    parser.add_argument("--grad-accum", type=int, default=2, help="梯度累积（默认 2，有效 batch=8）")
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=16)
    parser.add_argument("--lora-dropout", type=float, default=0.1)
    parser.add_argument("--no-rslora", action="store_true",
                        help="禁用 rsLoRA（默认开启：Phase1 sweep 表明 lr=1e-4 + rsLoRA(r=8) 最优）")
    parser.add_argument("--max-seq-length", type=int, default=4096,
                        help="默认 4096，覆盖最终数据全部（实测 max=3895 tokens）")
    parser.add_argument("--save-steps", type=int, default=200)
    parser.add_argument("--eval-steps", type=int, default=None)
    parser.add_argument("--logging-steps", type=int, default=5)
    parser.add_argument("--warmup-ratio", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model-id", type=str, default=MODEL_ID)
    parser.add_argument("--data-file", type=str, default=None)
    parser.add_argument("--dev-ratio", type=float, default=0.15)
    parser.add_argument("--no-early-stopping", action="store_true")
    parser.add_argument("--early-stopping-patience", type=int, default=2)
    parser.add_argument("--no-load-best", action="store_true")
    parser.add_argument("--output-suffix", type=str, default="")
    parser.add_argument("--subset", type=int, default=None, help="只取前 N 条（快速验证用）")
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--dtype", type=str, default="bf16", choices=["bf16", "fp16"],
                        help="混合精度（A100+ 用 bf16；旧卡无 bf16 用 fp16）")
    args = parser.parse_args()

    data_file = Path(args.data_file) if args.data_file else DATA_FILE
    use_bf16 = args.dtype == "bf16"
    use_rslora = not args.no_rslora

    if not torch.cuda.is_available():
        print("错误：未检测到 GPU")
        sys.exit(1)
    n_gpus = torch.cuda.device_count()
    print(f"检测到 GPU 数量: {n_gpus}")
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    print(f"训练数据: {data_file}")
    full_dataset = load_chatml_dataset(data_file, args.subset)
    train_dataset, dev_dataset = split_train_dev(full_dataset, args.dev_ratio, seed=42)

    print(f"加载 tokenizer: {args.model_id}")
    tokenizer = AutoTokenizer.from_pretrained(args.model_id, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if "qwen3" in args.model_id.lower():
        _orig_apply = tokenizer.apply_chat_template
        def _patched_apply(*args, **kwargs):
            kwargs.setdefault("enable_thinking", False)
            return _orig_apply(*args, **kwargs)
        tokenizer.apply_chat_template = _patched_apply
        print("Qwen3: 已 patch apply_chat_template 默认 enable_thinking=False")

    print(f"加载模型: {args.model_id} ({args.dtype} 原生，无量化)")
    model = AutoModelForCausalLM.from_pretrained(
        args.model_id,
        torch_dtype=torch.bfloat16 if use_bf16 else torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        use_rslora=use_rslora,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    peft_tags = []
    if use_rslora:
        peft_tags.append("rslora")
    peft_tag = ("_" + "_".join(peft_tags)) if peft_tags else ""
    print(f"LoRA: r={args.lora_r} alpha={args.lora_alpha} dropout={args.lora_dropout} rslora={use_rslora}")
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    output_dir = OUTPUT_DIR / f"lora_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}"
    output_dir.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    short_run = args.max_steps > 0

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        max_grad_norm=1.0,
        logging_steps=args.logging_steps,
        save_strategy="no" if short_run else "steps",
        save_steps=args.save_steps,
        save_total_limit=10,
        max_steps=args.max_steps,
        bf16=use_bf16,
        fp16=not use_bf16,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="adamw_torch",
        weight_decay=0.01,
        seed=args.seed,
        max_length=args.max_seq_length,
        packing=False,
        dataset_text_field=None,
        assistant_only_loss=True,  # 只对 assistant 部分计算 loss
        report_to="none",
        logging_dir=str(LOG_DIR),
        eval_strategy="no" if short_run else "steps",
        eval_steps=args.eval_steps if args.eval_steps else args.save_steps,
        load_best_model_at_end=(not short_run) and (not args.no_load_best),
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        per_device_eval_batch_size=args.batch_size,
        dataloader_pin_memory=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=dev_dataset,
        processing_class=tokenizer,
    )

    print(f"\n开始训练: {args.epochs} epochs, lr={args.lr}, batch={args.batch_size}x{args.grad_accum}, seed={args.seed}")
    print(f"train={len(train_dataset)} dev={len(dev_dataset)}")
    print(f"输出目录: {output_dir}")
    train_result = trainer.train()

    if short_run:
        print(f"\n✅ 短跑模式完成（max_steps={args.max_steps}），不保存模型")
        for k, v in train_result.metrics.items():
            print(f"   {k}: {v}")
        return

    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    if args.no_load_best:
        print(f"\n（--no-load-best：model 为 final 状态）LoRA adapter 已保存到: {best_dir}")
    else:
        print(f"\nBest LoRA adapter（按 dev_loss 选）已保存到: {best_dir}")

    metrics = train_result.metrics
    print("\n训练指标:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    if trainer.state.log_history:
        print("\nDev loss 历史:")
        for entry in trainer.state.log_history:
            if "eval_loss" in entry:
                print(f"  epoch={entry.get('epoch', 0):.2f}  eval_loss={entry['eval_loss']:.4f}")

    log_file = LOG_DIR / f"train_log_cloud_r{args.lora_r}_e{args.epochs}_lr{args.lr:g}_s{args.seed}{peft_tag}{args.output_suffix}.json"
    with open(log_file, "w") as f:
        json.dump(
            {
                "args": vars(args),
                "metrics": metrics,
                "model": args.model_id,
                "dtype": args.dtype,
                "train_samples": len(train_dataset),
                "dev_samples": len(dev_dataset),
                "log_history": trainer.state.log_history,
            },
            f, indent=2, ensure_ascii=False,
        )
    print(f"训练日志: {log_file}")


if __name__ == "__main__":
    main()