"""
KnItLM 知识注入脚本（Phase 3）—— 在 base model 上做 CPT with LoRA，
合并到 Instruct 模型，注入漏洞领域知识而不破坏 instruction following。

对应 docs/方法.md §9 Phase 3，原理见 §8.3 KnItLM。
论文：KnItLM (ICLR 2026 投稿, https://openreview.net/forum?id=2uctT30vTS)

流程：
  Stage A: 加载 Qwen3-8B-Base（非 Instruct）
          在 cpt_corpus.jsonl 上做 causal LM CPT with LoRA
          得到注入漏洞知识的 LoRA adapter

  Stage B: 加载 Qwen3-8B
          merge Stage A 的 LoRA adapter 进去
          保存合并后的 Instruct 模型（既懂漏洞知识又不丢对话能力）
          见 merge_lora_to_instruct.py

设计要点：
  - 必须用 base 模型而非 Instruct，避免 CPT 破坏对话能力
  - 用 causal LM loss（next token prediction），不是 SFT loss
  - 不做 assistant_only_loss（CPT 学的是整个文本的分布）
  - LoRA rank 可以大一些（r=64），因为 CPT 容量需求高
  - 4bit QLoRA 在 16GB 上跑 7B base

硬件：AMD Radeon RX 9060 XT 16GB + ROCm 7.2
模型：Qwen3-8B-Base（非 Instruct）

用法（在 AI conda 环境中运行，需 GPU）：
  HF_HUB_OFFLINE=1 python3 train_knitlm_cpt.py \\
      --epochs 1 --lr 2e-5 --lora-r 64 --lora-alpha 128

输出：
  outputs/knitlm_cpt_r64_a128_e1_lr2e-5/best/   - CPT LoRA adapter
  logs/train_log_knitlm_cpt_*.json                - 训练日志
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ROCm 多设备保护
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
# 离线模式
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
# RDNA4 注意力优化：AOTRITON 提供 ~58% step time 降低
os.environ.setdefault("TORCH_ROCM_AOTRITON_ENABLE_EXPERIMENTAL", "1")

import torch

# TunableOp 启用（PyTorch 2.11+ 三种模式：recording / tuning / deploy）
# 参考 docs/方法.md §12.2.2：必须用 Python API 显式启用，环境变量不够
if os.environ.get("PYTORCH_TUNABLEOP_ENABLED", "0") == "1":
    try:
        t = torch.cuda.tunable
        t.enable(True)
        if os.environ.get("PYTORCH_TUNABLEOP_RECORD_UNTUNED", "0") == "1":
            t.record_untuned_enable(True)
            t.tuning_enable(False)
        else:
            t.tuning_enable(False)
            tuned_csv = os.environ.get("PYTORCH_TUNABLEOP_FILE_NAME")
            if tuned_csv:
                t.set_filename(tuned_csv)
        print(f"TunableOp 已启用: enabled={t.is_enabled()} "
              f"tuning={t.tuning_is_enabled()} "
              f"record_untuned={t.record_untuned_is_enabled()} "
              f"file={t.get_filename()}")
    except Exception as e:
        print(f"⚠️ TunableOp 启用失败: {e}")

from datasets import Dataset
from torch.utils.data import WeightedRandomSampler, DataLoader
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from peft import LoraConfig, get_peft_model, TaskType
from transformers.data.data_collator import DataCollatorForLanguageModeling

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"

# ⚠️ 关键：用 BASE 模型而非 Instruct
# Qwen3-8B-Base 是纯 CPT 基座，没有 instruction tuning
BASE_MODEL_ID = "Qwen/Qwen3-8B-Base"
CORPUS_FILE = DATA_DIR / "cpt_corpus.jsonl"


def parse_args():
    p = argparse.ArgumentParser(description="KnItLM CPT 训练（base model）")
    p.add_argument("--corpus", type=Path, default=CORPUS_FILE,
                   help="CPT 语料文件（默认 cpt_corpus.jsonl）")
    p.add_argument("--model", type=str, default=BASE_MODEL_ID,
                   help=f"base 模型 ID（默认 {BASE_MODEL_ID}）")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--lr", type=float, default=2e-5, help="CPT lr（默认 2e-5，比 SFT 低）")
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=16)
    p.add_argument("--max-seq-length", type=int, default=2048, help="CPT 上下文长度")
    p.add_argument("--lora-r", type=int, default=64, help="CPT LoRA rank（默认 64）")
    p.add_argument("--lora-alpha", type=int, default=128)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--use-rslora", action=argparse.BooleanOptionalAction, default=True,
                   help="启用 rsLoRA（CPT 默认开启，§9 Phase 1 已验证有效；用 --no-use-rslora 关闭）")
    p.add_argument("--warmup-ratio", type=float, default=0.05)
    p.add_argument("--logging-steps", type=int, default=10)
    p.add_argument("--save-steps", type=int, default=10)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-steps", type=int, default=0,
                   help="最大训练步数（>0 时覆盖 epochs，用于稳定性测试）")
    p.add_argument("--early-stopping", action="store_true", default=False,
                   help="启用 EarlyStopping（CPT 默认不启用：raw text 语料 dev_loss 波动大）")
    p.add_argument("--early-stopping-patience", type=int, default=3)
    p.add_argument("--dev-ratio", type=float, default=0.05,
                   help="dev 集比例（CPT 默认 5%，比 SFT 的 15% 少）")
    return p.parse_args()


def load_corpus(path: Path, dev_ratio: float, seed: int, max_seq_length: int):
    """加载 CPT 语料，分拆 train/dev，保留 priority/layer/weight 字段。"""
    records = []
    with open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                text = rec.get("text", "")
                if text:
                    records.append({
                        "text": text,
                        "priority": rec.get("priority", "medium"),
                        "layer": rec.get("layer", "B"),
                    })
            except json.JSONDecodeError:
                continue

    # 打乱并分拆
    import random
    rng = random.Random(seed)
    rng.shuffle(records)
    n_dev = max(1, int(len(records) * dev_ratio))
    dev = records[:n_dev]
    train = records[n_dev:]

    print(f"CPT 语料: {path}")
    print(f"  总段数: {len(records)}")
    print(f"  train: {len(train)}  dev: {len(dev)}")
    return Dataset.from_list(train), Dataset.from_list(dev)


def tokenize_fn(example, tokenizer, max_seq_length):
    """对 CPT 语料做 tokenize，所有 token 都参与 loss（无 assistant_only_loss）。"""
    text = example["text"]
    result = tokenizer(
        text,
        truncation=True,
        max_length=max_seq_length,
        padding=False,
        return_tensors=None,
    )
    # labels = input_ids（causal LM 自回归学习）
    result["labels"] = result["input_ids"].copy()
    # 保留 priority/layer 供 WeightedRandomSampler 使用
    result["priority"] = example.get("priority", "medium")
    result["layer"] = example.get("layer", "B")
    return result


def compute_sample_weights(dataset, priority_weights=None, layer_weights=None):
    """根据 priority 和 layer 计算每条样本的采样权重。

    参考 docs/cpt.md §2.1：高优先级样本应多被采样；
    Layer B/C（推理/代码应用）比 Layer A（知识）和 Layer D（通用回放）更关键。
    """
    if priority_weights is None:
        priority_weights = {"high": 5.0, "medium": 2.0, "low": 1.0}
    if layer_weights is None:
        # A 知识层、B 推理层、C 代码层、D 通用回放
        layer_weights = {"A": 1.0, "B": 1.2, "C": 1.5, "D": 0.8}

    weights = []
    for i in range(len(dataset)):
        prio = dataset[i].get("priority", "medium")
        layer = dataset[i].get("layer", "B")
        w = priority_weights.get(prio, 1.0) * layer_weights.get(layer, 1.0)
        weights.append(w)
    return weights


class WeightedTrainer(Trainer):
    """带 WeightedRandomSampler 的 Trainer，支持 priority + layer 加权采样。"""

    def get_train_dataloader(self):
        if self.train_dataset is None:
            raise ValueError("Trainer: training requires a train_dataset.")

        weights = compute_sample_weights(self.train_dataset)
        sampler = WeightedRandomSampler(
            weights=weights,
            num_samples=len(weights),
            replacement=True,
        )
        return DataLoader(
            self.train_dataset,
            batch_size=self.args.per_device_train_batch_size,
            sampler=sampler,
            collate_fn=self.data_collator,
            drop_last=self.args.dataloader_drop_last,
            num_workers=self.args.dataloader_num_workers,
            pin_memory=self.args.dataloader_pin_memory,
        )


def main():
    args = parse_args()

    print("=" * 60)
    print("KnItLM CPT 训练（Phase 3 知识注入）")
    print("=" * 60)
    print(f"Base 模型: {args.model}")
    print(f"语料: {args.corpus}")
    print(f"LoRA: r={args.lora_r} alpha={args.lora_alpha} dropout={args.lora_dropout} rslora={args.use_rslora}")
    print(f"训练: epochs={args.epochs} lr={args.lr} batch={args.batch_size}x{args.grad_accum}")
    print(f"max_seq_length={args.max_seq_length}")

    if not args.corpus.exists():
        print(f"\n❌ 语料文件不存在: {args.corpus}")
        print(f"   先运行: python3 prepare_cpt_corpus.py")
        sys.exit(1)

    # 输出目录
    output_subdir = f"knitlm_cpt_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_lr{args.lr:g}"
    if args.use_rslora:
        output_subdir += "_rslora"
    output_dir = OUTPUT_DIR / output_subdir
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"输出目录: {output_dir}")

    # 加载 tokenizer
    print(f"\n加载 tokenizer: {args.model}")
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 4bit 量化
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )

    # 加载 base 模型
    print(f"加载 base 模型: {args.model} (4bit)")
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb_config,
        device_map={"": 0},  # ROCm 上 "auto" 易段错误，强制单 GPU（参考 train_qlora.py）
        trust_remote_code=True,
        torch_dtype=torch.float16,
    )
    model.config.use_cache = False
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})

    # LoRA 配置（CPT 用 causal LM task type）
    # 2026-07-19: 加入 embed_tokens/lm_head，加强对 CWE 专有术语的吸收
    # 参考 docs/cpt.md §2.2：新领域术语多，微调 embedding 更稳
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        use_rslora=args.use_rslora,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
            "embed_tokens", "lm_head",
        ],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 加载语料
    print(f"\n加载语料: {args.corpus}")
    train_ds, dev_ds = load_corpus(args.corpus, args.dev_ratio, args.seed, args.max_seq_length)

    # Tokenize
    print("Tokenizing...")
    train_ds = train_ds.map(
        lambda x: tokenize_fn(x, tokenizer, args.max_seq_length),
        batched=False,
        remove_columns=train_ds.column_names,
        desc="Tokenizing train",
    )
    dev_ds = dev_ds.map(
        lambda x: tokenize_fn(x, tokenizer, args.max_seq_length),
        batched=False,
        remove_columns=dev_ds.column_names,
        desc="Tokenizing dev",
    )

    # TrainingArguments（CPT 版）
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs if args.max_steps <= 0 else 1,
        max_steps=args.max_steps if args.max_steps > 0 else -1,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        save_strategy="steps",
        save_total_limit=5,
        bf16=False,  # RDNA4 不支持 bf16
        fp16=True,   # 4bit + fp16
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="adamw_torch",  # RDNA4 上 paged_adamw_8bit 可能造成模型状态静默损坏
        seed=args.seed,
        eval_strategy="steps",
        eval_steps=args.save_steps,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        per_device_eval_batch_size=1,
        eval_accumulation_steps=16,
        dataloader_pin_memory=False,
        report_to="none",
        logging_dir=str(LOG_DIR),
    )

    # Callbacks（CPT 默认不启用 EarlyStopping：raw text 语料 dev_loss 波动大）
    callbacks = []
    if args.early_stopping:
        callbacks.append(EarlyStoppingCallback(
            early_stopping_patience=args.early_stopping_patience,
            early_stopping_threshold=0.001,
        ))
        print(f"启用 EarlyStopping: patience={args.early_stopping_patience}")
    else:
        print("禁用 EarlyStopping（CPT 默认）")

    # Trainer（用原生 Trainer，不用 SFTTrainer，因为 CPT 是纯 causal LM）
    # 2026-07-19: 改用 WeightedTrainer，支持 priority + layer 加权采样
    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=dev_ds,
        callbacks=callbacks,
        processing_class=tokenizer,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )

    # 训练
    print("\n" + "=" * 60)
    print("开始 CPT 训练")
    print("=" * 60)
    trainer.train()

    # 保存 best adapter（trainer.save_model 内部调用 model/tokenizer.save_pretrained，
    # 并保存 trainer_state.json 记录完整训练过程）
    best_dir = output_dir / "best"
    trainer.save_model(str(best_dir))
    trainer.save_state()
    print(f"\n✅ CPT LoRA adapter 已保存: {best_dir}")
    print(f"\n下一步：运行 merge_lora_to_instruct.py 把此 adapter 合并到 Instruct 模型")
    print(f"  python3 merge_lora_to_instruct.py \\")
    print(f"      --cpt-adapter {best_dir}")


if __name__ == "__main__":
    main()
