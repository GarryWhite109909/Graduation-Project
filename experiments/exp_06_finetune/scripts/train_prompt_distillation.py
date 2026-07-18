"""
Phase 4 - Prompt Distillation 训练脚本（自蒸馏）。

对应 docs/方法.md §9 Phase 4，论文 Prompt Distillation (TMLR 2025)。

原理：
  Student = Qwen-Coder-Instruct + LoRA（无 CWE 规则 context）
  Loss = (1-α) × CE(student_logits, labels) + α × KL(teacher_logits || student_logits)

  其中 teacher_logits 由 precompute_teacher_logits.py 预计算好，
  每个样本的 top-K (indices, values) 已存到磁盘。

设计要点：
  - 只加载一个 student 模型（teacher 已预计算，无需加载）
  - 自定义 Trainer.compute_loss 实现 KD loss
  - KL loss 只在 answer 部分计算（与 teacher 对齐）
  - top-K 近似：用 teacher top-K 的 softmax 作为软标签
  - 16GB 显存：4bit QLoRA + 7B 单模型 ≈ 8GB，足够

硬件：AMD Radeon RX 9060 XT 16GB + ROCm 7.2
模型：Qwen2.5-Coder-7B-Instruct

用法（先跑 precompute_teacher_logits.py）：
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python train_prompt_distillation.py \\
      --teacher-logits data/teacher_logits \\
      --alpha 0.5 --temperature 2.0 \\
      --epochs 1 --lr 1e-4 --lora-r 32
"""

import argparse
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

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

import torch.nn.functional as F
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
from peft import LoraConfig, get_peft_model, TaskType

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"
LOG_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/logs"
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"

INSTRUCT_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"


def parse_args():
    p = argparse.ArgumentParser(description="Prompt Distillation 训练")
    p.add_argument("--teacher-logits", type=Path, default=DATA_DIR / "teacher_logits",
                   help="precompute_teacher_logits.py 的输出目录")
    p.add_argument("--train-file", type=Path, default=DATA_DIR / "train_chatml_v2.jsonl",
                   help="训练数据（ChatML）")
    p.add_argument("--model", type=str, default=INSTRUCT_MODEL_ID)
    p.add_argument("--alpha", type=float, default=0.5,
                   help="distillation loss 权重（1.0=纯 KL, 0.0=纯 SFT, 0.5=各半）")
    p.add_argument("--temperature", type=float, default=2.0,
                   help="KL softmax 温度（默认 2.0，论文推荐）")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--lr", type=float, default=1e-4)
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=8)
    p.add_argument("--max-seq-length", type=int, default=2048)
    p.add_argument("--lora-r", type=int, default=32, help="LoRA rank（默认 32，§9 Phase 2 推荐值）")
    p.add_argument("--lora-alpha", type=int, default=64)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--use-rslora", action="store_true", default=True)
    p.add_argument("--use-dora", action="store_true", default=False,
                   help="启用 DoRA（§9 Phase 1 验证过，慢 2.1 倍，慎用）")
    p.add_argument("--warmup-ratio", type=float, default=0.05)
    p.add_argument("--logging-steps", type=int, default=10)
    p.add_argument("--save-steps", type=int, default=50)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-early-stopping", action="store_true")
    p.add_argument("--early-stopping-patience", type=int, default=2)
    p.add_argument("--dev-ratio", type=float, default=0.15)
    return p.parse_args()


class PromptDistillationDataset:
    """数据集：加载 ChatML + 对应的 teacher logits。

    每条样本提供：
      - input_ids: 学生输入 token 序列（仅 user + assistant，无 CWE context）
      - labels: 标准答案（用于 SFT loss，user 部分 -100）
      - teacher_logits_path: 对应 teacher logits 文件路径
      - student_answer_start: student answer 部分的起始 token 位置
      - student_answer_len: student answer 部分的 token 长度

    两种后端对齐策略：
      - transformers 后端（teacher forcing）：teacher answer == student answer
        KL loss 对齐到 student_answer_start : student_answer_start + teacher_answer_len
      - ollama 后端（on-policy）：teacher 自己生成 answer，可能与 student answer 不同
        KL loss 对齐到 min(student_answer_len, teacher_answer_len) 个位置
        （teacher 的前 N 个 token 引导 student 的前 N 个 token）
    """

    def __init__(self, chatml_path: Path, teacher_logits_dir: Path,
                 tokenizer, max_seq_length: int, dev_ratio: float, seed: int,
                 limit: int = 0):
        self.tokenizer = tokenizer
        self.max_seq_length = max_seq_length
        self.teacher_logits_dir = teacher_logits_dir  # 修复：存下来

        # 加载 ChatML
        self.samples = []
        with open(chatml_path, "r", encoding="utf-8") as fp:
            for i, line in enumerate(fp):
                if limit and i >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    self.samples.append(rec)
                except json.JSONDecodeError:
                    continue

        # 加载 teacher logits 索引
        index_path = teacher_logits_dir / "index.json"
        if not index_path.exists():
            raise FileNotFoundError(
                f"Teacher logits 索引不存在: {index_path}\n"
                f"先运行: precompute_teacher_logits.py"
            )
        with open(index_path, "r", encoding="utf-8") as fp:
            self.teacher_index = json.load(fp)
        # 探测后端类型
        self.teacher_backend = self.teacher_index.get("backend", "transformers")
        print(f"Teacher 后端: {self.teacher_backend}")

        # 分拆 train/dev
        import random
        rng = random.Random(seed)
        indices = list(range(len(self.samples)))
        rng.shuffle(indices)
        n_dev = int(len(indices) * dev_ratio)
        self.dev_ids = set(indices[:n_dev])

        print(f"PD 数据集: {len(self.samples)} 样本, dev={n_dev}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        rec = self.samples[idx]
        msgs = rec["messages"]

        # 构造 student 输入：只 user + assistant（无 CWE context）
        text = self.tokenizer.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=False,
        )
        enc = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_seq_length,
            padding=False,
            return_tensors=None,
        )
        input_ids = enc["input_ids"]

        # 找 student answer 起始位置：用 user-only 的长度
        # ChatML: <|im_start|>user\n...<|im_end|>\n<|im_start|>assistant\n
        user_only_msgs = [{"role": "user", "content": msgs[0]["content"]}]
        user_only_text = self.tokenizer.apply_chat_template(
            user_only_msgs, tokenize=False, add_generation_prompt=True,
        )
        user_only_enc = self.tokenizer(
            user_only_text, truncation=True, max_length=self.max_seq_length,
            padding=False, return_tensors=None,
        )
        student_answer_start = len(user_only_enc["input_ids"])

        # labels: user 部分 -100，assistant 部分参与 loss
        labels = [-100] * student_answer_start + input_ids[student_answer_start:]

        # 找 teacher logits 文件
        teacher_path = self.teacher_logits_dir / f"sample_{idx:04d}.pt"

        return {
            "input_ids": input_ids,
            "attention_mask": enc["attention_mask"],
            "labels": labels,
            "teacher_logits_path": str(teacher_path),
            "student_answer_start": student_answer_start,
            "student_answer_len": len(input_ids) - student_answer_start,
        }


class DataCollator:
    """自定义 collator：pad input_ids 并保留 teacher_logits_path + answer 位置。"""

    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def __call__(self, batch):
        max_len = max(len(x["input_ids"]) for x in batch)
        input_ids = []
        attention_mask = []
        labels = []
        teacher_paths = []
        student_answer_starts = []
        student_answer_lens = []

        for x in batch:
            ids = x["input_ids"]
            mask = x["attention_mask"]
            lab = x["labels"]
            pad_len = max_len - len(ids)
            # 右 pad
            input_ids.append(ids + [self.tokenizer.pad_token_id] * pad_len)
            attention_mask.append(mask + [0] * pad_len)
            labels.append(lab + [-100] * pad_len)
            teacher_paths.append(x["teacher_logits_path"])
            student_answer_starts.append(x["student_answer_start"])
            student_answer_lens.append(x["student_answer_len"])

        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
            "teacher_logits_paths": teacher_paths,  # list of str
            "student_answer_starts": torch.tensor(student_answer_starts, dtype=torch.long),
            "student_answer_lens": torch.tensor(student_answer_lens, dtype=torch.long),
        }


class PromptDistillationTrainer(Trainer):
    """Prompt Distillation Trainer: (1-α)×CE + α×KL。

    KL loss 用 teacher top-K logits 近似：
      teacher_softmax_topk = softmax(teacher_topk_values / T)
      student_softmax_topk = softmax(student_topk_logits_at_teacher_indices / T)
      KL = T^2 × KL(teacher_topk || student_topk)

    两种后端对齐策略：
      - transformers 后端（teacher forcing）：teacher answer_start 是 prompt 长度
        student answer 对齐到 [student_answer_start, student_answer_start + teacher_answer_len]
      - ollama 后端（on-policy）：teacher answer_start=0，teacher 自己生成 answer
        student answer 对齐到 [student_answer_start, student_answer_start + min(student_answer_len, teacher_answer_len)]
        只对齐前 min 长度的 token（teacher 引导 student 的前缀）
    """

    def __init__(self, *args, alpha: float = 0.5, temperature: float = 2.0,
                 teacher_backend: str = "transformers", **kwargs):
        super().__init__(*args, **kwargs)
        self.alpha = alpha
        self.temperature = temperature
        self.teacher_backend = teacher_backend
        print(f"PromptDistillationTrainer: alpha={alpha}, T={temperature}, backend={teacher_backend}")
        print(f"  Loss = {1-alpha:.2f} × CE + {alpha:.2f} × KL")

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        teacher_paths = inputs.pop("teacher_logits_paths", None)
        student_answer_starts = inputs.pop("student_answer_starts", None)
        student_answer_lens = inputs.pop("student_answer_lens", None)

        # Student forward
        outputs = model(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
            labels=inputs["labels"],
        )
        sft_loss = outputs.loss
        student_logits = outputs.logits  # [B, L, V]

        if self.alpha > 0 and teacher_paths is not None:
            kl_loss = self._compute_kl_loss(
                student_logits, teacher_paths,
                student_answer_starts, student_answer_lens,
            )
            loss = (1 - self.alpha) * sft_loss + self.alpha * kl_loss
        else:
            loss = sft_loss

        return (loss, outputs) if return_outputs else loss

    def _compute_kl_loss(self, student_logits, teacher_paths,
                         student_answer_starts, student_answer_lens):
        """计算 KL loss（仅对有 teacher logits 的样本）。"""
        T = self.temperature
        kl_total = 0.0
        n_valid = 0

        for b, teacher_path in enumerate(teacher_paths):
            if not os.path.exists(teacher_path):
                continue

            teacher_data = torch.load(teacher_path, map_location="cpu", weights_only=False)
            teacher_indices = teacher_data["indices"].to(student_logits.device)  # [answer_len, K]
            teacher_values = teacher_data["values"].to(student_logits.device)    # [answer_len, K]
            teacher_answer_len = teacher_indices.shape[0]
            teacher_answer_start = teacher_data.get("answer_start", 0)

            # 对齐 student answer 位置
            student_ans_start = int(student_answer_starts[b].item())
            student_ans_len = int(student_answer_lens[b].item())

            if self.teacher_backend == "ollama":
                # on-policy：teacher answer_start=0，对齐到 student answer 起始
                # 只对齐前 min(student_ans_len, teacher_answer_len) 个位置
                align_len = min(student_ans_len, teacher_answer_len)
                if align_len <= 0:
                    continue
                student_answer_logits = student_logits[
                    b, student_ans_start:student_ans_start + align_len, :
                ]
                teacher_indices_aligned = teacher_indices[:align_len, :]
                teacher_values_aligned = teacher_values[:align_len, :]
            else:
                # transformers teacher forcing：teacher answer_start 是 prompt 长度
                # student answer 对齐到 student_ans_start + teacher_answer_start 偏移
                # 但 transformers 后端 teacher 看的是 prompt+cwe+answer，student 看的是 prompt+answer
                # 所以 teacher_answer_start 是 teacher 的 prompt 长度，与 student 不同
                # 简化：直接对齐到 student answer 起始 + teacher answer 长度
                align_len = min(student_ans_len, teacher_answer_len)
                if align_len <= 0:
                    continue
                student_answer_logits = student_logits[
                    b, student_ans_start:student_ans_start + align_len, :
                ]
                teacher_indices_aligned = teacher_indices[:align_len, :]
                teacher_values_aligned = teacher_values[:align_len, :]

            # 取 teacher_indices 位置的 student logits
            student_topk = torch.gather(
                student_answer_logits, dim=-1, index=teacher_indices_aligned,
            )  # [align_len, K]

            # Softmax with temperature
            teacher_softmax = F.softmax(teacher_values_aligned / T, dim=-1)  # [align_len, K]
            student_log_softmax = F.log_softmax(student_topk / T, dim=-1)  # [align_len, K]

            # KL(teacher || student) = sum p_teacher * (log p_teacher - log p_student)
            kl = (teacher_softmax * (torch.log(teacher_softmax + 1e-10) - student_log_softmax)).sum(dim=-1)
            kl_total = kl_total + kl.mean()
            n_valid += 1

        if n_valid == 0:
            return torch.tensor(0.0, device=student_logits.device, requires_grad=True)

        # T^2 scaling（标准 distillation trick）
        return (T * T) * kl_total / n_valid


def main():
    args = parse_args()

    print("=" * 60)
    print("Phase 4: Prompt Distillation 训练")
    print("=" * 60)
    print(f"Teacher logits: {args.teacher_logits}")
    print(f"Student model: {args.model}")
    print(f"LoRA: r={args.lora_r} alpha={args.lora_alpha} dropout={args.lora_dropout} rslora={args.use_rslora} dora={args.use_dora}")
    print(f"Loss: alpha={args.alpha} T={args.temperature}")
    print(f"训练: epochs={args.epochs} lr={args.lr} batch={args.batch_size}x{args.grad_accum}")

    if not args.teacher_logits.exists():
        print(f"\n❌ teacher_logits 目录不存在: {args.teacher_logits}")
        print(f"   先运行: precompute_teacher_logits.py")
        sys.exit(1)

    # 输出目录
    output_subdir = (
        f"pd_r{args.lora_r}_a{args.lora_alpha}_e{args.epochs}_lr{args.lr:g}"
        f"_alpha{args.alpha}_T{args.temperature}_s{args.seed}"
    )
    if args.use_rslora:
        output_subdir += "_rslora"
    if args.use_dora:
        output_subdir += "_dora"
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

    # 加载 student 模型
    print(f"加载 student 模型 (4bit): {args.model}")
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb_config,
        device_map={"": 0},  # ROCm 上 "auto" 易段错误，强制单 GPU（参考 train_qlora.py）
        trust_remote_code=True,
    )
    model.config.use_cache = False
    if hasattr(model, "gradient_checkpointing_enable"):
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})

    # LoRA
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        use_rslora=args.use_rslora,
        use_dora=args.use_dora,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 加载数据集
    print(f"\n加载数据集...")
    full_dataset = PromptDistillationDataset(
        chatml_path=args.train_file,
        teacher_logits_dir=args.teacher_logits,
        tokenizer=tokenizer,
        max_seq_length=args.max_seq_length,
        dev_ratio=args.dev_ratio,
        seed=args.seed,
    )

    # 转 Dataset 格式（实际是预加载所有样本）
    # 为了节省内存，这里直接生成 dict
    train_samples = []
    dev_samples = []
    for i in range(len(full_dataset)):
        sample = full_dataset[i]
        if i in full_dataset.dev_ids:
            dev_samples.append(sample)
        else:
            train_samples.append(sample)

    train_ds = Dataset.from_list(train_samples)
    dev_ds = Dataset.from_list(dev_samples)
    print(f"train={len(train_ds)} dev={len(dev_ds)}")

    collator = DataCollator(tokenizer)

    # TrainingArguments
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        save_strategy="epoch",
        save_total_limit=3,
        bf16=False,
        fp16=True,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="paged_adamw_8bit",
        seed=args.seed,
        eval_strategy="epoch",
        eval_steps=None,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        per_device_eval_batch_size=1,
        eval_accumulation_steps=16,
        dataloader_pin_memory=False,
        report_to="none",
        logging_dir=str(LOG_DIR),
        remove_unused_columns=False,  # 保留 teacher_logits_paths 字段
    )

    callbacks = []
    if not args.no_early_stopping:
        callbacks.append(EarlyStoppingCallback(
            early_stopping_patience=args.early_stopping_patience,
            early_stopping_threshold=0.001,
        ))
        print(f"启用 EarlyStopping: patience={args.early_stopping_patience}")

    # Trainer
    trainer = PromptDistillationTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=dev_ds,
        data_collator=collator,
        callbacks=callbacks,
        alpha=args.alpha,
        temperature=args.temperature,
        teacher_backend=full_dataset.teacher_backend,
    )

    print("\n" + "=" * 60)
    print("开始 Prompt Distillation 训练")
    print("=" * 60)
    trainer.train()

    # 保存 best adapter
    best_dir = output_dir / "best"
    model.save_pretrained(str(best_dir))
    tokenizer.save_pretrained(str(best_dir))
    print(f"\n✅ Prompt Distillation adapter 已保存: {best_dir}")
    print(f"\n下一步：用 evaluate.py 在此 adapter 上评估")
    print(f"  /home/zane/miniconda3/envs/AI/bin/python evaluate.py --adapter {best_dir}")


if __name__ == "__main__":
    main()
