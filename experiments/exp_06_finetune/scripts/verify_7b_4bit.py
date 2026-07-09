"""
7B 4bit QLoRA 在 ROCm 上的最小验证脚本。

验证目标：
  1. bitsandbytes 4bit 量化加载 Qwen2.5-Coder-7B-Instruct 不段错误
  2. 实际显存占用（推理 + 训练）
  3. 能跑通一次前向推理
  4. 能挂载 LoRA 并做一次前向+反向（验证训练可行性）

用法：
  /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/verify_7b_4bit.py
"""

import os
import time

# ROCm 单 GPU
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training


MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"


def vram_gb():
    """当前已用 VRAM（GB）。"""
    free, total = torch.cuda.mem_get_info()
    return round((total - free) / 1e9, 2)


def step(title):
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    print(f"VRAM 已用: {vram_gb()} GB")


def main():
    print(f"PyTorch: {torch.__version__}")
    print(f"ROCm: {torch.version.hip}")
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"VRAM total: {round(torch.cuda.get_device_properties(0).total_memory/1e9, 2)} GB")

    # ------------------------------------------------------------------
    # 步骤 1：4bit 量化加载模型
    # ------------------------------------------------------------------
    step("步骤 1：4bit 量化加载 Qwen2.5-Coder-7B-Instruct")

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,  # 双量化进一步省显存
    )

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    t0 = time.time()
    try:
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_ID,
            quantization_config=bnb_config,
            device_map={"": 0},
            trust_remote_code=True,
            torch_dtype=torch.float16,
            attn_implementation="sdpa",
        )
        print(f"加载耗时: {time.time()-t0:.1f}s")
        print(f"加载后 VRAM: {vram_gb()} GB  ← 4bit 权重占用")
    except Exception as e:
        print(f"加载失败: {type(e).__name__}: {e}")
        print(">>> bitsandbytes 4bit 在此 ROCm 上仍不可用，7B QLoRA 路线受阻")
        return

    # ------------------------------------------------------------------
    # 步骤 2：跑一次推理（代码安全分析）
    # ------------------------------------------------------------------
    step("步骤 2：推理测试（代码安全分析）")

    code_sample = '''import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT id, name FROM products WHERE name LIKE '%{keyword}%'"
    cur.execute(query)
    results = cur.fetchall()
    return {"results": results}
'''

    messages = [
        {"role": "system", "content": "你是代码安全审计专家。分析代码是否有漏洞，最后输出 JSON。"},
        {"role": "user", "content": f"分析以下代码的安全漏洞：\n\n{code_sample}"},
    ]
    # apply_chat_template 返回 dict（input_ids + attention_mask），用 return_dict=True
    inputs = tokenizer.apply_chat_template(
        messages, add_generation_prompt=True, return_tensors="pt", return_dict=True
    )
    inputs = {k: v.to("cuda:0") for k, v in inputs.items()}

    t0 = time.time()
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    elapsed = time.time() - t0
    response = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print(f"推理耗时: {elapsed:.2f}s")
    print(f"推理后 VRAM: {vram_gb()} GB  (+KV cache)")
    print(f"输出前 300 字:\n{response[:300]}")

    # ------------------------------------------------------------------
    # 步骤 3：挂载 LoRA + 准备训练
    # ------------------------------------------------------------------
    step("步骤 3：挂载 LoRA + prepare_model_for_kbit_training")

    model.train()
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.1,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    print(f"LoRA 挂载后 VRAM: {vram_gb()} GB")

    # ------------------------------------------------------------------
    # 步骤 4：一次前向+反向（验证训练可行性）
    # ------------------------------------------------------------------
    step("步骤 4：前向+反向测试（mini batch）")

    # 构造一个简单的 ChatML 训练样本
    train_text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=False
    )
    enc = tokenizer(
        train_text, return_tensors="pt", truncation=True, max_length=1024
    ).to("cuda:0")
    labels = enc["input_ids"].clone()

    t0 = time.time()
    try:
        with torch.amp.autocast("cuda", dtype=torch.float16):
            out = model(**enc, labels=labels)
            print(f"前向 loss: {out.loss.item():.4f}")
            out.loss.backward()
        print(f"前向+反向耗时: {time.time()-t0:.2f}s")
        print(f"训练峰值 VRAM: {vram_gb()} GB  ← 关键数字")
        print(f"梯度范数: {model.parameters().__next__().grad.norm().item():.4f}")
    except Exception as e:
        print(f"训练失败: {type(e).__name__}: {e}")
        print(f"失败时 VRAM: {vram_gb()} GB")
        return

    # ------------------------------------------------------------------
    # 结论
    # ------------------------------------------------------------------
    step("验证结论")
    peak = vram_gb()
    print(f"7B 4bit QLoRA 峰值 VRAM: {peak} GB / 17.1 GB")
    if peak < 14:
        print(">>> 稳定，可放心训练（预留 3GB 余量给长序列）")
    elif peak < 16:
        print(">>> 紧张但可行，需注意 max_seq_length 和 batch_size")
    else:
        print(">>> 风险高，OOM 可能性大")


if __name__ == "__main__":
    main()
