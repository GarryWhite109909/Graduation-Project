"""
合并 SFT v5 LoRA adapter 到 Qwen3-8B base 模型。

在台式机（有 base 模型权重）上一次性运行，产出完整合并模型，
随后用 llama.cpp 转 GGUF → 量化 → push 到 Ollama Registry。
用户侧无需合并，直接 ollama pull 即可。

用法：
    python tools/merge_lora.py \
        --base Qwen/Qwen3-8B \
        --adapter experiments/exp_06_finetune/outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best \
        --out outputs/merged_v5

前置条件：
    - 台式机上有完整 Qwen3-8B base 权重（HuggingFace 缓存）
    - 16GB 内存即可（CPU 合并，不耗显存）
    - pip install peft transformers accelerate
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def merge(base_model_id: str, adapter_path: str, out_path: str) -> None:
    try:
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        print("[ERROR] 缺少依赖：pip install peft transformers accelerate", file=sys.stderr)
        sys.exit(1)

    print(f"[1/4] 加载 base 模型: {base_model_id}")
    base = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        torch_dtype="auto",
        device_map="cpu",  # CPU 合并，避免显存占用
    )
    tokenizer = AutoTokenizer.from_pretrained(base_model_id)

    print(f"[2/4] 加载 LoRA adapter: {adapter_path}")
    model = PeftModel.from_pretrained(base, adapter_path)

    print("[3/4] 合并权重（merge_and_unload）...")
    merged = model.merge_and_unload()

    out_dir = Path(out_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[4/4] 保存合并模型到: {out_dir}")
    merged.save_pretrained(str(out_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(out_dir))

    print("\n[完成] 合并模型已保存。下一步：")
    print(f"  1. 转 GGUF：python llama.cpp/convert_hf_to_gguf.py {out_dir} --outtype f16")
    print(f"  2. 量化：./llama.cpp/quantize {out_dir}-f16.gguf {out_dir}-q4km.gguf q4_k_m")
    print(f"  3. 创建 Ollama 模型：ollama create graduation-vuln-scanner:v5 -f Modelfile")


def main():
    parser = argparse.ArgumentParser(description="合并 LoRA adapter 到 base 模型")
    parser.add_argument("--base", default="Qwen/Qwen3-8B", help="HuggingFace base 模型 ID")
    parser.add_argument(
        "--adapter",
        default="experiments/exp_06_finetune/outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best",
        help="LoRA adapter 路径",
    )
    parser.add_argument("--out", default="outputs/merged_v5", help="合并模型输出目录")
    args = parser.parse_args()
    merge(args.base, args.adapter, args.out)


if __name__ == "__main__":
    main()
