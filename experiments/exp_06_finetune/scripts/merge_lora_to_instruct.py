"""
KnItLM Stage B：把 CPT 阶段得到的 LoRA adapter 合并到 Instruct 模型。

对应 docs/方法.md §9 Phase 3，原理见 §8.3 KnItLM。

流程：
  1. 加载 Qwen2.5-Coder-7B-Instruct（fp16，不量化，因为合并后还要做 SFT）
  2. 加载 train_knitlm_cpt.py 保存的 CPT LoRA adapter
  3. 调用 peft.merge_and_unload() 把 LoRA 权重融入基础权重
  4. 保存合并后的完整模型（fp16）

注意：
  - 合并需要 fp16/bf16，4bit 量化下无法 merge（量化权重不可逆）
  - 7B fp16 约 14GB，加上加载 adapter 的开销，需要 ~16GB 显存
  - 输出是完整模型（不是 LoRA adapter），后续 SFT 时基于这个合并后的模型训
  - 合并后模型大小约 14GB（fp16）

输入：
  outputs/knitlm_cpt_r64_a128_e1_lr2e-5_rslora/best/   - CPT LoRA adapter

输出：
  outputs/knitlm_merged_7b_instruct/   - 合并后的完整 Instruct 模型
    - 包含 config.json, model-*.safetensors, tokenizer.json 等

用法：
  HF_HUB_OFFLINE=1 /home/zane/miniconda3/envs/AI/bin/python merge_lora_to_instruct.py \\
      --cpt-adapter outputs/knitlm_cpt_r64_a128_e1_lr2e-5_rslora/best
"""

import argparse
import os
import sys
from pathlib import Path

os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
os.environ.setdefault("HIP_VISIBLE_DEVICES", "0")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/outputs"

INSTRUCT_MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"


def parse_args():
    p = argparse.ArgumentParser(description="KnItLM LoRA 合并到 Instruct")
    p.add_argument("--cpt-adapter", type=Path, required=True,
                   help="train_knitlm_cpt.py 保存的 CPT LoRA adapter 目录")
    p.add_argument("--instruct-model", type=str, default=INSTRUCT_MODEL_ID,
                   help=f"Instruct 模型 ID（默认 {INSTRUCT_MODEL_ID}）")
    p.add_argument("--output", type=Path, default=None,
                   help="输出目录（默认 outputs/knitlm_merged_7b_instruct）")
    p.add_argument("--dtype", type=str, default="fp16",
                   choices=["fp16", "bf16", "fp32"],
                   help="合并后的精度（默认 fp16，RDNA4 不支持 bf16）")
    p.add_argument("--push-to-hub", action="store_true",
                   help="合并后推送到 HuggingFace Hub（默认不推送）")
    p.add_argument("--repo-id", type=str, default=None,
                   help="推送到的 repo ID（如 user/knitlm-7b-instruct）")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("KnItLM Stage B: LoRA → Instruct 合并")
    print("=" * 60)
    print(f"Base Instruct: {args.instruct_model}")
    print(f"CPT adapter:   {args.cpt_adapter}")
    print(f"精度: {args.dtype}")

    if not args.cpt_adapter.exists():
        print(f"\n❌ CPT adapter 不存在: {args.cpt_adapter}")
        print(f"   先运行 train_knitlm_cpt.py 生成 adapter")
        sys.exit(1)

    output_dir = args.output or (OUTPUT_DIR / "knitlm_merged_7b_instruct")
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"输出目录: {output_dir}")

    dtype_map = {
        "fp16": torch.float16,
        "bf16": torch.bfloat16,
        "fp32": torch.float32,
    }
    torch_dtype = dtype_map[args.dtype]

    # 1. 加载 Instruct 模型（fp16，不量化）
    print(f"\n[1/3] 加载 Instruct 模型: {args.instruct_model} ({args.dtype})")
    model = AutoModelForCausalLM.from_pretrained(
        args.instruct_model,
        torch_dtype=torch_dtype,
        device_map="cpu",  # 在 CPU 上合并，省 GPU 显存
        trust_remote_code=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(args.instruct_model, trust_remote_code=True)

    # 2. 加载 CPT LoRA adapter
    print(f"\n[2/3] 加载 CPT LoRA adapter: {args.cpt_adapter}")
    model = PeftModel.from_pretrained(model, str(args.cpt_adapter))

    # 3. 合并
    print(f"\n[3/3] 合并 LoRA 权重到基础模型...")
    model = model.merge_and_unload()

    # 保存
    print(f"\n保存合并后的模型到: {output_dir}")
    model.save_pretrained(str(output_dir), safe_serialization=True)
    tokenizer.save_pretrained(str(output_dir))

    # 写一个 README 说明这个模型是怎么来的
    readme_path = output_dir / "README.md"
    readme_content = f"""---
language: zh
base_model: {args.instruct_model}
inference: false
---

# KnItLM-Merged Qwen2.5-Coder-7B-Instruct

合并了在 Qwen2.5-Coder-7B（base）上做的 CPT LoRA adapter 的 Instruct 模型。

## 训练流程

1. Stage A (CPT): 在 Qwen2.5-Coder-7B（base）上用 CPT LoRA (CPT adapter: `{args.cpt_adapter.name}`) 做继续预训练
2. Stage B (Merge): 把 CPT LoRA 权重合并到 Instruct 模型（本步骤）

## 后续使用

合并后的模型可直接作为 SFT 的基座：
- 输入到 train_qlora.py 做漏洞检测 SFT
- 期望效果：在保留 Instruct 能力的同时注入漏洞领域知识

参考：docs/方法.md §9 Phase 3 KnItLM 知识注入
论文：KnItLM (ICLR 2026, https://openreview.net/forum?id=2uctT30vTS)
"""
    readme_path.write_text(readme_content, encoding="utf-8")

    print(f"\n✅ 合并完成")
    print(f"   模型: {output_dir}")
    print(f"   README: {readme_path}")
    print(f"\n下一步：")
    print(f"  1. 用此合并后的模型作为 SFT 基座（替换 Qwen2.5-Coder-7B-Instruct）")
    print(f"  2. 修改 train_qlora.py 的 --model 参数指向 {output_dir}")
    print(f"  3. 跑常规 SFT 训练（Phase 1 sweep 在此基础上做 lr × rsLoRA 网格）")

    if args.push_to_hub and args.repo_id:
        print(f"\n推送到 Hub: {args.repo_id}")
        model.push_to_hub(args.repo_id)
        tokenizer.push_to_hub(args.repo_id)


if __name__ == "__main__":
    main()
