---
language: zh
base_model: Qwen/Qwen2.5-Coder-7B-Instruct
inference: false
---

# KnItLM-Merged Qwen2.5-Coder-7B-Instruct

合并了在 Qwen2.5-Coder-7B（base）上做的 CPT LoRA adapter 的 Instruct 模型。

## 训练流程

1. Stage A (CPT): 在 Qwen2.5-Coder-7B（base）上用 CPT LoRA (CPT adapter: `best`) 做继续预训练
2. Stage B (Merge): 把 CPT LoRA 权重合并到 Instruct 模型（本步骤）

## 后续使用

合并后的模型可直接作为 SFT 的基座：
- 输入到 train_qlora.py 做漏洞检测 SFT
- 期望效果：在保留 Instruct 能力的同时注入漏洞领域知识

参考：docs/方法.md §9 Phase 3 KnItLM 知识注入
论文：KnItLM (ICLR 2026, https://openreview.net/forum?id=2uctT30vTS)
