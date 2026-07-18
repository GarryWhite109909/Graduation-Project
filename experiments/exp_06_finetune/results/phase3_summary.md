# Phase 3 对比：KnItLM 知识注入 vs Phase 1/2

> 目标：验证 CPT 知识注入是否提升严格 recall（CWE 错标减少）。

- 基座：Qwen2.5-Coder-7B-Base → CPT (r=64, rsLoRA, e=1, lr=2e-5) → merge to Instruct
- 训练数据：cpt_corpus.jsonl (1400 样本, 5.06 MB)
- 测试集：exp_04_hard_samples 87 段
- RDNA4 优化：AOTRITON attention + 部分 TunableOp + device_map={"": 0}

## 1. 训练侧：CPT 训练指标

| 配置 | 方法 | r | epochs | dev_loss | train_loss | 训练耗时 |
|------|------|---|--------|----------|------------|----------|

## 2. 评估侧：exp_04 87 段测试集指标

| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 |
|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|
| Phase 1 baseline (r=8, e=1, lr=1e-5) | 57 | 23 | 3 | 4 | 93.4% | 41.0% | 11.5% | 92.0% | 32 | 56.1% |
| Phase 2: r32_lr1e-5_rslora_e2 | 58 | 18 | 8 | 3 | 95.1% | 42.6% | 30.8% | 87.4% | 32 | 55.2% |
| Phase 3: KnItLM (CPT + merge) | 55 | 25 | 1 | 6 | 90.2% | 63.9% | 3.8% | 92.0% | 16 | 29.1% |

## 3. 与 Phase 1 baseline 的差值

| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 |
|------|---------|----------------|------|-----------|---------|
| Phase 2: r32_lr1e-5_rslora_e2 | +1.6pp | +1.6pp | +19.2pp | -4.6pp | +0 |
| Phase 3: KnItLM (CPT + merge) | -3.3pp | +23.0pp | -7.7pp | +0.0pp | -16 |

## 4. 结论与下一步建议

- **Phase 3 严格 recall 差值**: +23.0pp
- **Phase 3 FPR 差值**: -7.7pp
- **Phase 3 CWE 错标差值**: -16

**判定**：✅ **Phase 3 KnItLM 有效**：严格 recall 显著提升，FPR 未恶化。
**下一步**：Phase 4 Prompt Distillation（自蒸馏进一步提升）
