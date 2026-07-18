# Phase 2 对比：r=32 + rsLoRA + e=2 vs Phase 1 baseline

> 目标：验证增大 LoRA rank (r=8→32) + rsLoRA + 双 epoch 是否提升严格 recall。

- 基座：Qwen2.5-Coder-7B-Instruct (4bit QLoRA)
- Phase 1 baseline: r=8, alpha=16, e=1, lr=1e-5
- Phase 2: r=32, alpha=64, rsLoRA, e=2, lr=1e-5
- 训练数据：train_chatml_v2.jsonl (700 train + 123 dev)
- 测试集：exp_04_hard_samples 87 段
- RDNA4 优化：AOTRITON attention + 部分 TunableOp (46/1104 GEMM)

## 1. 训练侧：dev_loss / train_loss 对比

| 配置 | r | rsLoRA | DoRA | epochs | dev_loss | train_loss | 训练耗时 | step time |
|------|---|--------|------|--------|----------|------------|----------|-----------|
| Phase 1 baseline (r=8, e=1, lr=1e-5) | 8 | | | 1 | — | — | — | 73-76s |
| Phase 2: r=32 + rsLoRA + e=2 | 32 | ✓ |  | 2 | 0.9406 | 1.0318 | 95.4min | ~31s |
| Phase 2: r=32 + rsLoRA + DoRA + e=2 | 32 | ✓ |  | 2 | — | — | — | ~31s |

## 2. 评估侧：exp_04 87 段测试集指标

| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE错标 | 幻觉率 | CoT不一致 | 平均耗时 |
|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|-----------|----------|
| **Phase 1 baseline (r=8, e=1, lr=1e-5)** | 57 | 23 | 3 | 4 | **93.4%** | **41.0%** | **11.5%** | **92.0%** | 32 | 56.1% | 0 | 18.1s |
| Phase 2: r=32 + rsLoRA + e=2 | 58 | 18 | 8 | 3 | 95.1% | 42.6% | 30.8% | 87.4% | 32 | 55.2% | 0 | 18.3s |

## 3. 与 Phase 1 baseline 的差值

| 配置 | Δrecall | Δstrict_recall | ΔFPR | Δaccuracy | ΔCWE错标 | Δ幻觉率 |
|------|---------|----------------|------|-----------|---------|---------|
| Phase 2: r=32 + rsLoRA + e=2 | +1.6pp | +1.6pp | +19.2pp | -4.6pp | +0 | -1.0pp |

## 4. 结论与下一步建议

- 最佳配置：Phase 2: r=32 + rsLoRA + e=2
- 严格 recall 差值：+1.6pp
- FPR 差值：+19.2pp
- 判定：⚠️ **Phase 2 提升有限**：严格 recall 有小幅提升但不显著
- 下一步：考虑跳过 Phase 2 run2 (DoRA)，直接进 Phase 3