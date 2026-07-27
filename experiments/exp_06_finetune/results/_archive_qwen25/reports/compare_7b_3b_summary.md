# 7B vs 3B 原始输出对比 —— 汇总报告

- 7B baseline: `experiments/exp_06_finetune/results/exp_06_eval.baseline.20260709_144644.json`
- 3B finetuned: `experiments/exp_06_finetune/results/exp_06_eval.finetuned_custom.20260711_031127.json`
- 7B model: Qwen/Qwen2.5-Coder-7B-Instruct-baseline
- 3B model: Qwen/Qwen2.5-Coder-3B-Instruct-finetuned  adapter: experiments/exp_06_finetune/outputs/lora_r8_a16_e1_s42/best

## 1. 核心指标对比

| 指标 | 7B baseline | 3B finetuned | 差值 |
|------|------------|--------------|------|
| TP | 55 | 50 | -5 |
| TN | 24 | 15 | -9 |
| FP | 3 | 11 | +8 |
| FN | 5 | 11 | +6 |
| CWE 错标数（TP 中） | 35 | 31 | -4 |
| 严格 TP（CWE 也对） | 20 | 19 | -1 |
| 宽松 recall | 91.67% | 81.97% | -0.0970 |
| 严格 recall（CWE 对） | 33.33% | 31.15% | -0.0219 |
| 平均输出字符数 | 1072 | 1021 | -51 |
| 最长输出 | 1600 | 2409 | +809 |
| 最短输出 | 696 | 538 | -158 |
| 平均耗时(s) | 17.18 | 18.88 | +1.70 |

## 2. 问题类型分布

| 问题类型 | 7B baseline | 3B finetuned | 说明 |
|---------|------------|--------------|------|
| cot_json_inconsistent | 2 | 0 | CoT 与 JSON 结论不一致 |
| cwe_mismatch | 35 | 31 | CWE 错标（TP 但 CWE 不匹配） |
| fp_with_cwe | 3 | 11 | 安全样本误报且给出 CWE |
| no_json_block | 0 | 1 | 缺少 JSON 代码块 |
| repetition | 0 | 1 | 文本重复 |

## 3. 指标解读

- **幻觉率**：CWE 错标数 / TP 总数。模型检测到漏洞但给了错误的 CWE 编号，属于「方向对但归因错」的幻觉。
- **蒙题率**：CoT-JSON 不一致数 + missing_verdict 数。模型推理过程与结论脱节，说明结论可能是「蒙」的。
- **失误率**：FP + FN。硬性错误判断。
- **随机性**：确定性解码下不应有随机性；若两模型在同一样本上结论相反，反映的是模型能力差异而非随机。
