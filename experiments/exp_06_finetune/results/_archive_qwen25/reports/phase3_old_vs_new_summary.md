# Phase 3 语料清洗前后对比

> 目标：量化测试集泄露和 SYSTEM_PROMPT 重复污染对 Phase 3 指标的贡献，验证清洗后的三层分离语料是否仍能保持知识注入效果。

- 旧结果：`exp_06_eval.knitlm_merged.20260719_070818.json`
- 新结果：`exp_06_eval.knitlm_merged.20260719_194118_new_corpus.json`
- 新版训练日志：`未找到`

## 1. 87 段测试集指标对比

| 配置 | TP | TN | FP | FN | 宽松 recall | 严格 recall | FPR | accuracy | CWE 错标 | 幻觉率 |
|------|----|----|----|----|-------------|-------------|-----|----------|---------|--------|
| Phase 3 旧版 (扁平语料 + SYSTEM 重复 + 测试集泄露) | 55 | 25 | 1 | 6 | 90.2% | 63.9% | 3.8% | 92.0% | 16 | 29.1% |
| Phase 3 新版 (三层分离 + 清洗后语料) | 49 | 25 | 1 | 12 | 80.3% | 44.3% | 3.8% | 85.1% | 22 | 44.9% |

## 2. 新版 vs 旧版差值

| 指标 | 差值（新版 - 旧版）|
|------|------------------|
| recall | -9.8pp |
| strict_recall | -19.7pp |
| fpr | +0.0pp |
| accuracy | -6.9pp |
| hallucination_rate | +15.8pp |
| CWE 错标 | +6 |

## 3. 新版训练侧指标

| dev_loss | train_loss | train_runtime(s) |
|----------|------------|------------------|
| — | — | — |

## 4. 单样本变化（回归 / 修复）

> 共 12 个样本 outcome 发生变化。

| 文件 | expected | 旧 outcome | 新 outcome | 变化 | 旧 CWE | 新 CWE |
|------|----------|-----------|-----------|------|--------|--------|
| hard_bypass_04_path_regex.py | True | TP | FN | 回归 | CWE-22 路径穿越 | none |
| hard_crossfile_01_input.py | False | TN | FP | 回归 | none | Design Flaw |
| hard_crossfile_02_input.py | True | TP | FN | 回归 | CWE-22 路径穿越 | none |
| hard_crossfile_03_input.py | False | FP | TN | 修复 | CWE-209 数据泄露 | none |
| hard_crossfile_03_sink.py | True | TP | FN | 回归 | CWE-862 数据泄露 | none |
| hard_cve_01_samba_2017_7494.py | True | TP | FN | 回归 | CWE-78 命令注入 | none |
| hard_cve_02_python_log_injection.py | True | TP | FN | 回归 | CWE-117 日志注入 | none |
| hard_owasp_01_file_upload.py | True | FN | TP | 修复 | none | CWE-78 路径穿越 |
| hard_owasp_02_dvwa_sql.py | True | FN | TP | 修复 | none | CWE-89 SQL注入 |
| typical_04_path.py | True | TP | FN | 回归 | CWE-22 路径穿越 | none |
| typical_15_missing_authz.py | True | TP | FN | 回归 | CWE-862 缺失授权 | none |
| typical_31_open_redirect_glob.py | True | TP | FN | 回归 | CWE-601 开放重定向 | none |

## 5. 结论

- **严格 recall 变化**：-19.7pp
- **FPR 变化**：+0.0pp
- **幻觉率变化**：+15.8pp
- **CWE 错标变化**：+6
- **单样本 outcome 变化数**：12

**判定**：❌ **清洗后的语料性能显著退化**。严格 recall 倒退 19.7pp；幻觉率上升 +15.8pp。这说明旧版 Phase 3 的指标突破可能部分依赖测试集泄露或 SYSTEM 重复污染，需要进一步扩增清洗后的语料规模或调整训练配置。
