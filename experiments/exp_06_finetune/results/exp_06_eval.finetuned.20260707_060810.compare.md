# exp_06_finetune 微调效果对比报告

- baseline 文件: `/home/zane/文档/code/毕业设计/experiments/exp_06_finetune/results/exp_06_eval.baseline.20260707_063940.json`
- finetuned 文件: `/home/zane/文档/code/毕业设计/experiments/exp_06_finetune/results/exp_06_eval.finetuned.20260707_060810.json`
- 模型: qwen2.5-coder-3b-instruct-baseline  vs  qwen2.5-coder-3b-instruct-finetuned

## 1. 总体指标

| 指标 | Baseline | Finetuned | 变化 |
|------|----------|-----------|------|
| TP | 46 | 51 | +5 |
| TN | 21 | 21 | +0 |
| FP | 6 | 6 | +0 |
| FN | 14 | 9 | -5 |
| 召回率 (recall) | 76.67% | 85.00% | +8.33pp |
| 准确率 (accuracy) | 77.01% | 82.76% | +5.75pp |
| 误报率 (FPR) | 22.22% | 22.22% | +0.00pp |
| 平均耗时 | 21.29s | 10.66s | -10.63s |

## 2. 逐样本变化

- 改善样本数（错误→正确）: **13**
- 退化样本数（正确→错误）: **8**
- 同类错误变化（FP↔FN）: 0
- 保持不变: 66

### 2.1 改善的样本（错误 → 正确）

| 文件 | Baseline | Finetuned |
|------|----------|-----------|
| hard_bypass_04_path_regex.py | FN | TP |
| hard_crossfile_02_sink.py | FN | TP |
| hard_crossfile_03_input.py | FP | TN |
| hard_cve_02_python_log_injection.py | FN | TP |
| hard_cve_07_tarfile_symlink.py | FN | TP |
| hard_owasp_01_file_upload.py | FN | TP |
| safe_08_shlex.py | FP | TN |
| safe_16_ldap_escape.py | FP | TN |
| typical_19_weak_random.py | FN | TP |
| typical_23_ssti.py | FN | TP |
| typical_31_open_redirect_glob.py | FN | TP |
| typical_32_proto_pollution.js | FN | TP |
| typical_33_php_type_juggling.php | FN | TP |

### 2.2 退化的样本（正确 → 错误）

| 文件 | Baseline | Finetuned |
|------|----------|-----------|
| hard_crossfile_01_input.py | TN | FP |
| hard_longfile_03_hidden_ssti.py | TP | FN |
| noise_01_try_catch.py | TN | FP |
| noise_02_misleading_comment.py | TN | FP |
| typical_06_secret.py | TP | FN |
| typical_15_missing_authz.py | TP | FN |
| typical_22_csrf.py | TP | FN |
| typical_29_integer_overflow.java | TP | FN |

## 3. 分类别统计

| 类别 | Baseline (TP/TN/FP/FN/PF) | Finetuned (TP/TN/FP/FN/PF) |
|------|---------------------------|----------------------------|
| code_injection | 2/0/0/0/0 (n=2) | 2/0/0/0/0 (n=2) |
| command_injection | 4/0/0/1/0 (n=5) | 4/0/0/1/0 (n=5) |
| cross_file_helper | 0/2/1/0/0 (n=3) | 0/2/1/0/0 (n=3) |
| csrf | 2/0/0/0/0 (n=2) | 1/0/0/1/0 (n=2) |
| cve_real | 2/0/0/2/0 (n=4) | 3/0/0/1/0 (n=4) |
| hardcoded_secret | 1/0/0/0/0 (n=1) | 0/0/0/1/0 (n=1) |
| idor | 2/0/0/0/0 (n=2) | 2/0/0/0/0 (n=2) |
| information_disclosure | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| insecure_deserialization | 3/0/0/0/0 (n=3) | 3/0/0/0/0 (n=3) |
| insecure_tls | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| integer_overflow | 1/0/0/0/0 (n=1) | 0/0/0/1/0 (n=1) |
| jwt_confusion | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| ldap_injection | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| log_injection | 0/0/0/1/0 (n=1) | 1/0/0/0/0 (n=1) |
| mass_assignment | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| missing_authentication | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| missing_authorization | 1/0/0/0/0 (n=1) | 0/0/0/1/0 (n=1) |
| noise | 0/3/3/0/0 (n=6) | 0/1/5/0/0 (n=6) |
| nosql_injection | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| open_redirect | 1/0/0/1/0 (n=2) | 2/0/0/0/0 (n=2) |
| path_traversal | 2/0/0/2/0 (n=4) | 4/0/0/0/0 (n=4) |
| prototype_pollution | 0/0/0/1/0 (n=1) | 1/0/0/0/0 (n=1) |
| race_condition | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| safe_control | 0/16/2/0/0 (n=18) | 0/18/0/0/0 (n=18) |
| session_fixation | 0/0/0/1/0 (n=1) | 0/0/0/1/0 (n=1) |
| sql_injection | 5/0/0/1/0 (n=6) | 5/0/0/1/0 (n=6) |
| ssrf | 2/0/0/0/0 (n=2) | 2/0/0/0/0 (n=2) |
| ssti | 2/0/0/1/0 (n=3) | 2/0/0/1/0 (n=3) |
| timing_attack | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| type_juggling | 0/0/0/1/0 (n=1) | 1/0/0/0/0 (n=1) |
| unrestricted_upload | 0/0/0/1/0 (n=1) | 1/0/0/0/0 (n=1) |
| weak_cryptography | 2/0/0/1/0 (n=3) | 3/0/0/0/0 (n=3) |
| xpath_injection | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |
| xss | 3/0/0/0/0 (n=3) | 3/0/0/0/0 (n=3) |
| xxe | 1/0/0/0/0 (n=1) | 1/0/0/0/0 (n=1) |

## 4. Finetuned 仍然失败的样本

| 文件 | 期望 | 预测 | 结果 | 类别 | CWE |
|------|------|------|------|------|-----|
| hard_cve_05_spring4shell.java | 有漏洞 | False | FN | cve_real | CWE-915 |
| hard_longfile_01_hidden_sql.py | 有漏洞 | False | FN | sql_injection | CWE-89 |
| hard_longfile_02_hidden_cmd.py | 有漏洞 | False | FN | command_injection | CWE-78 |
| hard_longfile_03_hidden_ssti.py | 有漏洞 | False | FN | ssti | CWE-1336 |
| typical_06_secret.py | 有漏洞 | False | FN | hardcoded_secret | CWE-798 |
| typical_15_missing_authz.py | 有漏洞 | False | FN | missing_authorization | CWE-862 |
| typical_16_session_fixation.py | 有漏洞 | False | FN | session_fixation | CWE-384 |
| typical_22_csrf.py | 有漏洞 | False | FN | csrf | CWE-352 |
| typical_29_integer_overflow.java | 有漏洞 | False | FN | integer_overflow | CWE-190 |
| hard_crossfile_01_input.py | 安全 | True | FP | cross_file_helper | N/A |
| noise_01_try_catch.py | 安全 | True | FP | noise | N/A |
| noise_02_misleading_comment.py | 安全 | True | FP | noise | N/A |
| noise_03_harden_string_concat.py | 安全 | True | FP | noise | N/A |
| noise_04_commented_dangerous.py | 安全 | True | FP | noise | N/A |
| noise_06_shell_true_hardcoded.py | 安全 | True | FP | noise | N/A |
