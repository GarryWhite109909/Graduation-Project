# exp_06_finetune/data/ 数据字典

> 整理日期：2026-07-23（Qwen3-8B 重构 P0 完成后），2026-07-26 更新（v5_clean 入册），2026-07-31 更新（v7_realworld + v8_cwe_attribution 入册），**2026-08-01 更新（v9_augmented 跑前优化，914 条，CWE 命名标准化）**
> 整理人：自动归档脚本 + 手工标注

## 一、当前在用（SFT/DPO 训练直接消费）

| 文件 | 行数 | 用途 | 生成方式 |
|---|---|---|---|
| `train_chatml_v9_augmented.jsonl` | 914 | **v9 增强训练数据**（2026-08-01，跑前优化后，待训练） | v8_cwe_attribution 819 + 95 条新样本（A:变量重命名 10 / B:防御迷惑 8 / C:注意力分散 5 / D:框架代码误判 5 / E:安全代码 20 / F:CWE归因 7 / G:Java/JS LDAP注入 10 / H:信任边界绕过 10 / I:整数溢出 10 / J:Java/JS安全 10），由 `build_v9_augmented.py` 生成；CWE 命名标准化修正 56 条；Jaccard 泄漏审计覆盖 107 个测试样本，0 泄漏（>=0.5），新样本间 0 高重叠（>=0.8） |
| `train_chatml_v8_cwe_attribution.jsonl` | 819 | **v8 CWE 归因专项 SFT 训练数据**（2026-07-31，训练中） | v7_realworld 799 + 24 条对比 CoT 样本（注入混淆 5 / 认证权限混淆 4 / 密码学混淆 3 / 模板表达式混淆 4 / 其他高频误判 8），由 `build_v8_cwe_attribution.py` 生成，Jaccard 泄漏审计 0 泄漏（阈值 0.8） |
| `train_chatml_v7_realworld.jsonl` | 799 | **v7 实战专用 SFT 训练数据**（2026-07-31，v8 基底） | v5_clean 749 + 50 条新增样本（CWE-90 LDAP 10 / CWE-441 信任边界 10 / CWE-190 整数溢出 8 / FP 反事实 CoT 6 / 对比 CoT 6 / CVE 启发实战 10），由 `build_v7_realworld.py` 生成，Jaccard 泄漏审计 0 高重叠 |
| `train_chatml_v5_clean.jsonl` | 749 | **SFT 训练数据**（v5，v7 基底） | 基于 v4 清洗 100 个测试集泄漏/近泄漏样本 + 新增 10 条弱密码学样本 |
| `dpo_merged.jsonl` | 104 | DPO 数据（本地未使用） | `merge_dpo_data.py` 合并 v1+v3+expansion+fp_v5 后去重；**本地 16GB GPU 无法训练 8B DPO** |

## 二、上游资产（已合并到上述最终数据，保留供重生成）

| 文件 | 行数 | 上游属于 | 说明 |
|---|---|---|---|
| `train_chatml.jsonl` | 222 | → train_chatml_v2/v3/v4 | `build_dataset.py` 输出的原始手写样本（42 CWE / 9 语言） |
| `distill_corpus_annotated_v2.jsonl` | 400 | → train_chatml_v2/v3/v4 | 教师蒸馏 CoT v2，由 `regenerate_cot_with_teacher.py` 用 qwen2.5-coder:7b 重生成 |
| `supplement_chatml.jsonl` | 49 | → train_chatml_v2/v3/v4 | 难样本对抗补充，由 `supplement_hard_samples.py` 生成 |
| `glm_cot_map.jsonl` | 400 | → distill_v2 上游 | GLM 教师生成的 CoT 映射，distill_v2 的输入 |
| `dpo_preference_pairs_v3.jsonl` | 98 | → dpo_merged | DPO v3 改进版 |
| `dpo_v3_expansion.jsonl` | 36 | → dpo_merged | DPO v3 扩展（长尾 CWE） |
| `dpo_preference_pairs.jsonl` | 62 | → dpo_merged | DPO v1 原始（质量较低，已被 v3 大量替代） |
| `dpo_fp_pairs_v4.jsonl` | 5 | → dpo_merged (已归档) | **Step 4 真实 FP DPO pair v4**（rejected=模型实际 FP 输出，chosen=数据流推理式正确拒绝），由 `generate_fp_dpo_pairs.py` 从 v3 评估结果提取。**已被 v5 替代** |
| `dpo_fp_pairs_v5.jsonl` | 6 | → dpo_merged | **Step 4 真实 FP DPO pair v5**（基于 v5 评估的 6 个 FP，含新增 noise_05_decorator_wrapper.py），由 `generate_fp_dpo_pairs.py` 从 v5 评估结果提取 |

## 二·补、历史 SFT 数据（已被 v5_clean 替代，保留供回溯对比）

| 文件 | 行数 | 状态 | 说明 |
|---|---|---|---|
| `train_chatml_v7.jsonl` | 757 | **v7 早期实验数据（已被 v7_realworld 替代）** | `build_v7_dataset.py` 生成的早期版本，仅追加 8 条样本，覆盖不足。已被 `train_chatml_v7_realworld.jsonl`（799 条，50 新增样本）替代 |
| `train_chatml_v6_hard_neg.jsonl` | 755 | 已归档为失败尝试 | v5_clean + 6 个 FP 正确拒绝 CoT。**引起负迁移**：CVE-fix recall 从 57.1% 掉到 42.9%，新增 `cve_fix_0003.py` FN；合成集 recall 从 100% 掉到 98.4% |
| `_archive_failed/train_chatml_v4_LEAKED_DO_NOT_USE.jsonl` | 839 | **已归档为泄漏数据，严禁复用** | v3 + CoT 清单化修复 + 7 条 CWE-441 样本。**含测试集泄漏**（3 精确匹配 + 63 高重叠变体），不可用于可信评估 |
| `train_chatml_v3_fixed.jsonl` | 832 | 已被 v4 替代 | v3 修复 CWE 标注冲突 + 107 条 CoT 重写 + 9 条 LDAP 补充 |
| `train_chatml_v3.jsonl` | 823 | 已被 v3_fixed 替代 | v3 首版（含 CWE 标注冲突） |
| `train_chatml_v2.jsonl` | 823 | 已被 v3 替代 | Qwen2.5-Coder 时代 SFT 数据（含模板化 CoT） |
| `rewrite_progress.jsonl` | 107 | v3 中间产物 | CoT 重写进度记录（Ollama qwen3:8b 重写） |

## 三、已暂缓（CPT 路线，方向已变，归档到 `_archive_cpt/`）

> CPT/KnItLM 路线在 2026-07-22 切换到 Qwen3-8B 后**整体暂缓**。原因：
> 1. Qwen3-8B 零样本 recall 96.7% 已很强，CPT 注入已掌握知识会引发知识冲突（负迁移）
> 2. CPT 引入"参数化查询幻觉"副作用（Phase 3 已观测到 4 个 TP→FN 回归）
> 3. 新方向改走 SFT（攻 strict_recall）→ DPO（降 FPR）→ 错题闭环

| 文件 | 行数 | 原用途 |
|---|---|---|
| `cpt_corpus.jsonl` | 1568 | KnItLM CPT 训练语料（CVE/CWE/OWASP 知识） |
| `probe_report_qwen3.json` | 778 | `probe_model.py` 知识探测报告（mastered/fuzzy/error 分类） |
| `distill_corpus_annotated.jsonl` | 400 | 蒸馏标注 v1（模板 CoT，已被 v2 教师版替代） |

## 四、已暂缓（Phase 3 错题闭环 supplement，归档到 `_archive_supplement/`）

> Phase 3 错题闭环（`run_error_driven_loop.sh`）依赖 CPT 路线，CPT 暂缓后这些 supplement 不再使用。
> 未来若 P4 错题闭环重启，需重新生成（基于 Qwen3-8B 错题而非 7B 错题）。

| 文件 | 行数 | 原针对问题 |
|---|---|---|
| `supplement_7b_weakness.jsonl` | 14 | 7B 模型能力盲区 |
| `supplement_blindspot_cwe.jsonl` | 10 | CWE 知识盲点 |
| `supplement_ccot_contrastive.jsonl` | 22 | contrastive CoT 对比 |
| `supplement_ccot_contrastive_v2.jsonl` | 40 | contrastive CoT v2 |
| `supplement_ccot_v3_expansion.jsonl` | 36 | CoT v3 扩展 |
| `supplement_crypto_noise.jsonl` | 24 | 加密噪声样本 |
| `supplement_cwe_attribution_nosql.jsonl` | 9 | NoSQL CWE 归因 |
| `supplement_cwe_attribution_spel.jsonl` | 8 | SpEL CWE 归因 |
| `supplement_cwe_attribution_ssti.jsonl` | 14 | SSTI CWE 归因 |
| `supplement_longfile_defense.jsonl` | 16 | 长文件防御 |
| `supplement_longtail_cwe.jsonl` | 35 | 长尾 CWE 补充 |

## 五、其他子目录

- `teacher_logits/` - Phase 4 Prompt Distillation 用的教师 logits 缓存（PD 已暂缓）
- `teacher_logits_test/` - 同上，测试集缓存

## 六、重生成路径（若需重建训练数据）

```bash
# SFT 数据流
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/build_dataset.py                    # → train_chatml.jsonl
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/generate_distill_data.py            # → distill_corpus_annotated.jsonl (v1)
# distill_corpus_annotated_v2.jsonl 需用 Ollama qwen2.5-coder:7b 教师重生成：
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/regenerate_cot_with_teacher.py
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/supplement_hard_samples.py          # → supplement_chatml.jsonl
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/combine_and_augment.py              # → train_chatml_v2.jsonl

# DPO 数据流
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/generate_dpo_pairs.py               # → dpo_preference_pairs*.jsonl
PYTHONPATH=. python3 \
  experiments/exp_06_finetune/scripts/merge_dpo_data.py                   # → dpo_merged.jsonl
```

## 七、Qwen3-8B 切换后的注意点

- `train_chatml_v5_clean.jsonl` 是当前 Qwen3-8B SFT 数据（2026-07-26）：
  - 基于 v4 清洗 100 个测试集泄漏/近泄漏样本（3 个精确匹配 + 63 个 30%+ Jaccard 重叠变体）
  - 新增 10 条弱密码学样本（DES/AES 硬编码密钥/IV、CBC 模式固定 IV）
  - v5 评估：合成集 recall 1.000 / FPR 0.231 / strict_recall 0.590；CVE-fix recall 0.571 / strict_recall 0.143
- `_archive_failed/train_chatml_v4_LEAKED_DO_NOT_USE.jsonl` 已归档为泄漏数据（2026-07-26）：
  - 含测试集泄漏（`safe_03_subprocess_list`/`typical_04_path`/`hard_bypass_04_path_regex` 等反复出现的变体）
  - v4 评估指标不可信（recall 0.885 是污染假低，FPR 0.115 是污染假高）
  - 对应生成脚本 `fix_cot_quality.py` / `gen_cwe441_samples.py` 已移至 `scripts/_archive/`
- `train_chatml_v6_hard_neg.jsonl` 已归档为失败尝试（2026-07-27）：
  - 在 v5_clean 上追加 6 个 FP 正确拒绝 CoT，想降 FPR
  - 结果：CVE-fix recall 从 57.1% → 42.9%，合成集 recall 从 100% → 98.4%；`cve_fix_0003.py` 从 TP 掉回 FN
  - **结论**：simple hard-negative SFT 引起负迁移，v5 仍为最佳
- DPO 本地不可行（2026-07-27）：
  - 8bit 量化 OOM 黑屏；4bit 量化 DPO 双前向梯度失效（grad_norm=0，loss=ln(2) 不下降）
  - `dpo_merged.jsonl` / `dpo_fp_pairs_v5.jsonl` 保留但未使用；若换 24GB+ GPU 可直接复用
- `train_chatml_v7_realworld.jsonl` 实战专用训练数据（2026-07-31）：
  - v5_clean 749 + 50 条新增样本，针对 CVE-fix 持续 FN 的三个盲区（CWE-90 LDAP / CWE-441 信任边界 / CWE-190 整数溢出）
  - 能力提升设计：(a) 反事实 CoT（FP 修正，教逻辑推理"去掉防御会怎样"）；(b) 对比 CoT（易混 CWE 判别，教语义理解）；(c) CVE 启发实战样本（隐蔽漏洞模式，教真实代码语义理解）；(d) 严格 JSON schema（字符输出能力）
  - Jaccard 泄漏审计：0 高重叠（>=0.5），6 疑似重叠（0.3-0.5，均为设计内的对比/修正样本）
  - 训练配置与 v5 一致（r=8, alpha=16, epochs=3, lr=1e-4, rslora），避免 v6 负迁移风险
- `train_chatml_v9_augmented.jsonl` 增强训练数据（2026-08-01）：
  - v8_cwe_attribution 819 + 50 条新样本，基于修正后方法论（见 `docs/和一个AI的讨论1.md` 评判）
  - 六类新增样本设计：
    - (A) 变量重命名增强 10 条：对已有 CWE 模式做等价变换（变量重命名 + 跨语言变体：Go/Ruby/Java/Node.js/PHP），拉大同类 CWE 表征区分度，防记忆表面特征
    - (B) 防御迷惑靶向 8 条：针对 CVE-fix FN 根因 1（看到部分防御就判安全），含 LDAP 部分编码 / SQL 错误转义 / XSS 部分转义 / 路径 startswith 未规范化 / 正则白名单可绕过等；其中 3 条为"防御有效但模式脆弱"的安全样本（教模型区分有效防御 vs 脆弱模式）
    - (C) 注意力分散靶向 5 条：针对 CVE-fix FN 根因 2（被无关安全措施分散注意），含 bcrypt+LDAP / CSRF+SQLi / HTTPS+XSS / RateLimit+CmdI / Session+Path；CoT 显式写出"X 防御有效但与 Y 漏洞无关"
    - (D) 框架代码误判靶向 5 条：针对 CVE-fix FN 根因 3（真实漏洞误判为演示代码），含 JSON-RPC eval / 动态模板 / 插件动态导入 / 配置 exec / 计算器 eval
    - (E) 多样安全代码 15 条：非 hard-negative 方式增加安全代码多样性降 FPR，覆盖 subprocess 列表参数 / shlex.quote / PreparedStatement / HTML 转义 / 路径校验 / bcrypt / json.loads / JWT 完整验证 / 模板渲染 / defusedxml / 环境变量凭证 / CSRF token / secrets / hmac.compare_digest / yaml.safe_load
    - (F) CWE 归因增强 7 条：补充 v8 未覆盖的易混边界（CWE-190 整数溢出 / CWE-601 开放重定向 / CWE-117 日志注入 / CWE-200 信息泄露 / CWE-611 XXE / CWE-798 硬编码 API Key / CWE-327 ECB 模式）
  - 泄漏审计：修复了原脚本指向 `exp_04_hard_samples/` 顶层（仅含脚本）的 bug，改为正确检查 `exp_04_hard_samples/samples/`（86 合成）+ `exp_06_finetune/testset_cve_fix/`（21 CVE-fix），共 107 个测试样本，0 泄漏（>=0.5）
  - 训练配置与 v8 一致（r=8, alpha=16, epochs=3, lr=1e-4, rslora），待 v8 训练完成后启动
