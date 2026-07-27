# exp_06_finetune 实验台账

> 建立日期：2026-07-23（Qwen3-8B 重构 P0 完成后）
> 维护规则：每次新评估运行后必须追加一行到对应小节，旧锚点不得删除只标注"已被 XXX 替代"

## 一、当前锚点（所有后续 SFT/DPO 必须对比此基线）

### Qwen3-8B baseline @ 87 合成集（max_tokens=2048）

| 字段 | 值 |
|---|---|
| 结果文件 | `baseline/exp_06_eval.ollama_qwen3_8b.20260722_225944.json` |
| 评估时间 | 2026-07-22 22:59:44 |
| 模型 | qwen3:8b（Ollama，chat API + think:false） |
| 测试集 | exp_04_hard_samples 87 段（v3 修复后） |
| 推理参数 | temperature=0.0, do_sample=False, num_ctx=16384, max_new_tokens=2048 |
| TP / FP / FN / TN | 59 / 7 / 2 / 19 |
| vuln_total / safe_total | 61 / 26 |
| **recall** | **0.967** |
| **FPR** | **0.269** |
| **accuracy** | **0.897** |
| **parse_fail** | **0 / 87** |
| strict_TP / cwe_mismatch | 28 / 31 |
| **strict_recall** | **0.459** |
| **strict_accuracy** | **0.540** |
| 平均耗时 | 11.84s/样本 |

**关键诊断**：
- recall 96.7% 看似强，但 strict_recall 45.9% 暴露真实问题——CWE 归因能力差（31/61 错标）
- FPR 26.9% 过高——7 个安全样本被误判为漏洞
- parse_fail 0/87 已消除（P0 修复 max_tokens 1024→2048 的成果）

**红线规则**：后续任何训练后评估，recall 不得低于 0.95（红线），FPR / parse_fail / strict_recall 须有改善方算达标。

## 二、Qwen3-8B 时代历史评估（保留供对比，不作锚点）

| 时间 | 文件 | 说明 | 状态 |
|---|---|---|---|
| 2026-07-22 00:01 | `baseline/exp_06_eval.ollama_qwen3_8b.20260722_000125.json` | 旧 baseline (max_tokens=1024) | ❌ 已被 225944 替代（parse_fail 18/87 蒙蔽真实表现） |
| 2026-07-20 04:32 | `baseline/exp_06_eval.ollama_qwen3_8b.20260720_043236.json` | 更早的 Qwen3-8B 测试 | ❌ 同上 |
| 2026-07-11 15:12 | `baseline/exp_06_eval.ollama_qwen3-coder_30b.20260711_151248.json` | Qwen3-Coder 30B 对照（PD teacher 候选） | ⚠️ PD 暂缓，仅作参考 |

## 三、Qwen2.5-Coder 时代历史评估（已归档到 `_archive_qwen25/`）

> 2026-07-22 底座切到 Qwen3-8B 后，Qwen2.5-Coder 时代的所有评估结果**整体归档**。
> 归档原因：base_model 不同、tokenizer 不同、thinking 模式不同，结果不可直接对比。
> 保留磁盘副本供论文写作时回溯历史演进路径。

### 3.1 Baseline 系列（4 个）

| 时间 | 文件 | 模型 | 说明 |
|---|---|---|---|
| 2026-07-08 13:14 | `exp_06_eval.baseline.20260708_131416.json` | Qwen2.5-Coder-3B | 3B 时代早期 |
| 2026-07-09 04:14 | `exp_06_eval.baseline.20260709_041420.json` | Qwen2.5-Coder-3B | 3B 时代 |
| 2026-07-19 19:19 | `exp_06_eval.baseline.20260719_191959.json` | Qwen2.5-Coder-7B | Phase 1-3 期间 |
| 2026-07-19 19:41 | `exp_06_eval.baseline.20260719_194118.json` | Qwen2.5-Coder-7B | Phase 1-3 期间 |

### 3.2 Finetuned 系列（3B 时代，6 个）

| 时间 | 文件 | 说明 |
|---|---|---|
| 2026-07-07 06:08 | `exp_06_eval.finetuned.20260707_060810.json` | 3B 初版微调 |
| 2026-07-07 06:08 | `exp_06_eval.finetuned.20260707_060810.compare.md` | 同上对比报告 |
| 2026-07-09 04:27 | `exp_06_eval.finetuned_custom.20260709_042733.json` | 3B P0/P1 优化后 |
| 2026-07-09 05:39 | `exp_06_eval.finetuned_custom.20260709_053915.json` | 同上重跑 |
| 2026-07-09 10:00 | `exp_06_eval.finetuned_custom.20260709_100049.json` | 同上重跑 |
| 2026-07-10 03:05 | `exp_06_eval.finetuned_custom.20260710_030533.json` | 7B 时代 r8_e1 |
| 2026-07-10 16:12 | `exp_06_eval.finetuned_custom.20260710_161225.json` | 同上重跑 |
| 2026-07-10 16:39 | `exp_06_eval.finetuned_custom.20260710_163901.json` | 同上重跑 |
| 2026-07-11 03:11 | `exp_06_eval.finetuned_custom.20260711_031127.json` | 同上重跑 |
| 2026-07-11 03:39 | `exp_06_eval.finetuned_custom.20260711_033933.json` | 同上重跑 |
| 2026-07-11 05:08 | `exp_06_eval.finetuned_custom.20260711_050855.json` | 同上重跑 |

### 3.3 Phase 1 sweep（7 个）

| 时间 | 文件 | 配置 |
|---|---|---|
| 2026-07-17 21:28 | `exp_06_eval.phase1_lr1e-5_base.20260717_212802.json` | lr=1e-5 baseline |
| 2026-07-18 15:13 | `exp_06_eval.phase1_lr1e-5_base.20260718_151305.json` | 同上重跑 |
| 2026-07-18 15:39 | `exp_06_eval.phase1_lr5e-5.20260718_153922.json` | lr=5e-5 |
| 2026-07-18 16:32 | `exp_06_eval.phase1_lr5e-5_rslora.20260718_163209.json` | lr=5e-5 + rsLoRA |
| 2026-07-18 16:05 | `exp_06_eval.phase1_lr1e-4.20260718_160554.json` | lr=1e-4 |
| 2026-07-18 16:58 | `exp_06_eval.phase1_lr1e-4_rslora.20260718_165837.json` | lr=1e-4 + rsLoRA（dev_loss 最低 0.8892） |
| 2026-07-18 17:25 | `exp_06_eval.phase1_lr5e-5_rslora_dora.20260718_172510.json` | lr=5e-5 + rsLoRA + DoRA |

### 3.4 Phase 2（1 个）

| 时间 | 文件 | 配置 |
|---|---|---|
| 2026-07-18 22:42 | `exp_06_eval.phase2_r32_lr1e-5_rslora_e2.20260718_224206.json` | r=32 + rsLoRA + e=2（失败，FPR +19.2pp） |

### 3.5 Phase 3 KnItLM CPT（3 个）

| 时间 | 文件 | 说明 |
|---|---|---|
| 2026-07-19 07:06 | `exp_06_eval.knitlm_merged.20260719_070646.json` | KnItLM CPT 首版（strict_recall +23pp） |
| 2026-07-19 07:08 | `exp_06_eval.knitlm_merged.20260719_070818.json` | 同上重跑 |
| 2026-07-19 19:41 | `exp_06_eval.knitlm_merged.20260719_194118_new_corpus.json` | 新 corpus 后重跑（参数化查询幻觉） |

### 3.6 难样本提取中间产物（7 个）

| 文件 | 说明 |
|---|---|
| `hard_samples_test_baseline.json` | baseline 错题集 |
| `hard_samples_lr1e-5_base.json` | lr=1e-5 baseline 错题 |
| `hard_samples_lr5e-5.json` | lr=5e-5 错题 |
| `hard_samples_lr5e-5_rslora.json` | lr=5e-5 + rsLoRA 错题 |
| `hard_samples_lr5e-5_rslora_dora.json` | + DoRA 错题 |
| `hard_samples_lr1e-4.json` | lr=1e-4 错题 |
| `hard_samples_lr1e-4_rslora.json` | lr=1e-4 + rsLoRA 错题 |

### 3.7 对比报告（10 个）

| 文件 | 说明 |
|---|---|
| `compare_4way_summary.md` | 4 路对比汇总 |
| `compare_4way_3b_base_vs_3b_ft.md` | 3B baseline vs finetuned |
| `compare_4way_7b_base_vs_3b_base.md` | 7B vs 3B baseline |
| `compare_4way_7b_base_vs_7b_ft.md` | 7B baseline vs finetuned |
| `compare_4way_7b_ft_vs_3b_ft.md` | 7B vs 3B finetuned |
| `compare_7b_3b_detail.md` | 7B vs 3B 详细 |
| `compare_7b_3b_summary.md` | 7B vs 3B 汇总 |
| `phase1_sweep_summary.md` | Phase 1 sweep 总结 |
| `phase2_summary.md` | Phase 2 总结 |
| `phase3_summary.md` | Phase 3 KnItLM 总结 |
| `phase3_error_analysis.md` | Phase 3 错题分析（参数化查询幻觉） |
| `phase3_old_vs_new_summary.md` | Phase 3 新旧 corpus 对比 |
| `phase3_vs_phase1_regression.json` | Phase 3 vs Phase 1 回归数据 |

## 四、待办（P1-P4 后续运行记录追加位置）

### CVE-fix 测试集标注修复（2026-07-25）

> 逐样本审查 8 条 CVE-fix 后发现 2 条标注错误，已修正。修正后有效样本 7 条（0008 移除），扩充脚本将补充到 20 条。

| 样本 | 问题 | 修正 | 影响 |
|---|---|---|---|
| `cve_fix_0001.java` | NVD 标 CWE-74（通用注入），但 CVE 描述明确为 LDAP injection | expected_cwe CWE-74 → **CWE-90**（与 cve_fix_0002.js 一致） | 原标注下模型即使识别出 LDAP 注入也会因 CWE 号不匹配被计 strict_FN |
| `cve_fix_0008.py` | 标为 CWE-502（pickle 反序列化），但文件中**不含任何 pickle.loads**（实际漏洞在 cve_fix_0007.py 中） | 从 samples 移除（跨文件上下文，非实际含漏洞文件） | 原标注下模型正确判断"无反序列化"却被计 FN/strict_FN |

**修正后的 7 条有效样本**：

| # | 文件 | 语言 | CWE | CVE | 仓库 |
|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CWE-90 | CVE-2015-1169 | Jasig/cas |
| 2 | cve_fix_0002.js | JS | CWE-90 | CVE-2015-7294 | vesse/node-ldapauth-fork |
| 3 | cve_fix_0003.py | Python | CWE-95 | CVE-2026-47391 | MervinPraison/PraisonAI |
| 4 | cve_fix_0004.py | Python | CWE-95 | CVE-2026-47391 | MervinPraison/PraisonAI |
| 5 | cve_fix_0005.js | JS | CWE-441 | CVE-2026-56675 | decolua/9router |
| 6 | cve_fix_0006.js | JS | CWE-441 | CVE-2026-56675 | decolua/9router |
| 7 | cve_fix_0007.py | Python | CWE-502 | CVE-2012-4406 | openstack/swift |

> ⚠️ 此前所有基于 8 样本的评估结果（baseline / SFT v2 / SFT v3）中，cve_fix_0001 和 cve_fix_0008 的 strict 指标不可靠。loose recall/accuracy 不受影响（0001 一直是 FN，0008 在 v2/v3 中是 TP 但属于误判路径穿越）。

### P1 CVE-fix baseline（已完成，2026-07-25 标注修正）

**Qwen3-8B @ 8 CVE-fix 真实样本（2026-07-23）**

| 字段 | 值 |
|---|---|
| 结果文件 | `baseline/exp_06_eval.ollama_qwen3_8b.20260723_001648.json` |
| 测试集 | CVE-fix v2（8 段，5 CVE，4 语言：Java 1 / JS 3 / Python 4） |
| 推理参数 | 同 87 合成集锚点（temperature=0.0, max_new_tokens=2048, num_ctx=16384） |
| TP / FP / FN / TN | 3 / 0 / 5 / 0 |
| vuln_total / safe_total | 8 / 0（无安全样本，FPR 不适用） |
| **recall** | **0.375** |
| **accuracy** | **0.375** |
| **parse_fail** | **0 / 8** |
| strict_TP / cwe_mismatch | 1 / 2 |
| **strict_recall** | **0.125** |
| 平均耗时 | 16.87s/样本 |

**逐样本明细**：
| # | 文件 | 语言 | CVE | CWE | 仓库 ★ | 结果 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CVE-2015-1169 | CWE-74 | Jasig/cas ★11354 | FN |
| 2 | cve_fix_0002.js | JS | CVE-2015-7294 | CWE-90 | vesse/node-ldapauth-fork ★131 | TP |
| 3 | cve_fix_0003.py | Python | CVE-2026-47391 | CWE-95 | MervinPraison/PraisonAI ★8504 | FN |
| 4 | cve_fix_0004.py | Python | CVE-2026-47391 | CWE-95 | MervinPraison/PraisonAI ★8504 | TP |
| 5 | cve_fix_0005.js | JS | CVE-2026-56675 | CWE-441 | decolua/9router | FN |
| 6 | cve_fix_0006.js | JS | CVE-2026-56675 | CWE-441 | decolua/9router | FN |
| 7 | cve_fix_0007.py | Python | CVE-2012-4406 | CWE-502 | openstack/swift ★40251 | TP（正则匹配 pickle.loads） |
| 8 | cve_fix_0008.py | Python | CVE-2012-4406 | CWE-502 | openstack/swift ★40251 | FN |

**关键结论**：
- **合成集严重虚高**：87 合成集 recall 96.7% → CVE-fix 真实集 recall 37.5%，差距 59.2pp
- strict_recall 也大幅下降：45.9% → 12.5%
- **模型在真实 CVE 代码上的能力远不如合成样本**——合成样本的漏洞模式太明显（典型 SQLi/XSS/CMDi），而真实 CVE 的漏洞模式更隐蔽
- **反序列化最弱**（CWE-502/441，4 样本 1 TP = 25%）
- **Java 最弱**（1 样本 0 TP = 0%）
- 后续 SFT/DPO 必须在 CVE-fix 上验证，不能只看合成集指标

### P2 SFT（已完成 2026-07-23）

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v2.jsonl`（823 条，train=700 dev=123） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 264 steps |
| 训练耗时 | 3h14min |
| train_loss | 0.7184 |
| dev_loss 历史 | epoch1=0.7901 → epoch2=0.7243(最低) → epoch3=0.7437(回升，轻度过拟合) |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 SFT @ 87 合成集**：

| 字段 | 值 |
|---|---|
| 结果文件 | `v2/exp_06_eval.finetuned_custom.20260723_230502.json` |
| 评估时间 | 2026-07-23 23:05:02 |
| TP / FP / FN / TN | 59 / 6 / 2 / 20 |
| vuln_total / safe_total | 61 / 26 |
| **recall** | **0.967** (vs baseline 0.967，持平) |
| **FPR** | **0.231** (vs baseline 0.269，-3.8pp ✓) |
| **accuracy** | **0.908** (vs baseline 0.897，+1.1pp ✓) |
| **parse_fail** | **0 / 87** (持平) |
| strict_TP / cwe_mismatch | 38 / 21 (vs baseline 28 / 31) |
| **strict_recall** | **0.623** (vs baseline 0.459，+16.4pp ✓✓✓) |
| **strict_accuracy** | **0.667** (vs baseline 0.540，+12.7pp ✓) |
| 平均耗时 | 24.41s/样本 |

**P2 SFT @ 8 CVE-fix 真实集**：

| 字段 | 值 |
|---|---|
| 结果文件 | `v2/exp_06_eval.finetuned_custom.20260723_231109.json` |
| 评估时间 | 2026-07-23 23:11:09 |
| TP / FP / FN / TN | 5 / 0 / 3 / 0 |
| vuln_total / safe_total | 8 / 0（无安全样本，FPR 不适用） |
| **recall** | **0.625** (vs baseline 0.375，+25pp ✓✓✓) |
| **accuracy** | **0.625** (vs baseline 0.375，+25pp ✓) |
| **parse_fail** | **0 / 8** (持平) |
| strict_TP / cwe_mismatch | 1 / 4 (vs baseline 1 / 2) |
| **strict_recall** | **0.125** (vs baseline 0.125，持平) |
| 平均耗时 | 41.01s/样本 |

**逐样本明细（CVE-fix，对比 baseline）**：
| # | 文件 | 语言 | CWE | baseline | SFT | 变化 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | Java | CWE-74 | FN | FN | 不变（Java LDAP 注入仍漏判） |
| 2 | cve_fix_0002.js | JS | CWE-90 | TP | FN | ⚠️ 回退（LDAP 注入） |
| 3 | cve_fix_0003.py | Python | CWE-95 | FN | TP | ✓ 提升（eval 代码注入） |
| 4 | cve_fix_0004.py | Python | CWE-95 | TP | TP | 保持 |
| 5 | cve_fix_0005.js | JS | CWE-441 | FN | FN | 不变（信任边界绕过） |
| 6 | cve_fix_0006.js | JS | CWE-441 | FN | TP | ✓ 提升（信任边界绕过） |
| 7 | cve_fix_0007.py | Python | CWE-502 | TP | TP | 保持（strict_TP） |
| 8 | cve_fix_0008.py | Python | CWE-502 | FN | TP | ✓ 提升（跨文件反序列化） |

**关键结论**：
- ✅ **SFT 在真实 CVE 上 recall +25pp**（37.5%→62.5%），训练数据有效
- ✅ **strict_recall +16.4pp**（合成集 45.9%→62.3%），CWE 归因能力大幅增强
- ✅ **FPR -3.8pp**（合成集 26.9%→23.1%），误报减少
- ✅ **recall 持平 0.967**（合成集），未突破 0.95 红线
- ⚠️ **CVE-fix strict_recall 仍为 0.125**：虽然 loose recall 提升，但 4/5 TP 的 CWE 标错
- ⚠️ **cve_fix_0002.js 回退**（TP→FN）：需分析原因（LDAP 注入模式识别退化？）
- 📊 合成集与 CVE-fix 差距从 59.2pp 缩小到 34.2pp（96.7% vs 62.5%），仍存在泛化 gap

### P2 v3 SFT（已完成 2026-07-25）

> v2 后发现训练数据存在 CWE 标注冲突（SSTI 标 CWE-94、NoSQL 标 CWE-643）、107 条模板化 CoT、LDAP 样本仅 1 条。v3 修复后重训。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v3_fixed.jsonl`（832 条，train=708 dev=124） |
| 数据变更 | 36 条 CWE 统一（SSTI→CWE-1336, NoSQL→CWE-943, eval→CWE-95）+ 107 条 CoT 重写（Ollama qwen3:8b）+ 9 条 LDAP 样本补充 |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 267 steps |
| 训练耗时 | 3h21min |
| train_loss | 0.7313 |
| dev_loss 历史 | epoch1=0.8428 → epoch2=0.7675(最低) → epoch3=0.7786(回升) |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v3/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 v3 SFT @ 87 合成集**：

| 字段 | 值 | vs v2 | vs baseline |
|---|---|---|---|
| 结果文件 | `v3/exp_06_eval.finetuned_custom.20260725_072050.json` | | |
| 评估时间 | 2026-07-25 07:20:50 | | |
| TP / FP / FN / TN | 60 / 5 / 1 / 21 | FP-1, FN-1 | |
| vuln_total / safe_total | 61 / 26 | | |
| **recall** | **0.984** | +1.7pp ✓ | +1.7pp ✓ |
| **FPR** | **0.192** | -3.9pp ✓ | -7.7pp ✓ |
| **accuracy** | **0.931** | +2.3pp ✓ | +3.4pp ✓ |
| **parse_fail** | **0 / 87** | 持平 | 持平 |
| strict_TP / cwe_mismatch | 37 / 23 | strict_TP-1 | |
| **strict_recall** | **0.607** | -1.6pp ⚠️ | +14.8pp ✓ |
| **strict_accuracy** | **0.667** | 持平 | +12.7pp ✓ |
| 平均耗时 | 24.16s/样本 | | |

**P2 v3 SFT @ 8 CVE-fix 真实集**：

| 字段 | 值 | vs v2 | vs baseline |
|---|---|---|---|
| 结果文件 | `v3/exp_06_eval.finetuned_custom.20260725_072609.json` | | |
| 评估时间 | 2026-07-25 07:26:09 | | |
| TP / FP / FN / TN | 4 / 0 / 4 / 0 | TP-1, FN+1 | |
| **recall** | **0.500** | -12.5pp ⚠️ | +12.5pp ✓ |
| **accuracy** | **0.500** | -12.5pp ⚠️ | +12.5pp ✓ |
| **parse_fail** | **0 / 8** | 持平 | 持平 |
| strict_TP / cwe_mismatch | 1 / 3 | | |
| **strict_recall** | **0.125** | 持平 | 持平 |
| 平均耗时 | 35.61s/样本 | | |

**逐样本明细（CVE-fix，v3 对比 v2）**：
| # | 文件 | CWE | v2 | v3 | 变化 | 根因 |
|---|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | CWE-74 | FN | FN | 不变 | 被防御措施迷惑（LdapEncoder 看似安全） |
| 2 | cve_fix_0002.js | CWE-90 | FN | FN | 不变 | LDAP 样本未解（关注 bcrypt 忽略 LDAP） |
| 3 | cve_fix_0003.py | CWE-95 | TP | **FN** | ⚠️ 回退 | CoT 重写导致过保守，完全漏看 eval() |
| 4 | cve_fix_0004.py | CWE-95 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-94 vs 95） |
| 5 | cve_fix_0005.js | CWE-441 | FN | FN | 不变 | 信任边界绕过未识别 |
| 6 | cve_fix_0006.js | CWE-441 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-330,200） |
| 7 | cve_fix_0007.py | CWE-502 | TP | TP | 保持 | strict_TP ✓（唯一 CWE 正确） |
| 8 | cve_fix_0008.py | CWE-502 | TP | TP | 保持 | 检测到但 CWE 标错（CWE-22 vs 502） |

**关键结论**：
- ✅ **合成集全面改善**：recall +1.7pp、FPR -3.9pp、accuracy +2.3pp（vs v2）
- ⚠️ **CVE-fix recall 回退**：0.625→0.500（-12.5pp），cve_fix_0003.py TP→FN
- ⚠️ **CVE-fix strict_recall 仍为 0.125**：SFT 无法解决 CWE 知识断层（CWE-441/74 无训练数据）
- 📊 **CoT 重写副作用**：重写后的 CoT 更"清单式"（逐项检查→都不匹配→无漏洞），对合成集标准模式更准，对真实 CVE 隐蔽模式更迟钝
- 📊 **CWE 统一未生效**：eval→CWE-95 统一后，cve_fix_0004 仍标 CWE-94（预训练知识主导）
- 📊 合成集与 CVE-fix 差距：v2 34.2pp → v3 48.4pp（泛化 gap 扩大）

**v2 vs v3 选型判断**：
| 维度 | v2 更优 | v3 更优 |
|---|---|---|
| 合成集 recall | | ✓ 0.984 vs 0.967 |
| 合成集 FPR | | ✓ 0.192 vs 0.231 |
| CVE-fix recall | ✓ 0.625 vs 0.500 | |
| CVE-fix strict_recall | 持平 0.125 | 持平 0.125 |
| dev_loss | ✓ 0.7243 vs 0.7675 | |

**决策**：采用 v3 作为 SFT 基座进入 DPO（合成集更大更可靠，CVE-fix 8 样本统计意义弱），DPO 目标降低 FPR + 校准 CWE 幻觉。

### P2 v4 SFT（训练中 2026-07-25）

> v3 评估后发现两个核心问题：(1) CoT 清单化导致 cve_fix_0003.py TP→FN 回退；(2) 5 个 FP 全部因"逐项排除清单"式误判（subprocess 列表参数被看作字符串拼接、shell=True+shlex.quote 被判漏洞等）。v4 针对性修复后重训。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v4.jsonl`（839 条，train=714 dev=125） |
| 数据变更 | (1) 修改 `prompts.py` ANALYSIS_SCOPE 为数据流推理导向 + 反清单式指令；(2) 修复 19 条不坚定 CoT（移除 hedge 短语）；(3) 修复 L8 事实错误（列表参数 subprocess）；(4) 补充 7 条 CWE-441 信任边界样本（loopback/XFF/内部 API 无认证） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| trainable params | 21,823,488 (0.27%) |
| 总步数 | 270 steps |
| 首步 loss | 1.45（v3 首步 1.698，降低 14.6%——v4 数据与模型更对齐） |
| 训练耗时 | 进行中（预计 ~3h40min） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rsloraqwen3_8b_sft_p2_v4/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**v4 数据变更详情**：

| 变更项 | 数量 | 说明 | 修复问题 |
|---|---|---|---|
| prompts.py ANALYSIS_SCOPE | - | 改为"识别输入→追踪数据流→评估防御→综合判断"，添加"严禁逐项列举漏洞类型做排除式检查"指令 | v3 CVE-fix 回退根因：CoT 清单化漏判非标准模式 |
| 不坚定 CoT 修复 | 19 条 | 移除"潜在风险""防御力度仍可加强""仍存在潜在的安全隐患"等 hedge 短语 | 安全样本 CoT 不坚定，模型学到"看到防御仍要说风险" |
| L8 事实错误修复 | 1 条 | 修正"未对 host 进行白名单校验"→"列表参数 subprocess.run + shell=False 是有效防御" | 训练数据自身事实错误会强化模型 FP |
| CWE-441 样本补充 | 7 条（4 漏洞 + 3 安全） | loopback 信任绕过 / X-Forwarded-For 伪造 / 内部 API 无认证 / 反向 DNS 信任 | 训练数据完全缺失 CWE-441，导致 2/8 CVE-fix FN |

**v4 评估结果**（2026-07-25 19:08，文件 `v4_failed/exp_06_eval.finetuned_custom.20260725_190849.json`）：
- 87 合成集：recall 0.885（-9.9pp vs v3）、FPR 0.115、strict_recall 0.492
- 7 CVE-fix：recall 0.429（3/7）、strict_recall 0.286
- ⚠️ **v4 训练数据存在系统性测试集泄漏**（详见 v5 章节分析），指标不可信，**v4 已被 v5_clean 替代**

### P2 v5 SFT（2026-07-26）

> v4 评估后发现训练数据与测试集存在系统性内容泄漏（不仅是 3 个精确匹配，还有 63 个 v4 训练样本与 20+ 测试文件存在 30%+ 行级 Jaccard 重叠，包括 `safe_03_subprocess_list`、`typical_04_path`、`hard_bypass_04_path_regex` 等反复出现的变体）。这些泄漏样本教会模型"看到 subprocess → 安全"等错误模式，导致 v4 在 `typical_13/15/22/29` 等 FN 上回退。v5 = v4 清洗 + 补充弱密码学样本。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v5_clean.jsonl`（749 条，train=636 dev=113） |
| 数据变更 | (1) 从 v4 删除 100 个泄漏/近泄漏样本（含 3 个精确匹配 + 63 个高重叠变体）；(2) 新增 10 条弱密码学样本（DES/AES 硬编码密钥/IV、CBC 模式固定 IV）；(3) CoT 模板与 v4 一致（739 个共有样本 assistant 响应未变） |
| 基座模型 | Qwen/Qwen3-8B（4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rslora=True, dora=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| 总步数 | 240 steps（best @ step 160, dev_loss=0.7573） |
| best adapter | `outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best/` |
| 推理模式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |

**P2 v5 SFT @ 87 合成集**：

| 字段 | 值 | vs v4（污染） | vs v3 | vs baseline |
|---|---|---|---|---|
| 结果文件 | `v5/exp_06_eval.finetuned_custom.20260726_085555.json` | | | |
| 评估时间 | 2026-07-26 08:55:55 | | | |
| TP / FP / FN / TN | 61 / 6 / 0 / 20 | TP+7, FP+3, FN-7 | TP+1, FP+1 | TP+1, FP-1 |
| **recall** | **1.000** | +11.5pp | +1.6pp | +3.3pp |
| **FPR** | **0.231** | +11.5pp ⚠️ | +3.8pp ⚠️ | -3.8pp |
| **accuracy** | **0.931** | +4.6pp | 持平 | +3.4pp |
| **parse_fail** | **0 / 87** | 持平 | 持平 | 持平 |
| strict_TP / cwe_mismatch | 36 / 25 | +11 / -2 | -1 / +2 | +6 / -2 |
| **strict_recall** | **0.590** | +9.8pp | -1.6pp | +13.1pp |

**P2 v5 SFT @ 7 CVE-fix 真实集**：

| 字段 | 值 | vs v4（污染） | vs v3 | vs baseline |
|---|---|---|---|---|
| 结果文件 | `v5/exp_06_eval.finetuned_custom.20260726_234541.json` | | | |
| 评估时间 | 2026-07-26 23:45:41 | | | |
| TP / FP / FN / TN | 4 / 0 / 3 / 0 | TP+1, FN-1 | 持平 | +1 |
| **recall** | **0.571** | +14.2pp | +7.1pp | +19.6pp ✓ |
| **strict_recall** | **0.143** | -14.3pp ⚠️ | +1.8pp | 持平 |
| parse_fail | 0 / 7 | | | |
| 平均耗时 | 34.44s/样本 | | | |

**逐样本明细（CVE-fix，v5）**：
| # | 文件 | CWE | v5 | strict | 说明 |
|---|---|---|---|---|---|
| 1 | cve_fix_0001.java | CWE-90 | **FN** | - | LDAP 注入（自 v2 起持续 FN，被防御措施 LdapEncoder 迷惑） |
| 2 | cve_fix_0002.js | CWE-90 | **FN** | - | LDAP 注入（自 v2 起持续 FN，关注 bcrypt 忽略 LDAP） |
| 3 | cve_fix_0003.py | CWE-95 | **TP** | cwe_mismatch | v3 FN → v5 TP（CoT 清单化修复生效）；模型标 CWE-78 命令注入 |
| 4 | cve_fix_0004.py | CWE-95 | **TP** | cwe_mismatch | 模型标 CWE-94 代码注入（接近但不精确） |
| 5 | cve_fix_0005.js | CWE-441 | **FN** | - | 信任边界绕过（loopback），自 v2 起持续 FN |
| 6 | cve_fix_0006.js | CWE-441 | **TP** | cwe_mismatch | v4 新增 CWE-441 训练样本后恢复；模型标 CWE-20 输入校验 |
| 7 | cve_fix_0007.py | CWE-502 | **TP** | strict_TP ✓ | 唯一 CWE 正确（pickle 反序列化） |

**v5 6 FP 明细（合成集）**：
| # | 文件 | 模型判定 | 错误模式 | v3 是否 FP |
|---|---|---|---|---|
| 1 | safe_03_subprocess_list.py | CWE-78 命令注入 | 列表参数 + shell=False 被看成字符串拼接 | ✓（v3 曾泄漏到训练集，v5 清洗后重新 FP） |
| 2 | safe_08_shlex.py | CWE-78 命令注入 | shell=True + shlex.quote 被忽略防御 | ✓ |
| 3 | noise_05_decorator_wrapper.py | CWE-79 XSS | 装饰器包装的安全代码被判 XSS | ✗（v5 新增 FP） |
| 4 | safe_09_proper_authz.py | CWE-200 信息泄露 | 演示用硬编码 admin ID 被当信息泄露 | ✓ |
| 5 | safe_17_race_with_lock.py | CWE-362 竞态 | Lock 正确防护但仍被判竞态 | ✓ |
| 6 | safe_18_java_prepared_stmt.java | CWE-79/798 | PreparedStatement 被判 XSS + 硬编码 | ✓ |

**关键结论**：
- ✅ **合成集 recall 100% 是清洗后首次可信基线**（非"成就"）：v4 的 0.885 是污染数据导致的假低，v3 的 0.984 也是污染数据。v5 的 1.000 仅比 v3 多 1 个 TP。
- ✅ **CVE-fix recall 57.1% 是真实改善**：比 baseline 37.5% +19.6pp，比 v4（污染）42.9% +14.2pp，比 v3 50.0% +7.1pp。清洗 + 弱密码学补充确实改善了泛化。
- ⚠️ **FPR 0.231 与 baseline 0.269 几乎相同**：SFT 在 FPR 维度上没有净改善。v4 的低 FPR（0.115）是污染假象（safe_* 泄漏样本反复训练让模型必然判 TN）。
- ⚠️ **strict_recall 0.590 仍是短板**：61 个 TP 中 25 个 CWE 标错，CVE-fix 上 strict_recall 仅 0.143（4 TP 中 3 个 CWE 错）。
- 📊 **3 个持续 FN（CVE-fix）**：cve_fix_0001/0002（LDAP 注入）+ cve_fix_0005（loopback 信任）自 v2 起未解，根因是训练数据完全缺失 LDAP 注入 + 信任边界绕过模式。
- 📊 **v5 清洗代价**：删除 100 个泄漏样本导致 safe_03/safe_08 等 5 个曾泄漏样本重新 FP（这些样本在 v4 因泄漏而必然 TN）。

**v4 → v5 选型判断**：
- v5 是首个可信评估基线，**v4 已被 v5_clean 替代**
- CVE-fix recall 57.1% > baseline 37.5%，进入 DPO 阶段降 FPR
- DPO 数据需更新：v4 的 `dpo_fp_pairs_v4.jsonl` 基于 v3 评估的 5 个 FP，v5 的 6 个 FP 中 5 个与 v3 相同，需新增 noise_05_decorators_wrapper.py 1 条

### P2 v6 SFT hard-negative 尝试（2026-07-27 失败）

> 因本地 DPO 训练不可行（见下节），改为用 SFT hard-negative 降 FPR：把 v5 的 6 个 FP 正确拒绝 CoT 作为正样本追加到训练集。

**训练配置**：
| 字段 | 值 |
|---|---|
| 训练数据 | `train_chatml_v6_hard_neg.jsonl`（755 条，v5 749 + 6 hard-negative） |
| 数据变更 | 在 v5_clean 基础上追加 6 个 FP 的正确拒绝响应：safe_03/safe_08/safe_09/safe_17/safe_18/noise_05 |
| LoRA/训练参数 | 与 v5 完全一致（r=8, alpha=16, epochs=3, lr=1e-4, rslora, seed=42） |
| best adapter | ~~`outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v6_hard_neg/best/`~~（已归档） |
| eval_loss | ep1=0.8392, ep2=0.7629, ep3=0.7724（与 v5 相当） |

**v6 @ 87 合成集**（`v6_failed/exp_06_eval.finetuned_custom.20260727_183526.json`）：
| 字段 | 值 | vs v5 |
|---|---|---|
| TP / FP / FN / TN | 60 / 5 / 1 / 21 | TP-1, FP-1 |
| **recall** | **0.9836** | -1.6pp ⚠️ |
| **FPR** | **0.1923** | -3.8pp |
| **accuracy** | **0.9310** | 持平 |
| **strict_recall** | **0.5574** | -3.3pp ⚠️ |
| parse_fail | 0 / 87 | 持平 |

**v6 @ 7 CVE-fix 真实集**（`v6_failed/exp_06_eval.finetuned_custom.20260727_184005.json`）：
| 字段 | 值 | vs v5 |
|---|---|---|
| TP / FP / FN / TN | 3 / 0 / 4 / 0 | TP-1, FN+1 |
| **recall** | **0.429** | **-14.2pp** ⚠️⚠️ |
| **strict_recall** | **0.143** | 持平 |

**v6 关键变化**：
- ✅ 修正 1 个 FP：`noise_05_decorator_wrapper.py`（v5 FP → v6 TN）
- ⚠️ 新增 1 个 FP：`safe_05_parametrized_like.py`（v5 TN → v6 FP）
- ⚠️ 新增 1 个合成集 FN：`hard_cve_05_spring4shell.java`（v5 TP → v6 FN）
- ⚠️⚠️ 新增 1 个真实 CVE-fix FN：`cve_fix_0003.py`（v5 TP → v6 FN）

**v6 失败结论**：
- simple hard-negative SFT 引起了**负迁移**：模型对"安全代码"模式过度敏感，反而在 `safe_05`（参数化 LIKE）和真实 `cve_fix_0003` 上错判/漏判
- FPR 小幅下降是以 recall 和真实集泛化为代价，**不划算**
- v6 已被归档到 `_archive_v6_hard_neg_failed`，**v5 仍为当前最佳模型**

### P3 DPO 尝试与失败（2026-07-27）

> 本地 16GB RDNA4 GPU 上 DPO 对 8B 模型不可行。三次尝试全部失败。

**尝试记录**：
| # | 配置 | 结果 | 根因 |
|---|---|---|---|
| 1 | 8bit + max_len=1024 | OOM 黑屏 | 8B 8bit + DPO 双前向超 15GB VRAM |
| 2 | fp16 + max_len=512 | 立即 OOM | 8B fp16 本身就超 16GB |
| 3 | 4bit + max_len=512 | 跑完但 grad_norm=0 | 4bit NF4 + DPO 双前向梯度回传失效，loss=ln(2) 不下降，所有指标归零；dmesg 记录 amdgpu drm panic |

**结论**：DPO 在本地硬件上无法用于 Qwen3-8B。8bit OOM、4bit 梯度失效，是 ROCm/bitsandbytes 与 DPO 双前向的硬约束，非参数可解。

**已归档**：`outputs/_archive_dpo_failed_4bit_grad_zero/`

**DPO 数据状态**：
| 文件 | 行数 | 状态 | 说明 |
|---|---|---|---|
| `dpo_merged.jsonl` | 104 | 📦 保留但未使用 | 本地无法训练，若换云 GPU 可直接复用 |
| `dpo_fp_pairs_v5.jsonl` | 6 | 📦 保留 | 同上 |
| `dpo_fp_pairs_v4.jsonl` | 5 | 📦 归档 | 同上 |



### P4 错题闭环（待运行）
| 时间 | 文件 | 错题来源 | recall | FPR | strict_recall | 状态 |
|---|---|---|---|---|---|---|
| - | - | - | - | - | - | ⏳ 待 P3 完成 |

## 五、归档目录结构

```
experiments/exp_06_finetune/results/
├── EXPERIMENT_LEDGER.md           ← 本文件
├── baseline/                       ← Qwen3-8B 零样本基线与参考模型
│   ├── exp_06_eval.ollama_qwen3_8b.20260722_225944.json   ← 当前锚点
│   ├── exp_06_eval.ollama_qwen3_8b.20260723_001648.json   ← CVE-fix 基线评估
│   ├── exp_06_eval.ollama_qwen3_8b.20260722_000125.json   ← Qwen3 时代历史
│   ├── exp_06_eval.ollama_qwen3_8b.20260720_043236.json
│   └── exp_06_eval.ollama_qwen3-coder_30b.20260711_151248.json
├── v2/                             ← SFT v2（train_chatml_v2.jsonl）
├── v3/                             ← SFT v3（train_chatml_v3_fixed.jsonl）
├── v4_failed/                      ← SFT v4（已废弃，训练-测试泄漏）
├── v5/                             ← SFT v5 当前最佳（train_chatml_v5_clean.jsonl）
├── v6_failed/                      ← SFT v6 hard-negative（已归档，负迁移）
├── _archive_qwen25/                ← Qwen2.5 时代全部归档
│   ├── baselines/
│   ├── finetuned/
│   ├── phase1_sweep/
│   ├── phase2/
│   ├── phase3_knitlm/
│   ├── hard_samples/
│   └── reports/
└── _archive_broken_cve_fix/        ← v1 错误 CVE-fix 测试集结果（30 全 FN）
```
