# 蒸馏 v2 数据质量评审

> 评审时间：2026-08-01
> 评审范围：`deepseek_cc_memory`（1000 条，已跑完）+ `deepseek_pentest`（1002/1800 条，未跑完）
> 评审方法：前中后各抽样 2 条共 12 条精读 + 全量统计（CWE/语言/风险/CoT 步数/套话率）
> 评审脚本：`experiments/exp_06_finetune/scripts/distill_v2/inspect_quality.py`、`stats_quality.py`

---

## 一、结论：能让模型学到东西

核心推理能力的教学质量是扎实的，抽样里多条样本是教科书级示范。模型从这批数据能学到：

- **真实代码识别**：Linux 内核驱动（mutex/kmalloc/copy_from_user）、C++ RAII/多线程、CI/CD 脚本（execSync/spawn/execFile）、Go exec.Command、Shell+awk 格式串——不是玩具代码
- **source→sink 数据流追踪**：每条漏洞样本都锚定行号，数据流路径教得扎实
- **防御有效性评估**：安全样本普遍写"假设攻击者传入 X→第 Y 行拦截→不可达"，否定推理是真在教
- **"防御迷惑"识别**：pentest 前1 代码里有 `safeExecuteStartup` 但未被调用，CoT 明确指出"有安全函数不等于安全"——这是高阶能力
- **行号锚定**：抽样 12 条 100% 每步锚定行号
- **JSON 语义一致**：CVSS 评分与 risk_level 对齐（9.8→High、10.0→Critical、7.1→High、5.5→Medium、0.0→None），source/sink 与 CoT 对齐

---

## 二、内容层面的隐忧（会让模型学歪，按优先级）

### 🔴 P0：`vulnerability_type` 字段格式三套混用（必修）

全量统计里同一个 CWE 出现三种写法：

| CWE | 写法 A | 写法 B | 写法 C |
|---|---|---|---|
| CWE-78 | `CWE-78` | `CWE-78 OS Command Injection` | `OS Command Injection` |
| CWE-416 | `CWE-416 UAF` | `Use-After-Free` | `CWE-416 Use-After-Free` |

**为什么影响学习**：学生模型会学到"这个字段有时带编号有时不带、有时带名称有时不带"的混乱分布，推理时输出格式不可控，下游解析也困难。

**修复路径**：在 `validate_sample.py` 加归一化规则，统一成 `CWE-XXX 名称` 格式。**必须自动化**——1000+ 条人工补不动，且可对已跑数据回溯修复（写个 `normalize_vuln_type.py` 遍历 jsonl 重写）。

### 🟡 P1：CoT 步数分布失衡（96% 是 4-5 步）

| 包 | 2 步 | 3 步 | 4 步 | 5 步 |
|---|---|---|---|---|
| cc_memory | 0% | 3.6% | 40.3% | 56.1% |
| pentest | 0.1% | 3.5% | 48.4% | 48.0% |

方法论要求"低复杂度 2-3 步"，但实际 0 条是 2 步，3 步也只有 3.5%。教师几乎总是写满 5 步。

**为什么影响学习**：学生模型会学到"不管漏洞多简单都写 5 步"，推理时对所有输入都输出长 CoT，浪费 token、降低吞吐。

**修复路径**：已跑的 2 个 pack 后处理补不了（删步数会破坏逻辑）；下几个 pack（web/shell/fix）的 teacher prompt 里强化"低复杂度必须 2-3 步硬约束"。

### 🟡 P2：推理路径偏科（A 主导，C 不足）

| 路径关键词 | cc_memory | pentest |
|---|---|---|
| 数据流（A 路径） | 21.3% | **39.8%** |
| 假设验证（C 路径） | 2.9% | **2.1%** |

方法论要求 A/B/C 交替，实际 A 路径占主导，C 路径（假设验证）严重不足。

**为什么影响学习**：学生遇到"防御迷惑样本"时，C 路径（假设恶意输入→追踪→防御是否阻断）最有效，但训练数据里示范太少。

**修复路径**：下个 pack 的 teacher prompt 里加"每 3 条强制 1 条走 C 路径"的轮换约束；现有数据可把"否定推理"段落重标为 C 路径示范。

### 🟢 P3：风险等级偏 High（可接受）

cc_memory 漏洞样本 91% 是 High，只有 2 条 Critical、20 条 Medium、0 条 Low。但内存类漏洞确实多为 High，**可接受**。pentest 的 Critical 占 28%，分布更合理。

---

## 三、不影响学习的小问题（可人工补）

- **CoT 起始话术 7 种变体**：`**分析过程**` / `**分析过程：**` / `## 分析过程` 等，格式发散但语义统一
- **个别 explanation 用英文**：pentest 后2 的 explanation 是 "safe: target validated against whitelist..."
- **漏洞代码里有 `// VULN:` 注释**：相当于答案写在代码里，学生可能学到"看注释而非看代码"
- **cc_memory 前1 的 CoT 兜转**：教师先说"没越界"再推翻找到整数符号问题——其实有教学价值（教"别停在第一个解释"），两面性，可保留

---

## 四、pentest 包未跑完

pentest 只跑了 1002/1800 条，且**漏洞样本已满 449/450，安全样本只有 553/1350**。明天需继续跑完，否则安全样本占比会偏高（当前 55% 安全 vs 设计的 75%）。

---

## 五、分布健康度（设计层面通过）

| 维度 | cc_memory | pentest | 评价 |
|---|---|---|---|
| CWE 分布 | 10 个 CWE 各 10% | 7 个 CWE 各 14.3% | ✅ 完全均匀 |
| 语言分布 | C/C++ 各 50% | JS/Python/Shell/Go 各 25% | ✅ 均匀 |
| has_vuln | 25%/75% | 44.8%/55.2%（未跑完） | ✅ 符合设计 |
| JSON 完整性 | 100% | 100% | ✅ |
| fix_suggestion（安全样本） | 737/750 = 98.3% "no fix needed" | 547/553 = 98.9% | ✅ |

---

## 六、建议的修复优先级

1. **明天跑 pentest 剩余 798 条前**：先改 teacher prompt 强化"低复杂度 2-3 步"和"每 3 条 1 条 C 路径"，避免新数据重蹈覆辙
2. **跑完所有 pack 后**：写 `normalize_vuln_type.py` 对全部 jsonl 统一 `vulnerability_type` 格式
3. **合并训练数据前**：跑一遍 `stats_quality.py` 复查分布
