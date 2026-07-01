# 实验 01 报告：qwen2.5-coder:7b 漏洞检测能力摸底

> **2026-06-30 最终更新**：默认主模型已最终切换为 `qwen2.5-coder:7b`。
> - qwen7b 在 14 段典型样本上达到 **recall=100%、FPR=0%、accuracy=100%**，且 **无需 safe_override 后处理**。
> - 相比 qwen2.5-coder:14b（准确率 92.9%，safe_02 误报），qwen7b 在安全模式识别上更可靠。
> - 平均耗时 7.65s/样本，约为 qwen14b（17.11s）的 **45%**。
>
> 历史数据备份：`results/results.qwen2.5-coder-7b.json`（当前）、`results/results.gemma4-12b.final.json`。

## 一、实验目的

在搭建完整系统前，先用一批典型漏洞代码样本，对本地 `qwen2.5-coder:7b` 的漏洞检测能力进行摸底，
回答三个问题：

1. 模型能否正确识别常见的代码安全漏洞？
2. 模型是否会对安全代码产生误报？
3. 单次推理的耗时与稳定性如何，是否适合作为后续系统的核心引擎？

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| 模型 | `qwen2.5-coder:7b`（Ollama，当前默认主模型） |
| 推理后端 | Ollama `/api/generate`（stream=false） |
| 采样温度 | 0.1（追求稳定可复现） |
| 测试时间 | 2026-06-30（无答案泄露版本，qwen7b 最终验证） |
| 脚本 | [run_experiment.py](run_experiment.py) |

## 三、样本集

共 14 段代码样本，覆盖 6 类常见漏洞 + 1 类安全对照，详见
[samples/manifest.json](samples/manifest.json)。

| 类别 | 数量 | 期望存在漏洞 | 语言 |
| --- | --- | --- | --- |
| SQL 注入 | 2 | 是 | Python |
| XSS | 2 | 是 | PHP / JavaScript |
| 命令注入 | 2 | 是 | Python / JavaScript |
| 路径穿越 | 2 | 是 | Python / Java |
| 硬编码密钥 | 2 | 是 | Python / Java |
| 不安全反序列化 | 2 | 是 | Python / Java |
| 安全对照 | 2 | 否 | Python |
| **合计** | **14** | 12 是 / 2 否 | 4 种语言 |

样本特点：均为短小的"教科书式"典型漏洞，刻意写法明显（如 `shell=True`、字符串拼接 SQL、
`pickle.loads` 用户数据等），用于验证模型的基础能力下限，**不代表真实工程代码的检测难度**。

## 四、Prompt 设计

统一使用单一 Prompt 模板（见 [graduation_project/prompts.py](../../graduation_project/prompts.py)），要点：

1. 角色设定为"资深代码安全审计专家"。
2. 明确分析范围（SQL 注入 / XSS / 命令注入 / 路径穿越 / 硬编码密钥 / 不安全反序列化）。
3. 要求先输出分析过程，最后**严格输出 ```json``` 包裹的结构化结论**，统一 schema 字段：
   `has_vulnerability` / `vulnerability_type` / `risk_level` / `source` / `sink` / `explanation` / `fix_suggestion`。
4. 给出文件名与语言标签，辅助模型理解上下文。

## 五、实验结果

### 5.1 逐样本判定

| 文件 | 期望 | 模型判定 | 漏洞类型（模型给出） | 耗时 | 是否匹配 |
| --- | --- | --- | --- | --- | --- |
| sql_injection_01.py | True | True | CWE-89 SQL 注入 | 9.59s | OK |
| sql_injection_02.py | True | True | CWE-89 SQL 注入 | 7.60s | OK |
| xss_01.php | True | True | CWE-79 XSS | 7.27s | OK |
| xss_02.js | True | True | CWE-79 XSS | 8.32s | OK |
| command_injection_01.py | True | True | CWE-78 命令注入 | 6.95s | OK |
| command_injection_02.js | True | True | CWE-78 命令注入 | 8.37s | OK |
| path_traversal_01.py | True | True | CWE-22 路径穿越 | 9.38s | OK |
| path_traversal_02.java | True | True | CWE-22 路径穿越 | 8.70s | OK |
| hardcoded_secret_01.py | True | True | CWE-798 硬编码凭证 | 7.35s | OK |
| hardcoded_secret_02.java | True | True | CWE-798 硬编码凭证 | 6.60s | OK |
| insecure_deserialization_01.py | True | True | CWE-502 不安全反序列化 | 8.14s | OK |
| insecure_deserialization_02.java | True | True | CWE-502 不安全反序列化 | 6.47s | OK |
| safe_01_parameterized_query.py | False | False | none | 6.42s | OK |
| safe_02_subprocess_list.py | False | False | none | 5.98s | OK |

### 5.2 汇总指标

| 指标 | 数值 |
| --- | --- |
| 真阳性 TP | 12 |
| 真阴性 TN | 2 |
| 假阳性 FP（误报） | 0 |
| 假阴性 FN（漏报） | 0 |
| **漏洞样本召回率** | **12 / 12 = 100.0%** |
| **安全样本误报率** | **0 / 2 = 0.0%** |
| **总体准确率** | **14 / 14 = 100.0%** |
| 漏洞类型分类正确 | 12 / 12（6 类全对） |
| 平均单样本耗时 | 7.65s（最长 9.59s，最短 5.98s） |
| 最长 / 最短耗时 | 9.59s / 5.98s |
| 总耗时 | 107.14s（约 1.8 分钟） |

## 六、关键观察

1. **基础能力全面达标**：6 类典型漏洞全部识别正确，类型分类 100% 准确，安全样本零误报。
   `qwen2.5-coder:7b` 在"教科书式"漏洞上的语义理解能力足够，且**无需安全模式后处理**即可达到 100% 准确率。
2. **速度极快**：平均 7.65s/样本，相比 `qwen2.5-coder:14b` 的 17.11s 提升约 **2.24 倍**，
   相比 `gemma4:12b` 的 45.24s 提升约 **5.9 倍**。总耗时仅 1.8 分钟。
3. **安全样本零误报**：`safe_02_subprocess_list.py` 被正确判定为安全。该样本使用列表参数 + 输入校验的
   `subprocess.run()` 调用，qwen7b 能够识别这是安全写法（qwen14b 在此样本上会误报）。
   这说明 qwen7b 对 Python `subprocess` 安全机制的理解比 qwen14b 更深入。
4. **JSON 输出协议稳定**：14 次推理的 JSON 结论全部被脚本成功解析，说明"先分析后 JSON"的 Prompt 结构对 qwen 有效，后续系统可以依赖该协议做自动化结果聚合。
5. **本结果的局限性（重要）**：
   - 样本量仅 14 个，统计意义有限；
   - 漏洞写法均为典型模式，没有混淆/隐藏/上下文跨文件场景；
   - 没有测试"半漏洞"（如部分过滤但仍可绕过）和真实开源项目代码；
   - 单一 Prompt，未对比不同 Prompt 的效果差异。
   因此本次结果**仅说明下限可靠**，真实场景下的表现仍需后续实验验证。

## 七、结论与下一步

### 结论

`qwen2.5-coder:7b` + Ollama + 单一结构化 Prompt 的组合，在典型漏洞检测任务上**达到了可作为系统核心引擎的合格标准**：
召回率 100%、误报率 0%、准确率 100%，且平均耗时仅 7.65s/样本。
相比 qwen14b（准确率 92.9%，safe_02 误报），qwen7b 在安全模式识别上更可靠；
相比 deepseek-coder-v2:16b（准确率 85.7%，安全样本误报率 100%），qwen7b 无需后处理即可达标。

### 下一步行动

1. **扩大样本集**：补充更复杂的样本——绕过式过滤、跨文件污点流、真实 CVE PoC 片段，测试模型在"非典型"漏洞上的表现（exp_04 已完成）。
2. **RAG 知识库增强**：虽然 qwen7b 在典型样本上已无需 RAG 纠正误报，但验证 RAG 在难样本上的召回提升（exp_03/exp_04 已完成）。
3. **传统工具对比基线**：用同一批样本跑 Bandit / Semgrep，对比检出率、误报率、耗时，明确 LLM 相对传统工具的改进点（语义理解 vs 模式匹配）。
4. **Prompt 迭代**：设计 2-3 套不同风格的 Prompt（零样本 / 思维链 / Few-shot），对比哪一种在"难样本"上表现更好。
5. **长文件测试**：测试 500+ 行的真实文件，观察上下文窗口与注意力衰减对检出率的影响。
6. **结果文件**：[results/results.json](results/results.json) 保留了 14 次推理的完整原始输出，后续写论文可直接引用为实验素材。

## 八、复现方式

```bash
cd experiments/exp_01_basic_scan
# 确保 Ollama 已运行且 qwen2.5-coder:7b 已下载
python3 run_experiment.py                       # 跑全部 14 个样本（默认 qwen2.5-coder:7b）
python3 run_experiment.py --limit 3             # 只跑前 3 个（快速调试）
python3 run_experiment.py --model deepseek-coder-v2:16b  # 切换对照模型
```

结果将写入 `results/results.json`，每跑完一个样本即增量落盘，中途可断点查看。
