# 实验 01 报告：Gemma 4 26B 漏洞检测能力摸底

## 一、实验目的

在搭建完整系统前，先用一批典型漏洞代码样本，对本地 Gemma 4 26B 的漏洞检测能力进行摸底，
回答三个问题：

1. 模型能否正确识别常见的代码安全漏洞？
2. 模型是否会对安全代码产生误报？
3. 单次推理的耗时与稳定性如何，是否适合作为后续系统的核心引擎？

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| 模型 | `gemma4:26b`（Ollama，Q4_K_M，25.8B） |
| 推理后端 | Ollama `/api/generate`（stream=false） |
| 采样温度 | 0.1（追求稳定可复现） |
| 测试时间 | 2026-06-28 12:38–12:52 |
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

统一使用单一 Prompt 模板（见 [run_experiment.py](run_experiment.py) 中的 `PROMPT_TEMPLATE`），要点：

1. 角色设定为"资深代码安全审计专家"。
2. 明确分析范围（SQL 注入 / XSS / 命令注入 / 路径穿越 / 硬编码密钥 / 不安全反序列化）。
3. 要求先输出分析过程，最后**严格输出 ```json``` 包裹的结构化结论**，统一 schema 字段：
   `has_vulnerability` / `vulnerability_type` / `risk_level` / `source` / `sink` / `explanation` / `fix_suggestion`。
   > 注：exp_01 首跑时 schema 仅有 4 个字段（`vulnerability_found` 等），后已统一为 7 字段版本，
   > `results.json` 的 `parsed_verdict` 已迁移；`raw_output` 保留模型原始输出未改。
4. 给出文件名与语言标签，辅助模型理解上下文。

## 五、实验结果

### 5.1 逐样本判定

| 文件 | 期望 | 模型判定 | 漏洞类型（模型给出） | 耗时 | 是否匹配 |
| --- | --- | --- | --- | --- | --- |
| sql_injection_01.py | True | True | SQL Injection | 53.4s | OK |
| sql_injection_02.py | True | True | SQL Injection | 53.9s | OK |
| xss_01.php | True | True | Reflected XSS | 50.5s | OK |
| xss_02.js | True | True | Reflected XSS | 53.0s | OK |
| command_injection_01.py | True | True | Command Injection | 58.3s | OK |
| command_injection_02.js | True | True | Command Injection | 54.7s | OK |
| path_traversal_01.py | True | True | Path Traversal | 52.6s | OK |
| path_traversal_02.java | True | True | Path Traversal | 60.3s | OK |
| hardcoded_secret_01.py | True | True | Hardcoded Credentials | 45.0s | OK |
| hardcoded_secret_02.java | True | True | Hardcoded Credentials | 48.5s | OK |
| insecure_deserialization_01.py | True | True | Insecure Deserialization | 45.9s | OK |
| insecure_deserialization_02.java | True | True | Insecure Deserialization | 59.7s | OK |
| safe_01_parameterized_query.py | False | False | none | 47.4s | OK |
| safe_02_subprocess_list.py | False | False | none | 110.7s | OK |

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
| 平均单样本耗时 | 56.7s |
| 最长 / 最短耗时 | 110.7s / 45.0s |
| 总耗时 | 794s（约 13 分钟） |

## 六、关键观察

1. **基础能力达标**：6 类典型漏洞全部识别正确，类型分类 100% 准确，说明 Gemma 4 26B 在
   "教科书式"漏洞上的语义理解能力足够，可以作为后续系统的核心引擎候选。
2. **零误报**：两段安全对照样本（参数化查询、subprocess 参数列表 + 输入校验）均被判为
   `has_vulnerability: false`，模型没有陷入"看到用户输入就报警"的过度敏感模式。
3. **JSON 输出协议稳定**：14 次推理的 JSON 结论全部被脚本成功解析，说明"先分析后 JSON"
   的 Prompt 结构对 Gemma 4 有效，后续系统可以依赖该协议做自动化结果聚合。
4. **耗时分布**：平均 56.7s/样本，符合 26B 模型在本地推理的预期。`safe_02_subprocess_list.py`
   耗时 110.7s（最长），原因是模型对该安全样本做了较长的逐项分析后才给出"无漏洞"结论——
   说明模型在"证明安全"时比"指出漏洞"时更啰嗦，后续批量扫描需要考虑超时与并发策略。
5. **本结果的局限性（重要）**：
   - 样本量仅 14 个，统计意义有限；
   - 漏洞写法均为典型模式，没有混淆/隐藏/上下文跨文件场景；
   - 没有测试"半漏洞"（如部分过滤但仍可绕过）和真实开源项目代码；
   - 单一 Prompt，未对比不同 Prompt 的效果差异。
   因此 100% 的准确率**仅说明下限可靠**，真实场景下的表现仍需后续实验验证。

## 七、结论与下一步

### 结论
Gemma 4 26B + Ollama + 单一结构化 Prompt 的组合，在典型漏洞检测任务上**达到了可作为
MVP 核心引擎的最低门槛**，可以进入下一阶段（与传统工具对比 + 真实代码测试）。

### 下一步行动
1. **扩大样本集**：补充更复杂的样本——绕过式过滤、跨文件污点流、真实 CVE PoC 片段，
   测试模型在"非典型"漏洞上的表现。
2. **传统工具对比基线**：用同一批样本跑 Bandit / Semgrep，对比检出率、误报率、耗时，
   明确 LLM 相对传统工具的改进点（语义理解 vs 模式匹配）。
3. **Prompt 迭代**：设计 2-3 套不同风格的 Prompt（零样本 / 思维链 / Few-shot），
   对比哪一种在"难样本"上表现更好。
4. **长文件测试**：测试 500+ 行的真实文件，观察上下文窗口与注意力衰减对检出率的影响。
5. **结果文件**：[results/results.json](results/results.json)
   保留了 14 次推理的完整原始输出，后续写论文可直接引用为实验素材。

## 八、复现方式

```bash
cd experiments/exp_01_basic_scan
# 确保 Ollama 已运行且 gemma4:26b 已下载
python3 run_experiment.py                       # 跑全部 14 个样本
python3 run_experiment.py --limit 3             # 只跑前 3 个（快速调试）
python3 run_experiment.py --model gemma4:26b --temperature 0.1
```

结果将写入 `results/results.json`，每跑完一个样本即增量落盘，中途可断点查看。
