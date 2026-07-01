# 实验 03 报告：RAG 增强漏洞检测

> **2026-06-30 最终更新**：默认主模型已最终切换为 `qwen2.5-coder:7b`。
> - qwen7b 纯 LLM 已达到 **recall=100%、FPR=0%、accuracy=100%**，无需 RAG 纠正典型样本误报。
> - RAG+LLM 同样达到 100% 准确率，在典型样本上未改变判定结果，但显著提升了输出可解释性与结构化程度。
> - RAG 的真正价值在**难样本**上得到验证（见 exp_04：RAG 召回率 96.2% vs 纯 LLM 88.5%）。
> - 知识库已从 34 条扩充至 **39 条**（含安全模式识别条目）。
>
> 历史数据：`results/results.qwen2.5-coder-7b.json`、`results/results.gemma4-12b.final.json`。

## 一、实验目的

在 exp_01（纯 LLM 基线）和 exp_02（传统工具基线）基础上，本阶段引入检索增强生成（RAG），
在 LLM 推理前从本地漏洞知识库检索 Top-K 相关知识，注入 prompt 上下文，回答三个问题：

1. RAG 是否提升检出率 / 降低误报率？
2. RAG 检索质量如何？Top-K 是否命中正确漏洞类型？
3. RAG 在输出可解释性、知识可扩展性上带来什么改进？

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| LLM | `qwen2.5-coder:7b`（Ollama 本地推理，当前默认主模型） |
| Embedding | all-MiniLM-L6-v2（sentence-transformers 5.6.0） |
| 向量库 | ChromaDB 1.5.9（持久化到 `data/chroma_db`） |
| 知识库 | 39 条，覆盖 14 类漏洞（含安全模式识别条目，见 3.1） |
| 测试时间 | 2026-06-30（qwen7b 最终验证） |
| 脚本 | [run_rag_experiment.py](run_rag_experiment.py) |
| Python | 3.11（miniconda graproj 环境） |

## 三、知识库构建

### 3.1 知识来源与结构

知识库从 [knowledge.json](knowledge_data/knowledge.json) 导入，共 **39 条**，覆盖 14 类漏洞。
每条知识包含：漏洞定义 + 典型代码特征 + 危险函数/Sink + 安全写法 + 常见绕过陷阱 + 修复方案。

| 漏洞类型 | 条数 | CWE |
| --- | --- | --- |
| SQL 注入 | 5 | CWE-89 |
| XSS | 4 | CWE-79 |
| 命令注入 | 4 | CWE-78 |
| 路径遍历 | 3 | CWE-22 |
| 硬编码凭证 | 3 | CWE-798 |
| 不安全反序列化 | 3 | CWE-502 |
| 敏感数据泄露 | 2 | CWE-200/209 |
| CSRF | 2 | CWE-352 |
| IDOR | 2 | CWE-639 |
| 安全配置错误 | 2 | CWE-16/693 |
| SSRF | 1 | CWE-918 |
| XXE | 1 | CWE-611 |
| 认证失效 | 1 | CWE-287 |
| 日志监控不足 | 1 | CWE-778 |
| **合计** | **34** | |

### 3.2 知识库设计原则

1. **每类漏洞配 1 条总论 + N 条细分**：总论给定义，细分覆盖变体/绕过/安全模式
2. **包含安全模式识别**：如 `cmdi_safe_pattern` 教 LLM 识别"列表参数 + shell=False"是安全的，降低误报
3. **包含假过滤绕过**：如 `sqli_bypass_filter` 教 LLM 识别 `replace("'","")` 这类无效过滤

## 四、实验结果

### 4.1 逐样本判定

| 文件 | 期望 | 纯 LLM (qwen) | RAG+LLM (qwen) | RAG Top-1 类型 | Top-1 distance |
| --- | --- | --- | --- | --- | --- |
| sql_injection_01.py | True | True ✅ | True ✅ | SQL注入 | 0.4062 |
| sql_injection_02.py | True | True ✅ | True ✅ | SQL注入 | 0.3625 |
| xss_01.php | True | True ✅ | True ✅ | XSS | 0.6463 |
| xss_02.js | True | True ✅ | True ✅ | XSS | 0.6124 |
| command_injection_01.py | True | True ✅ | True ✅ | 命令注入 | 0.5484 |
| command_injection_02.js | True | True ✅ | True ✅ | 命令注入 | 0.747 |
| path_traversal_01.py | True | True ✅ | True ✅ | 路径遍历 | 0.4147 |
| path_traversal_02.java | True | True ✅ | True ✅ | 路径遍历 | 0.5336 |
| hardcoded_secret_01.py | True | True ✅ | True ✅ | 硬编码凭证 | 0.4805 |
| hardcoded_secret_02.java | True | True ✅ | True ✅ | 硬编码凭证 | 0.5329 |
| insecure_deserialization_01.py | True | True ✅ | True ✅ | 不安全的反序列化 | 0.4119 |
| insecure_deserialization_02.java | True | True ✅ | True ✅ | 不安全的反序列化 | 0.6132 |
| safe_01_parameterized_query.py | False | False ✅ | False ✅ | SQL注入 | 0.3957 |
| safe_02_subprocess_list.py | False | False ✅ | False ✅ | 命令注入 | 0.566 |

> Top-1 类型命中正确率：12/14 = 85.7%。两个偏离的样本（command_injection_02.js、
> hardcoded_secret_02.java）Top-1 仍命中同大类，且 LLM 判定不受影响。
>
> **关键差异**：qwen7b 纯 LLM 已能正确识别 `safe_02_subprocess_list.py` 为安全代码，
> RAG+LLM 在此典型样本上未改变判定结果。RAG 的价值主要体现在输出可解释性增强（知识可追溯）
> 和难样本召回提升（见 exp_04）。

### 4.2 汇总指标对比

| 指标 | 纯 LLM (exp_01, qwen) | RAG+LLM (exp_03, qwen) | Bandit | Semgrep |
| --- | --- | --- | --- | --- |
| 有效样本 | 14 | 14 | 8 | 14 |
| TP | 12 | 12 | 5 | 9 |
| TN | 2 | 2 | 1 | 2 |
| FP | 0 | 0 | 1 | 0 |
| FN | 0 | 0 | 1 | 3 |
| **召回率** | **100.0%** | **100.0%** | 83.3% | 75.0% |
| **误报率** | **0.0%** | **0.0%** | 50.0% | 0.0% |
| **准确率** | **100.0%** | **100.0%** | 75.0% | 78.6% |
| 平均耗时 | 7.65s | 7.74s | 0.04s | 8.9s |
| 总耗时 | 107.1s | 108.4s | 0.54s | 124.61s |

## 五、关键发现

### 5.1 RAG 在典型样本上未改变判定：qwen7b 基线能力已达标

qwen2.5-coder:7b 在纯 LLM 模式下已达到 **100% 准确率**，包括正确识别 `safe_02_subprocess_list.py` 为安全代码。
该样本使用参数化列表调用 `subprocess.run(["ping", "-c", "1", host], ...)` 配合输入校验，
qwen7b 能够正确判断这是安全写法（qwen14b 在此样本上会误报）。

因此，在典型样本集上，RAG+LLM 与纯 LLM 的判定结果完全一致（均为 100% 准确）。
RAG 在此场景下的价值**不再是纠正误报**，而是：
1. **可解释性增强**：每条判定有 Top-3 知识条目支撑，可追溯、可审计；
2. **输出结构化**：RAG 版本更倾向采用 Source → Sink → 结论的分析框架；
3. **知识可扩展**：新增漏洞类型无需重训模型，只需入库新知识。

**论文论点**：对于基线能力强的模型（如 qwen7b），RAG 在典型样本上的价值是**可解释性增强**而非**误报纠正**；
误报纠正价值在基线能力较弱的模型（如 qwen14b、deepseek 16B）上更显著。
RAG 的真正价值需在难样本上验证（见 exp_04）。

### 5.2 RAG 不引入误报：安全样本的关键验证

两个安全样本的 RAG 检索结果都命中了"危险知识"，但 LLM **没有误报**：

| 安全样本 | RAG 检索 Top-1 | distance | LLM 判定 | 说明 |
| --- | --- | --- | --- | --- |
| safe_01_parameterized_query.py | SQL注入 | 0.3957 | False ✅ | 知识库教了 SQL 注入，但 LLM 识别出参数化查询是安全写法 |
| safe_02_subprocess_list.py | 命令注入 | 0.566 | False ✅ | 知识库含 `cmdi_safe_pattern`，教 LLM 识别列表参数是安全的 |

**论文论点**：这是 RAG 设计的关键风险验证——注入"危险知识"可能诱导 LLM 误报。
  通过在知识库中同时收录"安全模式识别"条目（如 `cmdi_safe_pattern`），
  RAG+LLM 在安全样本上保持 0 误报，与纯 LLM（qwen7b）一致。
  该验证确保了 RAG 不会在典型样本上引入新的误报风险。

### 5.3 输出质量提升：结构化与术语统一

对比 `safe_02_subprocess_list.py` 的输出：

| 维度 | 纯 LLM | RAG+LLM |
| --- | --- | --- |
| 判定 | True（误报） | False（正确） |
| 分析框架 | 功能概述 + 详细分析 | **Source → Validation → Sink → 结论** |
| 术语 | 日常描述 | 污点分析术语（Source/Sink/校验） |
| 可追溯性 | 无 | Top-3 知识 ID 可查 |

RAG 版本采用污点分析的标准框架（Source/Sink），与知识库中的分析范式一致，
输出更结构化、可审计。

### 5.4 RAG 检索质量分析

| 指标 | 数值 |
| --- | --- |
| Top-1 类型命中率 | 12/14 = 85.7% |
| Top-3 类型覆盖率 | 14/14 = 100%（Top-3 内必含正确类型） |
| 平均 Top-1 distance | 0.514 |
| 最小 distance | 0.3625（sql_injection_02.py） |
| 最大 distance | 0.747（command_injection_02.js） |

> distance 越小越相似。0.3625 表示检索高度精准，0.747 表示相关性较弱但 Top-3 仍命中。
> 两个 Top-1 偏离的样本，LLM 仍正确判定，说明 LLM 对检索噪声有鲁棒性。

### 5.5 耗时几乎不变

RAG+LLM 平均 7.74s/样本，纯 LLM 7.65s/样本，差距 0.09s（<2%）。
RAG 检索本身 <0.1s（本地向量库），注入的知识上下文仅增加约 500 token 的 prompt，
对 `qwen2.5-coder:7b` 的推理时间影响可忽略。

## 六、结论与论文论据

### 结论

1. **qwen7b 纯 LLM 已达到 100% 准确率**：在典型样本上无需 RAG 即可实现零漏报、零误报，
   基线能力显著优于 qwen14b（92.9%）和 deepseek 16B（85.7%）。
2. **RAG 在典型样本上的核心价值是可解释性增强**：每条判定有 Top-3 知识支撑可追溯；
   安全模式识别条目确保 RAG 不引入误报。误报纠正价值在基线能力较弱的模型上更显著。
3. **RAG 的真正价值在难样本上得到验证**（exp_04）：RAG K=5 在 42 段难样本上实现 recall=100%、
   accuracy=92.9%，显著优于纯 LLM（recall=88.5%、accuracy=83.3%）。
4. **知识库设计是关键**：收录"安全模式识别"条目（`cmdi_safe_pattern` 等）能有效
   防止 RAG 诱导误报，safe_02 案例验证了这一点。
5. **RAG 检索质量高**：Top-3 类型覆盖率 100%，Top-1 命中率 85.7%，
   且 LLM 对检索噪声有鲁棒性（Top-1 偏离时仍正确判定）。
6. **耗时代价可忽略**：RAG 增加 <2% 推理时间，换取可解释性与难样本召回收益。

### 论文论据映射

| 论文论点 | 实验证据 |
| --- | --- |
| qwen7b 基线能力全面达标 | 纯 LLM 100% 准确率，safe_02 零误报，无需 RAG 纠正 |
| RAG 不引入误报（关键风险验证） | safe_01/02 检索到危险知识但仍判 False |
| RAG 提升输出可解释性 | safe_02 输出采用 Source/Sink 框架，可追溯知识 ID |
| RAG 知识可扩展 | 知识库从 10→39 条，无需重训 |
| RAG 检索质量高 | Top-3 覆盖率 100%，Top-1 命中率 85.7% |
| LLM 对检索噪声鲁棒 | 2 个 Top-1 偏离样本，LLM 仍正确判定 |

### 局限与后续

- **典型样本上 RAG 未改变判定，价值需在难样本验证**：已在 exp_04 完成验证——RAG K=5 在 42 段难样本上 recall=100%、accuracy=92.9%，显著优于纯 LLM（recall=88.5%、accuracy=83.3%）。
- **知识库规模仍小**：39 条覆盖 14 类，后续可扩充到 100+ 条，加入真实 CVE 模式与反混淆示例。
- **Top-K 已对比**：exp_04 P2-8 中对比 K=1/3/5/10，推荐 K=5 为最优平衡点。

## 七、复现方式

```bash
# 1. 构建知识库（首次运行，会下载 embedding 模型）
cd experiments/exp_03_rag_knowledge/knowledge_data
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 ~/miniconda3/envs/graproj/bin/python3 build_knowledge.py

# 2. 跑批量 RAG 对比实验（14 样本，约 4 分钟）
cd ..
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 ~/miniconda3/envs/graproj/bin/python3 run_rag_experiment.py

# 3. 调试模式（只跑前 3 个样本）
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 ~/miniconda3/envs/graproj/bin/python3 run_rag_experiment.py --limit 3
```

结果写入 [results/results.json](results/results.json)，每跑完一个样本即增量落盘。
跑完自动卸载模型（`--keep-loaded` 可保留）。
