# 基于大语言模型的代码安全分析系统

> 本地部署的开源大语言模型（当前默认主模型为 Qwen2.5-Coder 7B，DeepSeek-Coder-V2-Lite 16B 等保留为对照）驱动的代码漏洞检测系统，对比传统基于规则的静态分析工具，验证 LLM 在代码安全审计中的语义理解优势。

***

## 一、项目简介

利用本地部署的开源大语言模型对源代码进行安全审计，目标是构建一个相比传统静态分析工具（Bandit / Semgrep / CodeQL）具备以下优势的系统：

| 维度   | 传统工具（Bandit/Semgrep） | 本系统（LLM 驱动）          |
| ---- | -------------------- | -------------------- |
| 检测方式 | 固定规则模式匹配             | 代码语义理解、上下文感知         |
| 漏洞覆盖 | 已知漏洞模式               | 可发现变体/非典型漏洞          |
| 输出形式 | 漏洞类型 + 规则编号          | 自然语言解释 + 修复建议 + 修复代码 |
| 多语言  | 工具专属规则集              | 跨语言统一理解              |
| 误报控制 | 规则泛化能力差              | 上下文判断过滤/净化逻辑         |

**核心卖点**：传统工具是"模式匹配"，本系统是"语义理解"。

***

## 二、实验环境

| 项目     | 配置                                                                                          |
| ------ | ------------------------------------------------------------------------------------------- |
| CPU    | AMD Ryzen 5 9600X × 12                                                                      |
| 内存     | 32 GB                                                                                       |
| 显卡     | AMD Radeon RX 9060 XT                                                                       |
| 操作系统   | Ubuntu 26.04 LTS（内核 7.0.0-15-generic）                                                       |
| 桌面环境   | GNOME 50 / Wayland                                                                          |
| 本地 LLM | Ollama                                                                                      |
| 主模型    | `qwen2.5-coder:7b`（当前默认主模型，典型样本无需后处理即可 100% 准确率）                                            |
| 对照模型   | `deepseek-coder-v2:16b` / `qwen2.5-coder:14b` / `gemma4:12b` / `gemma4:26b` / `gpt-oss:20b` |

> 注：模型文件不入库（见 `.gitignore`），默认主模型需通过 `ollama pull qwen2.5-coder:7b` 自行下载。
> 默认主模型于 2026-06-30 最终从 `deepseek-coder-v2:16b` 切换为 `qwen2.5-coder:7b`：exp\_01 平均耗时从 deepseek 的 9.63s 降至约 7.7s，且无需安全模式后处理即可在典型样本上达到 100% 准确率。`deepseek-coder-v2:16b` 保留作为对照模型。
> 以上为台式机配置（实验运行环境）；本人笔记本仅用于代码编辑，跑不动模型推理。

***

## 三、项目结构

```
Graduation-Project/
├── README.md                              # 本文档
├── .gitignore
├── pyproject.toml                         # 项目元数据 + 依赖声明（支持 pip install -e .）
├── requirements.txt                       # 锁版本依赖清单
├── TODO.md                                # 代码审查问题清单（处理进度跟踪）
├── 规划.md                                 # 项目阶段规划与进度
├── docs/                                  # 设计文档与改进建议
│   ├── _archive/                          #   历史建议归档
│   │   ├── glm的建议_20260628.md          #     GLM 给出的改进路线建议
│   │   └── kimi的建议_20260628.md         #     Kimi 给出的智能体分工建议
│   ├── 临时提示词_下一步计划.md            # 八大修复建议与执行方案
│   ├── 必须手动学习的地方.md              # 手工任务详细操作指南（唯一来源）
│   └── 过程.md                            # 实验过程记录
├── graduation_project/                    # 核心代码库（pip install -e . 后可全局 import）
│   ├── __init__.py
│   ├── schema.py                          # 统一输出 schema（VERDICT_SCHEMA 唯一来源 + 解析函数）
│   ├── prompts.py                         # 统一 Prompt 模板（SYSTEM_PROMPT + build_user_prompt）
│   ├── llm_client.py                      # Ollama LLM 客户端（支持 RAG 增强）
│   └── chroma_manager.py                  # Chroma 向量数据库管理器（add / upsert / query）
├── experiments/                           # 实验目录（按阶段编号）
│   ├── utils.py                           #   实验公共工具（manifest 加载 / 指标统计 / 结果落盘）
│   ├── exp_01_basic_scan/                 # 阶段一：LLM 漏洞检测能力摸底
│   │   ├── run_experiment.py              #   批量测试脚本（调 Ollama API + 增量落盘 + 自动卸载显存）
│   │   ├── exp_01_report.md               #   实验报告
│   │   ├── samples/                       #   14 段漏洞代码样本
│   │   │   ├── manifest.json              #     样本清单（含期望标签）
│   │   │   ├── sql_injection_01.py / 02.py
│   │   │   ├── xss_01.php / 02.js
│   │   │   ├── command_injection_01.py / 02.js
│   │   │   ├── path_traversal_01.py / 02.java
│   │   │   ├── hardcoded_secret_01.py / 02.java
│   │   │   ├── insecure_deserialization_01.py / 02.java
│   │   │   ├── safe_01_parameterized_query.py
│   │   │   └── safe_02_subprocess_list.py
│   │   └── results/
│   │       └── results.json               #   14 次推理的完整原始输出
│   ├── exp_02_baseline_tools/             # 阶段二：传统工具对比基线
│   │   ├── run_baseline.py                #   Bandit + Semgrep 批量调用脚本
│   │   ├── exp_02_report.md               #   实验报告（含 LLM vs 传统工具横向对比）
│   │   ├── README.md                      #   实验说明
│   │   └── results/                       #   复用 exp_01 样本，结果按工具分组
│   ├── exp_03_rag_knowledge/              # 阶段三：RAG 知识库增强
│   │   ├── run_rag_experiment.py          #   RAG+LLM 批量对比实验脚本
│   │   ├── exp_03_report.md               #   实验报告（纯 LLM vs RAG+LLM 对比）
│   │   ├── results/                       #   实验结果
│   │   └── knowledge_data/
│   │       ├── knowledge.json             #   漏洞知识条目（手工编写，34 条）
│   │       ├── build_knowledge.py         #   从 JSON 加载 → upsert 入库 Chroma（幂等可重复运行）
│   │       └── test_rag.py                #   单样本快速验证脚本（正式实验用 run_rag_experiment.py）
│   └── exp_04_hard_samples/               # 阶段四：难样本压力测试 + 消融实验
│       ├── samples/                       #   42 段扩展样本（典型 12 + 安全 8 + 难 16 + 噪音 6）
│       │   ├── manifest.json              #     12 列 ground truth 标注
│       │   ├── typical_*.py/php/js         #     典型漏洞样本
│       │   ├── safe_*.py                  #     安全对照样本
│       │   ├── hard_bypass_*.py            #     绕过式过滤难样本
│       │   ├── hard_crossfile_*_{input,sink}.py  # 跨文件污点流难样本
│       │   ├── hard_cve_*.py              #     真实 CVE 片段难样本
│       │   ├── hard_longfile_*.py         #     长文件隐藏漏洞难样本
│       │   ├── hard_owasp_*.py            #     OWASP/DVWA 风格难样本
│       │   └── noise_*.py                 #     混淆/噪音样本
│       ├── run_experiment.py              #   P1-4：纯 LLM 重复实验 + 置信区间（--repeat N）
│       ├── run_rag_experiment.py           #   P1-5/P2-8：RAG 消融对照（--mode）+ Top-K（--top-k）
│       ├── run_ablation_and_topk.sh        #   顺序跑 4 组消融 + 3 个 Top-K 的驱动脚本
│       ├── generate_report.py             #   从 results/ 汇总生成 exp_04_report.md
│       ├── exp_04_report.md               #   实验报告（P1-4 + P1-5 + P2-8 综合分析）
│       └── results/                       #   所有实验结果 JSON + 运行日志
└── data/                                  # 本地持久化数据（不入库，见 .gitignore；首次运行 build_knowledge.py 后自动生成）
    └── chroma_db/                         #   Chroma 向量数据库
```

***

## 四、当前进度

### ✅ 已完成：阶段一 — LLM 漏洞检测能力摸底（2026-06-28，默认主模型最终切换为 qwen2.5-coder:7b）

- 14 段样本：6 类典型漏洞 × 2 + 2 安全对照，覆盖 Python / PHP / JavaScript / Java 4 种语言
- 统一结构化 Prompt（角色设定 → 分析范围 → JSON 结论协议）
- 批量测试脚本 `run_experiment.py`：调用 Ollama API、增量落盘、自动卸载显存
- **当前默认主模型结果（qwen2.5-coder:7b）**：召回率 100% (12/12)、误报率 0% (0/2)、准确率 100%（14/14），平均约 7.7s/样本；无需安全模式后处理
- **历史对照结果**：deepseek-coder-v2:16b 召回率 100%、误报率 100%（2/2）、准确率 85.7%，经安全模式后处理可提升至 100%；qwen2.5-coder:14b 准确率 92.9%（1 处误报）
- **关键发现**：qwen7b 在典型样本上能力达标且无需后处理；deepseek 速度快但存在安全模式知识盲区，已降级为对照模型（其安全样本优化专项已失败，放弃作为安全专用模型基座）

详见 [experiments/exp\_01\_basic\_scan/exp\_01\_report.md](experiments/exp_01_basic_scan/exp_01_report.md)（历史报告为 qwen2.5-coder:14b 数据，当前默认主模型结果见 `results/results.qwen2.5-coder-7b.json`）。

> ⚠️ **结果局限性**：样本为"教科书式"典型漏洞，高准确率仅证明能力下限；真实工程代码（混淆、跨文件、CVE 变体）难度更高，需结合 exp\_04 难样本集评估。

### ✅ 已完成：阶段二 — 传统工具对比基线（2026-06-29）

- Bandit 1.9.4 + Semgrep 1.168.0 调用脚本 `run_baseline.py`，复用 exp\_01 的 14 段样本
- 输出与 exp\_01 统一的 JSON 格式，自动适配 conda/venv 环境的 PATH
- **结果（基于当前默认主模型 qwen2.5-coder:7b）**：RAG+LLM 准确率 100% vs 纯 LLM 100% vs Bandit 75.0%（Python 样本） vs Semgrep 78.6%；qwen7b 在典型样本上无需 RAG 即可达到 100% 准确率
- 关键论据：path\_traversal\_01.py LLM 唯一检出；RAG+LLM 在召回率上优于传统工具；qwen7b 已能解决 deepseek 的安全样本误报问题

详见 [experiments/exp\_02\_baseline\_tools/exp\_02\_report.md](experiments/exp_02_baseline_tools/exp_02_report.md)。

### ✅ 已完成：阶段三 — RAG 漏洞知识库增强（2026-06-29）

- 知识库 34 条，覆盖 14 类漏洞（含安全模式识别条目防误报）
- ChromaDB 持久化 + all-MiniLM-L6-v2 embedding；`build_knowledge.py` 改用 upsert 幂等写入
- `run_rag_experiment.py` 批量对比纯 LLM vs RAG+LLM
- **当前默认主模型结果（qwen2.5-coder:7b）**：RAG+LLM 召回率 100%、误报率 0% (0/2)、准确率 100%；RAG 上下文未对 qwen7b 产生负面影响
- **历史对照结果**：deepseek-coder-v2:16b 在 RAG+LLM 下召回率 100%、误报率 100%（2/2）、准确率 85.7%；RAG 知识库未能纠正其安全模式知识盲区
- 关键论据：检索知识与模型最终判定之间仍存在鸿沟；对 qwen7b 而言当前 RAG 更多是可解释性增强，对 deepseek 则需要 Prompt / RAG / 后处理 / 微调联合优化

详见 [experiments/exp\_03\_rag\_knowledge/exp\_03\_report.md](experiments/exp_03_rag_knowledge/exp_03_report.md)。

### ✅ 已完成：阶段四-1 — 实验严谨性修复与难样本集构建（2026-06-29）

针对 exp\_01\~03 评估中发现的实验设计问题（详见 [docs/临时提示词\_下一步计划.md](docs/临时提示词_下一步计划.md)），完成 4 项关键修复：

- **P0-1 样本答案泄露修复**：删除 14 段样本中所有 `# 期望/漏洞/安全/样本` 注释，ground truth 仅保留在 manifest.json。用 `gemma4:12b` 重跑三个实验，准确率仍为 100%，证明模型不靠注释作弊。后续默认主模型最终切换为 `qwen2.5-coder:7b`
- **P0-2 样本集扩充**：在 `experiments/exp_04_hard_samples/samples/` 下新建 42 段样本：
  - 典型漏洞 12 段（SQL/XSS/命令注入/路径穿越/pickle/硬编码密钥/SSRF/eval/PHP XSS/JS 命令注入/YAML/开放重定向）
  - 安全对照 8 段（参数化查询/HTML 转义/subprocess 列表/路径白名单/LIKE 参数化/CSP/正则校验/shlex）
  - 难样本 16 段，覆盖 5 类：绕过式过滤 4 / 跨文件污点流 4 / 真实 CVE 片段 4 / 长文件隐藏漏洞 2 / OWASP-DVWA 风格 2
  - 混淆噪音 6 段
  - 每段附带 12 列 ground truth（file/language/category/difficulty/expected\_present/expected\_vulnerability/expected\_cwe/expected\_risk\_level/source/sink/taint\_path/fix\_idea）
- **P1-3 Schema 统一**：`graduation_project/schema.py` 的 `VERDICT_SCHEMA` 为 7 字段版本；安全样本 `risk_level` 填 `N/A`，`source/sink` 填 `None`；新增 DeepSeek 风格畸形 JSON 容错修复（连续字符串值合并）
- **P1-7 耗时统计增强**：报告新增中位数耗时与异常值说明（当前默认主模型 qwen2.5-coder:7b 在 exp\_01 平均约 7.7s；deepseek-coder-v2:16b 平均 9.63s；qwen2.5-coder:14b 平均 17.11s）

默认主实验模型最终由 `deepseek-coder-v2:16b` 切换为 `qwen2.5-coder:7b`（dense 代码模型，exp\_01 平均约 7.7s，典型样本无需后处理即可达到 100% 准确率）。`deepseek-coder-v2:16b` 保留作为对照模型。提示：DeepSeek 安全样本优化专项已失败——该模型存在根本性安全模式知识盲区，纯 Prompt 工程与 RAG 均无法克服，后处理白名单虽能修复指标但非模型本身能力提升，维护成本高且泛化性差。**后续安全专用模型将以 qwen2.5-coder:7b 为基座进行 LoRA 微调与蒸馏**。

### ✅ 已完成：阶段四-2 — 难样本压力测试 + 消融实验（2026-07-01）

在 exp\_04 难样本集（42 段：典型 12 + 安全 8 + 难 16 + 噪音 6）上完成 3 项实验，
详见 [experiments/exp\_04\_hard\_samples/exp\_04\_report.md](experiments/exp_04_hard_samples/exp_04_report.md)：

- **P1-4 重复性与置信区间**：qwen7b，repeat=3，多数表决 recall=96.2%、FPR=25.0%、accuracy=88.1%（Wilson 95% CI）
- **P1-5 RAG 消融对照**：A(RAG+LLM) recall=96.2%/FPR=18.8% vs B(纯 LLM) 88.5%/25.0% vs C(随机) 88.5%/18.8% vs D(无关) 92.3%/25.0%。
  **核心发现**：RAG 召回提升（+7.7pp）来自知识相关性，FPR 下降部分来自 prompt 变长效应。
- **P2-8 Top-K 对比**：K=5 为最优平衡点（recall=100%、FPR=18.8%、accuracy=92.9%），K=10 因噪声引入 FPR 升至 25.0%。

后续阶段（以 qwen2.5-coder:7b 为基座构建网络安全专用模型，deepseek 16B 因知识盲区问题已放弃作为基座）：

- Prompt 工程对比（零样本 / Few-shot / 思维链 / 安全模式白名单）
- RAG 安全知识增强（扩充 `cmdi_safe_pattern`、`sqli_safe_pattern` 等安全模式条目）
- AST 代码切片（tree-sitter，长文件按函数切分）
- LoRA/QLoRA 微调 deepseek-coder-v2:16b → 网络安全专用模型
- 多模型对比（deepseek-coder-v2:16b / qwen2.5-coder:14b / gemma4:26b / gpt-oss:20b）

***

## 五、路线图

> 整合自 [docs/\_archive/glm的建议\_20260628.md](docs/_archive/glm的建议_20260628.md)，按"必做 / 创新点 / 加分项"三级划分。

### 🔥 必做（毕设立足点）

| 任务                                   | 对应实验    | 状态                |
| ------------------------------------ | ------- | ----------------- |
| 传统工具对比基线（Bandit / Semgrep）           | exp\_02 | ✅ 完成              |
| 真实代码测试（CVE PoC / OWASP WebGoat 等难样本） | exp\_04 | ✅ 已完成（P1-4/P1-5/P2-8 全部完成） |

### 💡 创新点（论文核心价值）

| 任务                                                                                       | 对应实验    | 状态    |
| ---------------------------------------------------------------------------------------- | ------- | ----- |
| RAG 漏洞知识库（OWASP/CWE/CVE → Chroma，检索注入 Prompt）                                            | exp\_03 | ✅ 完成  |
| AST 代码切片（tree-sitter，长文件按函数/块切分，解决注意力衰减）                                                 | exp\_04 | ⏳ 待开始 |
| DeepSeek 安全样本优化（Prompt 工程 / RAG 安全知识 / 后处理白名单，已失败并放弃；改用 qwen2.5-coder:7b 为安全专用模型基座）                                            | exp\_05 | ⏳ 待开始 |
| 多模型对比（deepseek-coder-v2:16b / qwen2.5-coder:14b / gemma4:12b / gemma4:26b / gpt-oss:20b） | exp\_06 | ⏳ 待开始 |

### ⭐ 加分项（提升完成度）

| 任务                                       | 对应实验    | 状态    |
| ---------------------------------------- | ------- | ----- |
| 污点流分析（Source→Sink 跨函数追踪）                 | exp\_06 | ⏳ 待开始 |
| 修复建议质量评分（生成代码能否编译/通过测试）                  | -       | ⏳ 待开始 |
| Prompt 工程对比（零样本 / Few-shot / 思维链）        | -       | ⏳ 待开始 |
| 工程化系统（Web 界面 + 报告导出 PDF/Markdown + 批量扫描） | -       | ⏳ 待开始 |

### 阶段总览

| 阶段               | 目标                                                 | 状态     |
| ---------------- | -------------------------------------------------- | ------ |
| 一、模型能力摸底         | 验证 LLM 在典型漏洞上的下限能力                                 | ✅ 完成   |
| 二、传统工具对比基线       | 明确 LLM 相对传统工具的改进点                                  | ✅ 完成   |
| 三、RAG 知识增强       | 引入向量库，对比有/无 RAG 的检出率                               | ✅ 完成   |
| 四、难样本压力测试 + 消融实验 | 验证 LLM/RAG/传统工具在绕过/CVE/长文件等难样本上的表现                 | ✅ 已完成 |
| 五、网络安全专用模型训练与蒸馏  | 以 qwen2.5-coder:7b 为基座，用安全/漏洞数据做 LoRA/QLoRA 微调与蒸馏（deepseek 16B 已放弃作为基座） | ⏳ 待开始  |
| 六、系统设计与开发        | MVP：代码上传 → LLM 分析 → 结果展示；批量扫描、报告导出                 | ⏳ 待开始  |
| 七、论文与答辩          | 整理实验数据、撰写论文、答辩演示                                   | ⏳ 待开始  |

### 📌 答辩核心论点（整合自 [docs/\_archive/kimi的建议\_20260628.md](docs/_archive/kimi的建议_20260628.md)）

> 以下三点是答辩时容易被问、且当前路线图未覆盖的论证维度，作为论文写作与答辩准备的素材。

#### 1. 速度 vs 质量的权衡论证

LLM 单样本耗时约 7.7s（qwen2.5-coder:7b），比 Bandit（\~0.5s）慢约 15 倍，但传统工具只输出"漏洞类型 + 规则号"，人工理解每个漏洞仍需 \~30 分钟；LLM 直接给出自然语言解释 + 修复代码，把人工审计时间降到 \~5 分钟。

**核心论点**：LLM 慢 15 倍，但整体效率（含人工理解成本）显著提升——定位为"增强审计"而非"替代"。
当前默认主模型 qwen2.5-coder:7b 在典型样本上无需后处理即可达到 100% 准确率，在难样本上 RAG K=5 达到 recall=100%、accuracy=92.9%，显著优于纯 LLM（recall=88.5%、accuracy=83.3%）。
后续通过专用模型训练（LoRA/QLoRA）进一步提升泛化能力。

| 指标      | Bandit           | Semgrep    | LLM (qwen2.5-coder:7b) |
| ------- | ---------------- | ---------- | ---------------------- |
| 单样本耗时   | \~0.5s           | \~2s       | \~7.7s                 |
| 人工理解时间  | \~30 分钟/漏洞       | \~30 分钟/漏洞 | \~5 分钟/漏洞              |
| 修复代码生成  | ❌                | ❌          | ✅                      |
| 典型样本准确率 | 75.0%（Python 样本） | 78.6%      | 100%（纯 LLM / RAG+LLM） |
| 难样本准确率 | - | - | 92.9%（RAG K=5）/ 83.3%（纯 LLM） |

> 数据来自 exp\_01 / exp\_02 / exp\_03 实测结果。

#### 2. 配置门槛的应对

答辩必被问"LLM 这么吃资源，普通团队怎么用"。应对方向：

| 优化方向  | 方案                                                                                                | 论文定位   |
| ----- | ------------------------------------------------------------------------------------------------- | ------ |
| 模型轻量化 | qwen2.5-coder:7b 主审（7B dense，约 4-5GB），deepseek-coder-v2:16b / qwen2.5-coder:14b / gemma4:26b 作为对照 | 降低门槛论证 |
| 专用模型  | LoRA/QLoRA 微调 qwen7b / deepseek → 网络安全专用模型                                                        | 核心创新点  |
| 批处理   | vLLM 一次分析多文件                                                                                      | 摊薄加载时间 |
| 混合架构  | 传统工具先筛，LLM 只审可疑文件                                                                                 | 工程化优化  |
| 云端部署  | 实验室集中部署，多人共享                                                                                      | 后续扩展   |

**核心论点**：定位为面向具备 GPU 资源团队的辅助审计工具，是增强而非替代。

#### 3. 答辩核心故事线（一段话）

> "传统静态分析工具在 CI/CD 流水线中表现优秀，但面对复杂业务逻辑、绕过式过滤、跨函数污点等场景时力不从心。本系统利用本地部署的大语言模型，通过 RAG 知识库增强和语义级代码理解，在保证检出率的同时，生成可执行的修复代码和自然语言解释，将人工审计时间从 30 分钟缩短到 5 分钟。实验表明，在典型漏洞上 LLM 不弱于传统工具，在难样本上显著优于传统工具，证明了 LLM 在代码安全审计中的差异化价值。"

***

## 六、技术栈规划

### 核心分析引擎

- **本地 LLM 推理**：Ollama（已用）/ vLLM（后期高性能部署）/ llama.cpp
- **默认主模型**：qwen2.5-coder:7b（当前默认，典型样本无需后处理即可 100% 准确率）
- **对照/基座模型**：deepseek-coder-v2:16b / qwen2.5-coder:14b / gemma4:12b / gemma4:26b / gpt-oss:20b
- **RAG 检索增强**：LangChain / LlamaIndex
- **向量数据库**：Chroma（已用）/ Milvus / Qdrant
- **代码解析**：tree-sitter / Python `ast` 模块

### 系统服务层

- **后端**：FastAPI 或 Spring Boot
- 任务调度 / 文件预处理 / 结果聚合

### 前端展示层

- **前端**：Vue.js 或 React
- 代码上传 / 分析结果 / 漏洞详情 / 修复建议

### 系统架构草图

```
┌─────────────────────────────────────────┐
│           前端界面 (Vue.js/React)        │
│    代码上传 | 分析结果 | 漏洞详情 | 修复建议  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│           后端服务 (FastAPI/Spring Boot)   │
│    任务调度 | 文件预处理 | 结果聚合      │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│         核心分析引擎 (Python)             │
│  ┌─────────┐  ┌─────────┐  ┌────────┐ │
│  │ AST解析   │  │ RAG检索  │  │ LLM推理 │ │
│  │ 代码切片  │  │ 漏洞知识库│  │ qwen2.5-coder:7b │ │
│  └─────────┘  └─────────┘  └────────┘ │
└─────────────────────────────────────────┘
```

***

## 七、复现方式

### 环境准备（所有实验的前置步骤，只需执行一次）

```bash
cd Graduation-Project

# 使用 conda 环境 graproj（项目所有依赖与工具均在此环境中）
source ~/miniconda3/etc/profile.d/conda.sh
conda activate graproj

# 安装依赖 + 注册 graduation_project 为可导入包
pip install -r requirements.txt
pip install -e .

# 确保 Ollama 已运行且默认主模型已下载
ollama pull qwen2.5-coder:7b
ollama serve   # 若未启动
```

> **环境约定**：所有实验脚本（尤其 exp\_03 / exp\_04 RAG 相关）依赖 `chromadb`、`sentence-transformers` 等包，这些只在 `graproj` conda 环境中安装。请在运行任何实验前激活该环境，否则会出现 `ModuleNotFoundError`。
>
> **离线运行约定**：`graduation_project/chroma_manager.py` 已强制离线模式（`HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1`），运行时不会从 HuggingFace 下载 embedding 模型。首次使用前请确保 `all-MiniLM-L6-v2` 已缓存到本地：
>
> ```bash
> # 在有网络的环境执行一次即可
> python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"
> # 默认缓存到 ~/.cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2
> ```
>
> 若缓存路径非默认，可设置 `export CHROMA_EMBEDDING_MODEL_PATH=/path/to/local/model`。

### 跑第一阶段实验（exp\_01）

```bash
cd experiments/exp_01_basic_scan

python3 run_experiment.py                       # 跑全部 14 个样本（默认 qwen2.5-coder:7b）
python3 run_experiment.py --limit 3             # 只跑前 3 个（快速调试）
python3 run_experiment.py --model deepseek-coder-v2:16b --temperature 0.1   # 切换对照模型
python3 run_experiment.py --keep-loaded         # 跑完保留模型在显存（默认卸载）
```

结果写入 `results/results.json`，每跑完一个样本即增量落盘，中途可断点查看。

### 跑第二阶段实验（exp\_02，传统工具对比基线）

```bash
cd experiments/exp_02_baseline_tools

# 需先安装工具：pip install bandit semgrep
python3 run_baseline.py                         # Bandit + Semgrep 都跑
python3 run_baseline.py --tool bandit           # 只跑 Bandit
python3 run_baseline.py --tool semgrep          # 只跑 Semgrep
python3 run_baseline.py --limit 3               # 只跑前 3 个样本（调试）
```

复用 exp\_01 的 14 段样本，结果按工具分组写入 `results/results.json`。

### 跑第三阶段实验（exp\_03，RAG 知识库增强）

```bash
# 1. 构建漏洞知识库（幂等，可重复运行）
cd experiments/exp_03_rag_knowledge/knowledge_data
python3 build_knowledge.py                      # 从 knowledge.json upsert 34 条知识 → Chroma

# 2. 批量对比实验：纯 LLM vs RAG+LLM
cd ..
python3 run_rag_experiment.py                   # 跑全部 14 个样本（默认 qwen2.5-coder:7b）
python3 run_rag_experiment.py --top-k 5         # 检索 Top-5 知识
python3 run_rag_experiment.py --limit 3         # 只跑前 3 个（调试）
python3 run_rag_experiment.py --model deepseek-coder-v2:16b  # 切换对照模型

# 3. 单样本快速验证（可选，正式实验用 run_rag_experiment.py）
cd knowledge_data
python3 test_rag.py
```

### 跑第四阶段实验（exp\_04，难样本压力测试 + 消融对照）

```bash
cd experiments/exp_04_hard_samples

# P1-4：纯 LLM 重复实验 + 95% 置信区间（默认 --repeat 3，约 95 分钟）
python3 run_experiment.py --repeat 3
python3 run_experiment.py --repeat 3 --limit 3      # 只跑前 3 个样本（调试）

# P1-5：RAG 消融对照（4 组分别运行，每组约 30 分钟）
python3 run_rag_experiment.py --mode rag            # A 组：RAG+LLM
python3 run_rag_experiment.py --mode pure           # B 组：纯 LLM
python3 run_rag_experiment.py --mode random         # C 组：随机知识注入
python3 run_rag_experiment.py --mode irrelevant     # D 组：等长无关文本注入

# P2-8：Top-K 对比（K=1,3,5,10）
python3 run_rag_experiment.py --mode rag --top-k 1
python3 run_rag_experiment.py --mode rag --top-k 5
python3 run_rag_experiment.py --mode rag --top-k 10

# 一键顺序跑完 P1-5 + P2-8（约 4 小时，需 P1-4 已完成释放显存）
nohup bash run_ablation_and_topk.sh > results/ablation_topk.run.log 2>&1 &

# 生成最终报告
python3 generate_report.py
```

***

## 八、参考资源

### 工具与平台

- **传统代码审计**：[Semgrep](https://semgrep.dev/) / [CodeQL](https://codeql.github.com/) / [Bandit](https://bandit.readthedocs.io/)
- **LLM 安全应用**：[Garak](https://github.com/leondz/garak) / Promptmap
- **漏洞管理平台**：[OpenVAS](https://www.openvas.org/) / [Nuclei](https://github.com/projectdiscovery/nuclei)
- **数据集来源**：[OWASP WebGoat](https://owasp.org/www-project-webgoat/) / CVE PoC 仓库 / CodeQL 测试用例

### 难样本设计参考（exp\_04）

以下资料用于设计 exp\_04 中的真实 CVE 片段与 OWASP 风格难样本（详见 `experiments/exp_04_hard_samples/samples/manifest.json`）：

- **CVE-2017-7494 Samba 远程命令执行**：`hard_cve_01_samba_2017_7494.py` 的设计依据
- **CVE-2021-44228 Log4j JNDI 注入**：`hard_cve_02_log4j_2021_44228.py` 的设计依据
- **CVE-2025-4517 Python tarfile 路径穿越**：`hard_cve_03_tarfile_2025_4517.py` 的设计依据
- **CVE-2025-54381 BentoML SSRF**：`hard_cve_04_ssrf_2025_54381.py` 的设计依据
- **Top 10 Python Security Vulnerabilities** (aikido.dev)：典型 Python 漏洞模式参考
- **Insecure Deserialization in Python** (semgrep.dev)：pickle / yaml 反序列化样本参考
- **Vulnerable Web Application examples** (offensive360.com)：OWASP/DVWA 风格样本参考
- **aiohttp CVE-2024-23334 路径穿越 PoC** (exploit-db.com)：路径穿越绕过样本参考

> 每段 CVE 样本文件头部的注释中标注了对应的 CVE 编号与原始漏洞描述，便于追溯。

***

## 九、评估方法学

为保证实验结果在论文/答辩中可被复现与质疑，本项目的指标定义、置信区间、口径选择都遵循以下规则。

### 9.1 混淆矩阵与基础指标

| 预测 \ 实际   | 漏洞（expected\_present=True） | 安全（expected\_present=False） |
| --------- | -------------------------- | --------------------------- |
| **判定为漏洞** | TP（真阳性）                    | FP（误报）                      |
| **判定为安全** | FN（漏报）                     | TN（真阴性）                     |

- **召回率（Recall）** = TP / (TP + FN)：漏洞样本被检出的比例
- **误报率（FPR）** = FP / (FP + TN)：安全样本被误判为漏洞的比例
- **准确率（Accuracy）** = (TP + TN) / (TP + TN + FP + FN)：总体判定正确率
- **无效样本**：模型输出无法解析为有效 JSON 时计入 invalid，不计入 TP/FP/FN/TN

### 9.2 重复实验与多数表决（P1-4）

`temperature=0.1` 不等于确定性输出，模型每次推理仍有随机性。每个样本连续跑 N 次（默认 N=3）：

- **多数表决**：N 次中判定为漏洞的比例 ≥ 50% 则最终判为漏洞；平票时保守判 True
- **一致率**：max(True 次数, False 次数) / 有效次数，反映模型对该样本的判定稳定性
- 一致率 < 2/3 的样本在报告中单独列出，作为"模型判定不稳定"的证据

### 9.3 置信区间（Wilson score interval）

采用 Wilson score interval 而非正态近似，因前者在比例接近 0 或 1（如 100% 召回率）时更稳定：

```
center = (p + z²/(2n)) / (1 + z²/n)
margin = z · √(p(1-p)/n + z²/(4n²)) / (1 + z²/n)
CI = [center - margin, center + margin]
```

其中 `p` 为样本比例，`n` 为样本数，`z=1.96` 对应 95% 置信度。例如 8/10 准确率的 95% CI 为 \[49.0%, 94.3%]，而非简单的 80% ± x。

### 9.4 耗时统计

单点耗时无意义，报告中同时给出：

- **均值**：所有样本耗时的算术平均
- **中位数**：更稳健，不受异常值影响（论文引用推荐用此）
- **标准差**：反映耗时波动
- **p95**：95 分位数，反映长尾
- **最长/最短**：异常值定位（如 safe\_02 因模型对安全样本过度分析导致耗时最长）

### 9.5 RAG 消融对照（P1-5）

为证明 RAG 提升来自知识相关性而非"prompt 变长"，对比 4 组：

| 组别               | 注入内容              | 验证目的             |
| ---------------- | ----------------- | ---------------- |
| A 组 (rag)        | 按代码语义检索 Top-K 知识  | 当前实现（baseline）   |
| B 组 (pure)       | 无 RAG 上下文         | 排除 RAG 干扰        |
| C 组 (random)     | 知识库随机抽 K 条（与样本无关） | 排除"注入任何知识都有用"    |
| D 组 (irrelevant) | 与漏洞无关但长度相近的文本     | 排除"prompt 变长就有用" |

**论证逻辑**：只有当 A 组显著优于 B/C/D 三组时，才能论证 RAG 真正有用；若 A ≈ C 或 A ≈ D，则提升仅来自 prompt 变长或随机注入。

### 9.6 评估口径

每个实验同时给出两种口径：

- **单次口径**：所有 run 拉平统计（如 42 样本 × 3 次 = 126 次判定），适合和 exp\_01\~03 历史数据对比
- **多数表决口径**：每个样本 N 次投票后的最终判定，更贴近实际使用场景

***

## 十、约定与备注

- 先不搭前后端框架，需求会在实验后明确。
- 所有实验过程和 Prompt 迭代都保留，后续写论文直接可用。
- 模型名称需与 Ollama 中实际可用的模型名一致。
- **显存管理约定**：每次实验脚本跑完必须主动从显存卸载模型（Ollama `keep_alive=0`），多模型场景下避免爆显存。`run_experiment.py` 默认在末尾卸载，如需保留加 `--keep-loaded`。
- 大模型文件（`.gguf` / `.bin` / `.safetensors` 等）绝不入库，见 `.gitignore`。
- **RAG 向量库**：`data/chroma_db/` 为本地持久化数据，不入库（见 `.gitignore`），需在本地通过 `build_knowledge.py` 自行构建。

