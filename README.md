# 基于大语言模型的代码安全分析系统

> 本地部署的开源大语言模型（Gemma 4 26B）驱动的代码漏洞检测系统，对比传统基于规则的静态分析工具，验证 LLM 在代码安全审计中的语义理解优势。

---

## 一、项目简介

利用本地部署的开源大语言模型对源代码进行安全审计，目标是构建一个相比传统静态分析工具（Bandit / Semgrep / CodeQL）具备以下优势的系统：

| 维度       | 传统工具（Bandit/Semgrep）     | 本系统（LLM 驱动）                |
| ---------- | ------------------------------ | --------------------------------- |
| 检测方式   | 固定规则模式匹配               | 代码语义理解、上下文感知           |
| 漏洞覆盖   | 已知漏洞模式                   | 可发现变体/非典型漏洞              |
| 输出形式   | 漏洞类型 + 规则编号            | 自然语言解释 + 修复建议 + 修复代码 |
| 多语言     | 工具专属规则集                 | 跨语言统一理解                     |
| 误报控制   | 规则泛化能力差                 | 上下文判断过滤/净化逻辑            |

**核心卖点**：传统工具是"模式匹配"，本系统是"语义理解"。

---

## 二、实验环境

| 项目        | 配置                                        |
| ----------- | ------------------------------------------- |
| CPU         | AMD Ryzen 5 9600X × 12                      |
| 内存        | 32 GB                                       |
| 显卡        | AMD Radeon RX 9060 XT                        |
| 操作系统    | Ubuntu 26.04 LTS（内核 7.0.0-15-generic）   |
| 桌面环境    | GNOME 50 / Wayland                          |
| 本地 LLM    | Ollama                                      |
| 主模型      | `gemma4:26b`（Q4_K_M，已验证可流畅运行）    |

> 注：模型文件不入库（见 `.gitignore`），需在本地通过 `ollama pull gemma4:26b` 自行下载。

---

## 三、项目结构

```
Graduation-Project/
├── README.md                              # 本文档
└── experiments/
    └── exp_01_basic_scan/                 # 阶段一：Gemma 漏洞检测能力摸底
        ├── run_experiment.py              # 批量测试脚本（调 Ollama API + 增量落盘 + 自动卸载显存）
        ├── exp_01_report.md               # 实验报告
        ├── samples/                       # 14 段漏洞代码样本
        │   ├── manifest.json              #   样本清单（含期望标签）
        │   ├── sql_injection_01.py / 02.py
        │   ├── xss_01.php / 02.js
        │   ├── command_injection_01.py / 02.js
        │   ├── path_traversal_01.py / 02.java
        │   ├── hardcoded_secret_01.py / 02.java
        │   ├── insecure_deserialization_01.py / 02.java
        │   ├── safe_01_parameterized_query.py
        │   └── safe_02_subprocess_list.py
        └── results/
            └── results.json               # 14 次推理的完整原始输出（保留作论文素材）
```

---

## 四、当前进度

### ✅ 已完成：第一阶段 — Gemma 4 26B 漏洞检测能力摸底（2026-06-28）

- 14 段样本：6 类典型漏洞 × 2 + 2 安全对照，覆盖 Python / PHP / JavaScript / Java 4 种语言
- 统一结构化 Prompt（角色设定 → 分析范围 → JSON 结论协议）
- 批量测试脚本 `run_experiment.py`：调用 Ollama API、增量落盘、自动卸载显存
- **结果**：召回率 100% (12/12)、误报率 0% (0/2)、平均 56.7s/样本、JSON 协议解析稳定

详见 [experiments/exp_01_basic_scan/exp_01_report.md](experiments/exp_01_basic_scan/exp_01_report.md)。

> ⚠️ **结果局限性**：样本为"教科书式"典型漏洞，100% 准确率仅证明能力下限，不代表真实工程代码的检测能力。

### 🔄 进行中：第二阶段 — 传统工具对比基线

- [ ] 安装 Bandit / Semgrep
- [ ] 在 `experiments/exp_02_baseline_tools/` 下编写统一对比脚本，复用第一阶段 14 段样本
- [ ] 用同一批样本分别跑 Bandit / Semgrep，记录检出、漏报、误报、耗时
- [ ] 生成对比表：LLM vs Bandit vs Semgrep，明确 LLM 的改进点
- [ ] 补充 3-5 段"难样本"（绕过式过滤、跨文件污点、真实 CVE 片段）
- [ ] 整理第二份实验报告 `exp_02_report.md`

---

## 五、路线图

| 阶段 | 目标 | 状态 |
| --- | --- | --- |
| 一、模型能力摸底 | 验证 Gemma 在典型漏洞上的下限能力 | ✅ 完成 |
| 二、传统工具对比基线 | 明确 LLM 相对传统工具的改进点 | 🔄 进行中 |
| 三、系统设计与开发 | MVP：代码上传 → LLM 分析 → 结果展示；引入 RAG / 向量库；多语言、批量扫描、报告导出 | ⏳ 待开始 |
| 四、论文与答辩 | 整理实验数据、撰写论文、答辩演示 | ⏳ 待开始 |

---

## 六、技术栈规划

### 核心分析引擎
- **本地 LLM 推理**：Ollama（已用）/ vLLM（后期高性能部署）/ llama.cpp
- **主模型**：Gemma 4 26B（已验证）
- **RAG 检索增强**：LangChain / LlamaIndex
- **向量数据库**：Chroma / Milvus / Qdrant
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
│  │ 代码切片  │  │ 漏洞知识库│  │ Gemma4 │ │
│  └─────────┘  └─────────┘  └────────┘ │
└─────────────────────────────────────────┘
```

---

## 七、复现方式

### 跑第一阶段实验

```bash
cd experiments/exp_01_basic_scan

# 确保 Ollama 已运行且 gemma4:26b 已下载
ollama pull gemma4:26b
ollama serve   # 若未启动

python3 run_experiment.py                       # 跑全部 14 个样本
python3 run_experiment.py --limit 3             # 只跑前 3 个（快速调试）
python3 run_experiment.py --model gemma4:26b --temperature 0.1
python3 run_experiment.py --keep-loaded         # 跑完保留模型在显存（默认卸载）
```

结果写入 `results/results.json`，每跑完一个样本即增量落盘，中途可断点查看。

---

## 八、参考资源

- **传统代码审计**：[Semgrep](https://semgrep.dev/) / [CodeQL](https://codeql.github.com/) / [Bandit](https://bandit.readthedocs.io/)
- **LLM 安全应用**：[Garak](https://github.com/leondz/garak) / Promptmap
- **漏洞管理平台**：[OpenVAS](https://www.openvas.org/) / [Nuclei](https://github.com/projectdiscovery/nuclei)
- **数据集来源**：[OWASP WebGoat](https://owasp.org/www-project-webgoat/) / CVE PoC 仓库 / CodeQL 测试用例

---

## 九、约定与备注

- 先不搭前后端框架，需求会在实验后明确。
- 所有实验过程和 Prompt 迭代都保留，后续写论文直接可用。
- 模型名称需与 Ollama 中实际可用的模型名一致。
- **显存管理约定**：每次实验脚本跑完必须主动从显存卸载模型（Ollama `keep_alive=0`），多模型场景下避免爆显存。`run_experiment.py` 默认在末尾卸载，如需保留加 `--keep-loaded`。
- 大模型文件（`.gguf` / `.bin` / `.safetensors` 等）绝不入库，见 `.gitignore`。
