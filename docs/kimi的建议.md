# 基于 LLM 的代码漏洞检测系统——智能体分工建议

基于项目现状（已有 14 个基础样本和一轮基础实验），建议按 **“核心检测 → 知识增强 → 实验对比 → 工程化”** 四条线拆分智能体。

---

## 一、建议创建的 6 个智能体

| 智能体 | 核心职责 | 为什么需要 |
| :--- | :--- | :--- |
| **漏洞检测核心 Agent** | 对单文件/函数做漏洞判定、风险等级、修复建议 | 项目主线，承接后续所有模块 |
| **RAG 知识库 Agent** | 构建/维护 OWASP/CWE/CVE 向量库，检索相关知识注入 Prompt | 对应建议 #3，是最易出创新点的模块 |
| **AST 切片 Agent** | 用 tree-sitter 把长文件切到函数/代码块级别，控制上下文长度 | 对应建议 #4，解决长上下文衰减 |
| **对比实验 Agent** | 跑 Bandit/Semgrep/多 LLM，输出检出/漏报/误报/耗时/解释质量对比表 | 对应建议 #1、#5 |
| **污点分析 Agent** | 做 Source→Sink 追踪，识别跨函数污染链 | 对应建议 #6，体现“比单点检测强” |
| **工程化/Web 报告 Agent** | 搭建 Web 界面、批量扫描、导出 PDF/Markdown 报告 | 对应建议 #9，让系统像系统 |

---

## 二、各智能体提示词与 MCP 建议

### 1. 漏洞检测核心 Agent

**提示词要点：**

```text
你是代码安全审计专家。输入为代码片段（可能已做 AST 切片）和检索到的漏洞知识。
任务：
1. 判断是否存在安全漏洞，给出 CWE/OWASP 分类；
2. 标注风险等级（Critical/High/Medium/Low）；
3. 输出漏洞说明、触发路径、修复建议代码；
4. 仅返回结构化 JSON，不要多余解释。
```

**建议 MCP：**

- 模型调用 MCP（Ollama / OpenAI 兼容 / vLLM）
- 文件系统 MCP（读写样本与结果）

---

### 2. RAG 知识库 Agent

**提示词要点：**

```text
你是漏洞知识库构建专家。任务：
1. 从 OWASP Top 10、CWE、CVE 描述中抽取“漏洞模式、典型代码特征、修复方案”；
2. 生成适合向量检索的 chunks，并存入 Chroma；
3. 当收到待测代码时，检索 Top-K 相关知识并格式化为 Prompt 上下文。
```

**建议 MCP：**

- Chroma / 向量数据库 MCP
- Web 搜索 MCP（查最新 CVE）
- GitHub MCP（拉 CVE PoC 仓库）

---

### 3. AST 切片 Agent

**提示词要点：**

```text
你是代码预处理专家。使用 tree-sitter 解析 Python/Java/JS/PHP/Java 等源码。
任务：
1. 按函数、类、方法切分代码单元；
2. 对每个切片保留调用链、依赖变量、导入信息；
3. 输出切片后的结构化代码块，供 LLM 分批检测。
```

**建议 MCP：**

- 文件系统 MCP
- tree-sitter 解释器 MCP（或本地 Python 执行 MCP）
- 可选：GitHub MCP 拉取测试仓库

---

### 4. 对比实验 Agent

**提示词要点：**

```text
你是实验评估专家。任务：
1. 在相同样本集上运行 Bandit、Semgrep、Gitleaks 等基线工具；
2. 运行多个 LLM（Gemma 4 26B / Llama 3 / Qwen2.5）；
3. 统计 TP/FP/FN/TN、耗时、解释质量评分；
4. 输出 Markdown/CSV 对比表和结论。
```

**建议 MCP：**

- 命令行执行 MCP（运行 Bandit/Semgrep）
- 模型调用 MCP（多模型调度）
- 文件系统 MCP（读写实验结果）

---

### 5. 污点分析 Agent

**提示词要点：**

```text
你是程序分析专家。任务：
1. 识别 Source（用户输入、文件读取、网络请求等）；
2. 识别 Sink（exec、eval、SQL 执行、文件操作等）；
3. 在函数内/跨函数间追踪变量传播路径；
4. 对无法静态确定的路径，调用 LLM 做“污染传播推断”。
```

**建议 MCP：**

- tree-sitter / AST 解析 MCP
- 代码图/依赖分析 MCP（如 CodeQL、Joern 可选）
- 模型调用 MCP

---

### 6. 工程化/Web 报告 Agent

**提示词要点：**

```text
你是全栈工程化专家。任务：
1. 用 Flask/FastAPI + React/Vue 搭建扫描任务管理 Web 界面；
2. 支持批量上传、任务队列、结果展示；
3. 支持导出 Markdown/PDF 报告；
4. 与后端检测 pipeline 解耦，通过 API 调用。
```

**建议 MCP：**

- Web 开发 MCP（或直接使用 Trae 的 web-dev skill）
- 浏览器 MCP（前端测试）
- PDF 生成 MCP（如 WeasyPrint / Playwright）

---

## 三、是否需要 Skill？

**需要，且建议优先使用以下 Skill：**

1. **TRAE-security-review**
   直接对应项目核心——安全扫描与漏洞审查，可以帮你快速做代码安全分析。

2. **TRAE-code-review**
   用于审查你自己写的检测 pipeline、切片逻辑、Prompt 模板代码，减少工程 bug。

3. **web-dev**
   对应建议 #9，如果你要从零搭 Web 界面+报告导出，直接用这个 skill 最省事。

4. **skill-creator**
   如果现有 skill 覆盖不够，比如你需要一个“批量跑 Bandit/Semgrep/LLM 并生成对比表”的专用能力，可以用它创建**自定义 Skill**，固化成可复用工具。

---

## 四、落地建议

现在项目已有 `experiments/exp_01_basic_scan/` 的基础实验。建议按以下顺序推进：

1. **先强化核心检测 Agent + RAG Agent**，这是论文创新点最容易出彩的部分；
2. **再补 AST 切片 Agent**，把 14 个简单样本扩展到真实 CVE/WebGoat 长文件；
3. **用对比实验 Agent 跑 Bandit/Semgrep**，把“为什么用 LLM”的论据做实；
4. **最后用 Web 报告 Agent 做界面**，答辩演示效果好。

需要我现在就帮你创建其中某个智能体或自定义 Skill 吗？
