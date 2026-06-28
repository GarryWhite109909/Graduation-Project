# 项目待优化问题清单

> 记录代码审查中发现的项目结构、代码质量、工程化问题。处理完一项勾选一项。

---

## ✅ 已处理

- [x] `src/src/llm_client.py` 嵌套目录修复 → 已移到 `src/llm_client.py`
- [x] `experiments/exp_03_rag_knowledge/knowledge_data/build_knowledge.py` 导入路径错误 → 已改为 `../../../src`
- [x] `experiments/exp_03_rag_knowledge/knowledge_data/test_rag.py` 相对导入问题 → 已加 `sys.path` 兜底
- [x] `test_rag.py` 中 `result["error"]` KeyError → 已改为判断 `result["text"].startswith("错误:")`
- [x] `pyproject.toml` 与 `requirements.txt` 依赖版本不一致 → 已统一为较高版本
- [x] README 项目结构图中 `exp_02/samples/` 和 `data/` 说明不准确 → 已补充注释
- [x] `docs/glm的建议.md` 缺少手工工作清单 → 已新增章节
- [x] `exp_02_baseline_tools/` 目录骨架 → 已新建 README 与 samples 目录
- [x] **抽取统一 schema 模块** → 已新建 `src/schema.py`，`llm_client.py` re-export 兼容
- [x] **抽取统一 Prompt 模板** → 已新建 `src/prompts.py`，统一 SYSTEM_PROMPT + build_user_prompt
- [x] **提取实验公共工具函数** → 已新建 `experiments/utils.py`，供 exp_01/02/03 共享
- [x] **Chroma 持久化路径优化** → `src/chroma_manager.py` 优先读取环境变量 `CHROMA_PERSIST_DIR`，未设置时回退到项目根目录 `data/chroma_db`
- [x] **脚本运行方式统一** → 所有实验脚本（run_experiment / run_baseline / run_rag_experiment / build_knowledge / test_rag）均已在开头加入项目根 `sys.path` 兜底，可从任意目录运行
- [x] **清理已入库的编译产物** → 经 `git ls-files` 核实无 `__pycache__` / `egg-info` 入库残留，`.gitignore` 已覆盖
- [x] **build_knowledge.py 幂等化** → `chroma_manager` 新增 `upsert_documents`，build_knowledge 改用 upsert，重复运行不再因 id 冲突报错
- [x] **test_rag.py 错误判断 bug 修复** → `text.startswith("错误:")` 永远不触发（错误时 text 为空），改为判断 `result["error"]`
- [x] **run_rag_experiment.py 局部 import 上提** → 循环内的 `from src.prompts import ...` 移到文件顶部
- [x] **run_baseline.py 错误注释清理** → 删除提到不存在的 `-r` 参数的注释
- [x] **README.md 同步实际进度** → 结构图补全缺失文件、进度更新到阶段三完成、路线图状态刷新、复现方式补充 exp_02/03

---

## 🔄 待处理（建议回台式机后处理）

### 一、代码结构重构

（暂无，schema / prompts / utils 已抽取完成）

### 二、包名与工程化

- [ ] **包名反模式修正**  
  当前 `pyproject.toml` 中 `packages = ["src"]`，导致 Python 包名是 `src`，与目录名冲突且语义不清。建议将源码目录重命名为 `graduation_project/`，或至少通过 `setuptools` 正确映射包名。
  > ⚠️ 此项改动会影响所有 `from src.xxx import ...` 的导入，需一次性全局替换。当前所有脚本已有 `sys.path` 兜底，不阻塞运行，越晚改影响面越大。

### 三、数据与产物清理

- [ ] **结果文件按时间戳命名**  
  `experiments/exp_01_basic_scan/results/results.json` 是单一文件，后续实验增多后容易被覆盖。建议按时间戳命名结果文件，保留历史记录。
  > 注意：现有报告引用了 `results.json` 路径，改动时需同步更新报告中的引用。

### 四、实验代码补全

- [x] **实现 `run_baseline.py`**  
  `experiments/exp_02_baseline_tools/run_baseline.py` 已实现，支持 Bandit + Semgrep 批量调用，
  输出与 exp_01 统一的 JSON 格式，自动适配 conda/venv 环境的 PATH。

- [x] **补充 exp_02 实验报告**  
  `experiments/exp_02_baseline_tools/exp_02_report.md` 已完成，含逐样本对比表、汇总指标、
  漏报/误报分析、LLM vs 传统工具横向对比、论文论据映射。
  exp_03 报告已完成：`experiments/exp_03_rag_knowledge/exp_03_report.md`，
  含 34 条知识库构建、14 样本逐样本判定、纯 LLM vs RAG+LLM 对比、
  RAG 检索质量分析、可解释性提升、论文论据映射。

### 五、实验数据标注

- [x] **注明模型幻觉记录**  
  已在 `exp_01_report.md` 第六节补充"模型幻觉记录"小节，列出两处事实性幻觉：
  `request.args.annotated`（虚构 Flask API）、`host.arg`（虚构字符串属性），
  并给出"LLM 适合作为漏洞提示器而非事实权威"的论文论点。

---

## 优先级建议

| 优先级 | 项目 | 原因 |
| --- | --- | --- |
| 高 | 扩充难样本集（CVE/WebGoat/绕过过滤） | 当前 14 样本统计意义有限，毕设核心论据 |
| 中 | 包名反模式修正 | 工程化基础，改动大但越晚越难改（当前不阻塞运行） |
| 中 | 结果文件按时间戳命名 | 便于追溯，避免历史数据被覆盖 |
