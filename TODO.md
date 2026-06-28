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

---

## 🔄 待处理（建议回台式机后处理）

### 一、代码结构重构

- [ ] **抽取统一 schema 模块**  
  当前 `VERDICT_SCHEMA` 和字段说明同时出现在 `src/llm_client.py` 和 `experiments/exp_01_basic_scan/run_experiment.py` 中。建议新建 `src/schema.py` 统一维护，两处脚本共同引用。

- [ ] **抽取统一 Prompt 模板**  
  `src/llm_client.py` 的 `analyze_vulnerability()` 系统提示词与 `run_experiment.py` 的 `PROMPT_TEMPLATE` 高度重复。建议新建 `src/prompts.py`，由 `llm_client.py` 提供 prompt 构建函数，`run_experiment.py` 直接调用。

- [ ] **提取实验公共工具函数**  
  `parse_verdict`、结果统计、JSON 落盘等逻辑在多个实验中会复用。建议新建 `experiments/utils.py`，供 exp_01 / exp_02 / exp_03 共享。

### 二、包名与工程化

- [ ] **包名反模式修正**  
  当前 `pyproject.toml` 中 `packages = ["src"]`，导致 Python 包名是 `src`，与目录名冲突且语义不清。建议将源码目录重命名为 `graduation_project/`，或至少通过 `setuptools` 正确映射包名。
  > ⚠️ 此项改动会影响所有 `from src.xxx import ...` 的导入，需一次性全局替换。

- [ ] **Chroma 持久化路径优化**  
  当前 `src/chroma_manager.py` 通过 `__file__` 定位项目根目录。若未来打包安装到 `site-packages`，持久化目录会创建到 site-packages 下。建议优先从环境变量（如 `CHROMA_PERSIST_DIR`）读取。

- [ ] **脚本运行方式统一**  
  当前实验脚本依赖 `pip install -e .` 后才能用 `from src.xxx import ...`。建议每个脚本开头增加项目根目录动态加入 `sys.path` 的兜底逻辑，或提供统一的 `run_all.sh` / `run_all.py` 入口。

### 三、数据与产物清理

- [ ] **清理已入库的编译产物**  
  `__pycache__/` 目录和 `graduation_project.egg-info/` 不应入库。当前工作区可能没有，但历史提交中可能残留。建议执行 `git rm -r --cached` 清理后提交。
  > 执行命令：`git rm -r --cached src/__pycache__ experiments/**/__pycache__ graduation_project.egg-info`

- [ ] **结果文件按时间戳命名**  
  `experiments/exp_01_basic_scan/results/results.json` 是单一文件，后续实验增多后容易被覆盖。建议按时间戳命名结果文件，保留历史记录。

### 四、实验代码补全

- [ ] **实现 `run_baseline.py`**  
  `experiments/exp_02_baseline_tools/` 目前只有 README。需编写脚本批量调用 Bandit / Semgrep，输出与 exp_01 统一的 JSON 结果格式。

- [ ] **补充 exp_02 / exp_03 实验报告**  
  缺失 `experiments/exp_02_baseline_tools/exp_02_report.md` 和 `experiments/exp_03_rag_knowledge/exp_03_report.md`。

### 五、实验数据标注

- [ ] **注明模型幻觉记录**  
  `results.json` 中出现 `request.args.annotated`、`host.arg` 等源代码中不存在的引用，属于 LLM 幻觉。在 exp_01_report.md 或后续论文中应明确说明，避免误用为有效分析。

---

## 优先级建议

| 优先级 | 项目 | 原因 |
| --- | --- | --- |
| 高 | 实现 `run_baseline.py` | 阶段二是毕设核心论据，必须做 |
| 高 | 抽取 `schema.py`、`prompts.py` | 避免后续实验越多，重复越多 |
| 中 | 包名反模式修正 | 工程化基础，改动大但越晚越难改 |
| 中 | Chroma 持久化路径优化 | 为后续打包/部署做准备 |
| 低 | 清理 `__pycache__` | 一次性清理，随时可做 |
| 低 | 结果文件按时间戳命名 | 便于追溯，但不是阻塞项 |
