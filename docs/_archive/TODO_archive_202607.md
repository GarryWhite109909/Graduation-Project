# 项目待优化问题清单 - 历史归档（2026-07-27 及之前）

> 本文件为 [TODO.md](../../TODO.md) 的历史归档。下方所有问题均已在 2026-07-27 前处理或明确归档，不再作为当前待办。

---

## ✅ 已处理

- [x] `src/src/llm_client.py` 嵌套目录修复 → 已移到 `src/llm_client.py`
- [x] `experiments/exp_03_rag_knowledge/knowledge_data/build_knowledge.py` 导入路径错误 → 已改为 `../../../src`
- [x] `experiments/exp_03_rag_knowledge/knowledge_data/test_rag.py` 相对导入问题 → 已加 `sys.path` 兜底
- [x] `test_rag.py` 中 `result["error"]` KeyError → 已改为判断 `result["text"].startswith("错误:")`
- [x] `pyproject.toml` 与 `requirements.txt` 依赖版本不一致 → 已统一为较高版本
- [x] README 项目结构图中 `exp_02/samples/` 和 `data/` 说明不准确 → 已补充注释
- [x] `docs/_archive/glm的建议_20260628.md` 缺少手工工作清单 → 已新增章节（后归档至 `_archive`）
- [x] `exp_02_baseline_tools/` 目录骨架 → 已新建 README 与 samples 目录
- [x] **抽取统一 schema 模块** → 已新建 `graduation_project/schema.py`，`llm_client.py` re-export 兼容
- [x] **抽取统一 Prompt 模板** → 已新建 `graduation_project/prompts.py`，统一 SYSTEM_PROMPT + build_user_prompt
- [x] **提取实验公共工具函数** → 已新建 `experiments/utils.py`，供 exp_01/02/03 共享
- [x] **Chroma 持久化路径优化** → `graduation_project/chroma_manager.py` 优先读取环境变量 `CHROMA_PERSIST_DIR`，未设置时回退到项目根目录 `data/chroma_db`
- [x] **脚本运行方式统一** → 所有实验脚本（run_experiment / run_baseline / run_rag_experiment / build_knowledge / test_rag）均已在开头加入项目根 `sys.path` 兜底，可从任意目录运行
- [x] **清理已入库的编译产物** → 经 `git ls-files` 核实无 `__pycache__` / `egg-info` 入库残留，`.gitignore` 已覆盖
- [x] **build_knowledge.py 幂等化** → `chroma_manager` 新增 `upsert_documents`，build_knowledge 改用 upsert，重复运行不再因 id 冲突报错
- [x] **test_rag.py 错误判断 bug 修复** → `text.startswith("错误:")` 永远不触发（错误时 text 为空），改为判断 `result["error"]`
- [x] **run_rag_experiment.py 局部 import 上提** → 循环内的 `from graduation_project.prompts import ...` 移到文件顶部
- [x] **run_baseline.py 错误注释清理** → 删除提到不存在的 `-r` 参数的注释
- [x] **README.md 同步实际进度** → 结构图补全缺失文件、进度更新到阶段三完成、路线图状态刷新、复现方式补充 exp_02/03
- [x] **包名反模式修正** → 源码目录由 `src/` 重命名为 `graduation_project/`，`pyproject.toml` 中 `packages` 同步改为 `["graduation_project"]`，所有 `from src.xxx import ...` 已全局替换为 `from graduation_project.xxx import ...`
- [x] **实现 `run_baseline.py`** → `experiments/exp_02_baseline_tools/run_baseline.py` 已实现
- [x] **补充 exp_02 / exp_03 实验报告** → 两篇报告均已完成
- [x] **注明模型幻觉记录** → 已在 `exp_01_report.md` 第六节补充

---

## 历史优先级清单

| 优先级 | 项目 | 结果 |
|---|---|---|
| 高 | **exp_04 v3 重跑**（修复答案泄露后） | ✅ 已完成（2026-07-05） |
| 高 | 完成 exp_04 难样本实验验证（P1-4 / P1-5 / P2-8） | ✅ v3 已完成（2026-07-05） |
| 高 | DeepSeek 安全样本优化专项 | ❌ 已失败（2026-06-30） |
| 中 | 结果文件按时间戳命名 | ✅ 已完成（2026-07-01） |
| 高 | **Qwen2.5-Coder-7B 时代 Phase 1-3 训练流程** | 🗄️ 已归档（2026-07-22 底座切换到 Qwen3-8B） |
| 高 | Phase 4 Prompt Distillation | 🗄️ 已暂缓（2026-07-22） |
| 中 | Phase 5 DPO | ❌ 本地不可行（2026-07-27） |
| 中 | Phase 6 hard sample mining 闭环 | ⏳ 已并入 P4 |
| 高 | **2026-07-23 项目整理** | ✅ 已完成 |
