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

---

## 🔄 待处理（建议回台式机后处理）

### 一、代码结构重构

（暂无，schema / prompts / utils 已抽取完成）

### 二、包名与工程化

（暂无，`graduation_project` 包名已修正）

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

> 截至 2026-07-19。Phase 1-4 训练流程进度详见 [docs/改进.md](docs/改进.md) §0 与 [docs/过程.md](docs/过程.md) 7-17~19 段。

| 优先级 | 项目 | 原因 |
| --- | --- | --- |
| 高 | **exp_04 v3 重跑**（修复答案泄露后） | ✅ 已完成（2026-07-05）：P1-4/P1-5/P2-8 全部用 v3 修复后样本重跑完成。v3 结果：纯 LLM 多数表决 accuracy=78.2%、recall=83.3%、FPR=33.3%；RAG K=5 accuracy=88.5%、recall=95.0%。RAG 未带来额外提升，模型基座已掌握典型漏洞模式。 |
| 高 | 完成 exp_04 难样本实验验证（P1-4 / P1-5 / P2-8） | ✅ v3 已完成（2026-07-05）。详见 `experiments/exp_04_hard_samples/exp_04_report.md`。 |
| 高 | DeepSeek 安全样本优化专项 | ❌ 已失败（2026-06-30）：Prompt 工程、RAG 安全知识增强、后处理白名单三轮尝试均无法从根本上解决 deepseek 16B 的知识盲区问题；最终指标靠 safe_override 外部规则覆盖，非模型能力提升。放弃 deepseek 作为安全专用模型基座，改用 qwen2.5-coder:7b。 |
| 中 | 结果文件按时间戳命名 | ✅ 已完成（2026-07-01）：exp_01/03/04 均已接入 default_results_path，文件名包含模型名 + 参数标签 + 时间戳 |
| 高 | **Phase 1-4 训练流程** | 🔄 进行中（2026-07-17~19）：Phase 1 sweep/Phase 2 r=32 已完成（失败结论：LoRA 增容 ≠ 知识注入）；Phase 3 KnItLM 突破（recall +23pp / FPR -7.7pp，但发现参数化查询幻觉副作用）；Phase 4 Prompt Distillation 进行中（qwen3-coder:30b teacher，目标修复幻觉） |
| 高 | Phase 4 完成后：FPR 守门 + 多种子评估 + Phase 3 vs Phase 4 错题对比 | ⏳ 待 Phase 4 eval 回传后立即执行（笔记本侧 `compare_phase4.py` + `extract_phase3_errors.py` 改造版 + `run_phase4_multiseed.sh` 已就绪） |
| 中 | Phase 5 DPO（视 Phase 4 结果决定是否上） | ⏳ 待定：硬件约束（ROCm 7.2.4 升级以解决 DPO 死机问题） |
| 中 | Phase 6 hard sample mining 闭环 | ⏳ 待定：用 Phase 4 best 模型跑 eval → 找错题 → teacher 重生成 CoT → 加权采样重训 |
