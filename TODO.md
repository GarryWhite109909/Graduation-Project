# 项目待优化问题清单

> 记录代码审查中发现的项目结构、代码质量、工程化问题。处理完一项勾选一项。
>
> **训练流程进度见 [规划.md](规划.md)；本文件仅保留工程化层面的当前待办。**
> 历史已处理项见 [docs/_archive/TODO_archive_202607.md](docs/_archive/TODO_archive_202607.md)。

---

## ✅ 已处理

- [x] README.md 开头优化：结果卡片、当前状态、待决策事项前置
- [x] docs/论文/大纲.md 状态表与写作进度同步
- [x] 历史 TODO 项归档至 `docs/_archive/TODO_archive_202607.md`
- [x] 为 exp_01~05 报告添加"一句话结论"卡片（含关键指标、核心发现、论文对应章节）
- [x] 创建 exp_06_finetune/exp_06_report.md 作为训练主线汇总报告
- [x] 生成 SFT v2~v6 训练趋势图并插入 README.md 与 docs/论文/第5章_训练主线.md
- [x] 统一术语与日期格式检查：修复规划.md CWE 40→42 表述，确认 HuggingFace ID 大写为合理用法
- [x] exp_01 结果文件按时间戳命名：`results.json` → `results.qwen2.5-coder-7b.20260630.json`，同步更新 exp_01_report.md 与 README.md 引用
- [x] 依赖声明补全：`requirements.txt` 与 `pyproject.toml` 补充 `pydantic` 与 `tree-sitter` 系列语言包
- [x] 一键部署脚本增强：`start_windows.bat` / `start_linux_macos.sh` 首次运行检测 Web 层 + 分析引擎层 + tree-sitter 语言包
- [x] README.md 工程化状态刷新：将 6.5/6.6 从"待启动"改为"已落地"，补充 `app/` 目录结构
- [x] 仪表盘（index.html）接入后端真实数据（`/api/stats`，2026-08-08 核实）
- [x] 扫描工作台（scan.html）报告下载入口：`/api/report` 与 `/api/report/single` 均已接入（2026-08-08 核实）
- [x] 安全态势页（posture.html）接入后端 `/api/stats`：后端优先、localStorage 回退（2026-08-08 完成）；CWE 样本库确认为静态内容，无需后端 API
- [x] 前后端路径对齐重构：`SingleResult`/`BatchResult` 下沉到核心层 `graduation_project/result_types.py`（`scanner.py` 复用同一数据源）；`multi_model_scanner.py` 迁移到业务服务层 `app/backend/services/`（消除核心层对 app 层的反向依赖）；`scan.html` 粘贴模式接入两阶段扫描入口 `/api/analyze/two-stage`

---

## 🔄 当前待办

- [x] 前端静态页面统一收纳到 `app/backend/static/`（index/scan/cwe/posture 四页共享 `nivis-common.js`/`backend-badge.js`/`theme.js`；原 `vuln-scanner-ui/pages/` 独立目录不存在且已废弃，页面增强版均已同步回 `app/backend/static/`）
- [ ] 文档一致性：检查 `docs/方法.md`、`docs/过程.md` 中对工程化层的描述是否与当前实现一致（2026-08-08 已修正方法.md/规划.md/README/exp_06_report 的"SFT v5 当前最佳"漂移与 recall 口径，工程化层描述仍待核）
