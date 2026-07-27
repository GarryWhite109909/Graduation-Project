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
