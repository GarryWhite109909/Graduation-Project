# 实验 02：传统静态分析工具对比基线

## 一、实验目的

在第一阶段（exp_01）验证了 Gemma 4 26B 在典型漏洞上的检测能力后，本阶段用同一批样本跑传统规则型工具（Bandit / Semgrep / Gitleaks），与 LLM 做横向对比，明确"为什么用 LLM 而不是传统工具"的核心论据。

## 二、对比维度

| 维度 | Bandit | Semgrep | Gitleaks | LLM (Gemma 4 26B) |
| --- | --- | --- | --- | --- |
| 检出率（TP） | - | - | - | 12/12 (exp_01) |
| 漏报率（FN） | - | - | - | 0 |
| 误报率（FP） | - | - | - | 0 |
| 平均耗时 | - | - | - | 56.7s |
| 漏洞类型分类 | - | - | - | 6 类全对 |
| 修复建议质量 | - | - | - | 自然语言 + 代码 |
| 多语言支持 | 仅 Python | 多语言 | 通用 | 多语言 |

## 三、样本集

复用 [exp_01_basic_scan/samples/](../exp_01_basic_scan/samples/) 的 14 段样本，保证对比公平。

## 四、任务清单

- [ ] 安装 Bandit / Semgrep / Gitleaks
- [ ] 编写 `run_baseline.py`：批量跑 14 段样本，输出统一格式结果
- [ ] 补充 3-5 段"难样本"（绕过式过滤、跨文件污点、真实 CVE 片段）
- [ ] 生成对比表 `exp_02_report.md`
- [ ] 结论：LLM 相对传统工具的改进点

## 五、运行方式（待实现）

```bash
cd experiments/exp_02_baseline_tools
python3 run_baseline.py                    # 跑全部样本
python3 run_baseline.py --tool bandit      # 单独跑 Bandit
python3 run_baseline.py --tool semgrep     # 单独跑 Semgrep
```
