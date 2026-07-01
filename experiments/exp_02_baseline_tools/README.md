# 实验 02：传统静态分析工具对比基线

## 一、实验目的

在第一阶段（exp_01）验证了 LLM 在典型漏洞上的检测能力后，本阶段用同一批样本跑传统规则型工具（Bandit / Semgrep），与 LLM 做横向对比，明确"为什么用 LLM 而不是传统工具"的核心论据。

## 二、对比维度

| 维度 | Bandit | Semgrep | LLM (deepseek-coder-v2:16b) |
| --- | --- | --- | --- |
| 检出率（TP） | 5/6（仅 Python） | 9/12 | 12/12 |
| 漏报率（FN） | 1/6 | 3/12 | 0 |
| 误报率（FP） | 1/2 | 0/2 | 2/2 |
| 总体准确率 | 75.0%（8 个 Python 样本） | 78.6% | 85.7% |
| 平均耗时 | ~0.04s | ~8.9s | ~9.63s |
| 漏洞类型分类 | 规则编号 | 规则编号 | 6 类全对 |
| 修复建议质量 | 规则文本 | 规则文本 | 自然语言 + 代码 |
| 多语言支持 | 仅 Python | 多语言 | 多语言 |

> 注：上表为当前主模型 deepseek 结果；详细 qwen 历史数据见 [exp_02_report.md](exp_02_report.md)。

## 三、样本集

复用 [exp_01_basic_scan/samples/](../exp_01_basic_scan/samples/) 的 14 段样本，保证对比公平。

## 四、任务清单

- [x] 安装 Bandit / Semgrep
- [x] 编写 `run_baseline.py`：批量跑 14 段样本，输出统一格式结果
- [x] 生成对比表 `exp_02_report.md`
- [x] 结论：LLM 相对传统工具的改进点

## 五、运行方式

```bash
cd experiments/exp_02_baseline_tools

# 需先安装工具：pip install bandit semgrep
python3 run_baseline.py                    # 跑全部样本（Bandit + Semgrep）
python3 run_baseline.py --tool bandit      # 单独跑 Bandit
python3 run_baseline.py --tool semgrep     # 单独跑 Semgrep
python3 run_baseline.py --limit 3          # 只跑前 3 个样本（调试）
```

结果按工具分组写入 `results/results.json`。
