# 实验 02 报告：传统静态分析工具对比基线

> **2026-06-30 最终更新**：默认主模型已最终切换为 `qwen2.5-coder:7b`。
> - 纯 LLM (qwen7b)：recall=100%、FPR=0%、accuracy=100%，平均 7.65s
> - RAG+LLM (qwen7b)：recall=100%、FPR=0%、accuracy=100%，平均 7.74s
> - qwen7b 在典型样本上**无需 RAG 即可达到 100% 准确率**，安全样本零误报。
>
> 历史数据：`../exp_01_basic_scan/results/results.qwen2.5-coder-7b.json`、

## 一、实验目的

在 exp_01 验证了 `qwen2.5-coder:7b` 在典型漏洞上的检测能力后，本阶段用同一批样本跑
传统规则型工具（Bandit / Semgrep），与 LLM 做横向对比，回答四个问题：

1. 传统工具在典型漏洞上的检出率、误报率如何？
2. 传统工具在多语言样本上的覆盖能力如何？
3. LLM 相对传统工具的改进点体现在哪里？
4. 速度 vs 质量的权衡如何？

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| Bandit | 1.9.4（pip 安装，conda graproj 环境） |
| Semgrep | 1.168.0（pip 安装，conda graproj 环境，规则集 `auto`） |
| LLM | `qwen2.5-coder:7b`（Ollama 本地推理，当前默认主模型） |
| 测试时间 | 2026-06-30（无答案泄露版本，qwen7b 最终验证） |
| 脚本 | [run_baseline.py](run_baseline.py) |
| Python | 3.11（miniconda graproj 环境） |

## 三、样本集

复用 [exp_01_basic_scan/samples/](../exp_01_basic_scan/samples/) 的 14 段样本，
保证对比公平：6 类典型漏洞 × 2 + 2 安全对照，覆盖 Python / PHP / JS / Java 四种语言。

| 语言 | 数量 | 漏洞 | 安全 |
| --- | --- | --- | --- |
| Python | 8 | 6 | 2 |
| PHP | 1 | 1 | 0 |
| JavaScript | 2 | 2 | 0 |
| Java | 3 | 3 | 0 |
| **合计** | **14** | **12** | **2** |

## 四、工具配置

| 工具 | 适用语言 | 调用方式 | 判定口径 |
| --- | --- | --- | --- |
| Bandit | 仅 Python | `bandit -f json -q <file>` | `results` 数组非空 → 有漏洞 |
| Semgrep | 多语言 | `semgrep --json --quiet --config auto <file>` | `results` 数组非空 → 有漏洞 |
| LLM（纯） | 多语言 | Ollama `/api/generate` | `has_vulnerability=true` → 有漏洞 |
| LLM（RAG） | 多语言 | Ollama + ChromaDB 知识库 | `has_vulnerability=true` → 有漏洞 |

> Bandit 不支持的文件后缀（.php/.js/.java）直接标记为 N/A，不计入有效样本。
> Semgrep 首次运行需从 registry 下载规则集，耗时较长；后续样本走本地缓存。

## 五、实验结果

### 5.1 逐样本判定

| 文件 | 语言 | 期望 | 纯 LLM (qwen) | RAG+LLM (qwen) | Bandit | Semgrep |
| --- | --- | --- | --- | --- | --- | --- |
| sql_injection_01.py | Python | True | True ✅ | True ✅ | True ✅ | True ✅ |
| sql_injection_02.py | Python | True | True ✅ | True ✅ | True ✅ | True ✅ |
| xss_01.php | PHP | True | True ✅ | True ✅ | N/A | False ❌(FN) |
| xss_02.js | JS | True | True ✅ | True ✅ | N/A | True ✅ |
| command_injection_01.py | Python | True | True ✅ | True ✅ | True ✅ | True ✅ |
| command_injection_02.js | JS | True | True ✅ | True ✅ | N/A | True ✅ |
| path_traversal_01.py | Python | True | True ✅ | True ✅ | False ❌(FN) | False ❌(FN) |
| path_traversal_02.java | Java | True | True ✅ | True ✅ | N/A | True ✅ |
| hardcoded_secret_01.py | Python | True | True ✅ | True ✅ | True ✅ | True ✅ |
| hardcoded_secret_02.java | Java | True | True ✅ | True ✅ | N/A | False ❌(FN) |
| insecure_deserialization_01.py | Python | True | True ✅ | True ✅ | True ✅ | True ✅ |
| insecure_deserialization_02.java | Java | True | True ✅ | True ✅ | N/A | True ✅ |
| safe_01_parameterized_query.py | Python | False | False ✅ | False ✅ | False ✅ | False ✅ |
| safe_02_subprocess_list.py | Python | False | False ✅ | False ✅ | True ❌(FP) | False ✅ |

> **关键差异**：qwen7b 纯 LLM 已能正确识别 `safe_02_subprocess_list.py` 为安全代码（列表参数 + 输入校验），
> 无需 RAG 纠正即可达到 100% 准确率。RAG 在此典型样本集上主要提供可解释性增强而非误报纠正
> （误报纠正价值在 qwen14b 上更显著，qwen7b 的基线能力已消除该误报）。
> Bandit 对 safe_02 产生 3 条误报（B602/B603/B404），是传统工具规则泛化能力不足的典型案例。

### 5.2 汇总指标

| 指标 | 纯 LLM (qwen) | RAG+LLM (qwen) | Bandit | Semgrep |
| --- | --- | --- | --- | --- |
| 有效样本数 | 14 | 14 | 8（仅 Python） | 14 |
| 不支持样本数 | 0 | 0 | 6 | 0 |
| 真阳性 TP | 12 | 12 | 5 | 9 |
| 真阴性 TN | 2 | 2 | 1 | 2 |
| 假阳性 FP（误报） | 0 | 0 | 1 | 0 |
| 假阴性 FN（漏报） | 0 | 0 | 1 | 3 |
| **召回率** | **100.0%** (12/12) | **100.0%** (12/12) | 83.3% (5/6) | 75.0% (9/12) |
| **误报率** | **0.0%** (0/2) | **0.0%** (0/2) | 50.0% (1/2) | 0.0% (0/2) |
| **总体准确率** | **100.0%** (14/14) | **100.0%** (14/14) | 75.0% (6/8) | 78.6% (11/14) |
| 平均单样本耗时 | 7.65s | 7.74s | 0.04s | 8.9s |
| 总耗时 | 107.1s | 108.4s | 0.54s | 124.61s |
| 修复建议 | 自然语言 + 代码 | 自然语言 + 代码 | 规则编号 + 文本 | 规则编号 + 文本 |

## 六、关键发现

### 6.1 LLM 唯一检出：path_traversal_01.py（语义理解优势）

```python
# 样本核心：用户输入拼接到路径，无过滤
filename = request.args.get('file', '')
full_path = "/app/data/" + filename
with open(full_path, 'r') as f:
    ...
```

- **Bandit 漏报**：Bandit 没有针对路径穿越的内置规则（B108 只检查可疑的临时文件路径），
  对"字符串拼接文件路径"这种语义级风险无感知。
- **Semgrep 漏报**：`auto` 规则集虽含路径穿越规则，但匹配条件偏严（要求明显的 `../` 字面量
  或特定 API），对"拼接 + open()"的写法未触发。
- **LLM 检出**：理解"用户输入 + 字符串拼接 + open()"的污点流，判定为路径穿越。

**论文论据**：这是"语义理解 vs 模式匹配"最直接的案例——两个传统工具都漏，只有 LLM 检出。

### 6.2 安全样本对比：safe_02_subprocess_list.py（RAG 的价值）

```python
# 样本核心：subprocess 用列表形式传参（安全），且对输入做了校验
cmd = validate_input(user_input)
subprocess.run(['ls', '-l', cmd], check=True)  # 列表形式，无 shell=True
```

| 工具 | 判定 | 说明 |
| --- | --- | --- |
| Bandit | True ❌(FP) | B602/B603/B404 看到 subprocess 就报警，不理解列表形式安全 |
| Semgrep | False ✅ | 正确 |
| 纯 LLM (qwen7b) | False ✅ | 正确识别列表参数 + 输入校验是安全写法 |
| RAG+LLM (qwen7b) | False ✅ | 同上，RAG 在此典型样本上未改变判定 |

**论文论据**：
- 传统工具基于规则触发，容易对"看起来危险但实际安全"的代码误报；
- qwen7b 纯 LLM 已能正确识别安全写法，基线能力优于 qwen14b（qwen14b 在此样本上误报）；
- RAG 在典型样本上对 qwen7b 主要提供可解释性增强（知识可追溯），误报纠正价值在难样本上更显著（见 exp_04）。

### 6.3 Semgrep 漏报 3 个（规则覆盖盲区）

| 漏报样本 | 漏洞类型 | 可能原因 |
| --- | --- | --- |
| xss_01.php | 反射型 XSS | `auto` 规则集对 PHP `echo` 未转义的检测偏弱 |
| path_traversal_01.py | 路径穿越 | 同 6.1，规则匹配条件过严 |
| hardcoded_secret_02.java | 硬编码密码 | Java 样本中的 `password` 字段未匹配到密钥规则 |

**论文论据**：即使是多语言工具 Semgrep，在 `auto` 默认规则集下仍有 3/12 漏报，
  说明"规则集覆盖度"是传统工具的固有瓶颈；LLM 不依赖规则集，泛化能力更强。

### 6.4 多语言支持差异

| 工具 | Python | PHP | JS | Java |
| --- | --- | --- | --- | --- |
| Bandit | ✅ | ❌ | ❌ | ❌ |
| Semgrep | ✅ | ✅ | ✅ | ✅ |
| LLM | ✅ | ✅ | ✅ | ✅ |

Bandit 6 个非 Python 样本全部 N/A，有效样本仅 8 个，统计基数小。
LLM 与 Semgrep 都支持全语言，但 LLM 召回率更高。

### 6.5 速度 vs 质量的权衡

| 维度 | Bandit | Semgrep | 纯 LLM (qwen) | RAG+LLM (qwen) |
| --- | --- | --- | --- | --- |
| 单样本耗时 | 0.04s | 8.9s | 7.65s | 7.74s |
| 相对 Bandit 倍数 | 基准 | 223× 慢 | 191× 慢 | 194× 慢 |
| 召回率 | 83.3% | 75.0% | **100%** | **100%** |
| 误报率 | 50.0% | 0.0% | **0.0%** | **0.0%** |
| 修复建议 | ❌ | ❌ | ✅ | ✅ |
| 多语言统一 | ❌ | ✅ | ✅ | ✅ |

**核心论点**：RAG+LLM 比 Bandit 慢约 194 倍，但：
1. 召回率从 75%–83% 提升到 100%，漏报率降为 0；
2. 误报率从 50%（Bandit）降到 0%（LLM/RAG+LLM）；
3. 把人工审计时间从"逐条核对告警"降到"阅读一段自然语言解释"；
4. 直接输出可执行的修复代码，传统工具只给规则编号；
5. qwen7b 速度（7.65s）已接近 Semgrep（8.9s），且 qwen7b 支持全语言而 Bandit 仅支持 Python。

## 七、结论与论文论据

### 结论

1. **LLM/RAG+LLM 在召回率、误报率、准确率上均优于传统工具**：召回率 100% vs 83.3%（Bandit）/ 75.0%（Semgrep），
   误报率 0% vs 50%（Bandit）/ 0%（Semgrep），准确率 100% vs 75.0% / 78.6%。
2. **qwen7b 纯 LLM 已达到 100% 准确率，无需 RAG 纠正典型样本误报**：qwen7b 在 `safe_02_subprocess_list.py` 上正确识别安全写法，
   基线能力显著优于 qwen14b（准确率 92.9%）和 deepseek 16B（准确率 85.7%）。
3. **传统工具的误报/漏报源于"模式匹配"本质**：Bandit 误报 subprocess 列表形式、
   Semgrep 漏报 PHP echo XSS，都是规则无法理解语义的体现。
4. **多语言场景下 Bandit 失效**：6/14 样本不支持，统计基数缩水近半。
5. **速度差距大幅缩小**：qwen7b 平均 7.65s/样本，已接近 Semgrep（8.9s），远快于 qwen14b（17.11s）和 gemma4:12b（45s）；
   考虑"检出 + 解释 + 修复"的端到端价值，整体效率更可接受。

### 论文论据映射

| 论文论点 | 实验证据 |
| --- | --- |
| LLM 语义理解优于模式匹配 | path_traversal_01.py 唯一检出 |
| qwen7b 基线能力优于 qwen14b/deepseek | qwen7b 纯 LLM 100% 准确率，safe_02 零误报 |
| 传统工具误报增加人工成本 | safe_02_subprocess_list.py Bandit 误报 3 条 |
| 传统工具规则覆盖有盲区 | Semgrep 漏报 3 个（XSS/路径/硬编码） |
| LLM 多语言统一 | Bandit 6 样本不支持，LLM/Semgrep 全支持 |
| LLM 端到端价值 | LLM 输出修复代码，传统工具仅规则编号 |

## 八、复现方式

```bash
# 使用 conda graproj 环境（已装 bandit + semgrep）
cd experiments/exp_02_baseline_tools
~/miniconda3/envs/graproj/bin/python run_baseline.py                    # 跑全部工具 + 全部样本
~/miniconda3/envs/graproj/bin/python run_baseline.py --tool bandit      # 只跑 Bandit
~/miniconda3/envs/graproj/bin/python run_baseline.py --tool semgrep     # 只跑 Semgrep
~/miniconda3/envs/graproj/bin/python run_baseline.py --limit 3          # 只跑前 3 个（调试）
```

LLM 对比数据来自：
```bash
cd ../exp_01_basic_scan && python3 run_experiment.py                      # 纯 LLM（默认 qwen7b）
cd ../exp_03_rag_knowledge && python3 run_rag_experiment.py               # RAG+LLM（默认 qwen7b）
```

结果写入 [results/results.json](results/results.json)，每跑完一个样本即增量落盘。

## 九、P2-6 Bandit 告警级别过滤（2026-07-06）

> **背景**：5.1 表中 Bandit 对 `safe_02_subprocess_list.py` 误报 3 条（B404/B607/B603），均源于 `subprocess` 模块的使用——
> B404 是 `import subprocess` 的信息性告警（severity=LOW），B607/B603 是部分路径/未校验输入的潜在告警（severity=LOW）。
> 这些 LOW severity 告警对"是否真有漏洞"的判别力很弱，计入漏洞会显著抬高误报率，对传统工具有失公平。
>
> **修复**：`run_baseline.py` 加 `--bandit-min-severity` / `--bandit-min-confidence` 参数，按 severity/confidence 过滤告警。
> 本节对比两种口径：宽松（LOW+MEDIUM，保留所有告警）与严格（MEDIUM+MEDIUM，过滤 LOW severity 告警）。

### 9.1 两种口径逐样本对比

| 文件 | 期望 | 宽松(LOW+MED) | 严格(MED+MED) | 宽松规则 | 严格规则 |
| --- | --- | --- | --- | --- | --- |
| sql_injection_01.py | True | False ❌(FN) | False ❌(FN) | — | — |
| sql_injection_02.py | True | True ✅ | True ✅ | B608 | B608 |
| command_injection_01.py | True | True ✅ | True ✅ | B404,B602 | B602 |
| path_traversal_01.py | True | False ❌(FN) | False ❌(FN) | — | — |
| hardcoded_secret_01.py | True | True ✅ | **False ❌(FN)** | B105 | — |
| insecure_deserialization_01.py | True | True ✅ | True ✅ | B403,B301 | B301 |
| safe_01_parameterized_query.py | False | False ✅ | False ✅ | — | — |
| safe_02_subprocess_list.py | False | **True ❌(FP)** | False ✅ | B404,B607,B603 | — |

### 9.2 两种口径汇总指标

| 口径 | TP | TN | FP | FN | 召回率 | 误报率 | 准确率 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 宽松 LOW+MEDIUM | 4 | 1 | 1 | 2 | 66.7% (4/6) | 50.0% (1/2) | 62.5% (5/8) |
| 严格 MEDIUM+MEDIUM | 3 | 2 | **0** | 3 | 50.0% (3/6) | **0.0%** (0/2) | 62.5% (5/8) |
| LLM (qwen7b) | 12 | 2 | 0 | 0 | **100%** | **0%** | **100%** |

### 9.3 关键发现

1. **严格口径消除了 safe_02 误报**：B404/B607/B603 全是 LOW severity，用 MEDIUM+MEDIUM 过滤后 safe_02 判 False（✅）。
   但代价是 `hardcoded_secret_01.py` 的 B105（hardcoded_password_string，LOW severity）也被过滤，导致真漏洞漏报（FN）。
2. **传统工具面临 recall/fpr 权衡**：严格口径 fpr 50%→0%，但 recall 66.7%→50.0%；宽松口径反之。
   无论哪种口径，准确率都卡在 62.5%（样本量小，TP→FN 与 FP→TN 互相抵消）。
3. **LLM 不存在此权衡**：qwen7b 同时达到 recall=100% 和 fpr=0%，无需在漏报与误报间取舍。
   这是 LLM 语义理解相对于规则匹配的核心优势——**不依赖 severity 阈值调参**。
4. **B105 漏报的启示**：B105（硬编码密码字符串）是 LOW severity 但高价值规则，过滤掉会导致真漏洞漏检。
   说明 Bandit 的 severity 标注本身并不完全可靠——真漏洞可能被标 LOW，信息性告警也可能标 LOW，
   严格口径无法区分两者。LLM 通过语义理解可以区分"真硬编码密码"与"subprocess import"。

### 9.4 论文论据增强

| 论点 | 旧论据（无过滤） | 新论据（P2-6 后） |
| --- | --- | --- |
| 传统工具误报增加人工成本 | safe_02 Bandit 误报 3 条 | 严格口径可消除误报但引入漏报，**传统工具面临 recall/fpr 权衡** |
| LLM 语义理解优于模式匹配 | path_traversal_01 唯一检出 | LLM 无需 severity 调参即可同时达到 100% recall + 0% fpr |
| 规则 severity 标注不可靠 | — | B105（真漏洞）与 B404（信息性）同为 LOW severity，规则无法区分 |

### 9.5 复现方式

```bash
# 宽松口径（LOW+MEDIUM，默认）
python run_baseline.py --tool bandit --bandit-min-severity LOW --bandit-min-confidence MEDIUM

# 严格口径（MEDIUM+MEDIUM）
python run_baseline.py --tool bandit --bandit-min-severity MEDIUM --bandit-min-confidence MEDIUM
```

结果文件：
- [results.bandit-loose.low-med.json](results/results.bandit-loose.low-med.json)：宽松口径
- [results.bandit-strict.med-med.json](results/results.bandit-strict.med-med.json)：严格口径
- [results.json](results/results.json)：历史完整结果（含 Semgrep + 旧版 Bandit，2026-06-29 跑）
