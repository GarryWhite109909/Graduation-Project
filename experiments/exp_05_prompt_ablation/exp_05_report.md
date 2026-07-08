# 实验 05 报告：Prompt 工程消融对比

> 在 `qwen2.5-coder:7b` 上系统对比 5 种 Prompt 策略对漏洞检测召回与误报的影响。
> 复用 exp_04 的 87 段样本集（含典型漏洞/安全对照/难样本/噪音），保证横向对比公平。

## 一、实验目的

回答以下问题：

1. **白名单的独立价值**：去掉 SYSTEM_PROMPT 中的多条要求与硬编码凭证规则，仅保留安全模式白名单，对召回与误报有何影响？
2. **Few-shot 是否带来增益**：在零样本基础上加入 3 组示例（漏洞/安全/漏洞），是否能进一步提升准确率？是否存在答案泄露风险？
3. **CoT 是否提升难样本召回**：显式要求模型按 5 步思维链分析，对绕过式过滤、跨文件污点、长文件隐藏漏洞等难样本是否有帮助？
4. **组合策略是否优于单一策略**：白名单 + Few-shot + CoT 三合一是否是最佳组合？
5. **Prompt 长度 vs 性能权衡**：组合策略 prompt 长达 4641 字符，是否带来推理延迟与性能的合理回报？

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| 模型 | `qwen2.5-coder:7b`（Ollama 本地推理，AMD RX 9060 XT 16GB GPU 全 offload） |
| 采样温度 | 0.1（低温度确保结果可复现） |
| 上下文窗口 | num_ctx=16384 |
| 测试时间 | 2026-07-06 |
| 脚本 | [run_ablation.py](run_ablation.py) |
| Python | 3.11（miniconda graproj 环境） |
| 样本集 | 复用 [exp_04_hard_samples/samples/](../exp_04_hard_samples/samples/)，87 段（typical 36 + safe 18 + hard 27 + noise 6） |

## 三、Prompt 变体设计

| 变体 | system prompt 长度 | 包含内容 |
| --- | --- | --- |
| `zero_shot` | 2966 字符 | 角色 + 分析范围 + 多条要求（6 条） + 安全模式白名单 + 硬编码凭证规则 + schema |
| `whitelist_only` | 2019 字符 | 角色 + 分析范围 + 安全模式白名单 + schema（去掉 6 条要求与硬编码规则） |
| `few_shot` | 4259 字符 | zero_shot + 3 组示例（SQL 注入漏洞 / 参数化查询安全 / 命令注入漏洞） |
| `cot` | 3348 字符 | zero_shot + 5 步思维链要求（识别 source → 追踪 sink → 检查防御 → 评估有效性 → 综合结论） |
| `combined` | 4641 字符 | zero_shot + CoT + Few-shot 三合一 |

### Few-shot 示例设计原则

- 3 组示例覆盖：SQL 注入漏洞（CWE-89） → 参数化查询安全 → 命令注入漏洞（CWE-78）
- 示例代码刻意与 manifest 样本不同（用 `def auth(user, pwd)` 而非 `def get_user(username)`），避免答案泄露
- 示例同时展示分析过程与 JSON 结论，让模型学习输出格式

### CoT 步骤设计

```
1. 识别代码中所有用户可控输入点（source）
2. 追踪数据流，判断是否到达危险函数（sink）
3. 检查 source 到 sink 之间是否存在防御措施
4. 若有防御措施，评估其是否有效
5. 综合分析得出最终结论
```

## 四、实验结果

### 4.1 总体指标对比（87 样本）

| 变体 | TP | TN | FP | FN | 召回率 | 误报率 | 准确率 | 平均耗时 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| zero_shot | 52 | 22 | 5 | 8 | 86.7% | 18.5% | 85.1% | 7.25s |
| whitelist_only | 44 | 23 | 4 | 16 | **73.3%** | **14.8%** | 77.0% | 6.67s |
| few_shot | 56 | 19 | 8 | 4 | 93.3% | 29.6% | 86.2% | 7.20s |
| **cot** | **57** | **21** | 6 | **3** | **95.0%** | 22.2% | **89.7%** | 8.61s |
| combined | 55 | 21 | 6 | 5 | 91.7% | 22.2% | 87.4% | 7.77s |

> 95% Wilson 置信区间（recall / fpr / acc）：
> - zero_shot: [75.8%, 93.1%] / [8.2%, 36.7%] / [76.1%, 91.1%]
> - whitelist_only: [61.0%, 82.9%] / [5.9%, 32.5%] / [67.1%, 84.6%]
> - few_shot: [84.1%, 97.4%] / [15.8%, 48.5%] / [77.4%, 91.9%]
> - **cot**: [86.3%, 98.3%] / [10.6%, 40.8%] / [81.5%, 94.5%]
> - combined: [81.9%, 96.4%] / [10.6%, 40.8%] / [78.8%, 92.8%]

### 4.2 按样本类别细分

#### typical 类（36 个全漏洞样本）

| 变体 | TP | FN | 召回率 |
| --- | --- | --- | --- |
| zero_shot | 32 | 4 | 88.9% |
| whitelist_only | 26 | 10 | 72.2%（-16.7pp） |
| few_shot / cot / combined | 34 | 2 | 94.4%（+5.5pp） |

#### hard 类（27 个：24 漏洞 + 3 安全）

| 变体 | TP | TN | FP | FN | 召回率 | 误报率 | 准确率 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| zero_shot | 20 | 1 | 2 | 4 | 83.3% | 66.7% | 77.8% |
| whitelist_only | 18 | 3 | 0 | 6 | 75.0% | **0.0%** | 77.8% |
| few_shot | 22 | 0 | 3 | 2 | 91.7% | **100.0%** | 81.5% |
| **cot** | **23** | 2 | 1 | 1 | **95.8%** | 33.3% | **92.6%** |
| combined | 21 | 1 | 2 | 3 | 87.5% | 66.7% | 81.5% |

#### safe 类（18 个全安全样本）

| 变体 | TN | FP | 误报率 |
| --- | --- | --- | --- |
| zero_shot | 16 | 2 | 11.1% |
| whitelist_only | 17 | 1 | **5.6%**（最低） |
| few_shot / combined | 16 | 2 | 11.1% |
| cot | 14 | 4 | **22.2%**（最高） |

#### noise 类（6 个全安全样本，混淆噪音）

| 变体 | TN | FP | 误报率 |
| --- | --- | --- | --- |
| zero_shot / cot | 5 | 1 | 16.7% |
| whitelist_only / few_shot | 3 | 3 | 50.0% |
| combined | 4 | 2 | 33.3% |

### 4.3 难样本漏报详情

| 样本 | zero_shot | whitelist_only | few_shot | cot | combined |
| --- | --- | --- | --- | --- | --- |
| hard_bypass_04_path_regex.py | FN | FN | ✓ | FN | FN |
| hard_cve_02_python_log_injection.py | FN | FN | FN | ✓ | ✓ |
| hard_cve_03_tarfile_2025_4517.py | ✓ | FN | FN | ✓ | ✓ |
| hard_cve_05_spring4shell.java | FN | FN | ✓ | ✓ | ✓ |
| hard_longfile_01_hidden_sql.py | ✓ | FN | ✓ | ✓ | ✓ |
| hard_longfile_02_hidden_cmd.py | ✓ | ✓ | ✓ | ✓ | FN |
| hard_longfile_03_hidden_ssti.py | ✓ | ✓ | ✓ | ✓ | FN |
| hard_crossfile_02_sink.py | FN | ✓ | ✓ | ✓ | ✓ |
| hard_crossfile_03_sink.py | ✓ | FN | ✓ | ✓ | ✓ |

> 跨文件 input 误报（hard_crossfile_*_input.py 期望 False 但被判 True）：
> - zero_shot: crossfile_01/03_input 误报
> - few_shot: crossfile_01/02/03_input 全误报
> - combined: crossfile_01/02_input 误报
> - whitelist_only / cot: 无 input 误报

## 五、关键发现

### 5.1 CoT 是最优单一策略

`cot` 变体在总体准确率（89.7%）和召回率（95.0%）上均居首位，且在难样本上召回 95.8%（最高）同时误报仅 33.3%（远优于 few_shot 的 100%）。

- **召回提升机制**：CoT 的 5 步分析（source → sink → 防御 → 有效性 → 结论）显式引导模型进行污点分析，避免"看一眼就下结论"。
- **耗时代价**：平均 8.61s（vs zero_shot 7.25s，+19%），但准确率提升 4.6pp，性价比高。
- **唯一短板**：在 safe 类样本上误报 22.2%（最高），CoT 让模型对简单安全样本"想太多"，过度分析导致误判。

### 5.2 Few-shot 是双刃剑

`few_shot` 召回 93.3%（+6.6pp）但误报 29.6%（+11.1pp），准确率 86.2% 与 zero_shot 85.1% 接近。

- **召回提升**：示例让模型学会"看到拼接 SQL / os.system 就判 True"。
- **误报暴涨**：模型变得激进，在 hard 类样本上 fpr 暴涨到 100%（crossfile_input 全误报）。Few-shot 示例让模型形成"看到用户输入就判漏洞"的偏见，忽略 sink 文件的实际防御。
- **结论**：Few-shot 在本任务上"提召回但增误报"，净收益不明显。示例代码的"漏洞模式"会让模型过度泛化。

### 5.3 白名单是"压误报但损召回"的策略

`whitelist_only` 误报 14.8%（最低，比 zero_shot 还低 3.7pp）但召回 73.3%（-13.4pp，灾难性下降）。

- **白名单的独立价值**：白名单本身确实能压低误报（safe 类 fpr 仅 5.6%，最低）。
- **白名单的代价**：光有白名单不够，zero_shot 中的"6 条要求"（特别是"不要遗漏明显漏洞"）对召回至关重要。去掉这些要求，模型对典型漏洞的召回从 88.9% 降到 72.2%。
- **重要论据**：这反驳了"白名单是作弊到直接给答案"的质疑——白名单只是 prompt 工程的一部分，光有白名单反而会让模型对真漏洞"过于宽容"。

### 5.4 组合策略不是最优（反直觉）

`combined` 准确率 87.4% < `cot` 89.7%。组合策略反而比单一 CoT 差 2.3pp。

- **可能原因 1**：prompt 过长（4641 字符）导致注意力分散，CoT 步骤与 few-shot 示例存在注意力竞争。
- **可能原因 2**：few-shot 示例的"激进判 True"偏见抵消了 CoT 的"仔细分析"优势。
- **结论**："prompt 越长越好"是误区。在 7b 模型上，单一 CoT 策略反而更聚焦。

### 5.5 跨文件污点是 prompt 工程的盲区

`hard_crossfile_*_input.py`（包含用户输入处理，期望 False）在多数变体上都被误报：

| 变体 | input 误报数 |
| --- | --- |
| zero_shot | 2/3 |
| whitelist_only | 0/3 |
| few_shot | 3/3 |
| cot | 0/3 |
| combined | 2/3 |

- **根因**：input 文件包含 `request.args.get` 等用户输入处理代码，模型看到"用户输入"就判漏洞，忽略 sink 文件的实际防御。
- **prompt 工程无法解决**：即使 CoT 也只是"看清楚 input 文件确实有用户输入"，但无法理解"input 文件本身不是 sink，应该看 sink 文件的防御"。
- **解决方向**：需要 RAG 上下文增强（检索跨文件污点流知识）或代码图谱（明确 input→sink 数据流），单纯 prompt 优化无法解决。

### 5.6 难样本漏报分布

- `hard_bypass_04_path_regex.py`（路径正则绕过）：4/5 变体漏报，是最难样本。
- `hard_cve_02_python_log_injection.py`（日志注入）：3/5 变体漏报。
- `hard_cve_05_spring4shell.java`（Java Spring）：2/5 变体漏报（Java 框架特定漏洞）。
- `hard_longfile_03_hidden_ssti.py`（SSTI）：仅 combined 漏报（CoT 单独能检出，组合反而漏）。

## 六、白名单的边界与局限（重要讨论）

### 6.1 白名单是工程手段，不是模型能力证明

| 方式 | 作弊程度 | 本质 |
| --- | --- | --- |
| 纯 LLM | 0 | 靠预训练知识 |
| RAG | 中 | 检索 + 模型判断相关性（开卷考试） |
| Prompt 白名单 | 中高 | 注入领域专家知识（考前划重点） |
| 后处理 override | 极高 | 直接改答案（已是规则引擎） |

白名单不是"直接给答案规则"。它给的是**抽象判定准则**（如"参数化查询是安全的"），模型仍需：

1. 识别代码里是否有参数化查询（语义理解）
2. 判断是否使用得当（如 LIKE `%{keyword}%` 变体）
3. 综合判断是否有其他漏洞

### 6.2 本实验的反证

`whitelist_only` 召回 73.3%（vs zero_shot 86.7%）证明：光有白名单反而让模型对真漏洞"过于宽容"。白名单必须配合"不要遗漏明显漏洞"等召回引导要求才能达到 zero_shot 的 86.7%。

→ 这反驳了"白名单是作弊到直接给答案"的质疑。白名单是 prompt 工程的一部分，不是答案注入。

### 6.3 与微调的对比展望

本实验的目的是评估 **prompt 工程的上限**，为后续 LoRA/QLoRA 微调提供 baseline：

- **prompt 注入知识**：白名单 + CoT 等策略，召回上限 95.0%（cot），难样本仍有 1 个漏报。
- **微调注入知识**：让模型本身学会安全模式识别，理论上可突破 prompt 工程天花板。
- **后续对照**：微调后可再做一次消融，对比"prompt 注入 vs 微调注入"两种知识注入方式的有效性差异。

## 七、结论与论文论据

### 结论

1. **CoT 是 prompt 工程的最优单一策略**：召回 95.0%、准确率 89.7%，优于组合策略。显式思维链步骤能有效引导模型进行污点分析，对难样本（绕过过滤、CVE）尤其有效。
2. **白名单是"压误报但损召回"的策略**：whitelist_only 误报最低（14.8%）但召回也最低（73.3%）。白名单本身不是"作弊到直接给答案"，它只是 prompt 工程的一部分，光有白名单不够。
3. **组合策略不是最优**：combined 准确率 87.4% < cot 89.7%。prompt 长度与性能不成正比，"越多越好"是误区。
4. **prompt 工程有天花板**：即使最优 CoT 召回仍为 95.0%（非 100%），难样本（hard_bypass_04_path_regex）4/5 变体漏报。论证了后续微调的必要性。
5. **跨文件污点是 prompt 工程盲区**：crossfile_input 在多数变体上误报，需 RAG 或代码图谱解决。

### 论文论据映射

| 论点 | 实验证据 |
| --- | --- |
| CoT 是 prompt 工程最优策略 | cot 召回 95.0% / 准确率 89.7%，优于 combined 87.4% |
| prompt 长度 ≠ 性能 | combined（4641 字符）准确率 < cot（3348 字符） |
| 白名单非"作弊" | whitelist_only 召回 73.3%（光有白名单反而损召回） |
| Few-shot 双刃剑 | few_shot 召回 +6.6pp 但误报 +11.1pp，净收益不明显 |
| prompt 工程有天花板 | cot 仍有 1 个难样本漏报，需微调突破 |
| 跨文件污点需 RAG | crossfile_input 在多数变体上误报，prompt 优化无法解决 |

## 八、复现方式

```bash
# 使用 conda graproj 环境
cd experiments/exp_05_prompt_ablation

# 跑全部 5 变体 × 87 样本 × 1 次（默认，约 60 分钟）
~/miniconda3/envs/graproj/bin/python run_ablation.py

# 只跑指定变体
~/miniconda3/envs/graproj/bin/python run_ablation.py --variants zero_shot,cot

# 每变体每样本重复 3 次（多数表决 + 95% 置信区间）
~/miniconda3/envs/graproj/bin/python run_ablation.py --repeat 3

# 断点续跑（按 (variant,file) 联合 key 跳过已完成组合）
~/miniconda3/envs/graproj/bin/python run_ablation.py --resume

# 只跑安全样本（快速验证误报率）
~/miniconda3/envs/graproj/bin/python run_ablation.py --filter safe
```

结果文件：[results/exp_05_prompt_ablation.qwen2.5-coder-7b.ablation.repeat1.20260706_042632.json](results/exp_05_prompt_ablation.qwen2.5-coder-7b.ablation.repeat1.20260706_042632.json)，包含 435 条样本记录（5 变体 × 87 样本）和 `metrics_by_variant` 汇总指标。
