# 基于大语言模型的代码安全分析系统

> 本地部署的开源大语言模型驱动的代码漏洞检测系统，对比传统基于规则的静态分析工具，验证 LLM 在代码安全审计中的语义理解优势。exp_01~05 以 `qwen2.5-coder:7b` 为推理基座做多模型对比与 prompt 消融；exp_06 起切换至训练主线，以 Qwen2.5-Coder-7B-Base + KnItLM CPT（LoRA r=64）为 student、Qwen3-Coder:30b 为 Phase 4 Prompt Distillation teacher。

***

## 一、项目简介

利用本地部署的开源大语言模型对源代码进行安全审计，目标是构建一个相比传统静态分析工具（Bandit / Semgrep / CodeQL）具备以下优势的系统：

| 维度   | 传统工具（Bandit/Semgrep） | 本系统（LLM 驱动）          |
| ---- | -------------------- | -------------------- |
| 检测方式 | 固定规则模式匹配             | 代码语义理解、上下文感知         |
| 漏洞覆盖 | 已知漏洞模式               | 可发现变体/非典型漏洞          |
| 输出形式 | 漏洞类型 + 规则编号          | 自然语言解释 + 修复建议 + 修复代码 |
| 多语言  | 工具专属规则集              | 跨语言统一理解              |
| 误报控制 | 规则泛化能力差              | 上下文判断过滤/净化逻辑         |

**核心卖点**：传统工具是"模式匹配"，本系统是"语义理解"。

**摘要**：

- **已完成**：在本地 7B 开源模型上验证了零样本代码漏洞检测的可行性；RAG 知识库与 Prompt 工程能提升判定质量，但很快遇到能力天花板。
- **关键突破**：通过 **KnItLM 继续预训练** 将网络安全领域知识注入 7B 模型，严格召回率（recall）提升 23 个百分点、误报率（FPR）下降 7.7 个百分点，证明“知识注入”优于单纯增大 LoRA 容量。
- **进行中**：以 qwen3-coder:30b 为 teacher、KnItLM 为 student 进行 **Prompt Distillation**，修复 CPT 引入的过度泛化副作用。
- **待完成**：DPO 边界校准评估、错题增强闭环、前后端工程化。

***

## 二、实验环境

| 项目 | 配置 |
| --- | --- |
| CPU | AMD Ryzen 5 9600X × 12 |
| 内存 | 32 GB |
| 显卡 | AMD Radeon RX 9060 XT 16 GB |
| 操作系统 | Ubuntu 26.04 LTS（内核 7.0.0-15-generic） |
| 桌面环境 | GNOME 50 / Wayland |
| GPU 驱动 / 计算栈 | ROCm 7.2.4 + PyTorch 2.11.0+rocm7.2 |
| Python 环境 | miniconda `graproj`（Python 3.11） |
| 本地 LLM 服务 | Ollama |

### 模型清单

| 角色 | 模型 | 阶段 |
| --- | --- | --- |
| 推理基座 | `qwen2.5-coder:7b` | exp_01 ~ exp_05 |
| 训练 student | Qwen2.5-Coder-7B-Base → KnItLM CPT (r=64) → merge 到 Instruct | exp_06 Phase 1-3 |
| PD teacher | `qwen3-coder:30b`（MoE，Ollama 后端提供 logits） | exp_06 Phase 4 |
| 对照模型 | `deepseek-coder-v2:16b` / `qwen2.5-coder:14b` / `gemma4:12b` / `gemma4:26b` / `gpt-oss:20b` | exp_04 多模型对比 |

> 完整环境清单（Embedding 模型、向量库版本、传统工具版本等）见 [规划.md](规划.md) §二；训练与推理全链路技术栈见 §六。
>
> 注：模型权重不入库（见 `.gitignore`）。推理基座需 `ollama pull qwen2.5-coder:7b`；训练基座从 HuggingFace 拉取。以上为台式机实验环境，笔记本仅用于代码编辑与文档审查。

***

## 三、项目结构

> 提示：大模型权重（`*.safetensors`/`*.gguf`）、`__pycache__/`、`*.log`、`outputs/`（除 `best/` 与 README 外的中间 checkpoint）以及 `data/chroma_db/` 均已通过 `.gitignore` 排除，详见各目录下的 README 与下方注释。

```
Graduation-Project/
├── README.md                              # 本文档
├── .gitignore                             # 排除大模型/缓存/日志/中间 checkpoint
├── pyproject.toml                         # 项目元数据 + 依赖声明（支持 pip install -e .）
├── requirements.txt                       # 锁版本依赖清单
├── TODO.md                                # 代码审查问题清单（处理进度跟踪）
├── 规划.md                                 # 项目阶段规划与进度（唯一进度源）
├── docs/                                  # 设计文档与改进建议
│   ├── _archive/                          #   历史建议归档
│   │   ├── glm的建议_20260628.md          #     GLM 给出的改进路线建议
│   │   ├── kimi的建议_20260628.md         #     Kimi 给出的智能体分工建议
│   │   ├── 临时提示词_下一步计划_20260706.md #   exp_01~03 时代八大修复建议（已归档）
│   │   └── wenti_20260719.md              #   r16_e5 时代问题分析笔记（历史快照）
│   ├── 方法.md                            #   训练方法体系（风格微调 vs 知识注入、KnItLM、DPO 等）
│   ├── 改进.md                            #   实验结果分析与改进记录（§0 Phase 1-3 总结 / §1-5 r8_e1 诊断）
│   ├── 过程.md                            #   实验过程记录（exp_01 ~ Phase 4 时间线）
│   ├── 必须手动学习的地方.md              #   手工任务详细操作指南（唯一来源）
│   ├── install_rocm_7.2.4.sh              #   ROCm 7.2.4 安装脚本
│   └── revert_rocm_to_ubuntu.sh           #   ROCm 回滚到 Ubuntu 仓库版本脚本
├── graduation_project/                    # 核心代码库（pip install -e . 后可全局 import）
│   ├── __init__.py
│   ├── schema.py                          # 统一输出 schema（VERDICT_SCHEMA 唯一来源 + 解析函数）
│   ├── prompts.py                         # 统一 Prompt 模板（SYSTEM_PROMPT + build_user_prompt）
│   ├── llm_client.py                      # Ollama LLM 客户端（支持 RAG 增强）
│   ├── chroma_manager.py                  # Chroma 向量数据库管理器（add / upsert / query）
│   └── code_slicer.py                     # AST 代码切片器（tree-sitter，长文件按函数/块切分）
├── experiments/                           # 实验目录（按阶段编号）
│   ├── utils.py                           #   实验公共工具（manifest 加载 / 指标统计 / 结果落盘）
│   ├── exp_01_basic_scan/                 # 阶段一：LLM 漏洞检测能力摸底
│   │   ├── run_experiment.py              #   批量测试脚本（调 Ollama API + 增量落盘 + 自动卸载显存）
│   │   ├── exp_01_report.md               #   实验报告
│   │   ├── samples/                       #   14 段漏洞代码样本
│   │   │   ├── manifest.json              #     样本清单（含期望标签）
│   │   │   ├── sql_injection_01.py / 02.py
│   │   │   ├── xss_01.php / 02.js
│   │   │   ├── command_injection_01.py / 02.js
│   │   │   ├── path_traversal_01.py / 02.java
│   │   │   ├── hardcoded_secret_01.py / 02.java
│   │   │   ├── insecure_deserialization_01.py / 02.java
│   │   │   ├── safe_01_parameterized_query.py
│   │   │   └── safe_02_subprocess_list.py
│   │   └── results/
│   │       └── results.json               #   14 次推理的完整原始输出
│   ├── exp_02_baseline_tools/             # 阶段二：传统工具对比基线
│   │   ├── run_baseline.py                #   Bandit + Semgrep 批量调用脚本
│   │   ├── exp_02_report.md               #   实验报告（含 LLM vs 传统工具横向对比）
│   │   ├── README.md                      #   实验说明
│   │   └── results/                       #   复用 exp_01 样本，结果按工具分组
│   ├── exp_03_rag_knowledge/              # 阶段三：RAG 知识库增强
│   │   ├── run_rag_experiment.py          #   RAG+LLM 批量对比实验脚本
│   │   ├── exp_03_report.md               #   实验报告（纯 LLM vs RAG+LLM 对比）
│   │   ├── results/                       #   实验结果
│   │   └── knowledge_data/
│   │       ├── knowledge.json             #   漏洞知识条目（手工编写，72 条，覆盖 39 类 CWE）
│   │       ├── build_knowledge.py         #   从 JSON 加载 → upsert 入库 Chroma（幂等可重复运行）
│   │       └── test_rag.py                #   单样本快速验证脚本（正式实验用 run_rag_experiment.py）
│   ├── exp_04_hard_samples/               # 阶段四：难样本压力测试 + 消融实验 + 多模型对比
│   │   ├── samples/                       #   87 段扩展样本（v2/v3，典型 36 + 安全 18 + 难 27 + 噪音 6）
│   │   │   ├── manifest.json              #     12 列 ground truth 标注
│   │   │   ├── typical_*.py/php/js         #     典型漏洞样本
│   │   │   ├── safe_*.py                  #     安全对照样本
│   │   │   ├── hard_bypass_*.py            #     绕过式过滤难样本
│   │   │   ├── hard_crossfile_*_{input,sink}.py  # 跨文件污点流难样本
│   │   │   ├── hard_cve_*.py              #     真实 CVE 片段难样本
│   │   │   ├── hard_longfile_*.py         #     长文件隐藏漏洞难样本
│   │   │   ├── hard_owasp_*.py            #     OWASP/DVWA 风格难样本
│   │   │   └── noise_*.py                 #     混淆/噪音样本
│   │   ├── run_experiment.py              #   P1-4：纯 LLM 重复实验 + 置信区间（--repeat N）
│   │   ├── run_rag_experiment.py          #   P1-5/P2-8：RAG 消融对照（--mode）+ Top-K（--top-k）
│   │   ├── run_v3_qwen7b_all.sh           #   v3 qwen7b 顺序跑 4 组消融 + 3 个 Top-K 的驱动脚本
│   │   ├── run_v3_multi_model.sh          #   v3 多模型横向对比驱动脚本（6 模型 × 87 段）
│   │   ├── rerun_fix_samples.py           #   结果审查修复重跑脚本
│   │   ├── generate_report.py             #   从 results/ 汇总生成 exp_04_report.md
│   │   ├── exp_04_report.md               #   实验报告（P1-4 + P1-5 + P2-8 + 多模型对比综合分析）
│   │   └── results/                       #   所有实验结果 JSON（含 _archive 历史版本）
│   ├── exp_05_prompt_ablation/            # 阶段五：Prompt 工程消融对比
│   │   ├── run_ablation.py                #   零样本 / Few-shot / 思维链 / 安全模式白名单 对比
│   │   ├── exp_05_report.md               #   实验报告
│   │   └── results/                       #   消融实验结果 JSON
│   └── exp_06_finetune/                   # 阶段六：网络安全专用模型训练与蒸馏
│       ├── data/                          #   训练数据（入库以保证复现性）
│       │   ├── train_chatml.jsonl         #     build_dataset.py 产出的 222 条手写样本
│       │   ├── train_chatml_v2.jsonl      #     combine_and_augment.py 合并的 622 条最终训练集
│       │   ├── cpt_corpus.jsonl           #     Phase 3 KnItLM CPT 语料（CVE/CWE/OWASP）
│       │   ├── distill_corpus_annotated_v2.jsonl  # 教师模型 CoT 蒸馏 400 条
│       │   ├── dpo_merged.jsonl           #     DPO 训练集（v1+v3 合并去重 196 条）
│       │   └── supplement_*.jsonl         #     各类对抗性补充样本（CCoT / 弱点 / 长尾 CWE 等）
│       ├── configs/                       #   TunableOp 离线调优产物（RDNA4 加速）
│       │   ├── tunableop_untuned0.csv     #     Step 1：录制所有 GEMM shape
│       │   └── tunableop_tuned.csv        #     Step 2：调优后的最优 kernel 选择表（训练自动加载）
│       ├── scripts/                       #   训练 / 评估 / 数据生成脚本
│       │   ├── train_qlora.py             #     QLoRA SFT 主训练脚本（Phase 1/2 通用）
│       │   ├── train_knitlm_cpt.py        #     Phase 3 KnItLM CPT 训练脚本
│       │   ├── train_dpo.py               #     DPO 训练脚本
│       │   ├── train_prompt_distillation.py #   Phase 4 Prompt 蒸馏训练脚本
│       │   ├── evaluate.py                #     评估脚本（支持 best/checkpoint-N/final）
│       │   ├── merge_lora_to_instruct.py  #     把 LoRA adapter 合并到 Instruct 基座
│       │   ├── build_dataset.py           #     手写样本 → train_chatml.jsonl
│       │   ├── combine_and_augment.py     #     合并蒸馏 + 手写 + 补充样本 → train_chatml_v2.jsonl
│       │   ├── generate_distill_data.py   #     教师模型 CoT 蒸馏数据生成
│       │   ├── prepare_cpt_corpus.py      #     Phase 3 CPT 语料构建
│       │   ├── compare_phase1_sweep.py    #     Phase 1 lr × rsLoRA 网格搜索对比
│       │   ├── compare_phase2.py          #     Phase 2 r=32 + rsLoRA + e=2 对比
│       │   ├── compare_phase3.py          #     Phase 3 KnItLM 评估对比
│       │   ├── tunableop_offline_tune.sh  #     TunableOp 离线调优三步流程
│       │   ├── run_phase1_sweep.sh        #     Phase 1 sweep 驱动脚本
│       │   ├── run_phase2_sft.sh          #     Phase 2 SFT 驱动脚本
│       │   ├── run_knitlm_cpt.sh          #     Phase 3 KnItLM 三阶段一键脚本（CPT → Merge → Eval）
│       │   └── run_phase4_prompt_distillation.sh  # Phase 4 Prompt 蒸馏驱动脚本
│       ├── outputs/                       #   训练产物（不入库；仅保留 best/，中间 checkpoint 已清理）
│       │   ├── knitlm_merged_7b_instruct/ #     Phase 3 合并后的 KnItLM 7B 模型（fp16，~15GB）
│       │   ├── knitlm_cpt_r64_a128_e1.0_lr2e-05_rslora/best/  # Phase 3 CPT LoRA adapter
│       │   ├── lora_r32_a64_e2_lr1e-05_s42_rslora_phase2_*/best/  # Phase 2 best LoRA
│       │   ├── lora_r8_a16_e1_lr{1e-5,5e-5,1e-4}_*_7b/best/  # Phase 1 sweep 各配置 best
│       │   ├── lora_r16_a32_e3_s42/best/  #     初版 3B LoRA（参考用）
│       │   └── dpo_r8_a16_e1_beta0.1_s42/best/  # DPO 实验 best adapter
│       ├── results/                       #   评估结果 JSON + 对比摘要
│       │   ├── exp_06_eval.phase1_*.json  #     Phase 1 sweep 各配置 87 段评估结果
│       │   ├── exp_06_eval.phase2_*.json  #     Phase 2 评估结果
│       │   ├── exp_06_eval.knitlm_merged.*.json  # Phase 3 KnItLM 评估结果
│       │   ├── hard_samples_*.json        #     分 CWE 类型的硬样本细分结果
│       │   ├── phase1_sweep_summary.md    #     Phase 1 sweep 汇总表
│       │   ├── phase2_summary.md          #     Phase 2 汇总表
│       │   └── compare_4way_*.md          #     4-way 对比报告（3B vs 7B / baseline vs finetuned）
│       ├── testset_cve_fix/               #   CVE-fix 独立测试集（30 个 Go 项目，需 GITHUB_TOKEN）
│       │   ├── cve_fix_00{01..30}.go      #     30 段 CVE 修复前后代码片段
│       │   ├── manifest.json              #     测试集清单
│       │   └── manifest_eval.json         #     评估用清单
│       └── logs/                          #   训练日志（不入库；train_log_*.json 含 dev_loss 曲线，compare_*.py 依赖）
└── data/                                  # 本地持久化数据（不入库，见 .gitignore；首次运行 build_knowledge.py 后自动生成）
    └── chroma_db/                         #   Chroma 向量数据库
```

***

## 四、当前进度

> **总体状态**：零样本推理基线（exp_01~05）已全部完成；训练主线（exp_06）中，Phase 1~3 已完成，Phase 3 取得关键突破（KnItLM CPT）。Phase 4（Prompt Distillation，qwen3-coder:30b → KnItLM student）正在台式机训练；Phase 5（DPO）已训练、待评估；Phase 6（错题增强闭环）待启动。详细进度与未完成事项见 [规划.md](规划.md) §三/§四。

### ✅ 阶段一：LLM 漏洞检测能力摸底（exp_01，2026-06-28）

- **qwen2.5-coder:7b**：14 段典型样本召回率 100%、误报率 0%、准确率 100%，平均 7.65s/样本
- 详见 [exp_01_report.md](experiments/exp_01_basic_scan/exp_01_report.md)

### ✅ 阶段二：传统工具对比基线（exp_02，2026-06-29）

- path_traversal_01.py 由 LLM 唯一检出，体现语义理解对模式匹配的优势；完整耗时与准确率对比见 §五 答辩核心论点 1
- 详见 [exp_02_report.md](experiments/exp_02_baseline_tools/exp_02_report.md)

### ✅ 阶段三：RAG 知识库增强（exp_03，2026-06-29）

- 知识库 39→72 条，覆盖 39 类 CWE；qwen7b 在 RAG+LLM 下准确率 100%
- 详见 [exp_03_report.md](experiments/exp_03_rag_knowledge/exp_03_report.md)

### ✅ 阶段四：难样本压力测试 + 多模型对比（exp_04 v3，2026-07-05）

- v3 修复后 87 段样本（答案泄露已修复），qwen7b 纯 LLM 多数表决 recall=83.3%、FPR=33.3%、accuracy=78.2%
- 6 模型横向对比：gemma4:12b/26b 最优（准确率 94.3%），deepseek 误报率最高（44.4%）
- 详见 [exp_04_report.md](experiments/exp_04_hard_samples/exp_04_report.md)

### ✅ 阶段五：Prompt 工程消融（exp_05，2026-07-06）

- 对比零样本 / Few-shot / 思维链（CoT）/ 安全模式白名单 四种 Prompt 策略
- CoT 在 recall 上表现最优（95%），但各策略在 FPR、稳定性上各有取舍
- 结论：Prompt 工程能提升判定质量，但无法替代模型层面的领域知识注入
- 详见 [exp_05_report.md](experiments/exp_05_prompt_ablation/exp_05_report.md)

### 🔄 阶段六：网络安全专用模型训练（exp_06 Phase 1~6，进行中）

- **Phase 1 sweep**：lr 调优反恶化 FPR（lr=1e-4+rsLoRA 最低 dev_loss 但 FPR +11.5pp）
- **Phase 2 r=32 失败**：LoRA 增容致 FPR +19.2pp，CWE 错标数未变——LoRA 增容 ≠ 知识注入
- **Phase 3 KnItLM 突破**：CPT 路线严格 recall +23pp、FPR -7.7pp、CWE 错标 -16（但发现参数化查询幻觉副作用）
- **Phase 4 Prompt Distillation 进行中**：qwen3-coder:30b teacher → KnItLM student，α=0.5, T=2.0
- 详见 [改进.md](docs/改进.md) §0 与 [过程.md](docs/过程.md) 7-17~19 段

***

## 五、研究主线与实验体系

> 本项目不是简单"用 LLM 跑一遍样本"，而是一条从**零样本推理**到**领域知识注入**再到**推理分布校准**的完整研究链。§四 已给出各阶段结果，本节说明实验之间的逻辑关系、方法演进与论文定位。

### 主线一：零样本与增强推理（exp_01 ~ exp_05）

验证"本地开源 LLM 能否在不做任何训练的情况下完成代码安全审计"，并逐步探索增强手段。

| 实验 | 核心问题 | 关键结论 | 论文定位 |
| --- | --- | --- | --- |
| exp_01 | 典型漏洞检出下限 | qwen2.5-coder:7b 在 14 段典型样本上 recall/FPR/accuracy 均达 100%，证明基座能力足够 | 能力基线 |
| exp_02 | 与传统工具（Bandit / Semgrep）的对比 | LLM 在 path_traversal 等语义依赖场景显著优于规则工具；但单样本耗时更高 | 差异化价值 |
| exp_03 | RAG 知识库能否提升判定质量 | 72 条 CWE/OWASP 知识 + Chroma 检索，典型样本准确率保持 100%，难样本上提供可解释依据 | 知识增强 |
| exp_04 | 难样本压力测试与消融 | v3 87 段样本（修复答案泄露后）上纯 LLM accuracy=78.2%；RAG 消融显示知识相关性价值有限，模型基座已掌握典型模式 | 能力边界 |
| exp_05 | Prompt 工程消融 | CoT 召回 95% 为最优单一策略；零样本 / Few-shot / 安全白名单各有适用场景 | 工程优化 |

### 主线二：网络安全专用模型（exp_06 Phase 1~6）

当零样本能力触顶后，转入训练主线，目标是**在 7B 规模上通过高效微调注入漏洞推理能力**，并保持本地可部署。

| Phase | 方法 | 假设 | 结果 | 方法论意义 |
| --- | --- | --- | --- | --- |
| Phase 1 | QLoRA SFT lr × rsLoRA sweep | 提高 lr / rank 能改善注入效果 | lr=1e-4+rsLoRA dev_loss 最低，但 FPR +11.5pp；lr=1e-5 baseline 综合最优 | 7B 高基座上 lr 是过拟合旋钮，不是性能旋钮 |
| Phase 2 | r=32 + rsLoRA + e=2 | 增大 LoRA 容量可学更多知识 | 严格 recall 仅 +1.6pp，FPR +19.2pp，CWE 错标数不变 | **LoRA 增容 ≠ 知识注入**（论文关键证据） |
| Phase 3 | **KnItLM CPT** | 在 base 模型上做继续预训练，再 merge 到 Instruct | 严格 recall 41%→64%（+23pp），FPR 11.5%→3.8%（-7.7pp），CWE 错标 32→16 | **真正的知识注入突破** |
| Phase 4 | **Prompt Distillation** | 用强 teacher（qwen3-coder:30b）蒸馏修复 CPT 副作用 | 🔄 进行中（α=0.5, T=2.0, r=32） | 修复参数化查询幻觉，校准推理分布 |
| Phase 5 | DPO 边界校准 | 用偏好对降低 FPR | 已训练（25 步完成），待评估 | 对齐人类审计偏好 |
| Phase 6 | Hard sample mining | 错题增强闭环 | 待启动 | 修复 missing feature 类回归 |

> Phase 1-3 详细数据见 [docs/改进.md](docs/改进.md) §0；方法体系见 [docs/方法.md](docs/方法.md)。

### 方法论演进：从"风格微调"到"知识注入"

本项目在训练主线上完成了一次关键认知升级：

1. **风格微调**（r=8 LoRA SFT）：只能调整输出格式，对 7B 强基座而言是轻量校准。
2. **容量迷信**（r=32 + 高 lr）：增大容量并不能自动带来知识，反而引入过拟合。
3. **知识注入**（KnItLM CPT）：在 base 模型上注入 CVE/CWE/OWASP 领域语言模式，再 merge 到 Instruct，既保留对话能力又获得漏洞领域先验。
4. **分布校准**（Prompt Distillation / DPO）：用强 teacher 和偏好对修复 CPT 的过度泛化副作用。

### 📌 核心论点与论文定位

#### 1. 速度 vs 质量的权衡论证

LLM 单样本推理耗时高于传统工具，但输出包含自然语言解释与可执行修复代码，可把人工审计理解时间从"逐条核对告警"降到"阅读一段解释"。**核心论点**：将 LLM 定位为"增强审计"工具而非"替代"，衡量整体效率时应计入人工理解成本。

| 指标 | Bandit | Semgrep | LLM (qwen2.5-coder:7b) |
| --- | --- | --- | --- |
| 单样本耗时 | ~0.5s | ~2s | ~7.65s |
| 人工理解时间 | ~30 分钟/漏洞 | ~30 分钟/漏洞 | ~5 分钟/漏洞 |
| 修复代码生成 | ❌ | ❌ | ✅ |
| 典型样本准确率 | 75.0%（8 个 Python 样本） | 78.6%（14 个全语言样本） | 100%（14 个全语言样本） |
| 难样本准确率（P1-5 单次口径） | - | - | 88.5%（RAG K=5）/ 88.5%（纯 LLM） |
| 难样本准确率（P1-4 多数表决） | - | - | 78.2%（纯 LLM，repeat=3） |

#### 2. 配置门槛的应对

| 优化方向 | 方案 | 论文定位 |
| --- | --- | --- |
| 模型轻量化 | qwen2.5-coder:7b 主审（7B dense，约 4-5GB），多模型作为对照 | 降低门槛论证 |
| 专用模型 | KnItLM CPT + Prompt Distillation → 网络安全专用 7B 模型 | 核心创新点 |
| 批处理 | vLLM 一次分析多文件 | 摊薄加载时间 |
| 混合架构 | 传统工具先筛，LLM 只审可疑文件 | 工程化优化 |
| 训练效率 | QLoRA + rsLoRA + AOTRITON + TunableOp，16 GB 可训 7B | 可行性论证 |

#### 3. 答辩核心故事线

> 传统静态分析工具在 CI/CD 流水线中表现优秀，但面对复杂业务逻辑、绕过式过滤、跨函数污点等场景时力不从心。本系统利用本地部署的开源大语言模型，通过 RAG 知识库增强、AST 代码切片与语义级代码理解建立基线；进一步通过 KnItLM 继续预训练将网络安全领域知识注入 7B 模型，再用 Prompt Distillation 校准推理分布。实验表明，在典型漏洞上 LLM 不弱于传统工具，在难样本上通过专用模型训练可显著缩小与更大模型的差距，并生成可执行的修复代码与自然语言解释，将人工审计时间从 30 分钟缩短到 5 分钟，证明了 LLM 在代码安全审计中的差异化价值。

***

## 六、技术架构与全栈

> 本节描述从数据到模型、从训练到推理、从评估到工程化的完整技术链路。硬件与模型清单见 §二，详细方法论文档见 [docs/方法.md](docs/方法.md)。

### 6.1 全链路数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│  数据层                                                              │
│  CVE/CWE/OWASP 语料  +  手写/蒸馏/增强 823 条 CoT 样本  +  87 段测试样本   │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│  训练层（exp_06）                                                     │
│  Qwen2.5-Coder-7B-Base ──KnItLM CPT──► merge ──► Qwen2.5-Coder-7B-Instruct │
│                                           │                         │
│                              Prompt Distillation (qwen3-coder:30b)   │
│                                           │                         │
│                              DPO 边界校准（偏好对）                       │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│  推理层（exp_01~05）                                                   │
│  源代码 ──► AST 切片 ──► RAG 检索 CWE 知识 ──► LLM 推理 ──► 结构化 verdict │
└─────────────────────────────────────────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│  评估层                                                              │
│  严格指标（CWE 对齐） / 多数表决 / Wilson 置信区间 / 错题闭环               │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 训练层：高效参数微调与知识注入

| 层级 | 技术 | 作用 | 项目落地 |
| --- | --- | --- | --- |
| 量化 | bitsandbytes 4-bit NF4 + double quant | 7B 模型在 16 GB 显存可训 | `train_qlora.py` / `train_knitlm_cpt.py` |
| LoRA 优化 | **rsLoRA**（缩放因子 1/√r）、**DoRA**（magnitude+direction 分解） | 高 rank 训练稳定、效果优于标准 LoRA | Phase 1 sweep 已验证 rsLoRA 有效 |
| 知识注入 | **KnItLM**：base 模型 CPT + LoRA → merge 到 Instruct | 注入漏洞领域知识，不破坏指令遵循 | Phase 3 核心突破 |
| 蒸馏 | **Prompt Distillation**：KL(teacher ‖ student)，ollama/transformers 双后端 | 用 qwen3-coder:30b teacher 校准 student 推理分布 | Phase 4 进行中 |
| 对齐 | **DPO**（Direct Preference Optimization） | 用偏好对降低 FPR、校准判断边界 | Phase 5 待评估 |
| 加速 | **AOTRITON** attention、TunableOp 离线调优 | ROCm/RDNA4 上训练 step time -58% | `run_phase1_sweep.sh` / `tunableop_offline_tune.sh` |
| 数据工程 | CoT 蒸馏、CCoT 对比样本、数据增强、错题闭环 | 把标签→反推改为推理→标签 | `generate_distill_data.py` / `supplement_*.py` |

### 6.3 推理层：语义理解增强

| 模块 | 技术 | 说明 |
| --- | --- | --- |
| 代码预处理 | tree-sitter + Python `ast` | 长文件按函数/块切片，缓解注意力衰减 |
| 知识检索 | ChromaDB + `all-MiniLM-L6-v2` / `bge-small-en-v1.5` | 72 条 CWE/OWASP 知识，Top-K 注入 prompt |
| LLM 服务 | Ollama（本地推理）、vLLM/llama.cpp（后续扩展） | 支持多模型横向对比与 teacher logits 预计算 |
| Prompt 协议 | SYSTEM_PROMPT + 7 字段 JSON schema | 统一输出格式，支持 CoT / 安全白名单 / 自校验 |

### 6.4 评估层

| 能力 | 实现 |
| --- | --- |
| 指标口径 | 单次口径 + 多数表决口径；严格 recall（CWE 对齐）+ 宽松 recall |
| 置信区间 | Wilson score interval（比例接近 0/1 时更稳定） |
| 消融对照 | RAG / pure / random / irrelevant 四组对照 |
| 错误分析 | 分 CWE 类型统计、幻觉率、CWE 错标数、source/sink 真实性校验 |
| 错题闭环 | `extract_phase3_errors.py` 等脚本支持 Phase N vs Phase N+1 回归追踪 |

### 6.5 工程化层（后续扩展）

| 方向 | 候选方案 | 状态 |
| --- | --- | --- |
| 后端服务 | FastAPI / Spring Boot | 待启动 |
| 前端界面 | Vue.js / React | 待启动 |
| 批量扫描 | 任务队列 + 文件级并行 | 待启动 |
| 报告导出 | PDF / Markdown | 待启动 |
| 污点流分析 | Source→Sink 跨函数追踪 | 待启动 |
| 修复建议验证 | 生成代码编译/测试通过率 | 待启动 |

### 6.6 系统架构草图（运行时）

```
┌─────────────────────────────────────────────┐
│  用户界面（Vue.js / React，规划中）             │
│  代码上传 │ 分析结果 │ 漏洞详情 │ 修复建议      │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  后端服务（FastAPI / Spring Boot，规划中）      │
│  任务调度 │ 文件预处理 │ 结果聚合             │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  核心分析引擎（Python）                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────────┐ │
│  │ AST 切片  │  │ RAG 检索  │  │ LLM 推理     │ │
│  │ tree-sitter│  │ Chroma   │  │ qwen2.5-coder│ │
│  └─────────┘  └─────────┘  └─────────────┘ │
└─────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────┐
│  训练与评估流水线（exp_06）                    │
│  KnItLM CPT → Prompt Distillation → DPO     │
│  evaluate.py / compare_phase*.py            │
└─────────────────────────────────────────────┘
```

***

## 七、复现方式

### 环境准备（所有实验的前置步骤，只需执行一次）

```bash
cd Graduation-Project

# 使用 conda 环境 graproj（项目所有依赖与工具均在此环境中）
source ~/miniconda3/etc/profile.d/conda.sh
conda activate graproj

# 安装依赖 + 注册 graduation_project 为可导入包
pip install -r requirements.txt
pip install -e .

# 确保 Ollama 已运行且默认主模型已下载
ollama pull qwen2.5-coder:7b
ollama serve   # 若未启动
```

> **环境约定**：所有实验脚本（尤其 exp\_03 / exp\_04 RAG 相关）依赖 `chromadb`、`sentence-transformers` 等包，这些只在 `graproj` conda 环境中安装。请在运行任何实验前激活该环境，否则会出现 `ModuleNotFoundError`。
>
> **离线运行约定**：`graduation_project/chroma_manager.py` 已强制离线模式（`HF_HUB_OFFLINE=1` / `TRANSFORMERS_OFFLINE=1`），运行时不会从 HuggingFace 下载 embedding 模型。首次使用前请确保 `bge-small-en-v1.5` 已缓存到本地：
>
> ```bash
> # 在有网络的环境执行一次即可（国内可用 HF 镜像: HF_ENDPOINT=https://hf-mirror.com）
> python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-small-en-v1.5')"
> # 默认缓存到 ~/.cache/huggingface/hub/models--BAAI--bge-small-en-v1.5
> ```
>
> 若缓存路径非默认，可设置 `export CHROMA_EMBEDDING_MODEL_PATH=/path/to/local/model`。

### 跑第一阶段实验（exp\_01）

```bash
cd experiments/exp_01_basic_scan

python3 run_experiment.py                       # 跑全部 14 个样本（默认 qwen2.5-coder:7b）
python3 run_experiment.py --limit 3             # 只跑前 3 个（快速调试）
python3 run_experiment.py --model deepseek-coder-v2:16b --temperature 0.1   # 切换对照模型
python3 run_experiment.py --keep-loaded         # 跑完保留模型在显存（默认卸载）
```

结果写入 `results/results.json`，每跑完一个样本即增量落盘，中途可断点查看。

### 跑第二阶段实验（exp\_02，传统工具对比基线）

```bash
cd experiments/exp_02_baseline_tools

# 需先安装工具：pip install bandit semgrep
python3 run_baseline.py                         # Bandit + Semgrep 都跑
python3 run_baseline.py --tool bandit           # 只跑 Bandit
python3 run_baseline.py --tool semgrep          # 只跑 Semgrep
python3 run_baseline.py --limit 3               # 只跑前 3 个样本（调试）
```

复用 exp\_01 的 14 段样本，结果按工具分组写入 `results/results.json`。

### 跑第三阶段实验（exp\_03，RAG 知识库增强）

```bash
# 1. 构建漏洞知识库（首次运行，会下载 embedding 模型）
cd experiments/exp_03_rag_knowledge/knowledge_data
python3 build_knowledge.py                      # 从 knowledge.json upsert 72 条知识 → Chroma

# 2. 批量对比实验：纯 LLM vs RAG+LLM
cd ..
python3 run_rag_experiment.py                   # 跑全部 14 个样本（默认 qwen2.5-coder:7b）
python3 run_rag_experiment.py --top-k 5         # 检索 Top-5 知识
python3 run_rag_experiment.py --limit 3         # 只跑前 3 个（调试）
python3 run_rag_experiment.py --model deepseek-coder-v2:16b  # 切换对照模型

# 3. 单样本快速验证（可选，正式实验用 run_rag_experiment.py）
cd knowledge_data
python3 test_rag.py
```

### 跑第四阶段实验（exp\_04，难样本压力测试 + 消融对照）

```bash
cd experiments/exp_04_hard_samples

# P1-4：纯 LLM 重复实验 + 95% 置信区间（默认 --repeat 3，约 95 分钟）
python3 run_experiment.py --repeat 3
python3 run_experiment.py --repeat 3 --limit 3      # 只跑前 3 个样本（调试）

# P1-5：RAG 消融对照（4 组分别运行，每组约 30 分钟）
python3 run_rag_experiment.py --mode rag            # A 组：RAG+LLM
python3 run_rag_experiment.py --mode pure           # B 组：纯 LLM
python3 run_rag_experiment.py --mode random         # C 组：随机知识注入
python3 run_rag_experiment.py --mode irrelevant     # D 组：等长无关文本注入

# P2-8：Top-K 对比（K=1,3,5,10）
python3 run_rag_experiment.py --mode rag --top-k 1
python3 run_rag_experiment.py --mode rag --top-k 5
python3 run_rag_experiment.py --mode rag --top-k 10

# 一键顺序跑完 P1-5 + P2-8（约 4 小时，需 P1-4 已完成释放显存）
nohup bash run_ablation_and_topk.sh > results/ablation_topk.run.log 2>&1 &

# 生成最终报告
python3 generate_report.py
```

***

## 八、参考资源

### 工具与平台

- **传统代码审计**：[Semgrep](https://semgrep.dev/) / [CodeQL](https://codeql.github.com/) / [Bandit](https://bandit.readthedocs.io/)
- **LLM 安全应用**：[Garak](https://github.com/leondz/garak) / Promptmap
- **漏洞管理平台**：[OpenVAS](https://www.openvas.org/) / [Nuclei](https://github.com/projectdiscovery/nuclei)
- **数据集来源**：[OWASP WebGoat](https://owasp.org/www-project-webgoat/) / CVE PoC 仓库 / CodeQL 测试用例

### 难样本设计参考（exp\_04）

以下资料用于设计 exp\_04 中的真实 CVE 片段与 OWASP 风格难样本（详见 `experiments/exp_04_hard_samples/samples/manifest.json`）：

- **CVE-2017-7494 Samba 远程命令执行**：`hard_cve_01_samba_2017_7494.py` 的设计依据
- **Python 日志注入（原引用 CVE-2021-44228 Log4j，已重命名去除误导）**：`hard_cve_02_python_log_injection.py` 的设计依据
- **CVE-2025-4517 Python tarfile 路径穿越**：`hard_cve_03_tarfile_2025_4517.py` 的设计依据
- **Python urllib SSRF（原引用 CVE-2025-54381 BentoML，已重命名去除误导）**：`hard_cve_04_ssrf_urllib.py` 的设计依据
- **Top 10 Python Security Vulnerabilities** (aikido.dev)：典型 Python 漏洞模式参考
- **Insecure Deserialization in Python** (semgrep.dev)：pickle / yaml 反序列化样本参考
- **Vulnerable Web Application examples** (offensive360.com)：OWASP/DVWA 风格样本参考
- **aiohttp CVE-2024-23334 路径穿越 PoC** (exploit-db.com)：路径穿越绕过样本参考

> 每段 CVE 样本文件头部的注释中标注了对应的 CVE 编号与原始漏洞描述，便于追溯。

### 训练与微调方法（exp_06）

本项目在训练主线上借鉴并落地了以下近期 PEFT / 知识注入 / 显存优化方法：

| 方法 | 核心思想 | 本项目用途 | 来源 |
| --- | --- | --- | --- |
| **rsLoRA** | LoRA 缩放因子从 `1/r` 改为 `1/√r`，高 rank 更稳定 | Phase 1 sweep 验证有效 | Hayou et al. 2024 |
| **DoRA** | 权重分解为 magnitude + direction | Phase 1 兼容性验证 | Liu et al., ICLR 2024 |
| **KnItLM** | base 模型 CPT + LoRA → merge 到 Instruct，注入领域知识不破坏对话能力 | Phase 3 核心突破 | ICLR 2026 投稿 |
| **Prompt Distillation** | 用 teacher 的 token 分布（logits）蒸馏 student | Phase 4 修复 CPT 副作用 | TMLR 2025 |
| **DPO** | 直接偏好优化，用偏好对校准模型 | Phase 5 边界校准 | Rafailov et al. 2023 |
| **GaLore** | 梯度低秩投影，全参数微调显存接近 LoRA | Phase 7 兜底备选 | Zhao et al., arXiv:2403.07404 |
| **AOTRITON / TunableOp** | ROCm 上的 Triton Flash Attention 与 GEMM 离线调优 | RDNA4 训练加速 | AMD / PyTorch 官方博客 |

> 更系统的文献梳理与适用性分析见 [docs/方法.md](docs/方法.md) §8 与 §10。

***

## 九、评估方法学

为保证实验结果在论文/答辩中可被复现与质疑，本项目的指标定义、置信区间、口径选择都遵循以下规则。

### 9.1 混淆矩阵与基础指标

| 预测 \ 实际   | 漏洞（expected\_present=True） | 安全（expected\_present=False） |
| --------- | -------------------------- | --------------------------- |
| **判定为漏洞** | TP（真阳性）                    | FP（误报）                      |
| **判定为安全** | FN（漏报）                     | TN（真阴性）                     |

- **召回率（Recall）** = TP / (TP + FN)：漏洞样本被检出的比例
- **误报率（FPR）** = FP / (FP + TN)：安全样本被误判为漏洞的比例
- **准确率（Accuracy）** = (TP + TN) / (TP + TN + FP + FN)：总体判定正确率
- **无效样本**：模型输出无法解析为有效 JSON 时计入 invalid，不计入 TP/FP/FN/TN

### 9.2 重复实验与多数表决（P1-4）

`temperature=0.1` 不等于确定性输出，模型每次推理仍有随机性。每个样本连续跑 N 次（默认 N=3）：

- **多数表决**：N 次中判定为漏洞的比例 ≥ 50% 则最终判为漏洞；平票时保守判 True
- **一致率**：max(True 次数, False 次数) / 有效次数，反映模型对该样本的判定稳定性
- 一致率 < 2/3 的样本在报告中单独列出，作为"模型判定不稳定"的证据

### 9.3 置信区间（Wilson score interval）

采用 Wilson score interval 而非正态近似，因前者在比例接近 0 或 1（如 100% 召回率）时更稳定：

```
center = (p + z²/(2n)) / (1 + z²/n)
margin = z · √(p(1-p)/n + z²/(4n²)) / (1 + z²/n)
CI = [center - margin, center + margin]
```

其中 `p` 为样本比例，`n` 为样本数，`z=1.96` 对应 95% 置信度。例如 8/10 准确率的 95% CI 为 \[49.0%, 94.3%]，而非简单的 80% ± x。

### 9.4 耗时统计

单点耗时无意义，报告中同时给出：

- **均值**：所有样本耗时的算术平均
- **中位数**：更稳健，不受异常值影响（论文引用推荐用此）
- **标准差**：反映耗时波动
- **p95**：95 分位数，反映长尾
- **最长/最短**：异常值定位（如 safe\_02 因模型对安全样本过度分析导致耗时最长）

### 9.5 RAG 消融对照（P1-5）

为证明 RAG 提升来自知识相关性而非"prompt 变长"，对比 4 组：

| 组别               | 注入内容              | 验证目的             |
| ---------------- | ----------------- | ---------------- |
| A 组 (rag)        | 按代码语义检索 Top-K 知识  | 当前实现（baseline）   |
| B 组 (pure)       | 无 RAG 上下文         | 排除 RAG 干扰        |
| C 组 (random)     | 知识库随机抽 K 条（与样本无关） | 排除"注入任何知识都有用"    |
| D 组 (irrelevant) | 与漏洞无关但长度相近的文本     | 排除"prompt 变长就有用" |

**论证逻辑**：只有当 A 组显著优于 B/C/D 三组时，才能论证 RAG 真正有用；若 A ≈ C 或 A ≈ D，则提升仅来自 prompt 变长或随机注入。

### 9.6 评估口径

每个实验同时给出两种口径：

- **单次口径**：所有 run 拉平统计（如 42 样本 × 3 次 = 126 次判定），适合和 exp\_01\~03 历史数据对比
- **多数表决口径**：每个样本 N 次投票后的最终判定，更贴近实际使用场景

***

## 十、约定与备注

- 本阶段聚焦核心算法验证与专用模型训练，前后端工程化框架待实验完成后再明确需求并启动。
- 所有实验过程、Prompt 迭代与训练日志均已保留，作为后续论文撰写的原始依据。
- 模型名称需与 Ollama 中实际可用的模型名一致。
- **显存管理约定**：每次实验脚本跑完必须主动从显存卸载模型（Ollama `keep_alive=0`），多模型场景下避免爆显存。`run_experiment.py` 默认在末尾卸载，如需保留加 `--keep-loaded`。
- 大模型文件（`.gguf` / `.bin` / `.safetensors` 等）绝不入库，见 `.gitignore`。
- **RAG 向量库**：`data/chroma_db/` 为本地持久化数据，不入库（见 `.gitignore`），需在本地通过 `build_knowledge.py` 自行构建。

