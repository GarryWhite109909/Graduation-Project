# 实验 06 报告：网络安全专用模型训练主线（Qwen3-8B 路线）

> 📋 **一句话结论**：基于 Qwen3-8B 的 4bit QLoRA SFT 迭代至 v5 后，在 87 段合成集上达到 **recall=1.000、FPR=0.231、strict_recall=0.590**，在 7 段 CVE-fix 真实集上 recall=0.571；但本地 16GB GPU 无法运行 DPO，v6 hard-negative SFT 引发负迁移，后续方向待决策。
>
> | 关键指标 | Qwen3-8B baseline | SFT v5（当前最佳） | 变化 |
> | --- | --- | --- | --- |
> | 合成集 recall | 0.967 | **1.000** | +3.3pp |
> | 合成集 FPR | 0.269 | **0.231** | -3.8pp |
> | 合成集 accuracy | 0.897 | **0.931** | +3.4pp |
> | 合成集 strict_recall | 0.459 | **0.590** | +13.1pp |
> | CVE-fix recall | 0.375 | **0.571** | +19.6pp |
> | CVE-fix strict_recall | 0.125 | 0.143 | +1.8pp |
>
> **核心发现**：
> 1. SFT v5 是首个可信评估基线：清洗了 v4 中 100 条测试集泄漏/近泄漏样本，recall 100% 不再依赖数据污染。
> 2. strict_recall 从 0.459 提升至 0.590，CWE 归因能力显著改善，但仍有 25/61 的 CWE 错标。
> 3. CVE-fix 真实集 recall 从 37.5% 提升至 57.1%，但 LDAP 注入与信任边界绕过仍是持续 FN。
> 4. 本地 DPO 不可行：8bit OOM、4bit 梯度失效；v6 hard-negative SFT 以牺牲 recall 与真实集泛化为代价降 FPR，已被归档。
>
> **论文对应章节**：第 5 章（训练主线：SFT 迭代、DPO 尝试与失败分析）

## 一、实验目的

在 exp_01~05 验证零样本 LLM 具备基础检测能力但难样本上仍有明显短板后，本阶段尝试通过监督微调（SFT）训练一个面向代码安全审计的专用模型，目标：

1. 提升 CWE 归因准确率（strict_recall）。
2. 降低安全样本误报率（FPR）。
3. 在真实 CVE-fix 片段上验证泛化能力。
4. 探索 DPO 等偏好优化方法进一步降 FPR 的可行性。

## 二、实验设置

| 项目 | 配置 |
| --- | --- |
| 基座模型 | `Qwen/Qwen3-8B`（HuggingFace，4bit NF4 QLoRA） |
| LoRA 配置 | r=8, alpha=16, dropout=0.1, rsLoRA=True, DoRA=False |
| 训练参数 | epochs=3, lr=1e-4, batch=1×8, seed=42, EarlyStopping patience=2 |
| 可训练参数 | 21,823,488（0.27%） |
| 推理方式 | 本地 transformers（4bit + LoRA merge_and_unload），max_new_tokens=2048 |
| 测试集 | 87 段合成集（exp_04_hard_samples v3）+ 7 段 CVE-fix 真实集 |

## 三、迭代路线

### 3.1 P0：parse_fail 修复（2026-07-22）

将 Ollama 推理的 `max_tokens` 从 1024 提升至 2048，消除 Qwen3-8B 在 87 合成集上的 parse_fail（18/87 → 0/87），建立可信基线。

### 3.2 P1：CVE-fix 真实集校准（2026-07-23~25）

逐样本审查 8 条 CVE-fix 样本，修正 2 条标注错误（`cve_fix_0001.java` CWE-74 → CWE-90；`cve_fix_0008.py` 移除），最终保留 7 条有效样本作为真实集。

### 3.3 P2：SFT 五版本迭代（2026-07-23~27）

| 版本 | 训练数据 | 合成集 recall | 合成集 FPR | 合成集 strict_recall | CVE-fix recall | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| v2 | `train_chatml_v2.jsonl`（823 条） | 0.967 | 0.231 | **0.623** | 0.625 | 历史 |
| v3 | `train_chatml_v3_fixed.jsonl`（832 条） | 0.984 | 0.192 | 0.607 | 0.500 | 历史 |
| v4 | `train_chatml_v4.jsonl`（839 条） | 0.885 | 0.115 | 0.492 | 0.429 | **废弃（测试集泄漏）** |
| **v5** | `train_chatml_v5_clean.jsonl`（749 条） | **1.000** | 0.231 | **0.590** | **0.571** | **当前最佳** |
| v6 | `train_chatml_v6_hard_neg.jsonl`（755 条） | 0.984 | 0.192 | 0.557 | 0.429 | **失败（负迁移）** |

> v4 因系统性测试集泄漏（3 精确匹配 + 63 高重叠变体）导致指标不可信，已归档到 `_archive_failed/`。
> v6 在 v5 基础上追加 6 个 FP 的正确拒绝 CoT，虽 FPR 降至 0.192，但 CVE-fix recall 从 0.571 跌至 0.429，被判定为负迁移。

### 3.4 P3：DPO 尝试与失败（2026-07-27）

| 尝试 | 配置 | 结果 | 根因 |
| --- | --- | --- | --- |
| 1 | 8bit + max_len=1024 | OOM 黑屏 | DPO 双前向超 16GB VRAM |
| 2 | fp16 + max_len=512 | 立即 OOM | 8B fp16 本身超显存 |
| 3 | 4bit + max_len=512 | grad_norm=0 | 4bit NF4 下梯度无法正确回传 LoRA |

**结论**：本地 16GB AMD GPU 无法运行 Qwen3-8B 的 DPO。已准备 `dpo_merged.jsonl`（104 条），若换用 24GB+ GPU 或云实例可直接复用。

## 四、关键发现

1. **SFT 显著提升 CWE 归因能力**：strict_recall 从 baseline 0.459 提升至 v5 0.590（+13.1pp），说明结构化 CoT 训练有效。
2. **真实 CVE 泛化仍有 gap**：CVE-fix recall 0.571 虽较 baseline +19.6pp，但远低于合成集 1.000，真实漏洞模式更隐蔽。
3. **FPR 是后续瓶颈**：v5 FPR 0.231 与 baseline 0.269 接近，SFT 在降误报上进展有限。
4. **简单 hard-negative 得不偿失**：v6 的 FPR 下降以 recall 和真实集泛化为代价，说明直接追加负样本会改变模型对安全代码的敏感阈值。
5. **DPO 是本地硬件不可解问题**：非参数调优可解决，需要更大显存或云环境。

## 五、后续方向

| 选项 | 描述 | 风险/成本 |
| --- | --- | --- |
| A. 云 GPU 跑 DPO | 使用 `dpo_merged.jsonl` 在 24GB+ GPU 上训练 | 需云实例或换卡 |
| B. 单个 FP micro-finetune | 针对 6 个 FP 中的某一个做极小学习率/短 epoch 微调 | 可能再次负迁移 |
| C. 停止微调，进入系统开发 | 以 v5 为最终模型，开发前后端与报告功能 | FPR 0.231 仍较高 |

## 六、复现方式

```bash
cd experiments/exp_06_finetune

# SFT 训练（v5）
PYTHONPATH=../.. python3 scripts/train_qlora.py \
  --train_data data/train_chatml_v5_clean.jsonl \
  --output_dir outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5

# 评估 v5
PYTHONPATH=../.. python3 scripts/evaluate.py \
  --adapter outputs/lora_r8_a16_e3_lr0.0001_s42_rslora_v5/best \
  --testset ../../experiments/exp_04_hard_samples/samples \
  --out results/v5/exp_06_eval.finetuned_custom.$(date +%Y%m%d_%H%M%S).json
```

完整实验台账与逐样本明细见 [results/EXPERIMENT_LEDGER.md](results/EXPERIMENT_LEDGER.md)。
