# 实验修复后需重跑清单

本次修复了 9 条实验方法学问题（文件名泄漏、指标口径、resume 失效等）。
由于 #1（文件名泄漏）改变了所有 LLM 实验 的 prompt 构造，**历史结果
不可比，以下实验必须在 GPU/Ollama 环境重新运行**，论文引用的指标需重新生成。

---

## 必须重跑（LLM 推理受 prompt 变化影响）

### 1. exp_01_basic_scan（基础扫描）
- **原因**：#1 `build_user_prompt` 不再注入 filename。原 100% 准确率被文件名标签
  （`sql_injection_01.py`、`safe_02_...py`）污染，重跑后才是真实指标。
- **命令**：
  ```bash
  cd d:\code\毕业设计\Graduation-Project
  python experiments/exp_01_basic_scan/run_experiment.py
  ```
- **验证点**：重跑后准确率应低于原 100%；若仍 100%，检查 prompt 是否真的不含文件名。
- **对比**：exp_01(LLM) vs exp_02(Bandit/Semgrep) 的对比表需用新 exp_01 结果。

### 2. exp_04_hard_samples（难样本扩展集）
- **原因**：#1 prompt 变了；#7 多数表决平票语义统一为 True（若 repeat>1）；#8 resume 逻辑修复。
- **命令**：
  ```bash
  python experiments/exp_04_hard_samples/run_experiment.py --repeat 3
  ```
- **注意**：#3 已在 manifest 加 `held_out_status` 字段——exp_04 因被 exp_06 hard sample
  mining 使用，**不再是独立 held-out 测试集**，重跑指标仅供趋势参考，不可作为泛化能力
  独立评估。论文独立评估改用 CVE-fix 测试集。
- **resume**：若中途中断，`--resume` 现在能正确找到最新同前缀文件续跑。

### 3. exp_05_prompt_ablation（prompt 消融）
- **原因**：#1 prompt 变了；#5 `--repeat` 默认值 1→3（原 repeat=1 下 cot 95% vs few_shot
  93.3% 仅差 1 个样本，不可下"最优"结论）；#7 多数表决统一。
- **命令**：
  ```bash
  python experiments/exp_05_prompt_ablation/run_ablation.py --repeat 3
  ```
- **验证点**：repeat=3 下各变体指标应有置信区间；原 cot vs few_shot 2 个样本差异
  可能被噪声覆盖，需重新判断显著性。

### 4. exp_06_finetune evaluate.py（微调模型评估）
- **原因**：#1 prompt 变了；evaluate.py 跨文件注释去 `sink`/`input` 标签。
- **命令**：
  ```bash
  python experiments/exp_06_finetune/scripts/evaluate.py
  ```
- **注意**：
  - #4 CVE-fix 测试集已加 `limitations` 字段——20 条全为正样本，仅 recall 可参考，
    FPR/accuracy 无意义。论文引用该集指标必须注明此局限。
  - #6 新增严格口径指标（`recall_with_parse_fail`/`accuracy_with_parse_fail`），
    论文主结论应优先引用严格口径。重跑后结果文件会自动包含两套口径。

---

## 不需重跑（仅工具扫描，不受 prompt 影响）

### exp_02_baseline_tools（Bandit/Semgrep 基线）
- Bandit/Semgrep 看代码内容不看文件名，本次 prompt 修复不影响其结果。
- **但**：论文中 exp_01(LLM) vs exp_02(工具) 的对比表需用重跑后的 exp_01 新结果。

---

## 可选：仅重新计算指标（不重跑推理）

如果已有历史结果 JSON 文件，且只想看 #6 严格口径指标，可单独跑 evaluate.py
对旧结果文件重算（evaluate.py 会自动输出两套口径）。但**论文主结论必须基于
重跑后的新结果**，因为 #1 prompt 变化影响推理本身。

---

## 重跑顺序建议

1. exp_01（最快，验证 prompt 修复生效）
2. exp_05（repeat=3，验证 prompt 消融结论显著性）
3. exp_04（repeat=3，难样本集，注意非独立 held-out）
4. exp_06 evaluate.py（微调模型评估，含 CVE-fix 测试集）

## 重跑后检查清单

- [ ] exp_01 准确率不再是 100%（若仍是，说明 prompt 修复未生效）
- [ ] exp_05 repeat=3 下 cot vs few_shot 差异是否有统计显著性
- [ ] 所有结果 JSON 含 `recall_with_parse_fail`/`accuracy_with_parse_fail` 字段
- [ ] CVE-fix 测试集结果仅引用 recall，不引用 FPR/accuracy
- [ ] exp_04 结果旁注明"非独立 held-out"局限性
- [ ] 论文实验章节更新所有受影响表格和结论
