# 分层审查框架（L1-L4）

> v9max 训练数据质量审查的完整框架。解决"三模型都有弱点，谁审？"的核心问题。

## 一、设计决策

### 为什么三大模型不能做最终裁决

| 原因 | 说明 |
|---|---|
| 共同盲区 | DeepSeek/GLM/K3 都是中国模型，预训练语料重叠，对某些 CWE 有相同认知偏差 |
| 同行放水 | 三模型各有偏置（DeepSeek 高误报、K3 保守、GLM 格式好但推理慢），互审会互相容忍 |
| 能力上限 | 审查要求能力 > 生成。三大模型在 CVE-fix 上 recall 仅 37-57%，让 60% 准确率的模型审 60% 准确率的数据不可信 |

→ 三模型互审的价值是**标记分歧**（L2），最终裁决由闭源模型完成（L3）。

### 为什么必须引入闭源模型

- **审查比生成容易**：闭源模型判断"这个标签对不对"比"从零生成标签"可靠得多
- **对齐差异带来客观性**：国外模型的安全对齐不同，对中国模型常见的偏差是独立第三方视角
- **能力代差**：Claude Opus 4.1 / GPT-5 推理能力显著强于开源，能识别开源模型的认知错误

### 为什么不全量审查

- **成本**：11500 条 × Claude API 单价可能几百到上千元
- **没必要**：L1 规则 + L2 投票已解决 80% 问题
- **反偏置**：闭源模型也有偏置（Claude 过度保守），全量审查可能引入新偏差
- **方案**：只审 L2 标记的分歧样本（约 20-30%）+ 每个生成器抽 5-10% 校准

## 二、分层架构

```
L1 规则校验（全量，免费，自动）
   ├─ JSON schema / CWE 合法性 / 行号范围 / 字段完整性
   ├─ CoT 步数 ≤5 / token ≤590
   └─ 一致性（has_vulnerability ↔ vulnerability_type ≠ "none"）
       ↓ 过滤 ~15% 格式错误
L2 三模型交叉投票（全量，API，标记分歧）
   ├─ DeepSeek 生成的样本 → GLM + K3 复审
   ├─ GLM 生成的样本 → DeepSeek + K3 复审
   ├─ K3 生成的样本 → DeepSeek + GLM 复审
   └─ 三方在 {漏洞/安全, CWE, 行号} 任一不一致 → 标记分歧
       ↓ ~20-30% 分歧样本
L3 闭源模型仲裁（分歧 + 抽样）
   ├─ 主审：Claude Opus 4.1（英文 prompt，反偏置）
   ├─ 副审：GPT-5（交叉验证 Claude 判断）
   ├─ 全部分歧样本送 Claude 仲裁
   ├─ 每个生成模型额外抽 5-10% 送 Claude 做质量评分
   └─ Claude 与 GPT-5 一致 → 采纳；分歧 → 标记"需人工"（预计 <5%）
       ↓
L4 金标准集校准（一次性，评估生成模型本身）
   ├─ 50-100 条金标准（已知 CVE + 人工确认无漏洞代码）
   ├─ 每个生成模型在金标准上跑准确率
   └─ 按准确率给该模型输出加权（≥0.85→1.0, 0.70-0.85→0.8, <0.70→0.5）
       ↓
合并最终数据 → train_chatml_v9max_final.jsonl
```

## 三、文件清单

| 文件 | 说明 | 状态 |
|---|---|---|
| `common.py` | 共享工具（jsonl 读写、CoT 统计、CWE 校验、verdict 提取） | ✅ 完整实现 |
| `l1_rule_check.py` | L1 规则校验（全量、免费、自动） | ✅ 完整实现 |
| `l2_cross_vote.py` | L2 三模型交叉投票（框架，需填 API key） | 🔧 框架就绪 |
| `l3_arbiter.py` | L3 闭源仲裁（框架，含 Claude/GPT-5 审查 prompt） | 🔧 框架就绪 |
| `l4_golden_eval.py` | L4 金标准校准（框架，需填 API key） | 🔧 框架就绪 |
| `run_pipeline.py` | 流水线编排（L1→L2→L3→L4→合并） | ✅ 完整实现 |

## 四、使用流程

### 4.1 首次运行（只跑 L1，免费验证）

```bash
cd experiments/exp_06_finetune/scripts/audit
PYTHONPATH=../../.. python3 run_pipeline.py \
    --data-file ../../../data/train_chatml_v9max.jsonl \
    --output-dir ../../../data/v9max_audited \
    --skip-l2 --skip-l3 --skip-l4
```

### 4.2 完整审查（需要 API key）

```bash
# 设置 API key
export DEEPSEEK_API_KEY=sk-xxx
export GLM_API_KEY=xxx
export KIMI_API_KEY=xxx
export ANTHROPIC_API_KEY=sk-ant-xxx
export OPENAI_API_KEY=sk-xxx

# 运行完整流水线
PYTHONPATH=../../.. python3 run_pipeline.py \
    --data-file ../../../data/train_chatml_v9max.jsonl \
    --output-dir ../../../data/v9max_audited \
    --golden-dir ../../../testset_cve_fix
```

### 4.3 单独运行某一层

```bash
# 只跑 L1
python3 l1_rule_check.py --data-file xxx.jsonl

# 只跑 L2（需先有 L1 通过的 jsonl）
python3 l2_cross_vote.py --data-file xxx_l1_passed.jsonl --output xxx_l2_disputed.jsonl

# 只跑 L3（需先有 L2 分歧 jsonl）
python3 l3_arbiter.py --disputed-file xxx_l2_disputed.jsonl --output-dir l3_output

# 只跑 L4
python3 l4_golden_eval.py --golden-dir ../../../testset_cve_fix --output l4_report.json
```

## 五、成本估算（11500 条规模）

| 层 | 调用量 | 单价（估） | 成本 |
|---|---|---|---|
| L1 | 0（本地） | 免费 | 0 |
| L2 | ~23000 次（国内 API） | ~0.004 元/次 | ~50-100 元 |
| L3 | ~3000 次 Claude + 3000 次 GPT-5 | Claude ~0.08 元/次, GPT-5 ~0.05 元/次 | ~240-400 元 |
| L4 | ~300 次（国内 API） | ~0.004 元/次 | ~10-20 元 |
| **总计** | | | **300-500 元** |

> L3 是主要成本。若分歧率低于 20%，成本可降到 200 元以内。

## 六、主审选型理由

| 模型 | 推理 | 长上下文 | 代码漏洞 | 偏置 | 角色 |
|---|---|---|---|---|---|
| Claude Opus 4.1 | 最强 | 200K | 强 | 可能过度保守 | **主审** |
| GPT-5 | 强 | 128K | 强 | 综合平衡 | **副审** |
| Gemini 2.5 Pro | 强 | 1M | 中 | 代码漏洞略弱 | 备选 |

**反偏置设计**（已写入 L3 prompt）：
- 显式要求"既不过度保守也不过度宽松"
- 给出正反两面判断标准
- 要求锚定具体行号，不允许"一般性怀疑"

## 七、与现有审查流程的关系

项目已有的审查工具与 L1-L4 的关系：

| 现有工具 | 对应层 | 说明 |
|---|---|---|
| `audit_leakage_precise.py` | L1 扩展 | Jaccard 泄漏审计，可集成到 L1 |
| `audit_cot_length.py` | L1 子集 | CoT 长度审计，已合并到 L1 |
| `analyze_cwe.py` / `analyze_data.py` | L1 统计 | 数据分布分析，可复用 |

L1 是现有审查工具的整合升级版，L2-L4 是新增的分层审查机制。
