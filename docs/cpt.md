### 2.1 数据侧：从"静态混合"到"动态课程 / 优先级采样"
你们现在把 A/B/C 三层打平后按顺序写入 jsonl，训练时默认是随机 shuffle 的。但前沿工作发现： CPT 的收益很大程度上来自数据混合比例和课程安排 。
 参考：人大 YuLan 团队 Towards Effective and Efficient Continual Pre-training of Large Language Models 明确提出 data mixture + curriculum strategy 是 CPT 核心。
可做的改动：

1. 按层动态调整采样权重
   
   - 训练前期：A 知识层占比高（先建立概念）
   - 训练中后期：B 推理层 / C 代码层占比提高（学应用）
   - 实现：给 Dataset 加 WeightedRandomSampler ，按 step 线性改变权重
2. 按优先级采样，而非等概率
   
   - 你们每条语料已经有 priority: high/medium/low
   - 可以让 high 优先级样本被抽中的概率是 low 的 3~5 倍
   - 比纯去重后随机抽更充分利用"精华样本"
3. 按困惑度（PPL）做课程学习
   
   - 先用 base 模型在语料上跑一遍，得到每条样本的 PPL
   - PPL 低的先学（简单/熟悉），PPL 高的后学（困难/新颖）
   - 人大团队用这种 simple-to-complex 策略提升了稳定性
### 2.2 训练侧：降低灾难性遗忘
你们已经在 base 上做 CPT，但对 base 原有的通用代码能力仍可能有遗忘。可以加：

1. 通用代码回放（General Code Replay）
   
   - 从 base 模型的预训练分布里采一些通用 Python/GitHub 代码
   - 和漏洞语料按 1:3 ~ 1:5 混合，保护通用代码理解
   - 这是 continual learning 里防遗忘的标准做法
2. LoRA target 加 embed_tokens / lm_head
   
   - 你们现在 target 是 attention + MLP，没碰 embedding
   - 如果新领域有大量 CWE 专有术语，微调 embedding 能更好吸收
   - 代价是合并后模型体积不变，但可训练参数量增加
3. 分层学习率（Layer-wise LR）
   
   - 底层（词嵌入/浅层）用更小 LR，高层用正常 LR
   - 对领域知识注入更稳，尤其防 base 通用能力被冲
### 2.3 语料生成侧：把"知识层"再扩大
你们现在的 A 层主要来自 knowledge.json + 白名单 + 方法.md。可以低成本扩充：

1. 合成百科式知识条目
   
   - 对每个 CWE，用教师模型生成"多形式表达"：
     - 危险 API 列表
     - 安全写法对照
     - 常见误用模式
     - 与其他 CWE 的区分要点
   - 目标：同一个知识点用 5~10 种不同叙述方式出现，缓解 reversal curse
2. 把 Layer B 的推理链再"Dense"化
   
   - 现在 B 层是 ChatML/DPO 提取的 reasoning
   - 可以像 Knowledge-Instruct 那样，把知识文档转成大量 instruction-response 对
## 3. 更先进的训练模式：从 CPT 到"Instruction Pre-training" 和 "Knowledge-Instruct"
如果你们想突破 CPT 的 ceiling，有几个 2024-2025 年的范式值得考虑：

### 3.1 Knowledge-Instruct（微软，2025）
核心思想： 用合成 instruction 数据做"基于指令的持续预训练" ，而不是原始文本的 next-token prediction。
 论文： Knowledge-Instruct: Effective Continual Pre-training from Limited Data using Instructions
对你们的启发最大：

- 你们 Layer B 本质上已经是 user+assistant 的 reasoning instruction
- 可以把 Layer A 的 CWE 百科也转成 QA/填空/判断对
- 直接在 Instruct 模型上做训练（不需要先 base 再 merge）
- 事实记忆效果更好，且不易遗忘通用能力
适用性 ：你们的数据量不大（<50MB），正是 Knowledge-Instruct 擅长的"low-data regime"。

### 3.2 Instruction Pre-training（微软+清华，2024） 论文： Instruction Pre-Training: Language Models are Supervised Multitask Learners
核心：把原始语料用一个小模型生成大量 instruction-response 对，然后再做预训练。

对你们的意义：

- 你们的"三层语料"天然适合：对 Layer A 生成知识问答，对 Layer C 生成漏洞分析任务
- 可以用一个 7B 小模型当 synthesizer，把知识密度提高
### 3.3 ADEPT（北大，2025）：动态扩容 + 解耦微调 论文： ADEPT: Continual Pretraining via Adaptive Expansion and Dynamic Decoupled Tuning
核心：给模型 增加少量新层 专门学习新领域，旧层尽量不动，从而大幅降低灾难性遗忘。

- 适合你们：如果目标是"领域漏洞检测专家"，可以试 layer expansion
- 不适合：如果必须保持模型结构和原始 base 一致，就不太方便
### 3.4 Response Tuning（2024） 论文： Revealing the Inherent Inherent Instructability of Pre-Trained Language Models
核心：只训练 response 分布，不训练 instruction-response 对齐。

- 对你们 Layer B 的 CoT reasoning 有启发：也许不需要完整 ChatML，只让模型反复看高质量 assistant CoT 也能建立推理分布
- 可作为轻量化对比实验
### 3.5 Curriculum + Model Averaging（ICLR 2026 Oral） 论文： How Learning Rate Decay Wastes Your Best Data in Curriculum-Based LLM Pretraining
核心发现：

- 课程学习 + 标准 LR decay 效果会被抵消
- 解决方案：用 constant LR + 模型平均（EMA/SMA） ，或 温和 LR decay + 平均
- 可以 +1~2% 平均 benchmark 分
对你们的启发：如果做课程学习，不要把学习率衰减得太狠，同时保存多个 checkpoint 做平均 merge。