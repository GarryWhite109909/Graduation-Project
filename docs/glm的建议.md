## 六、想得到理想模型的下一步优化
按性价比排序：

### 优先级 P0（必做，否则实验站不住脚）
1. 真正的蒸馏数据 ：用glm5.2在大量代码上生成 CoT 标注，1k-5k 条起步。手写 119 条只能算 PoC。
2. 独立测试集 ：用 BigVul、NIST Juliet、SARD 或 GitHub CVE-fix 的 held-out 子集做评估，避免与训练集同分布。
3. 验证集 + early stopping ：从训练集分 15-20% 作 dev，按 dev 指标选 checkpoint。当前第 3 epoch（loss=0.27）大概率过拟合，应在 epoch 1-2 之间停。
4. 多种子 + 显著性检验 ：至少 3 个种子，报告均值±标准差，用 bootstrap 判断提升是否显著。
### 优先级 P1（明显提升）
5. 修复类别不平衡 ：每个 CWE 至少 20-30 样本，特别补充 CSRF / authz / session / integer_overflow / secret / noise 类。
6. 真实 CVE 数据 ：从 GitHub CVE-fix 抓 commit 的漏洞版本作为训练样本，多样性远超手写。
7. 数据增强 ：变量重命名、控制流等价改写、无关代码插入（训练长文件鲁棒性）。
8. 课程学习 ：典型漏洞 → 绕过变体 → 噪声 → 长文件，分阶段训练。
### 优先级 P2（条件允许再做）
9. 更强基座 ：3B 容量不足以学安全语义，换 7B/14B + 4bit（需解决 ROCm 兼容）。（可能得等明年换5070super或者现在加上cpu一起推理？ddr5带宽应该够）
10. RAG + 微调结合 ：训练集教格式 + RAG 提供具体 CWE 知识，互补。
11. 多轮对话训练 ：让模型学会"先问代码上下文再判断"，而非单轮强答。
12. DPO/RLHF ：用 baseline 错误样本作为 negative，finetuned 修正的作为 positive，做偏好优化。
### 立即能做的最小改进（不改数据）
1. 把评估改成 temperature=0.0, do_sample=False ，跑 3 个种子取均值
2. 用 checkpoint-36（epoch 2.4）和 checkpoint-45（epoch 3）分别评估，看哪个更好——大概率 36 更好
3. 给 build_dataset.py 补充 missing_control 类的 CoT 模板（不只是 source-sink 格式）
## 总结
实验6是一个 有价值的 PoC ，证明了"小规模 SFT 能让 3B 模型在注入类漏洞上显著提升"，但它 不是真正的蒸馏 ，样本量、数据来源、评估方法都达不到学术严谨标准。模型的提升主要来自模板化模式匹配，而非真正的代码理解——这解释了它在 missing_control / noise / longfile 场景下的退化。

要得到能在综合多变场景下给出"有经验判断"的模型， 核心瓶颈不在 LoRA 超参，而在训练数据的规模、多样性和真实性 。优先级最高的一步是： 用强模型生成 1k+ 条多样化 CoT 数据 + 引入独立测试集 ，这一步做完才能判断微调本身是否有效。