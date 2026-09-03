# -*- coding: utf-8 -*-
from deck_common import *

# ---------- P27 章节页 06 ----------
p27 = slide(chapter_page("06", "未来规划",
    "当前不是终点：偏好优化、数据飞轮与发布收敛，下一步路径已经清晰。",
    5, 27, en="ROADMAP · NIVIS-α1 AND BEYOND"),
    "最后是未来规划。α1 版本的路线已经明确：用 DPO 到 GRPO 做偏好对齐，用独立测试集加固评估，让数据飞轮转起来，并按两档精度发布。")
save("p27.xml", p27)

# ---------- P28 α1 路线图 ----------
b = [header("06", "未来规划", "Nivis-α1：从规则约束走向偏好对齐，让飞轮自转", 28)]
tracks = [
    ("01", "偏好优化", BLUE,
     [("DPO 起步", "用 A/B 判定对、编号错的样本构造偏好对"),
      ("GRPO 进阶", "组相对优化，奖励三闸：FP 惩罚 ≥ FN、格式门前置、证据必须接地")]),
    ("02", "评估加固", TEAL,
     [("CVE-fix 测试集", "新建 20 段真实 CVE 修复独立测试集，专测泛化"),
      ("校准独立化", "共形预测改用独立校准集，杜绝 in-sample")]),
    ("03", "数据飞轮", GOLD,
     [("信号回流", "冻结集 + 回填信号 → 去重 / 泄漏审计 / 格式校验 → 版本化"),
      ("人工批准转正", "learn_pool 中的候选必须经人工批准才进入训练池")]),
]
tx = [54, 356, 658]
for (no, nm, c, items), x in zip(tracks, tx):
    b.append(rect(x, 124, 258, 3, fill=c))
    b.append(text(x, 138, 60, 30, [no], size=20, color=c, bold=True, font=MONO))
    b.append(text(x+48, 144, 200, 22, [nm], size=15, color=INK, bold=True))
    yy = 184
    for sn, ds in items:
        b.append(rect(x, yy, 258, 86, fill=MIST, radius=8))
        b.append(rect(x, yy, 4, 86, fill=c, radius=2))
        b.append(text(x+16, yy+12, 230, 18, [sn], size=12, color=INK, bold=True))
        b.append(text(x+16, yy+34, 232, 48, [ds], size=10, color=INK2, lh=1.5))
        yy += 98
# 发布收敛条
b.append(rect(54, 386, 852, 86, fill=DARK, radius=8))
b.append(text(78, 398, 400, 14, ["RELEASE · 两档发布收敛"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(rich(78, 418, 820, 24, [f"<p>{span('HuggingFace FP16 全精度版', color=WHITE, bold=True, size=12.5)}{span('  面向研究与二次开发    ／    ', color='rgb(180,192,202)', size=12)}{span('Ollama Q4 量化版', color=WHITE, bold=True, size=12.5)}{span('  面向本地一键部署', color='rgb(180,192,202)', size=12)}</p>"]))
b.append(text(78, 444, 820, 20, ["α1 的目标不是追更高的单点指标，而是让每一次改进都可持续、可审计、可复现。"], size=11.5, color=GOLD, bold=True))
p28 = slide("".join(b),
    "α1 有三条并行路线。第一是偏好优化，从 DPO 起步走向 GRPO，奖励函数设三道闸：误报惩罚不低于漏报、格式门前置、证据必须接地。"
    "第二是评估加固，新建 20 段真实 CVE-fix 独立测试集，共形校准改用独立校准集。第三是数据飞轮，回填信号经过审计和版本化后回流，人工批准才转正。"
    "最后按 FP16 和 Q4 两档发布，分别服务研究和本地部署。")
save("p28.xml", p28)

# ---------- P29 结束页 ----------
s = ['<style><fill><fillColor color="linear-gradient(135deg,rgba(31,46,56,1) 0%,rgba(20,32,41,1) 100%)"/></fill></style>']
s.append(rect(0, 0, 960, 4, fill=GOLD))
s.append(text(54, 44, 400, 20, ["NIVIS · GRADUATION DEFENSE"], size=10, color="rgb(140,156,168)", font=MONO, ls=2))
s.append(text(54, 130, 852, 50, ["恳请各位老师批评指正"], size=38, color=WHITE, bold=True, wrap=False))
s.append(rect(54, 190, 48, 3, fill=GOLD))
s.append(text(54, 206, 852, 22, ["THANK YOU FOR YOUR TIME AND FEEDBACK"], size=12, color="rgb(140,156,168)", font=MONO, ls=2))
# 硬数字带
nums = [("96.7%", "严格召回"), ("4.3%", "误报率"), ("39,298", "行手写代码"), ("67 天", "250 次提交")]
nx = [54, 278, 502, 726]
for i, ((n, lab), x) in enumerate(zip(nums, nx)):
    s.append(rect(x, 268, 180, 96, fill="rgba(255,255,255,0.05)", radius=8))
    s.append(rect(x, 268, 180, 3, fill=GOLD))
    s.append(text(x, 286, 180, 40, [n], size=28, color=GOLD, bold=True, align="center", font=MONO, wrap=False))
    s.append(text(x, 332, 180, 20, [lab], size=11, color="rgb(198,210,218)", align="center"))
# 底部署名
s.append(line(54, 420, 906, 420, color="rgb(74,92,106)"))
s.append(text(54, 438, 500, 22, ["答辩人：白明耀"], size=13, color=WHITE, bold=True))
s.append(text(54, 462, 500, 20, ["基于大语言模型的代码安全分析系统 · Nivis"], size=10.5, color="rgb(150,166,178)"))
s.append(text(600, 438, 306, 22, ["2026 年 6 月"], size=13, color=WHITE, bold=True, align="right"))
s.append(text(600, 462, 306, 20, ["感谢指导教师与学院的支持（请填写）"], size=10.5, color="rgb(150,166,178)", align="right"))
p29 = slide("".join(s),
    "汇报到此结束。最后用四个数字收束：96.7% 的严格召回、4.3% 的误报率、39298 行手写代码、67 天 250 次提交。"
    "这套系统证明了一件事：工具召回加大模型裁决的路线，在严谨的方法论约束下，可以同时做到准、全、可复现、可落地。恳请各位老师批评指正，谢谢。", dark=True)
save("p29.xml", p29)
print("p27-p29 done")
