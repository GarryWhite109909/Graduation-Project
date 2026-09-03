# -*- coding: utf-8 -*-
from deck_common import *

# ---------- P28 章节页 06 ----------
p28 = slide(chapter_page("06", "未来规划",
    "当前不是终点：α0.6 训练在即，α1 偏好对齐、评估飞轮与两档发布路径已经清晰。",
    5, 28, en="ROADMAP · NIVIS-α0.6, α1 AND BEYOND"),
    "最后是未来规划。先明确状态：α0.6 和 α1 都还没有开始训练，方案、脚本和语料已经就绪。路线分四步：α0.6 开训验证闭环、α1 偏好对齐、评估飞轮固化、两档发布。")
save("p28.xml", p28)

# ---------- P29 路线图：α0.6 → α1 → 飞轮 → 发布 ----------
b = [header("06", "未来规划", "下一步：α0.6 开训验证闭环，α1 走向偏好对齐", 29)]
tracks = [
    ("01", "α0.6 开训", BLUE,
     [("语料已冻结", "10,167 条经 15 个审计版本，覆盖缺口清零"),
      ("验证闭环", "启动 SFT，首次跑通“蒸馏→训练→双口径评估”全链路")]),
    ("02", "α1 偏好对齐", TEAL,
     [("DPO 起步", "用 A/B 判定对、编号错的样本构造偏好对"),
      ("GRPO 进阶", "奖励三闸：FP 惩罚 ≥ FN、格式门前置、证据接地")]),
    ("03", "评估飞轮", GOLD,
     [("独立集已建", "20 段真实 CVE-fix；共形预测改用独立校准集"),
      ("人工批准转正", "learn_pool 管道就绪，候选经人工批准才进训练池")]),
    ("04", "两档发布", BLUE_D,
     [("HuggingFace FP16", "全精度版，面向研究与二次开发"),
      ("Ollama Q4", "量化版，16GB 本地一键部署")]),
]
tx = [54, 269, 484, 699]
for (no, nm, c, items), x in zip(tracks, tx):
    b.append(rect(x, 124, 207, 3, fill=c))
    b.append(text(x, 136, 50, 28, [no], size=18, color=c, bold=True, font=MONO))
    b.append(text(x+40, 140, 160, 22, [nm], size=13.5, color=INK, bold=True, wrap=False))
    yy = 178
    for sn, ds in items:
        b.append(rect(x, yy, 207, 88, fill=MIST, radius=8))
        b.append(rect(x, yy, 4, 88, fill=c, radius=2))
        b.append(text(x+14, yy+12, 182, 16, [sn], size=11, color=INK, bold=True))
        b.append(text(x+14, yy+32, 184, 52, [ds], size=9.5, color=INK2, lh=1.5))
        yy += 98
# 状态声明条
b.append(rect(54, 386, 852, 88, fill=DARK, radius=8))
b.append(rect(54, 386, 4, 88, fill=GOLD, radius=2))
b.append(text(78, 398, 400, 14, ["STATUS · 状态声明"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(78, 418, 820, 20, ["α0.6 与 α1 均未开始训练：方案、脚本、语料已就绪，本页不预支任何结果。"], size=12, color=WHITE, bold=True))
b.append(text(78, 442, 820, 20, ["当前线上：α0.5 + 两阶段 + wave8 信任层　／　下一里程碑：α0.6 开训"], size=11, color="rgb(180,192,202)"))
p29 = slide("".join(b),
    "路线分四步。第一步 α0.6：10167 条语料已经过 15 个审计版本冻结、覆盖缺口清零，开训后首次完整验证蒸馏、训练、双口径评估闭环。"
    "第二步 α1：DPO 起步、GRPO 进阶，奖励函数三道闸。第三步评估飞轮：20 段真实 CVE-fix 独立集已建好，回流必须人工批准。第四步按 FP16 和 Q4 两档发布。"
    "特别声明：α0.6 和 α1 都未开训，这里不预支任何结果。")
save("p29.xml", p29)

# ---------- P30 结束页 ----------
s = ['<style><fill><fillColor color="linear-gradient(135deg,rgba(31,46,56,1) 0%,rgba(20,32,41,1) 100%)"/></fill></style>']
s.append(rect(0, 0, 960, 4, fill=GOLD))
s.append(text(54, 44, 400, 20, ["NIVIS · GRADUATION DEFENSE"], size=10, color="rgb(140,156,168)", font=MONO, ls=2))
s.append(text(54, 130, 852, 50, ["恳请各位老师批评指正"], size=38, color=WHITE, bold=True, wrap=False))
s.append(rect(54, 190, 48, 3, fill=GOLD))
s.append(text(54, 206, 852, 22, ["THANK YOU FOR YOUR TIME AND FEEDBACK"], size=12, color="rgb(140,156,168)", font=MONO, ls=2))
nums = [("100%", "合成集召回"), ("4.3%", "误报率"), ("1.000", "真实 CVE 严格归因"), ("39,298", "行手写代码")]
nx = [54, 278, 502, 726]
for (n, lab), x in zip(nums, nx):
    s.append(rect(x, 268, 180, 96, fill="rgba(255,255,255,0.05)", radius=8))
    s.append(rect(x, 268, 180, 3, fill=GOLD))
    s.append(text(x, 286, 180, 40, [n], size=27, color=GOLD, bold=True, align="center", font=MONO, wrap=False))
    s.append(text(x, 332, 180, 20, [lab], size=11, color="rgb(198,210,218)", align="center"))
s.append(line(54, 420, 906, 420, color="rgb(74,92,106)"))
s.append(text(54, 438, 500, 22, ["答辩人：白明耀、易卓玥"], size=13, color=WHITE, bold=True))
s.append(text(54, 462, 500, 20, ["指导教师：陈纪友 · 衡阳师范学院"], size=10.5, color="rgb(150,166,178)"))
s.append(text(600, 438, 306, 22, ["2026 年 9 月"], size=13, color=WHITE, bold=True, align="right"))
s.append(text(600, 462, 306, 20, ["基于大语言模型的代码安全分析系统 · Nivis"], size=10.5, color="rgb(150,166,178)", align="right"))
p30 = slide("".join(s),
    "汇报到此结束。最后用四个数字收束：合成集召回 100%、误报率 4.3%、20 段真实 CVE 严格归因 1.000、39298 行手写代码；"
    "67 天 246 次提交。这套系统证明了一件事：工具召回加大模型裁决的路线，在严谨的方法论约束下，可以同时做到准、全、可复现、可落地。恳请各位老师批评指正，谢谢。", dark=True)
save("p30.xml", p30)
print("p28-p30 done")
