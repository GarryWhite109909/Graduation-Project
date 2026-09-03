# -*- coding: utf-8 -*-
from deck_common import *

T_LOGO = "Nnycbcv7foTs91xnMWycgJXz6Rb"

# ---------------- P1 封面 ----------------
b = []
b.append('<style><fill><fillColor color="linear-gradient(135deg,rgba(31,46,56,1) 0%,rgba(20,32,41,1) 100%)"/></fill></style>')
b.append(rect(0, 0, 960, 4, fill=GOLD))
# 左上品牌
b.append(img(T_LOGO, 54, 40, 44, 44))
b.append(text(108, 42, 200, 28, ["Nivis"], size=24, color=WHITE, bold=True, font=MONO, wrap=False, valign="middle"))
b.append(text(109, 76, 300, 16, ["Code Security Analysis, Augmented by LLM"], size=9, color="rgb(130,150,162)", font=MONO, ls=1))
# 右侧淡色大 logo 装饰
b.append(f'<shape type="ellipse" topLeftX="700" topLeftY="150" width="240" height="240"><fill><fillColor color="rgba(74,127,165,0.10)"/></fill></shape>')
b.append(img(T_LOGO, 724, 174, 192, 192))
# 主标题区
b.append(text(54, 196, 640, 30, ["毕业设计（论文）答辩"], size=13, color=TEAL, bold=True, ls=3))
b.append(text(54, 230, 630, 100, ["基于大语言模型的", "代码安全分析系统"], size=37, color=WHITE, bold=True, wrap=False, lh=1.25))
b.append(rect(56, 372, 56, 3, fill=GOLD))
b.append(text(54, 388, 620, 44, ["工具召回 × LLM 裁决的两阶段架构，", "与一套被六轮审计反复验证过的评估方法论"], size=15, color="rgb(198,210,218)", lh=1.5))
# 底部信息栏
b.append(line(54, 466, 906, 466, color=LINE_D, w=1))
info = [("答辩人", "白明耀、易卓玥"), ("指导教师", "陈纪友"), ("所在学院", "衡阳师范学院"), ("答辩日期", "2026 年 9 月")]
ix = 54
for k, v in info:
    b.append(text(ix, 478, 200, 16, [k], size=10, color="rgb(130,150,162)"))
    b.append(text(ix, 496, 210, 20, [v], size=13, color=WHITE, bold=True, wrap=False))
    ix += 215
p1 = slide("".join(b),
    "各位老师好，我们是白明耀、易卓玥，毕业设计题目是《基于大语言模型的代码安全分析系统》，项目代号 Nivis，指导教师是陈纪友老师。"
    "这套系统没有走“让大模型直接找漏洞”的常见路线，而是设计了工具召回、大模型裁决的两阶段架构，"
    "并在两个多月里做了六轮数据与评估审计。下面从研究背景、研究目标、我们的价值、项目的价值、系统演示和未来规划六个部分汇报。", dark=True)
save("p01.xml", p1)

# ---------------- P2 目录 ----------------
b = []
b.append(text(54, 40, 500, 18, ["CONTENTS"], size=11, color=BLUE, bold=True, font=MONO, ls=3))
b.append(text(54, 60, 400, 40, ["目录"], size=30, color=INK, bold=True))
b.append(rect(54, 108, 36, 3, fill=GOLD))
items = [
    ("01", "研究背景", "漏洞规模激增，规则工具与纯 LLM 各有盲区"),
    ("02", "研究目标", "从安全专用模型出发，被问题逼出的演进路线"),
    ("03", "我们的价值", "数据 · 工程 · 训练 · 实验：四层可迁移能力"),
    ("04", "项目的价值", "两阶段架构、信任层、全栈工程与双口径硬指标"),
    ("05", "系统演示", "产品界面实拍与系统演示视频"),
    ("06", "未来规划", "α0.6 开训、α1 偏好对齐、数据飞轮与发布"),
]
positions = [(54, 140), (500, 140), (54, 262), (500, 262), (54, 384), (500, 384)]
for (no, nm, desc), (x, y) in zip(items, positions):
    b.append(text(x, y, 70, 40, [no], size=30, color=BLUE, bold=True, font=MONO, valign="top"))
    b.append(text(x+72, y+2, 340, 26, [nm], size=18, color=INK, bold=True, wrap=False))
    b.append(text(x+72, y+34, 360, 34, [desc], size=11.5, color=INK2, lh=1.4))
    b.append(line(x, y+76, x+410, y+76, color=LINE, w=1))
b.append(footer(2))
p2 = slide("".join(b),
    "汇报分为六个部分。前两章交代问题与目标；第三章是我们最想讲的部分——不是展示最终数字，而是展示团队在数据、工程、训练、实验四个层面沉淀的可迁移能力；"
    "第四章给出架构、工程与双口径结果证据；第五章是真实系统界面与演示视频；第六章是 α0.6、α1 的后续路线。")
save("p02.xml", p2)

# ---------------- P3 章节页 01 ----------------
p3 = slide(chapter_page("01", "研究背景",
    "年披露漏洞逼近 5 万，人工审计追不上增长速度，单一工具也追不上漏洞的语义复杂度。",
    0, 3, en="BACKGROUND · WHY THIS PROJECT MATTERS"),
    "首先是研究背景。我们从三个事实出发：全球漏洞披露量十年涨了七倍多；传统规则工具和纯大模型在我们自己的测试面上都暴露出结构性短板；而代码大模型近五年的能力跃迁，让“让模型做裁决”成为可能。")
save("p03.xml", p3)
print("p01-p03 done")
