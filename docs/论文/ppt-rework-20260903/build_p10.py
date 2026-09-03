# -*- coding: utf-8 -*-
from deck_common import *

b = [header("03", "我们的价值", "四层可迁移能力：一套让“不可靠”变“可靠”的方法论", 10)]

cards = [
    ("01", "数据层", "DATA", "iconpark/Office/doc-success.svg", BLUE, BLUE_L,
     ["给标签找最高权威：MITRE / NVD / GHSA 官方对齐",
      "先摸清失败模式，再按弱点定向补数据",
      "AI 审查 AI：双分区防合谋、六步协议、26 类错误分级"],
     "15 个审计版本 · 6 轮泄漏审计 · 68 个真实 CVE 对齐修 11 处"),
    ("02", "工程层", "ENGINEERING", "iconpark/Base/setting.svg", TEAL, TEAL_L,
     ["把模型注意力当预算：两级调度，先预筛后精审",
      "划清“提示”与“判定”的边界，机制替代许愿",
      "确定性优先：正则/AST 能解决的不调 LLM"],
     "送审 5,575→285 字符 · 调用 216→65，约降 70%"),
    ("03", "训练层", "TRAINING", "iconpark/Health/brain.svg", GOLD, GOLD_L,
     ["先判任务需要基座的什么能力，再选训练手段",
      "分得清什么能训、什么不能硬训（CPT 两次失败后果断放弃）",
      "为泛化设计变体数据，每轮只动一个变量"],
     "双教师蒸馏 8B、约百元成本 · 10,167 条语料冻结待训"),
    ("04", "实验层", "EXPERIMENT", "iconpark/Hardware/microscope-one.svg", BLUE_D, BLUE_L,
     ["主动设计能证伪自己的实验",
      "loose/strict + micro/加权双口径，测量与自举隔离",
      "归因分流记账，把每次失败沉淀成检查制度"],
     "N=3 + Bootstrap · score_batch 一键复算 · 三层测试面"),
]
xs = [54, 269, 484, 699]
CW, CH = 207, 262
for (no, nm, en, ic, c, bg, skills, proof), x in zip(cards, xs):
    b.append(rect(x, 118, CW, CH, fill=MIST, radius=8))
    b.append(rect(x, 118, CW, 4, fill=c, radius=2))
    b.append(icon(ic, x+16, 136, 26, color=c))
    b.append(text(x+52, 134, 140, 22, [nm], size=15, color=INK, bold=True))
    b.append(text(x+52, 158, 140, 12, [f"LAYER {no} · {en}"], size=8, color=c, bold=True, font=MONO))
    b.append(line(x+14, 178, x+CW-14, 178, color=LINE))
    b.append(text(x+14, 186, 180, 12, ["会什么 · CAPABILITY"], size=8.5, color=c, bold=True, font=MONO, ls=1))
    yy = 204
    for sk in skills:
        b.append(rect(x+14, yy+5, 5, 5, fill=c))
        b.append(text(x+26, yy, CW-40, 42, [sk], size=9.5, color=INK, lh=1.4))
        yy += 48
    b.append(rect(x+12, 336, CW-24, 36, fill=bg, radius=6))
    b.append(text(x+22, 342, CW-44, 28, [proof], size=8.5, color=INK, bold=True, lh=1.4, valign="middle"))
# 底部元能力条
b.append(rect(54, 396, 852, 82, fill=DARK, radius=8))
b.append(rect(54, 396, 4, 82, fill=GOLD, radius=2))
b.append(text(78, 408, 400, 14, ["META-CAPABILITY · 贯穿四层的元能力"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(78, 428, 816, 44, ["主动寻找并验证方法论：遇到新问题，先判断它属于数据、工程、训练还是实验层，再选对应工具——", "方法论本身就是可迁移能力。终点不是训出一个模型，而是知道怎么让不可靠的东西变得可靠。"], size=12.5, color=WHITE, bold=True, lh=1.5))
p10 = slide("".join(b),
    "这页是第三章总览。我们把自己在项目里沉淀的能力归成四层。数据层：给标签找官方权威、先摸失败模式再补数据、用不同家族的模型互相审查；"
    "工程层：把模型的注意力当预算做两级调度，分清提示和机制的边界，确定性问题不花 LLM 的钱；训练层：先分析任务需要基座的什么能力，分得清什么能训练、什么硬训反而有害；"
    "实验层：主动设计能证伪自己的实验，双口径测量、归因分流，把每次失败固化成下一轮的检查项。贯穿四层的元能力是寻找方法论本身——这比任何单一模型都更可迁移。")
save("p10.xml", p10)
print("p10 done")
