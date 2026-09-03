# -*- coding: utf-8 -*-
from deck_common import *

# ---------- P7 章节页 02 ----------
p7 = slide(chapter_page("02", "研究目标",
    "让大模型看得懂语义，让系统跑得在本地，让审计流程闭环。",
    1, 7, en="OBJECTIVES · WHAT WE SET OUT TO BUILD"),
    "第二章研究目标。先交代立项判断：漏洞检测走过规则、深度学习两代，大模型时代给了语义理解的新底座，我们最初的目标是做一个本地可跑的安全专用模型。"
    "三条硬目标始终没变：检测精准、流程自动化、本地可部署。下面这页展示路线如何被一个个真实问题逼成今天的样子。")
save("p07.xml", p7)

# ---------- P8 研究目标与技术路线（问题驱动叙事） ----------
b = [header("02", "研究目标", "从“安全专用模型”出发：一条被真实问题逼出来的路线", 8)]

# 立项判断：三代路线
b.append(text(54, 110, 600, 16, ["立项判断 · 漏洞检测的三代技术路线"], size=11, color=GOLD, bold=True, font=MONO, ls=1))
gen = [
    ("第一代 · 规则 SAST", "AST / 正则 / 污点分析（Bandit、Semgrep）", ["确定、可解释、零成本", "但不懂语义，规则覆盖有限"], BLUE_L, BLUE),
    ("第二代 · 深度学习", "GNN / CodeBERT 系检测（Devign、LineVul）", ["免人工规则", "但依赖大量标注，跨项目泛化差、黑盒"], TEAL_L, TEAL),
    ("第三代 · 大语言模型", "语义理解与风险推理", ["能力足够强，但开放生成不可控", "云端贵、代码不能出域——我们的机会"], GOLD_L, GOLD),
]
gx = [54, 356, 658]
for (nm, sub, lines, bg, c), x in zip(gen, gx):
    b.append(rect(x, 128, 258, 86, fill=bg, radius=8))
    b.append(rect(x, 128, 4, 86, fill=c, radius=2))
    b.append(text(x+14, 138, 232, 16, [nm], size=12, color=INK, bold=True))
    b.append(text(x+14, 158, 232, 14, [sub], size=9, color=INK2, font=MONO))
    b.append(text(x+14, 176, 232, 34, lines, size=10, color=INK2, lh=1.4))
b.append(text(54, 224, 852, 16, ["我们的起点：训练一个 16GB 显存可跑的安全专用 8B 模型；随后每一步都由上一阶段暴露的真实问题驱动"], size=11.5, color=BLUE_D, bold=True))

# 五步演进时间轴
b.append(line(96, 316, 860, 316, color="rgb(196,206,214)", w=2))
stages = [
    ("起点", "安全专用 8B", "本地可跑、补通用模型安全短板", None, TEAL),
    ("问题 1", "开放生成失控", "高误报 0.154、不可复现、成本高", "两阶段：工具召回 + 封闭裁决", BLUE),
    ("问题 2", "训练不涨归因", "SFT 只学会格式，CPT 知识注入负迁移", "方法分层：知识走 RAG、判别走证据", BLUE),
    ("问题 3", "云端依赖", "隐私出域、调用昂贵", "双教师蒸馏 8B，百元本地跑", BLUE),
    ("问题 4", "信任与落地", "误报回填污染、无候选会漏网", "信任层 + 全栈产品化", GOLD),
]
xs = [96, 287, 478, 669, 860]
for i, ((tag, nm, prob, fix, col), cx) in enumerate(zip(stages, xs)):
    b.append(f'<shape type="ellipse" topLeftX="{cx-8}" topLeftY="308" width="16" height="16"><fill><fillColor color="{col}"/></fill><border color="rgb(250,248,243)" width="2"/></shape>')
    b.append(rect(cx-86, 244, 172, 54, fill=MIST, radius=6))
    b.append(text(cx-76, 250, 158, 12, [tag], size=8.5, color=col, bold=True, font=MONO))
    b.append(text(cx-76, 264, 158, 16, [nm], size=11.5, color=INK, bold=True, wrap=False))
    b.append(text(cx-76, 282, 158, 16, [prob], size=8.5, color=INK2, lh=1.3))
    if fix:
        b.append(rect(cx-86, 330, 172, 72, fill=BLUE_L, radius=6))
        b.append(text(cx-76, 338, 158, 12, ["应对"], size=8.5, color=BLUE_D, bold=True, font=MONO))
        b.append(text(cx-76, 352, 158, 44, [fix], size=10, color=INK, bold=True, lh=1.4))
    else:
        b.append(rect(cx-86, 330, 172, 72, fill=TEAL_L, radius=6))
        b.append(text(cx-76, 338, 158, 12, ["目标"], size=8.5, color=TEAL, bold=True, font=MONO))
        b.append(text(cx-76, 352, 158, 44, ["精准检测 · 自动化 · 本地部署，三条硬目标贯穿始终"], size=10, color=INK, bold=True, lh=1.4))
# 结论条
b.append(rect(54, 424, 852, 56, fill=DARK, radius=8))
b.append(rect(54, 424, 4, 56, fill=GOLD, radius=2))
b.append(text(78, 434, 400, 14, ["META-METHOD · 贯穿全程的元方法"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(78, 454, 820, 20, ["路线不是先验规划：先判问题属于数据、模型、架构还是工程哪一层，再选对应方法——而不是换模型、堆参数碰运气。"], size=12, color=WHITE, bold=True))
p8 = slide("".join(b),
    "立项时我们判断：规则工具不懂语义，深度学习方案跨项目泛化差，而大模型第一次同时具备语义理解和风险推理能力，所以起点是做一个 16G 显存可跑的安全专用 8B 模型。"
    "但路线不是规划出来的。问题一，让模型开放式找漏洞，误报 0.154、不可复现，应对是改成工具召回加封闭裁决的两阶段；问题二，SFT 只学会输出格式、继续预训练知识注入两次失败，应对是按任务分层，知识走 RAG、判别靠证据；"
    "问题三，云端又贵又有隐私风险，应对是双教师蒸馏到 8B 本地；问题四，模型记忆会被误报污染、无候选文件会漏检，应对是 2.5 代信任层，并把它做成全栈产品。元方法是：先定位问题属于哪一层，再动手。")
save("p08.xml", p8)

# ---------- P9 章节页 03 ----------
p9 = slide(chapter_page("03", "我们的价值",
    "比最终系统更可迁移的，是四层能力：数据 · 工程 · 训练 · 实验——让不可靠的东西变可靠。",
    2, 9, en="OUR REAL VALUE · FOUR LAYERS OF TRANSFERABLE CAPABILITY"),
    "第三章讲我们的价值，主角不是指标，而是人：团队在这个项目里沉淀了四层可迁移能力。"
    "接下来五页：先给四层能力总览，再逐层展开——数据层让每条数据经得起追问，工程层把不确定性关进机制，训练层分得清什么能训什么不能硬训，实验层设计能证伪自己的测量。")
save("p09.xml", p9)
print("p07-p09 done")
