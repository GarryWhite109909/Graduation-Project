# -*- coding: utf-8 -*-
from deck_common import *

T_ARCH = "GQftbMSxlosniGxO6aGcjvRH63d"

# ---------- P15 章节页 04 ----------
p15 = slide(chapter_page("04", "项目的价值",
    "架构、数据、结果、工程：每一个结论背后，都有可运行的代码与可复现的实验。",
    3, 15, en="PROJECT VALUE · ARCHITECTURE, DATA, RESULTS, ENGINEERING"),
    "第四章进入项目本体。我会按总体架构、两个阶段、信任层、数据工程、核心结果、自研工具链和全栈工程的顺序展开，"
    "每一页的数字都来自我们自己的实验与代码仓库，可以现场复现。")
save("p15.xml", p15)

# ---------- P16 总体架构 ----------
b = [header("04", "项目的价值", "总体架构：工具召回 × LLM 裁决，信任层兜底", 16)]
b.append(img(T_ARCH, 54, 120, 572, 358, radius=8))
b.append(text(54, 484, 572, 14, ["图：fixed5 两阶段总体架构与 2.5 代信任层（工程实现与本图一致）"], size=9, color=INK3))
rx = 648
b.append(text(rx, 122, 260, 16, ["ARCHITECTURE · 三层结构"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
layers = [
    ("STAGE 1", "四路并行召回", "自研 TaintTracker / Prefilter 与 Semgrep、外部扫描器并行，候选带证据链与行号", BLUE, BLUE_L),
    ("STAGE 2", "封闭裁决", "RAG 注入 CWE 知识，CodeSlicer 切片，N=3 采样多数投票，只判候选真伪", TEAL, TEAL_L),
    ("TRUST 2.5", "信任层兜底", "A–E 分级 + 四重门控回填；无候选分支抽样 / 全量复核，绝不直接放行", GOLD, GOLD_L),
]
yy = 142
for tag, nm, ds, c, bg in layers:
    b.append(rect(rx, yy, 258, 88, fill=bg, radius=8))
    b.append(rect(rx, yy, 4, 88, fill=c, radius=2))
    b.append(text(rx+16, yy+9, 230, 14, [tag], size=9, color=c, bold=True, font=MONO, ls=1))
    b.append(text(rx+16, yy+24, 230, 18, [nm], size=13, color=INK, bold=True))
    b.append(text(rx+16, yy+45, 232, 40, [ds], size=10, color=INK2, lh=1.4))
    yy += 98
b.append(rect(rx, 436, 258, 60, fill=DARK, radius=8))
b.append(text(rx+16, 446, 230, 14, ["模型调用次数"], size=10, color="rgb(150,166,178)"))
b.append(rich(rx+16, 462, 232, 30, [f"<p>{span('216 → 65', color=GOLD, bold=True, size=22, font=MONO)}{span('   约降 70%', color=WHITE, size=11)}</p>"]))
p16 = slide("".join(b),
    "这是系统总体架构。Stage 1 四路并行召回，自研工具和开源工具一起上，每个候选都带证据链和行号；Stage 2 不开放找洞，只对候选做封闭裁决，"
    "RAG 注入 CWE 知识、代码切片、三次采样多数投票；2.5 代信任层负责分级回填和复核兜底。一个直接收益：模型调用次数从 216 次降到 65 次，大约省了 70%。")
save("p16.xml", p16)

# ---------- P17 Stage1 四泳道 ----------
b = [header("04", "项目的价值", "Stage 1 · 四路并行召回：让确定性工具把候选找全", 17)]
lanes = [
    ("iconpark/Connect/network-tree.svg", "TaintTracker", "自研", BLUE,
     "AST 级污点分析，自动追踪 source → sink 数据流路径", "产出数据流证据链"),
    ("iconpark/Edit/find.svg", "Semgrep", "开源", TEAL,
     "taint 模式整文件扫描，补齐跨函数与框架规则", "产出模式匹配候选"),
    ("iconpark/Edit/filter.svg", "Prefilter", "自研", BLUE,
     "高性能正则预筛，毫秒级覆盖硬编码密钥与危险函数", "产出确定性问题"),
    ("iconpark/Base/all-application.svg", "ExternalScanner", "集成", GOLD,
     "封装 Bandit / Gitleaks / Trivy，覆盖 sast · secret · sca · iac", "产出外部工具结果"),
]
yy = 124
for ic, nm, tag, c, ds, out in lanes:
    b.append(rect(54, yy, 852, 72, fill=MIST, radius=8))
    b.append(rect(54, yy, 4, 72, fill=c, radius=2))
    b.append(icon(ic, 78, yy+18, 36, color=c))
    b.append(text(132, yy+14, 180, 20, [nm], size=14, color=INK, bold=True, wrap=False, font=MONO))
    b.append(rect(132, yy+38, 40, 18, fill=c, radius=9))
    b.append(text(132, yy+40, 40, 16, [tag], size=9, color=WHITE, align="center", bold=True))
    b.append(text(300, yy+18, 380, 40, [ds], size=11.5, color=INK2, lh=1.5, valign="middle"))
    b.append(text(700, yy+18, 190, 40, [out], size=11, color=BLUE_D, bold=True, lh=1.4, valign="middle"))
    yy += 80
# 汇合条
b.append(rect(54, yy+4, 852, 52, fill=DARK, radius=8))
b.append(text(74, yy+14, 820, 18, ["四路候选汇合：合并去重 + CWE 归一 → 统一证据格式（行号 · source-sink · 规则 ID）→ 送 Stage 2 裁决"], size=12.5, color=WHITE, bold=True, valign="middle"))
p17 = slide("".join(b),
    "Stage 1 有四条并行召回线路。两个是我们自研的：TaintTracker 做 AST 级污点追踪，给出 source 到 sink 的数据流证据；Prefilter 用正则毫秒级抓硬编码密钥这类确定性问题。"
    "另外两条集成开源能力：Semgrep 补跨函数规则，ExternalScanner 把 Bandit、Gitleaks、Trivy 封在一起，覆盖 SAST、密钥、供应链和 IaC。四路结果合并去重、CWE 归一后，带着统一证据格式进入第二阶段。")
save("p17.xml", p17)

# ---------- P18 Stage2 封闭裁决 ----------
b = [header("04", "项目的价值", "Stage 2 · 封闭裁决：把开放作文变成三选一", 18)]
# 左：裁决流水线
b.append(rect(54, 118, 4, 18, fill=TEAL))
b.append(text(66, 118, 400, 20, ["裁决流水线 · 证据约束下的判别"], size=13.5, color=INK, bold=True))
flow = [
    ("输入", "Stage 1 候选：证据链 + 行号 + 代码切片", BLUE),
    ("处理 1", "RAG 检索注入对应 CWE 的判据与安全反例", TEAL),
    ("处理 2", "CodeSlicer 切出最小相关上下文，拒绝整文件投喂", TEAL),
    ("处理 3", "N=3 次独立采样，多数投票定结论", TEAL),
]
yy = 142
for tag, ds, c in flow:
    b.append(rect(70, yy, 470, 46, fill=MIST, radius=8))
    b.append(rect(70, yy, 4, 46, fill=c, radius=2))
    b.append(text(88, yy+7, 80, 16, [tag], size=10, color=c, bold=True, font=MONO))
    b.append(text(88, yy+24, 440, 18, [ds], size=11.5, color=INK))
    if tag != "处理 3":
        b.append(line(305, yy+46, 305, yy+58, color="rgb(160,172,182)", w=2, arrow="arrow"))
    yy += 58
# 三输出
outs = [("确认漏洞", "带 CWE 编号与理由", RED, RED_L),
        ("确认安全", "高置信否定进抑制池", TEAL, TEAL_L),
        ("存疑", "转人工复核", GOLD, GOLD_L)]
ox = [70, 232, 394]
for (nm, ds, c, bg), x in zip(outs, ox):
    b.append(rect(x, 374, 146, 46, fill=bg, radius=8))
    b.append(text(x, 382, 146, 18, [nm], size=12, color=c, bold=True, align="center"))
    b.append(text(x, 402, 146, 16, [ds], size=9, color=INK2, align="center"))
# 右：无候选兜底
b.append(rect(574, 118, 332, 302, fill=BLUE_L, radius=8))
b.append(rect(574, 118, 4, 302, fill=BLUE_D, radius=2))
b.append(text(594, 134, 300, 18, ["无候选分支 · 不直接放行"], size=13.5, color=BLUE_D, bold=True))
guards = [
    ("10% 抽样", "工具无候选的文件默认抽样 10% 送 LLM 复核，捕捉工具盲区"),
    ("全量兜底", "生产与评估默认 full_recheck 全量复核，安全优先于成本"),
    ("命中扩审", "抽样一旦命中，立即扩大该批次审计范围"),
]
gy = 168
for nm, ds in guards:
    b.append(rect(594, gy+4, 6, 6, fill=BLUE_D))
    b.append(text(610, gy, 280, 18, [nm], size=12, color=INK, bold=True))
    b.append(text(610, gy+20, 284, 40, [ds], size=10.5, color=INK2, lh=1.45))
    gy += 78
# 底部对比
b.append(rect(54, 432, 852, 64, fill=DARK, radius=8))
b.append(text(78, 442, 400, 14, ["WHY IT WORKS · 封闭裁决 vs 开放生成"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(rich(78, 462, 820, 30, [
    f"<p>{span('开放生成：', color='rgb(220,140,138)', bold=True, size=12)}{span('幻觉不可复现、整文件投喂成本高    →    ', color='rgb(200,210,218)', size=12)}{span('封闭裁决：', color=GOLD, bold=True, size=12)}{span('证据约束、投票可复现、调用量约降 70%', color=WHITE, bold=True, size=12)}</p>"]))
p18 = slide("".join(b),
    "Stage 2 的关键是封闭：输入只有 Stage 1 的候选，先 RAG 注入 CWE 判据，再用 CodeSlicer 切最小上下文，然后三次独立采样多数投票，输出只有确认漏洞、确认安全、存疑三选一。"
    "右边是兜底设计：工具没候选的文件绝不直接放行，默认抽样 10%，生产和评估环境用全量复核。开放生成有幻觉、不可复现、成本高，封闭裁决三个问题一起解决。")
save("p18.xml", p18)
print("p15-p18 done")
