# -*- coding: utf-8 -*-
from deck_common import *

# ---------- P23 全栈工程 ----------
b = [header("04", "项目的价值", "全栈工程：一套核心引擎，三端产品 × 四后端跨平台", 23)]
# 左：代码量
b.append(rect(54, 122, 4, 18, fill=BLUE))
b.append(text(66, 122, 320, 20, ["CODEBASE · 手写代码量（git 实测）"], size=11, color=BLUE, bold=True, font=MONO, ls=1))
code_rows = [
    ("核心引擎", "25 个文件 · 18,915 行 Python"),
    ("Web 端", "后端 4,764 行 / 前端 8,386 行"),
    ("IDE 插件", "VS Code 841 行 / IntelliJ 347 行"),
    ("Launcher / CLI", "6,045 行"),
]
yy = 152
for nm, ds in code_rows:
    b.append(rect(66, yy+5, 6, 6, fill=BLUE))
    b.append(text(82, yy, 200, 18, [nm], size=12, color=INK, bold=True))
    b.append(text(82, yy+20, 300, 18, [ds], size=10.5, color=INK2, font=MONO))
    yy += 50
b.append(rect(54, 356, 330, 66, fill=DARK, radius=8))
b.append(text(72, 366, 300, 14, ["合计手写"], size=9.5, color="rgb(150,166,178)"))
b.append(rich(72, 384, 300, 30, [f"<p>{span('39,298 行', color=GOLD, bold=True, size=22, font=MONO)}{span('  ·  52 个核心文件', color=WHITE, size=12)}</p>"]))
# 右：矩阵
mx, my = 414, 122
b.append(rect(mx, my, 4, 18, fill=TEAL))
b.append(text(mx+12, my, 400, 20, ["四后端 × 五硬件平台支持矩阵"], size=13, color=INK, bold=True))
cols = ["CUDA", "RTX 50", "ROCm", "Apple", "CPU"]
c0 = 130; cw = 72
ty = 150
b.append(rect(mx, ty, c0+cw*5, 28, fill=DARK))
b.append(text(mx+10, ty+7, c0-12, 18, ["后端 / 硬件"], size=9.5, color=WHITE, bold=True))
for j, c in enumerate(cols):
    b.append(text(mx+c0+j*cw, ty+7, cw, 18, [c], size=9.5, color=WHITE, bold=True, align="center"))
matrix = [
    ("Ollama", [2,2,2,2,2]),
    ("Transformers · Win", [2,1,0,-1,2]),
    ("Transformers · Linux", [2,2,1,1,2]),
    ("llama.cpp · Linux", [2,2,2,2,2]),
    ("llama.cpp · Win", [2,0,0,-1,2]),
    ("vLLM", [2,2,0,0,0]),
]
mark = {2: ("●", TEAL), 1: ("◐", GOLD), 0: ("—", INK3), -1: ("N/A", "rgb(206,210,214)")}
ry = ty+28
for i, (nm, vals) in enumerate(matrix):
    bg = MIST if i % 2 == 0 else WHITE
    b.append(rect(mx, ry, c0+cw*5, 32, fill=bg))
    b.append(text(mx+10, ry+8, c0-12, 18, [nm], size=9.5, color=INK, valign="middle"))
    for j, v in enumerate(vals):
        sym, col = mark[v]
        b.append(text(mx+c0+j*cw, ry+7, cw, 20, [sym], size=13, color=col, align="center", font=MONO, bold=True))
    ry += 32
# 图例
ly = ry+8
for j, (sym, lab, col) in enumerate([("●", "原生支持", TEAL), ("◐", "需额外配置", GOLD), ("—", "不支持", INK3)]):
    b.append(text(mx+10+j*150, ly, 30, 16, [sym], size=12, color=col, font=MONO, bold=True))
    b.append(text(mx+30+j*150, ly+1, 120, 16, [lab], size=9.5, color=INK2))
# 底部条
b.append(rect(54, 440, 852, 54, fill=DARK, radius=8))
b.append(rect(54, 440, 4, 54, fill=GOLD, radius=2))
b.append(rich(78, 454, 820, 30, [f"<p>{span('67 天 · 246 次提交', color=GOLD, bold=True, size=13, font=MONO)}{span('（2026-06-28 → 09-03），另有 914 段手写样本——从算法到产品全部自主完成', color=WHITE, size=12)}</p>"]))
p23 = slide("".join(b),
    "工程上，这套系统不是 demo。左边是 git 实测的手写代码量：核心引擎 18915 行 Python，加上 Web、两个 IDE 插件和命令行，合计手写 39298 行、52 个核心文件。"
    "右边是后端兼容矩阵：Ollama、Transformers、llama.cpp、vLLM 四套后端，覆盖 CUDA、AMD、苹果芯片和纯 CPU。67 天、246 次提交，从算法到产品全部自主完成。")
save("p23.xml", p23)

# ---------- P24 章节页 05 ----------
p24 = slide(chapter_page("05", "系统演示",
    "从粘贴代码到 SARIF 报告，每一个界面背后，都是刚才那套引擎在真实运行。",
    4, 24, en="LIVE SYSTEM · A FULL-STACK PRODUCT, NOT A DEMO"),
    "第五章系统演示。我会展示仪表盘、扫描工作台、CWE 样本库和仓库级安全态势四个真实界面。"
    "请大家注意，界面上每一个数字和裁决都来自实时运行的后端，不是预先准备的截图脚本。")
save("p24.xml", p24)
print("p23-p24 done")
