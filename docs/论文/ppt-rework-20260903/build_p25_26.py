# -*- coding: utf-8 -*-
from deck_common import *

T_DASH = "PTE9bgISwo3QawxeYZ5cMpYE6Jg"
T_SCAN = "BBFpbs4zEoz9CnxbD4scUJ2s6rf"
T_CWE  = "Pb6sb9mq7oaP5sxX2SucNT5Y6Mb"
T_POST = "LtTubmibAoUPDlxADUgcYTVs6pc"

# ---------- P25 仪表盘 + 扫描工作台 ----------
b = [header("05", "系统演示", "总览与扫描工作台：从代码输入到逐条裁决，全程可视", 25)]
# 行1：dashboard 图 + 说明
b.append(rect(46, 124, 316, 172, fill=WHITE, border=LINE, bw=1, radius=6))
b.append(img(T_DASH, 54, 132, 300, 156))
b.append(rect(378, 124, 528, 172, fill=MIST, radius=8))
b.append(rect(378, 124, 4, 172, fill=BLUE, radius=2))
b.append(text(400, 138, 60, 24, ["01"], size=18, color=BLUE, bold=True, font=MONO))
b.append(text(444, 142, 440, 20, ["仪表盘 · 系统总览"], size=14, color=INK, bold=True))
b.append(text(444, 172, 446, 110, ["四后端运行状态实时可见；汇总扫描文件数、待修数量，", "展示风险分 7.7、安全评分与历史趋势，", "一屏掌握仓库整体安全态势。"], size=11.5, color=INK2, lh=1.6))
# 行2：scan 图 + 说明
b.append(rect(46, 312, 316, 166, fill=WHITE, border=LINE, bw=1, radius=6))
b.append(img(T_SCAN, 54, 320, 300, 150))
b.append(rect(378, 312, 528, 166, fill=MIST, radius=8))
b.append(rect(378, 312, 4, 166, fill=TEAL, radius=2))
b.append(text(400, 326, 60, 24, ["02"], size=18, color=TEAL, bold=True, font=MONO))
b.append(text(444, 330, 440, 20, ["扫描工作台 · 主流程与可干预裁决"], size=14, color=INK, bold=True))
b.append(text(444, 360, 446, 110, ["粘贴或上传代码 → 开始分析；结果逐条展开：CWE 编号、", "命中行号、证据链、N=3 投票裁决与修复建议；每条显示", "置信度与一致性，抑制、回填、转人工均可一键操作。"], size=11.5, color=INK2, lh=1.6))
p25 = slide("".join(b),
    "先看两个核心界面。仪表盘汇总后端健康状态、文件与待修数量、风险分和安全评分；扫描工作台是主流程：粘贴或上传代码，点开始分析，结果逐条展开，"
    "每条都有 CWE 编号、行号、证据链、三次采样的裁决和修复建议。注意每条结论都显示置信度和投票一致性，抑制、回填、转人工都可以一键操作，模型决策对用户完全透明。")
save("p25.xml", p25)

# ---------- P26 CWE 库 + 安全态势 ----------
b = [header("05", "系统演示", "CWE 样本库与仓库级安全态势：从单条结论到全局视图", 26)]
b.append(rect(46, 118, 468, 262, fill=WHITE, border=LINE, bw=1, radius=6))
b.append(img(T_CWE, 54, 126, 452, 246))
b.append(rect(54, 392, 452, 96, fill=BLUE_L, radius=8))
b.append(rect(54, 392, 4, 96, fill=BLUE_D, radius=2))
b.append(text(74, 404, 420, 18, ["① CWE 样本库"], size=12.5, color=BLUE_D, bold=True))
b.append(text(74, 428, 420, 52, ["19 类 CWE 卡片，每类含风险等级、正反代码样例与修复模式；", "它既是裁决时 RAG 的知识来源，也是安全审计的学习库。"], size=10.5, color=INK, lh=1.5))
b.append(rect(624, 118, 282, 367, fill=WHITE, border=LINE, bw=1, radius=6))
b.append(img(T_POST, 632, 126, 266, 351))
b.append(rect(624, 492, 282, 22, fill=TEAL_L, radius=4))
b.append(text(632, 495, 270, 16, ["② 安全态势：评分 · 分布 · 高危文件 · P1–P4 修复优先级"], size=9, color="rgb(60,110,102)", bold=True))
p26 = slide("".join(b),
    "再看两个全局界面。CWE 样本库收录 19 类弱点卡片，每类都有风险等级、正反样例和修复模式，它同时是裁决阶段 RAG 的知识来源。"
    "右边是仓库级安全态势：整体安全评分、漏洞类型与等级分布、高危文件清单，以及按 P1 到 P4 排好的修复优先级，让开发者知道先修什么。")
save("p26.xml", p26)
print("p25-p26 done")
