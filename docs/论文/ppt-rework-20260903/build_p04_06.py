# -*- coding: utf-8 -*-
from deck_common import *

# ============ P4 NVD 漏洞增长 ============
b = [header("01", "研究背景", "十年 7.4 倍：漏洞披露量进入高速增长区间", 4)]
# 柱图
chart = '''<chart width="556" height="350" topLeftX="54" topLeftY="118">
  <chartPlotArea>
    <chartPlot type="column">
      <chartExtra/>
      <chartLabels position="outside" value="true" fontSize="8" format="#,##0" color="rgba(91,103,112,1)"/>
    </chartPlot>
    <chartAxes>
      <chartAxis type="x"><chartLabel fontSize="9"/></chartAxis>
      <chartAxis type="y" position="left">
        <chartGridLine color="rgb(226,230,234)"/>
        <chartLabel fontSize="9" format="#,##0"/>
      </chartAxis>
    </chartAxes>
  </chartPlotArea>
  <chartLegend position="bottom" fontSize="10"/>
  <chartData>
    <dim1><chartField name="年份">2015,2016,2017,2018,2019,2020,2021,2022,2023,2024,2025</chartField></dim1>
    <dim2>
      <chartField name="历年披露量">6500,9700,14700,16500,17300,18300,20100,25400,29000,,</chartField>
      <chartField name="近两年（高压区间）">,,,,,,,,,40000,48185</chartField>
    </dim2>
  </chartData>
  <chartStyle>
    <chartBackground color="rgba(0,0,0,0)"/>
    <chartBorder color="rgb(255,255,255)" width="0"/>
    <chartColorTheme><color value="rgb(74,127,165)"/><color value="rgb(192,80,77)"/></chartColorTheme>
  </chartStyle>
</chart>'''
b.append(chart)
# 右侧结论
rx = 640
b.append(text(rx, 124, 260, 16, ["KEY FINDING · 关键判断"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(rx, 144, 260, 60, ["7.4×"], size=52, color=INK, bold=True, font=MONO, wrap=False))
b.append(text(rx, 208, 266, 18, ["2015 → 2025，年新增 CVE 增长 7.4 倍"], size=11, color=INK2))
b.append(line(rx, 238, 900, 238, color=LINE, w=1))
pts = [
    ("48,185 条", "2025 年新增 CVE，连续两年站上 4 万量级"),
    ("≈132 条/天", "平均每自然日新增逾百条，人工审计产能无法同步扩张"),
    ("语义化趋势", "业务逻辑与组合缺陷占比上升，正则规则越来越难覆盖"),
]
yy = 250
for k, v in pts:
    b.append(rect(rx, yy+4, 6, 6, fill=GOLD))
    b.append(rich(rx+16, yy, 256, 20, [f"<p>{span(k, color=BLUE_D, bold=True, size=12.5, font=MONO)}</p>"]))
    b.append(text(rx+16, yy+20, 256, 30, [v], size=11, color=INK2, lh=1.4))
    yy += 68
b.append(text(54, 492, 600, 14, ["数据来源：NIST National Vulnerability Database（2026-01 检索），仅统计 Published 条目，不含预留/拒绝记录"], size=9, color=INK3))
p4 = slide("".join(b),
    "先看问题规模。NVD 的年新增 CVE 从 2015 年的 6500 条增长到 2025 年的 48185 条，十年 7.4 倍，平均每天新增超过 130 条。"
    "更关键的是结构变化：越来越多漏洞是业务逻辑和组合缺陷，靠正则匹配的传统工具越来越难覆盖，人工审计的产能也不可能线性扩张。")
save("p04.xml", p4)

# ============ P5 三方法实测对比（2026-09-03 最新口径） ============
b = [header("01", "研究背景", "自建测试面实测：规则工具看不全，纯 LLM 在真实代码上现形", 5)]
chart = '''<chart width="540" height="336" topLeftX="54" topLeftY="120">
  <chartPlotArea>
    <chartPlot type="column">
      <chartExtra/>
      <chartLabels position="outside" value="true" fontSize="9" format="0.0%" color="rgba(91,103,112,1)"/>
    </chartPlot>
    <chartAxes>
      <chartAxis type="x"><chartLabel fontSize="10"/></chartAxis>
      <chartAxis type="y" position="left">
        <chartGridLine color="rgb(226,230,234)"/>
        <chartLabel fontSize="9" format="0%"/>
      </chartAxis>
    </chartAxes>
  </chartPlotArea>
  <chartLegend position="bottom" fontSize="10"/>
  <chartData>
    <dim1><chartField name="方法（14 段典型样本）">纯 LLM 零样本,Bandit,Semgrep</chartField></dim1>
    <dim2>
      <chartField name="召回率">1.000,0.833,0.750</chartField>
      <chartField name="误报率">0.000,0.500,0.000</chartField>
      <chartField name="准确率">1.000,0.750,0.786</chartField>
    </dim2>
  </chartData>
  <chartStyle>
    <chartBackground color="rgba(0,0,0,0)"/>
    <chartBorder color="rgb(255,255,255)" width="0"/>
    <chartColorTheme><color value="rgb(74,127,165)"/><color value="rgb(192,80,77)"/><color value="rgb(111,163,155)"/></chartColorTheme>
  </chartStyle>
</chart>'''
b.append(chart)
rx = 616
b.append(text(rx, 120, 280, 16, ["EXP_02 · 14 段典型样本同题对打"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
rows = [
    ("Bandit", "召回 83.3% 但误报率 50%：把一半安全代码判成漏洞，关键案例与 Semgrep 双漏", RED),
    ("Semgrep", "误报为 0 但召回仅 75.0%：规则覆盖不到的写法一律看不见", BLUE),
    ("纯 LLM", "14 段小样本满分 ≠ 真实可用，需要更大、更真实的测试面", TEAL),
]
yy = 142
for t, v, c in rows:
    b.append(rect(rx, yy, 4, 48, fill=c))
    b.append(text(rx+14, yy-2, 272, 18, [t], size=12.5, color=INK, bold=True, font=MONO))
    b.append(text(rx+14, yy+18, 272, 34, [v], size=10.5, color=INK2, lh=1.45))
    yy += 62
b.append(line(rx, yy, 896, yy, color=LINE))
b.append(text(rx, yy+10, 280, 16, ["放大到 87 段合成集 + 20 段真实 CVE"], size=11.5, color=INK, bold=True))
b.append(rich(rx, yy+32, 282, 74, [
    "<p>" + span("纯 LLM 合成集误报 15.4%", color=BLUE_D, bold=True, size=11) +
    span("；真实 CVE-fix 召回仅 0.375", color=INK, size=11) + "</p>",
    "<p>" + span("合成集相对真实集虚高 59.2pp", color=RED, bold=True, size=11) +
    span("，单一测试集会自我误导", color=INK2, size=10.5) + "</p>"]))
b.append(rect(54, 452, 852, 40, fill=BLUE_L, radius=6))
b.append(text(72, 462, 820, 22, ["结论：规则工具“看不全 / 喊得多”，纯 LLM“合成集好看、真实代码现形”——工具找全、LLM 判准的分工是唯一解"], size=12, color=BLUE_D, bold=True, valign="middle"))
b.append(text(54, 498, 852, 14, ["口径：exp_02 为 14 段典型样本同题对打；87 段合成集为 fixed5 干净评估；20 段真实 CVE-fix anchor；2026-09-03 冻结，score_batch 可复现"], size=9, color=INK3))
p5 = slide("".join(b),
    "这张图全部来自我们自建测试面的同题对打，口径是 2026 年 9 月冻结的最新版本。在 14 段典型样本上，Bandit 召回 83.3% 但误报率高达 50%，Semgrep 零误报但召回只有 75%，纯大模型看似满分。"
    "但把测试面放大到 87 段合成集，纯 LLM 误报率 15.4%；换到 20 段真实 CVE-fix，召回只有 0.375，合成集虚高 59.2 个百分点。任何单一路线都不达标，分工架构是被数据逼出来的选择。")
save("p05.xml", p5)

# ============ P6 双基准：HumanEval + SWE-bench Verified 十厂家演进 ============
b = [header("01", "研究背景", "五年两个基准：代码智能从“能写函数”走到“能修真实仓库”", 6)]

# ---- 左：自绘 SWE-bench Verified 散点 ----
PX0, PY0, PW, PH = 96, 140, 496, 226
def sx(i):  # 2024-01 = 0, 每月一格, 2026-03 = 26
    return round(PX0 + i * PW / 26.0, 1)
def sy(v):  # 10% -> 底, 85% -> 顶
    return round(PY0 + PH - (v - 10) / 75.0 * PH, 1)
# 绘图区底框
b.append(rect(PX0, PY0, PW, PH, fill=MIST, radius=2))
# y 轴刻度值（不画穿图横线，避免压字）
for gv in [20, 40, 60, 80]:
    gy = sy(gv)
    b.append(text(PX0-36, gy-7, 32, 13, [f"{gv}%"], size=8, color=INK3, align="right", font=MONO))
# x 轴基线与刻度
b.append(line(PX0, PY0+PH, PX0+PW, PY0+PH, color=INK3, w=1))
for i, lab in [(0,"2024.01"),(6,"2024.07"),(12,"2025.01"),(18,"2025.07"),(24,"2026.01")]:
    gx = sx(i)
    b.append(line(gx, PY0+PH, gx, PY0+PH+4, color=INK3, w=1))
    b.append(text(gx-28, PY0+PH+6, 56, 12, [lab], size=8, color=INK3, align="center", font=MONO))

# 点：(label或None, value, month_index, 颜色, L/R, 标签y, 标签宽, 空心?, x抖动dx)；密集区只锚点带标签
pts = [
    ("Claude3 Opus 15.8", 15.8, 3, BLUE, "R", 344, 118, False, 0),
    ("GPT-4o 38.4", 38.4, 5, BLUE, "R", 287, 78, False, 0),
    ("Claude3.5 49.0", 49.0, 9, BLUE, "R", 234, 104, False, 0),
    ("DeepSeek V3 42.0", 42.0, 14, GOLD, "L", 256, 118, False, 0),
    ("Claude4 Opus 67.6", 67.6, 16, BLUE, "L", 162, 128, False, 0),
    ("Gemini2.5 53.6", 53.6, 18, BLUE, "L", 240, 110, False, 0),
    ("Qwen3-Coder 55.4", 55.4, 19, GOLD, "R", 256, 118, False, -8),
    ("GPT-5 65.0", 65.0, 19, BLUE, "L", 204, 78, False, 0),
    ("Grok* 70.8", 70.8, 19, INK3, "L", 148, 80, True, 8),
    (None, 43.8, 19, GOLD, None, 0, 0, False, -16),
    ("Doubao* 78.8", 78.8, 20, GOLD, "R", 166, 78, True, 0),
    (None, 54.2, 20, GOLD, None, 0, 0, False, -10),
    ("GLM-4.6 68.2", 68.2, 22, GOLD, "R", 196, 64, False, 0),
    ("Claude4.5 79.2", 79.2, 23, BLUE, "L", 120, 118, False, 0),
    (None, 60.0, 23, GOLD, None, 0, 0, False, -12),
    # 2026.02 mini-SWE-agent 统一 harness 批次（11 模型，六列蛇形蜂群避免同列点重叠）
    (None, 76.8, 25, BLUE, None, 0, 0, False, -14),
    (None, 75.8, 25, BLUE, None, 0, 0, False, -8),
    ("M2.5 75.8", 75.8, 25, GOLD, "L", 140, 66, False, -3),
    (None, 75.6, 25, BLUE, None, 0, 0, False, 3),
    (None, 72.8, 25, GOLD, None, 0, 0, False, 8),
    (None, 72.8, 25, BLUE, None, 0, 0, False, 14),
    (None, 71.4, 25, BLUE, None, 0, 0, False, -14),
    ("K2.5 70.8", 70.8, 25, GOLD, "L", 224, 66, False, -8),
    (None, 70.0, 25, GOLD, None, 0, 0, False, -3),
    (None, 69.6, 25, BLUE, None, 0, 0, False, 3),
    ("GPT5-mini 56.2", 56.2, 25, BLUE, "L", 240, 92, False, 8),
]
for lab, v, i, col, side, ty_, lw, hollow, dx in pts:
    cx, cy = sx(i) + dx, sy(v)
    if hollow:
        b.append(f'<shape type="ellipse" topLeftX="{cx-5}" topLeftY="{cy-5}" width="10" height="10"><fill><fillColor color="rgb(250,248,243)"/></fill><border color="{col}" width="2"/></shape>')
    else:
        b.append(f'<shape type="ellipse" topLeftX="{cx-5}" topLeftY="{cy-5}" width="10" height="10"><fill><fillColor color="{col}"/></fill></shape>')
    if lab:
        if side == "R":
            tx_ = cx + 8; al = "left"
        else:
            tx_ = cx - 8 - lw; al = "right"
        b.append(text(tx_, ty_, lw, 12, [lab], size=7.5, color=INK2, font=MONO, wrap=False, align=al))
# 图例
b.append(f'<shape type="ellipse" topLeftX="100" topLeftY="404" width="8" height="8"><fill><fillColor color="{BLUE}"/></fill></shape>')
b.append(text(112, 402, 150, 12, ["海外：GPT/Claude/Gemini"], size=8.5, color=INK2))
b.append(f'<shape type="ellipse" topLeftX="262" topLeftY="404" width="8" height="8"><fill><fillColor color="{GOLD}"/></fill></shape>')
b.append(text(274, 402, 220, 12, ["国产：DeepSeek/Kimi/GLM/Qwen 等"], size=8.5, color=INK2))
b.append(f'<shape type="ellipse" topLeftX="470" topLeftY="404" width="8" height="8"><fill><fillColor color="rgb(250,248,243)"/></fill><border color="{INK3}" width="1"/></shape>')
b.append(text(482, 402, 128, 12, ["* 厂商自报 harness"], size=8.5, color=INK2))
b.append(text(PX0-44, 116, 500, 16, ["SWE-bench Verified · % Resolved（真实 GitHub issue 修复）"], size=10, color=BLUE_D, bold=True))

# ---- 右：HumanEval 小折线 + 结论 ----
rx = 616
he = '''<chart width="290" height="160" topLeftX="616" topLeftY="132">
  <chartPlotArea>
    <chartPlot type="line">
      <chartExtra/>
      <chartLabels position="auto" value="true" fontSize="8" format="0.0" color="rgba(91,103,112,1)"/>
    </chartPlot>
    <chartAxes>
      <chartAxis type="x"><chartLabel fontSize="8"/></chartAxis>
      <chartAxis type="y" position="left">
        <chartGridLine color="rgb(226,230,234)"/>
        <chartLabel fontSize="8" format="0%"/>
      </chartAxis>
    </chartAxes>
  </chartPlotArea>
  <chartData>
    <dim1><chartField name="代际">21 Codex,22 GPT-3.5,23 GPT-4,24 GPT-4o,24 Qwen2.5</chartField></dim1>
    <dim2>
      <chartField name="HumanEval Pass@1">0.288,0.481,0.670,0.902,0.927</chartField>
    </dim2>
  </chartData>
  <chartStyle>
    <chartBackground color="rgba(0,0,0,0)"/>
    <chartBorder color="rgb(255,255,255)" width="0"/>
    <chartColorTheme><color value="rgb(111,163,155)"/></chartColorTheme>
  </chartStyle>
</chart>'''
b.append(he)
b.append(text(rx, 116, 290, 14, ["HumanEval Pass@1 · 函数级编码 2024 年趋于饱和"], size=10, color=TEAL, bold=True))
yy = 306
for t, v in [
    ("两个基准，一个判断", "函数级能力 2024 已饱和；仓库级修复 2025-26 仍每季度抬升"),
    ("国产进入第一梯队", "2026.02 统一 harness 批次：GLM、Kimi、DeepSeek、MiniMax 全部 70% 以上，与海外同档"),
    ("对本项目的意义", "外部模型能力是可替换底座：架构做“裁决者”，不绑定单一模型，能力进步直接受益"),
]:
    b.append(rect(rx, yy+3, 6, 6, fill=GOLD))
    b.append(text(rx+14, yy, 276, 16, [t], size=11.5, color=INK, bold=True))
    b.append(text(rx+14, yy+17, 276, 30, [v], size=10, color=INK2, lh=1.4))
    yy += 58
b.append(text(54, 478, 852, 38, ["来源：SWE-bench 官方榜单与各厂技术报告（2026-09 检索；优先 mini-SWE-agent 统一 harness，*为厂商自报 harness，不直接横比）", "2026.02 统一 harness 批次 11 模型：76.8 / 75.8 / 75.8 / 75.6 / 72.8 / 72.8 / 71.4 / 70.8 / 70.0 / 69.6 / 56.2，覆盖 Claude、Gemini、GPT、GLM、Kimi、DeepSeek、MiniMax", "HumanEval 取各代官方报告（Codex 28.8 → Qwen2.5-Coder-32B 92.7）；Grok、Doubao 未提交官方统一批次"], size=8.5, color=INK3, lh=1.45))
p6 = slide("".join(b),
    "这页把视野放到整个行业，用两个权威基准回答“为什么是现在”。HumanEval 考函数级编码，从 2021 年 Codex 的 28.8% 升到 2024 年 90% 以上，已经饱和；"
    "SWE-bench Verified 考真实 GitHub 仓库修复，左图按时间画出 GPT、Claude、Gemini、Grok 与 DeepSeek、Kimi、GLM、Qwen、MiniMax、豆包十家的代表点：海外蓝、国产金，2026 年 2 月统一测试框架的一批 11 个模型挤在 70 到 77 分，国产四家全部在列。"
    "模型能力是可替换的底座，这让我们敢于把模型放在裁决者位置，也让系统不绑定任何单一厂商，未来模型继续进步，系统直接受益。星号点是 Grok 和豆包的厂商自报框架，不与统一批次直接比较。")
save("p06.xml", p6)
print("p04-p06 done")
