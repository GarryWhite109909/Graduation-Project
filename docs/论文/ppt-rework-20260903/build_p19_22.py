# -*- coding: utf-8 -*-
from deck_common import *

T_TRUST = "Ya6AbXeEEoFETUxJjptc24Ad6pf"

# ---------- P19 信任层 ----------
b = [header("04", "项目的价值", "2.5 代信任层：让系统的每一次“记住”都经过门控", 19)]
b.append(img(T_TRUST, 54, 122, 560, 360, radius=8))
b.append(text(54, 486, 560, 14, ["图：A–E 分级、四重门控回填与复核兜底的完整信任层实现"], size=9, color=INK3))
rx = 636
b.append(text(rx, 124, 270, 16, ["TRUST LAYER · 三道关"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
items = [
    ("输出分级", "裁决结果分 A–E 五级，正确、错误、存疑区别对待，不做单点阈值", BLUE, BLUE_L),
    ("回填门控", "全票 · 聚合 · 可撤销 · 独立验证四重门控，全过才写入记忆", TEAL, TEAL_L),
    ("复核兜底", "抑制池压制已知误报；无候选分支抽样与全量复核双保险", GOLD, GOLD_L),
]
yy = 148
for nm, ds, c, bg in items:
    b.append(rect(rx, yy, 270, 86, fill=bg, radius=8))
    b.append(rect(rx, yy, 4, 86, fill=c, radius=2))
    b.append(text(rx+16, yy+12, 240, 18, [nm], size=13, color=INK, bold=True))
    b.append(text(rx+16, yy+36, 242, 44, [ds], size=10.5, color=INK2, lh=1.5))
    yy += 96
b.append(rect(rx, 436, 270, 58, fill=DARK, radius=8))
b.append(text(rx+16, 445, 240, 14, ["误报率 FPR（87 合成集实测）"], size=9.5, color="rgb(150,166,178)"))
b.append(rich(rx+16, 461, 244, 28, [f"<p>{span('0.154 → 0.0435', color=GOLD, bold=True, size=17, font=MONO)}{span('  -72%', color=WHITE, bold=True, size=12, font=MONO)}</p>"]))
p19 = slide("".join(b),
    "信任层是架构的 2.5 代升级。裁决结果先分 A 到 E 五级；只有 A、B 类且通过四重门控才允许回填记忆库；已知误报进抑制池，无候选分支还有抽样和全量复核兜底。"
    "实测效果：在 87 段合成集上，纯 LLM 误报率 0.154，信任层压到 0.0435，降幅 72%，而且这一切都有门控记录、可以回滚。")
save("p19.xml", p19)

# ---------- P20 数据工程 ----------
b = [header("04", "项目的价值", "数据工程：914 条手写样本起步，百元成本建成万条语料", 20)]
chain = [
    ("914", "手写种子样本", "逐段编写、逐段标注", BLUE),
    ("10,700", "双教师蒸馏", "长思维链压缩为短链", TEAL),
    ("7,692", "三次清洗", "泄漏排查后保留", GOLD),
    ("7,972", "α0.5 冻结", "已训练版本语料", BLUE_D),
    ("10,167", "α0.6 语料冻结", "15 审计版 · 尚未开训", GOLD),
]
xs5 = [54, 228, 402, 576, 750]
for i, ((num, nm, ds, c), x) in enumerate(zip(chain, xs5)):
    b.append(rect(x, 126, 156, 108, fill=MIST, radius=8))
    b.append(rect(x, 126, 156, 3, fill=c))
    b.append(text(x+14, 140, 130, 34, [num], size=24, color=c, bold=True, font=MONO, wrap=False))
    b.append(text(x+14, 178, 130, 18, [nm], size=12, color=INK, bold=True))
    b.append(text(x+14, 198, 132, 30, [ds], size=9.5, color=INK2, lh=1.35))
    if i < 4:
        b.append(line(x+157, 180, x+173, 180, color="rgb(150,162,172)", w=2, arrow="arrow"))
# 治理硬数字
b.append(rect(54, 258, 4, 18, fill=BLUE_D))
b.append(text(66, 258, 400, 20, ["治理留痕 · 每个版本都可回溯"], size=13.5, color=INK, bold=True))
stats = [("15", "个数据版本"), ("12", "个模型版本"), ("87+20", "合成+真实测试面"), ("6", "轮泄漏审计"), ("≈100 元", "云端总成本")]
sx = [54, 228, 402, 576, 750]
for (num, nm), x in zip(stats, sx):
    b.append(text(x, 292, 160, 34, [num], size=26, color=INK, bold=True, font=MONO, wrap=False))
    b.append(text(x, 330, 160, 18, [nm], size=11, color=INK2))
    b.append(line(x, 356, x+140, 356, color=LINE))
# 底部条
b.append(rect(54, 386, 852, 86, fill=DARK, radius=8))
b.append(rect(54, 386, 4, 86, fill=GOLD, radius=2))
b.append(text(78, 400, 400, 14, ["LEAKAGE AUDIT · 三次泄漏排查"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(78, 422, 816, 44, ["文件名含答案 · 训练-测试 Jaccard 重叠 · 反向拟合测试集——", "语料每一次扩张，都必须先过审计关，再谈训练。"], size=13, color=WHITE, bold=True, lh=1.5))
p20 = slide("".join(b),
    "数据从哪来？起点是逐段手写的 914 条样本；用 DeepSeek V4-Flash 和 GLM-5.2 双教师蒸馏扩到 10700 条，长思维链压缩成短链供 8B 小模型学；三次清洗和泄漏排查后保留 7692 条，"
    "α0.5 冻结时 7972 条并已完成训练；α0.6 的 10167 条语料经过 15 个审计版本冻结，但训练尚未启动，属于下一步规划。全过程 15 个数据版本、12 个模型版本、6 轮泄漏审计，云端总成本约 100 元，每一步扩张都先过审计关。")
save("p20.xml", p20)

# ---------- P21 核心结果表（四组态 × 双口径，2026-09-03 冻结口径） ----------
b = [header("04", "项目的价值", "核心结果：双口径下，两阶段+信任层全面优于纯 LLM", 21)]
tx, ty = 54, 122
w0 = 150; wv = 101.5; rh = 33
heads = ["指标（组态 →）", "纯 LLM\nα0.5", "两阶段\nfixed5 干净评估", "完整信任层\nwave8", "真实 CVE-fix\n20 段 anchor"]
# wave8 列高亮底框（先画，避免盖住文字）
b.append(f'<shape type="rect" topLeftX="{tx+w0+wv*2}" topLeftY="{ty}" width="{wv}" height="{34+rh*7}"><fill><fillColor color="rgba(74,127,165,0.07)"/></fill><border color="rgb(74,127,165)" width="1"/></shape>')
# 表头
b.append(rect(tx, ty, w0+wv*4, 34, fill=DARK))
hx = tx
for i, (w, t) in enumerate(zip([w0]+[wv]*4, heads)):
    b.append(text(hx+8, ty+5, w-12, 26, t.split("\n"), size=9 if i else 10, color=WHITE, bold=True,
                  align=("left" if i == 0 else "center"), lh=1.25, valign="middle"))
    hx += w
rows = [
    ("Recall 召回", "0.967", "1.000", "1.000", "0.941"),
    ("FPR 误报率", "0.154", "0.0435", "0.0435", "—"),
    ("Acc 已裁决准确", "0.931", "0.987", "0.987", "0.941"),
    ("未决率", "0", "12.6%", "13.8%", "15.0%"),
    ("Strict 判真且归因正确", "0.898", "0.774", "0.923", "1.000"),
    ("Micro 实例级召回", "0.675", "0.592", "0.778", "0.895"),
    ("风险加权分", "0.829", "0.786", "0.862", "0.864"),
]
ry = ty + 34
rh = 33
for i, row in enumerate(rows):
    bg = MIST if i % 2 == 0 else WHITE
    b.append(rect(tx, ry, w0+wv*4, rh, fill=bg))
    cx = tx
    for j, (w, v) in enumerate(zip([w0]+[wv]*4, row)):
        if j == 0:
            b.append(text(cx+10, ry+8, w-14, 20, [v], size=10, color=INK, bold=True, valign="middle"))
        else:
            col = INK
            if j == 3: col = BLUE_D
            if j == 4: col = "rgb(60,110,102)"
            b.append(text(cx, ry+8, w, 20, [v], size=10.5, color=col, bold=(j >= 3),
                          align="center", font=MONO, valign="middle"))
        cx += w
    hl_l, hl_r = tx+w0+wv*2, tx+w0+wv*3
    b.append(line(tx+8, ry+rh, hl_l, ry+rh, color=LINE))
    b.append(line(hl_r, ry+rh, tx+w0+wv*4-8, ry+rh, color=LINE))
    ry += rh
p21_note = ("口径：87 段合成集 + 20 段真实 CVE-fix；fixed5 为 --no-signal-feedback 干净压力测试；"
            "wave8 = signal-feedback on + ctx16384；2026-09-02 官方答案冻结（weights_20260903），score_batch.py 可复现。")
b.append(text(tx, ry+8, 560, 40, [p21_note], size=8.5, color=INK3, lh=1.5))
# 右侧解读
rx = 636
b.append(text(rx, 122, 270, 16, ["READING · 三句结论"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
reads = [
    ("误报 -72%，召回反升", ["FPR 0.154 → 0.0435", "Recall 0.967 → 1.000：不是靠漏报换误报"], BLUE),
    ("信任层补回归因能力", ["strict 0.898 → 0.923", "micro 0.675 → 0.778：证据链反哺 CWE 归因"], TEAL),
    ("真实 CVE 验证泛化", ["20 段真实修复 strict 1.000", "micro 0.895 · 加权 0.864，非合成集刷分"], GOLD),
]
yy = 146
for nm, lines, c in reads:
    b.append(rect(rx, yy, 4, 62, fill=c))
    b.append(text(rx+14, yy, 256, 16, [nm], size=11.5, color=INK, bold=True))
    b.append(text(rx+14, yy+20, 258, 40, lines, size=10, color=INK2, lh=1.5, font=MONO))
    yy += 72
b.append(rect(rx, 366, 270, 106, fill=BLUE_L, radius=8))
b.append(text(rx+14, 376, 244, 16, ["为什么 fixed5 有些指标更低？"], size=10.5, color=BLUE_D, bold=True))
b.append(text(rx+14, 396, 246, 72, ["它刻意关闭信号反馈做“干净压力测试”，strict/micro 暂时低于纯 LLM，正是为了排除自我证明；打开信任层（wave8）后全面反超。"], size=9.5, color=INK, lh=1.5))
p21 = slide("".join(b),
    "这是全篇最核心的结果表，口径在 2026 年 9 月冻结，脚本可复现。四列分别是纯 LLM 对照、两阶段干净评估、完整信任层和 20 段真实 CVE-fix。"
    "看三行：误报率从 0.154 压到 0.0435，召回反而升到 1.000，说明不是靠漏报换误报；严格归因 strict 从 0.898 升到 0.923，实例级 micro 召回从 0.675 升到 0.778；"
    "真实 CVE-fix 上 strict 达到 1.000。需要说明 fixed5 列刻意关闭信号反馈做压力测试，部分指标暂时偏低，这是为了排除自我证明，打开信任层后全面反超。")
save("p21.xml", p21)

# ---------- P22 自研工具链 ----------
b = [header("04", "项目的价值", "自研工具链：8 个组件串成 SARIF 标准产出流水线", 22)]
tools = [
    ("01", "TaintTracker", "AST 污点追踪 source→sink"),
    ("02", "Prefilter", "正则预筛确定性问题"),
    ("03", "ExternalScanner", "封装 Bandit/Gitleaks/Trivy"),
    ("04", "CodeSlicer", "最小相关上下文切片"),
    ("05", "LLM Judge", "封闭裁决 N=3 投票"),
    ("06", "CWE Normalizer", "CWE 编号归一去重"),
    ("07", "LineNormalizer", "行号级证据对齐"),
    ("08", "FixVerifier", "修复建议可验证"),
]
pos = [(54+ i*214, 130) if i < 4 else (54 + (3-(i-4))*214, 286) for i in range(8)]
for i, ((no, nm, ds), (x, y)) in enumerate(zip(tools, pos)):
    c = [BLUE, BLUE, TEAL, TEAL, GOLD, TEAL, TEAL, BLUE_D][i]
    b.append(rect(x, y, 198, 88, fill=MIST, radius=8))
    b.append(rect(x, y, 4, 88, fill=c, radius=2))
    b.append(text(x+16, y+12, 60, 18, [no], size=11, color=c, bold=True, font=MONO))
    b.append(text(x+16, y+32, 174, 20, [nm], size=12.5, color=INK, bold=True, wrap=False, font=MONO))
    b.append(text(x+16, y+56, 174, 26, [ds], size=9.5, color=INK2, lh=1.35))
    if i < 3:
        b.append(line(x+199, y+44, x+213, y+44, color="rgb(150,162,172)", w=2, arrow="arrow"))
# 第二行反向箭头（蛇形：04→05 在最右列下行后向左）
b.append(line(696+99, 218, 696+99, 286, color="rgb(150,162,172)", w=2, arrow="arrow"))
for i in range(4, 7):
    x, y = pos[i]
    b.append(line(x, y+44, x-16, y+44, color="rgb(150,162,172)", w=2, arrow="arrow"))
# 输出条
b.append(rect(54, 408, 852, 62, fill=DARK, radius=8))
b.append(text(78, 420, 500, 16, ["统一输出"], size=9.5, color=GOLD, bold=True, font=MONO, ls=1))
b.append(text(78, 440, 820, 22, ["SARIF 标准报告：行号 · CWE · 证据链 · 修复建议，可直接接入 VS Code 与 CI 流水线"], size=13, color=WHITE, bold=True))
p22 = slide("".join(b),
    "八个自研组件串成一条完整流水线。前三个负责召回：TaintTracker 污点追踪、Prefilter 正则预筛、ExternalScanner 封装外部工具；"
    "CodeSlicer 切片后交给 LLM Judge 封闭裁决；之后 CWE Normalizer 归一编号、LineNormalizer 对齐行号、FixVerifier 验证修复。最终统一输出 SARIF 标准报告，IDE 和 CI 可以直接消费。")
save("p22.xml", p22)
print("p19-p22 done")
