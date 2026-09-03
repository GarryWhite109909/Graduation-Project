# -*- coding: utf-8 -*-
from deck_common import *

# ---------- P27 系统演示视频占位页（深底） ----------
b = []
b.append('<style><fill><fillColor color="linear-gradient(135deg,rgba(31,46,56,1) 0%,rgba(20,32,41,1) 100%)"/></fill></style>')
b.append(rect(0, 0, 960, 4, fill=GOLD))
# 顶部章节标
b.append(text(54, 40, 300, 14, ["05  SYSTEM DEMO · 系统演示"], size=11, color=GOLD, bold=True, font=MONO, ls=2))
b.append(text(54, 60, 600, 36, ["系统演示视频"], size=28, color=WHITE, bold=True))
b.append(rect(54, 104, 48, 3, fill=GOLD))

# 中央虚线占位框
b.append('<shape type="round-rect" topLeftX="120" topLeftY="128" width="720" height="262" presetHandlers="12">'
         '<fill><fillColor color="rgba(74,127,165,0.07)"/></fill>'
         '<border color="rgb(217,150,46)" width="2" dashArray="dash"/></shape>')
# 播放圆钮
cx, cy = 480, 222
b.append(f'<shape type="ellipse" topLeftX="{cx-44}" topLeftY="{cy-44}" width="88" height="88"><fill><fillColor color="rgba(217,150,46,0.16)"/></fill><border color="rgb(217,150,46)" width="2"/></shape>')
b.append(icon("iconpark/Music/play.svg", cx-18, cy-18, 36, color=GOLD))
b.append(text(120, 286, 720, 24, ["演示视频占位 · 待插入"], size=17, color=WHITE, bold=True, align="center"))
b.append(text(120, 316, 720, 16, ["DEMO VIDEO PLACEHOLDER"], size=10, color="rgb(150,166,178)", font=MONO, align="center", ls=2))
b.append(text(120, 344, 720, 30, ["（本页为预留位，视频由答辩人后续自行插入；建议 2–3 分钟、16:9）"], size=11, color="rgb(170,184,194)", align="center"))

# 建议演示流程
b.append(text(54, 408, 300, 14, ["建议演示动线"], size=10, color=GOLD, bold=True, font=MONO, ls=1))
steps = ["粘贴待检代码", "四路并行召回", "N=3 封闭裁决", "证据链修复建议", "SARIF 导出 / IDE 联动"]
sx = 54
sw = 166
for i, st in enumerate(steps):
    x = 54 + i * 174
    b.append(rect(x, 428, sw, 40, fill="rgba(255,255,255,0.06)", radius=6))
    b.append(text(x+8, 428, sw-16, 40, [f"{i+1}  {st}"], size=10.5, color=WHITE, valign="middle", align="center"))
    if i < 4:
        b.append(line(x+sw+2, 448, x+172, 448, color=GOLD, w=2, arrow="arrow"))
# 插入提示
b.append(text(54, 486, 852, 14, ["插入方式：飞书幻灯片「插入 → 视频」；本地 PPTX「插入 → 视频 → 此设备」。本页其余元素可在视频放入后删除。"], size=9, color="rgb(140,154,166)"))
b.append(footer(27, dark=True))
p27 = slide("".join(b),
    "这一页预留给系统演示视频，之后我会把录制好的演示视频插入到这个位置。视频计划按这条动线走：粘贴待检代码，四路工具并行召回，模型三次采样封闭裁决，给出带证据链的修复建议，最后导出 SARIF 并在 IDE 中联动。"
    "建议时长两到三分钟。下面先看四个真实产品界面。", dark=True)
save("p27.xml", p27)
print("p27 video placeholder done")
