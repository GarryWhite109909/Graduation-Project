# -*- coding: utf-8 -*-
"""Nivis 答辩 PPT 统一组件库（960x540）。"""
import os

# ---------- 调色板 ----------
INK   = "rgb(43,47,54)"        # 深墨 主文字
INK2  = "rgb(91,103,112)"      # 次级文字
INK3  = "rgb(148,158,166)"     # 弱化文字
BLUE  = "rgb(74,127,165)"      # 雾蓝 主色
BLUE_D= "rgb(52,94,128)"       # 深雾蓝
BLUE_L= "rgb(232,240,246)"     # 雾蓝浅底
TEAL  = "rgb(111,163,155)"     # 青灰绿 辅色
TEAL_L= "rgb(233,242,240)"
GOLD  = "rgb(217,150,46)"      # 暖金 强调
GOLD_L= "rgb(250,240,224)"
RED   = "rgb(192,80,77)"       # 砖红 风险
RED_L = "rgb(247,235,234)"
PAPER = "rgb(250,248,243)"     # 象牙白底
MIST  = "rgb(244,247,250)"     # 雾白底
DARK  = "rgb(31,46,56)"        # 深墨蓝 章节页底
DARK2 = "rgb(24,36,45)"
LINE  = "rgb(220,224,228)"     # 浅分隔线
LINE_D= "rgb(74,92,106)"       # 深底上的分隔线
WHITE = "rgb(255,255,255)"
FONT  = "思源黑体"
MONO  = "Roboto Mono"

CHAPTERS = [
    ("01", "研究背景"), ("02", "研究目标"), ("03", "我们的价值"),
    ("04", "项目的价值"), ("05", "系统演示"), ("06", "未来规划"),
]

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def rect(x, y, w, h, fill=None, border=None, bw=1, radius=0, alpha=None):
    a = f' alpha="{alpha}"' if alpha is not None else ""
    t = "round-rect" if radius else "rect"
    ph = f' presetHandlers="{radius}"' if radius else ""
    s = f'<shape type="{t}" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{h}"{ph}{a}>'
    if fill is not None:
        s += f'<fill><fillColor color="{fill}"/></fill>'
    if border is not None:
        s += f'<border color="{border}" width="{bw}"/>'
    return s + "</shape>"

def line(x1, y1, x2, y2, color=LINE, w=1, arrow=None):
    s = f'<line startX="{x1}" startY="{y1}" endX="{x2}" endY="{y2}"><border color="{color}" width="{w}"/>'
    if arrow:
        s += f'<endArrow type="{arrow}"/>'
    return s + "</line>"

def text(x, y, w, h, body, size=14, color=INK, bold=False, align="left",
         font=FONT, wrap=True, lh=1.35, valign="top", ls=0, italic=False):
    """body: 字符串（多段用 \\n）或段落 list。"""
    if isinstance(body, str):
        paras = body.split("\n")
    else:
        paras = body
    ps = "".join(f"<p>{esc(p)}</p>" for p in paras)
    attrs = (f'textType="body" fontSize="{size}" color="{color}" textAlign="{align}" '
             f'fontFamily="{font}" lineSpacing="multiple:{lh}" verticalAlign="{valign}" '
             f'letterSpacing="{ls}"')
    if bold: attrs += ' bold="true"'
    if italic: attrs += ' italic="true"'
    if not wrap: attrs += ' wrap="false"'
    return (f'<shape type="text" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{h}">'
            f'<content {attrs}>{ps}</content></shape>')

def rich(x, y, w, h, runs_xml, size=14, color=INK, align="left", lh=1.35, valign="top"):
    """runs_xml: 已拼好的 <p>...</p>（内含 span）"""
    attrs = (f'textType="body" fontSize="{size}" color="{color}" textAlign="{align}" '
             f'fontFamily="{FONT}" lineSpacing="multiple:{lh}" verticalAlign="{valign}"')
    return (f'<shape type="text" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{h}">'
            f'<content {attrs}>{runs_xml}</content></shape>')

def span(t, color=None, bold=False, size=None, font=FONT):
    s = ""
    if color: s += f' color="{color}"'
    if bold: s += ' bold="true"'
    if size: s += f' fontSize="{size}"'
    if font != FONT: s += f' fontFamily="{font}"'
    return f"<span{s}>{esc(t)}</span>"

def icon(it, x, y, w, color=BLUE):
    return (f'<icon iconType="{it}" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{w}">'
            f'<fill><fillColor color="{color}"/></fill></icon>')

def img(token, x, y, w, h, radius=0):
    if radius:
        return (f'<img src="{token}" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{h}">'
                f'<crop type="rect" presetHandlers="{radius}"/></img>')
    return f'<img src="{token}" topLeftX="{x}" topLeftY="{y}" width="{w}" height="{h}"/>'

def header(sec_no, sec_name, title, page_no, total=30, title_w=720):
    """内容页统一页眉。"""
    s = []
    s.append(text(54, 34, 500, 18, [f"{sec_no}  {sec_name}"], size=11, color=BLUE, bold=True, ls=1))
    s.append(text(54, 54, title_w, 36, [title], size=23, color=INK, bold=True, wrap=False, lh=1.1))
    s.append(rect(54, 96, 36, 3, fill=GOLD))
    s.append(rect(92, 97, 814, 1, fill=LINE))
    s.append(footer(page_no, total))
    return "".join(s)

def footer(page_no, total=30, dark=False):
    c = "rgb(150,162,172)" if not dark else "rgb(120,136,148)"
    s = text(54, 516, 420, 16, ["Nivis · 基于大语言模型的代码安全分析系统"], size=9, color=c)
    s += text(840, 516, 66, 16, [f"{page_no:02d} / {total}"], size=9, color=c, align="right", font=MONO)
    return s

def chapter_page(no, name, guide, active_idx, page_no, total=30, en=""):
    """深底章节页。active_idx: 0-based 当前章。page_no: 实际页码。"""
    s = [f'<style><fill><fillColor color="linear-gradient(135deg,rgba(31,46,56,1) 0%,rgba(22,34,42,1) 100%)"/></fill></style>']
    # 顶部细金线 + logo 文字
    s.append(rect(0, 0, 960, 4, fill=GOLD))
    s.append(text(54, 40, 400, 20, ["NIVIS · GRADUATION DEFENSE"], size=10, color="rgb(140,156,168)", font=MONO, ls=2))
    # 大编号
    s.append(text(50, 150, 260, 200, [no], size=150, color="rgba(74,127,165,0.55)", bold=True, font=MONO, wrap=False, valign="middle"))
    # 章名
    s.append(rect(300, 218, 4, 64, fill=GOLD))
    s.append(text(324, 208, 560, 50, [name], size=40, color=WHITE, bold=True, wrap=False))
    if en:
        s.append(text(326, 258, 560, 20, [en], size=12, color="rgb(130,150,162)", font=MONO, ls=1))
    s.append(text(326, 292, 560, 60, [guide], size=15, color="rgb(198,210,218)", lh=1.5))
    # 六章进度
    x0 = 326
    for i, (cn, nm) in enumerate(CHAPTERS):
        cx = x0 + i * 88
        col = GOLD if i == active_idx else "rgb(86,104,118)"
        tc = "rgb(232,222,200)" if i == active_idx else "rgb(110,128,140)"
        s.append(rect(cx, 386, 40, 3, fill=col))
        s.append(text(cx, 394, 86, 18, [f"{cn} {nm}"], size=10, color=tc))
    s.append(text(54, 516, 420, 16, ["Nivis · 基于大语言模型的代码安全分析系统"], size=9, color="rgb(110,126,138)"))
    s.append(text(840, 516, 66, 16, [f"{page_no:02d} / {total}"], size=9, color="rgb(110,126,138)", align="right", font=MONO))
    return "".join(s)

def slide(body, note, dark=False):
    bg = DARK if dark else PAPER
    style = ""
    if body.startswith("<style>"):
        style = body[:body.index("</style>")+8]; body = body[body.index("</style>")+8:]
    if not style:
        style = f'<style><fill><fillColor color="{bg}"/></fill></style>'
    note_xml = f'<note><content textType="body" fontSize="12"><p>{esc(note)}</p></content></note>'
    return f'<slide xmlns="https://www.larkoffice.com/sml/2.0">{style}<data>{body}</data>{note_xml}</slide>'

def save(name, xml):
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
    os.makedirs(d, exist_ok=True)
    fp = os.path.join(d, name)
    with open(fp, "w", encoding="utf-8") as f:
        f.write(xml)
    return fp
