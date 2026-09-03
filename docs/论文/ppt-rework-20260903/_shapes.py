# -*- coding: utf-8 -*-
import re
t = open('pages/p06.xml', encoding='utf-8').read()
shapes = re.findall(r'<shape[^>]*>.*?</shape>', t)
for idx in [7, 31, 34, 39, 40, 43, 47, 53]:
    s = shapes[idx-1]
    m = re.search(r'type="([^"]+)" topLeftX="([^"]+)" topLeftY="([^"]+)" width="([^"]+)" height="([^"]+)"', s)
    txt = ''.join(re.findall(r'<p>([^<]*)</p>', s))
    fill = re.search(r'fillColor color="([^"]+)"', s)
    print(idx, m.groups() if m else None, '| fill=', fill.group(1) if fill else '-', '| txt=', txt[:30])
