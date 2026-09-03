# -*- coding: utf-8 -*-
import re, sys
t = open(sys.argv[1], encoding='utf-8').read()
for m in re.finditer(r'<shape type="text" topLeftX="([^"]+)" topLeftY="([^"]+)" width="([^"]+)" height="([^"]+)"><content[^>]*><p>([^<]*)</p>', t):
    x, y, w, h, txt = m.groups()
    if float(x) > 560 or (sys.argv[2] in txt if len(sys.argv) > 2 else False):
        print(x, y, w, h, txt[:40])
