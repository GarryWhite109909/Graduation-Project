# -*- coding: utf-8 -*-
from PIL import Image
from collections import Counter
for name in ["shot_scan.png", "shot_cwe.png"]:
    fp = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903\assets\\" + name
    im = Image.open(fp).convert("RGB")
    px = im.load()
    w, h = im.size
    c = Counter()
    for y in range(0, h, 2):
        for x in range(0, w, 2):
            r, g, b = px[x, y]
            if r > 180 and g < 90 and b < 90:
                # 量化到 16 级分箱
                c[(r // 16 * 16, g // 16 * 16, b // 16 * 16)] += 1
    print(name, im.size, "redish bins top10:")
    for k, v in c.most_common(10):
        print("   ", k, v)
