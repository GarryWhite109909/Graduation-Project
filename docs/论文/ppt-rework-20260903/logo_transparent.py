# -*- coding: utf-8 -*-
"""把白底雪鸮 logo 转成透明底（保留浅蓝青线稿）。"""
from PIL import Image
import numpy as np, os

ASSETS = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903\assets"
im = Image.open(os.path.join(ASSETS, "logo_icon.png")).convert("RGBA")
a = np.asarray(im).astype(np.float32)
r, g, b = a[..., 0], a[..., 1], a[..., 2]
gray = (r + g + b) / 3
# 越接近白色越透明；线稿（gray 较低）完全不透明
alpha = np.clip((248 - gray) / (248 - 140) * 255, 0, 255)
a[..., 3] = alpha
out = Image.fromarray(a.astype(np.uint8), "RGBA")
out.save(os.path.join(ASSETS, "logo_icon_t.png"))
print("saved logo_icon_t.png", out.size, "alpha range", alpha.min(), alpha.max())
