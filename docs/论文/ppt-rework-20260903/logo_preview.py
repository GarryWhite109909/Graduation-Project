# -*- coding: utf-8 -*-
from PIL import Image
import os
ASSETS = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903\assets"
logo = Image.open(os.path.join(ASSETS, "logo_icon_t.png"))
bg = Image.new("RGBA", logo.size, (31, 46, 56, 255))
bg.alpha_composite(logo)
bg.convert("RGB").save(os.path.join(ASSETS, "_logo_preview_dark.png"))
bg2 = Image.new("RGBA", logo.size, (250, 248, 243, 255))
bg2.alpha_composite(logo)
bg2.convert("RGB").save(os.path.join(ASSETS, "_logo_preview_light.png"))
print("ok")
