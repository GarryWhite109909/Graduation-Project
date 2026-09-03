# -*- coding: utf-8 -*-
import os, struct

def img_size(fp):
    with open(fp, "rb") as f:
        head = f.read(32)
        if head[:8] == b"\x89PNG\r\n\x1a\n":
            w, h = struct.unpack(">II", head[16:24])
            return w, h
        if head[:3] == b"\xff\xd8\xff":
            f.seek(2)
            b = f.read(1)
            while b and b != b"\xff":
                b = f.read(1)
            while True:
                marker = f.read(1)
                while marker == b"\xff":
                    marker = f.read(1)
                if 0xC0 <= marker[0] <= 0xCF and marker[0] not in (0xC4, 0xC8, 0xCC):
                    f.read(3); h, w = struct.unpack(">HH", f.read(4)); return w, h
                seg = struct.unpack(">H", f.read(2))[0]; f.seek(seg - 2, 1)
    return None

paths = [
    r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt图片提取_20260903",
    r"D:\code\毕业设计\Graduation-Project\app\backend\static\logo",
]
for d in paths:
    print("==", os.path.basename(d))
    for fn in sorted(os.listdir(d)):
        fp = os.path.join(d, fn)
        if os.path.isdir(fp): continue
        try:
            print(f"  {fn}: {img_size(fp)} {os.path.getsize(fp)//1024}KB")
        except Exception as e:
            print(f"  {fn}: ERR {e}")
for fn in ["two_stage_architecture.png", "trust_layer_25.png"]:
    fp = os.path.join(r"D:\code\毕业设计\Graduation-Project\docs\论文\figures", fn)
    w, h = img_size(fp)
    print(f"fig {fn}: {(w,h)} ratio={w/h:.3f}")
