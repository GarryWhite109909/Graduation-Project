# -*- coding: utf-8 -*-
"""去除产品截图上后加的高饱和红色手绘标注（粗框/圈），保留 UI 自身红色文字。"""
import cv2
import numpy as np
import os

ASSETS = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903\assets"

def clean(name, out_name, min_area=600, dilate=3, radius=5):
    fp = os.path.join(ASSETS, name)
    im = cv2.imdecode(np.fromfile(fp, dtype=np.uint8), cv2.IMREAD_COLOR)
    b, g, r = cv2.split(im)
    # 高饱和标注红：R 高、G/B 低
    mask = ((r > 190) & (g < 62) & (b < 72)).astype(np.uint8) * 255
    # 连通域过滤：只处理大块标注线条，保留小字红色 UI
    n, labels, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
    keep = np.zeros_like(mask)
    kept = 0
    for i in range(1, n):
        if stats[i, cv2.CC_STAT_AREA] >= min_area:
            keep[labels == i] = 255
            kept += 1
    keep = cv2.dilate(keep, np.ones((dilate, dilate), np.uint8), iterations=1)
    out = cv2.inpaint(im, keep, radius, cv2.INPAINT_TELEA)
    out_fp = os.path.join(ASSETS, out_name)
    ok, buf = cv2.imencode(".png", out)
    buf.tofile(out_fp)
    raw_px = int((mask > 0).sum()); kept_px = int((keep > 0).sum())
    print(f"{name}: comps={n-1} kept={kept} redpx={raw_px} inpaintpx={kept_px} -> {out_name}")

clean("shot_scan.png", "shot_scan_clean.png")
clean("shot_cwe.png", "shot_cwe_clean.png")
