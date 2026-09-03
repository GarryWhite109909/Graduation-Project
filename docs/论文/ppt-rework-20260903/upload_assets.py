# -*- coding: utf-8 -*-
import subprocess, json, os

WD = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903"
PID = "ZIq5sFPJDljcVhdji1ScL8jx6u3"
files = [
    "logo_icon.png",
    "two_stage_architecture.png",
    "trust_layer_25.png",
    "shot_dashboard.png",
    "shot_scan_clean.png",
    "shot_cwe_clean.png",
    "shot_posture.png",
]
tokens = {}
for fn in files:
    rel = f"./assets/{fn}"
    p = subprocess.run(
        ["lark-cli", "slides", "+media-upload", "--file", rel, "--presentation", PID],
        cwd=WD, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    out = (p.stdout or "") + (p.stderr or "")
    tok = None
    try:
        # 找到 JSON 段
        start = out.index("{")
        data = json.loads(out[start:])
        tok = data["data"]["file_token"]
    except Exception as e:
        print(f"[FAIL] {fn}: {e}\n{out[:500]}")
        continue
    tokens[fn] = tok
    print(f"[OK] {fn} -> {tok}")

with open(os.path.join(WD, "tokens.json"), "w", encoding="utf-8") as f:
    json.dump(tokens, f, ensure_ascii=False, indent=2)
print("saved tokens.json:", len(tokens))
