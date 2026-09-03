# -*- coding: utf-8 -*-
"""把 pages/<name> 追加到在线稿，返回 slide_id。用法: python add_page.py p01.xml [before_sid]"""
import subprocess, sys, json, os

WD = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903"
PID = "ZIq5sFPJDljcVhdji1ScL8jx6u3"
name = sys.argv[1]
cmd = ["lark-cli", "slides", "+add-slide", "--presentation", PID, "--slide", f"@./pages/{name}"]
if len(sys.argv) > 2:
    cmd += ["--before-slide-id", sys.argv[2]]
p = subprocess.run(cmd, cwd=WD, capture_output=True, text=True, encoding="utf-8", errors="replace")
out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
print(out)
try:
    j = json.loads(out[out.index("{"):])
    sid = (j.get("data") or {}).get("slide_id") or j.get("slide_id")
    rec = {}
    fp = os.path.join(WD, "new_slide_ids.json")
    if os.path.exists(fp):
        rec = json.load(open(fp, encoding="utf-8"))
    rec[name] = sid
    json.dump(rec, open(fp, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print("SAVED", name, sid)
except Exception as e:
    print("PARSE_FAIL", e)
