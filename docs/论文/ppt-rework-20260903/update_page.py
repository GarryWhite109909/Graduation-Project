# -*- coding: utf-8 -*-
"""整页覆盖: python update_page.py p01.xml pUw"""
import subprocess, sys, json, os
WD = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903"
PID = "ZIq5sFPJDljcVhdji1ScL8jx6u3"
name, sid = sys.argv[1], sys.argv[2]
p = subprocess.run(["lark-cli", "slides", "+update-slide", "--presentation", PID,
                    "--slide-id", sid, "--content", f"@./pages/{name}"],
                   cwd=WD, capture_output=True, text=True, encoding="utf-8", errors="replace")
print((p.stdout or "") + ("\n"+p.stderr if p.stderr else ""))
