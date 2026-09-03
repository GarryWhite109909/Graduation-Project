# -*- coding: utf-8 -*-
import subprocess, time
WD = r"D:\code\毕业设计\Graduation-Project\docs\论文\ppt-rework-20260903"
PID = "ZIq5sFPJDljcVhdji1ScL8jx6u3"
OLD = ["pUj","pUL","pUa","pUS","pUy","pUi","pUJ","pUF","pUX","pUg",
       "pUK","pUG","pUO","pUI","pUM","pUf","pUD","pUU","pUm","pUW",
       "pUo","pUQ","pUs","pUC","pUd","pUB","pUE","pUh"]
for sid in OLD:
    for attempt in range(3):
        p = subprocess.run(["lark-cli","slides","+delete-slide","--presentation",PID,"--slide-id",sid],
                           cwd=WD, capture_output=True, text=True, encoding="utf-8", errors="replace")
        out = (p.stdout or "") + (p.stderr or "")
        if '"deleted": true' in out or '"ok": true' in out:
            print("DEL OK", sid); break
        print("RETRY", sid, attempt, out[:160]); time.sleep(2)
    else:
        print("DEL FAIL", sid)
    time.sleep(0.5)
print("all done")
