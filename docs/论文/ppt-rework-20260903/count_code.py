# -*- coding: utf-8 -*-
import os

ROOT = r"D:\code\毕业设计\Graduation-Project"
TARGETS = {
    "后端(graduation_project)": ("graduation_project", {".py"}),
    "前端(app)": ("app", {".vue", ".ts", ".js", ".css", ".html"}),
}
SKIP_DIRS = {"node_modules", ".git", "dist", "__pycache__", ".venv", "venv", "build", ".idea", "datasets", "models", "results", "logs", "exports"}

for label, (sub, exts) in TARGETS.items():
    base = os.path.join(ROOT, sub)
    files = 0
    lines = 0
    by_ext = {}
    for dp, dns, fns in os.walk(base):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in exts:
                continue
            fp = os.path.join(dp, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    n = sum(1 for _ in f)
            except Exception:
                continue
            files += 1
            lines += n
            by_ext.setdefault(ext, [0, 0])
            by_ext[ext][0] += 1
            by_ext[ext][1] += n
    print(f"== {label}: {files} files, {lines} lines")
    for ext, (fc, lc) in sorted(by_ext.items(), key=lambda x: -x[1][1]):
        print(f"   {ext}: {fc} files, {lc} lines")
