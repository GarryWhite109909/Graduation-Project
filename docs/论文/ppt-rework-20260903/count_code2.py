# -*- coding: utf-8 -*-
import os
ROOT = r"D:\code\毕业设计\Graduation-Project"
SKIP = {"node_modules", ".git", "dist", "__pycache__", ".venv", "venv", "build",
        ".idea", ".gradle", "bin", ".codebuddy", ".workbuddy", ".zcode", "lib",
        "samples", "demo", "gradle", "wrapper", "migrations"}
groups = {
    "核心引擎 graduation_project": (os.path.join(ROOT, "graduation_project"), {".py"}),
    "Web后端 app/backend": (os.path.join(ROOT, "app", "backend"), {".py"}),
    "Web前端 static": (os.path.join(ROOT, "app", "backend", "static"), {".html", ".js", ".css"}),
    "VS Code插件": (os.path.join(ROOT, "app", "vscode-extension"), {".js"}),
    "IntelliJ插件": (os.path.join(ROOT, "app", "intellij-extension", "src"), {".java", ".kt"}),
    "启动器/CLI": (os.path.join(ROOT, "app", "launcher"), {".py"}),
}
grand_f = grand_l = 0
for label, (base, exts) in groups.items():
    fc = lc = 0
    for dp, dns, fns in os.walk(base):
        dns[:] = [d for d in dns if d not in SKIP]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() not in exts:
                continue
            if fn.endswith((".min.js",)):
                continue
            try:
                with open(os.path.join(dp, fn), "r", encoding="utf-8", errors="ignore") as f:
                    n = sum(1 for _ in f)
            except Exception:
                continue
            fc += 1; lc += n
    grand_f += fc; grand_l += lc
    print(f"{label}: {fc} files / {lc} lines")
print(f"TOTAL: {grand_f} files / {grand_l} lines")
