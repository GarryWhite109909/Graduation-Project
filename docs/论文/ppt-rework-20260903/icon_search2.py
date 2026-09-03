# -*- coding: utf-8 -*-
import subprocess
SKILL = r"C:\Users\zane\AppData\Local\Doubao\User Data\Default\.doubao\agent_mode\workspace\.skills\ppt"
queries = ["实验 烧瓶", "循环 刷新 重复", "大脑 思考 智能", "窗口 应用程序",
           "毕业帽 学位", "用户 单人", "分支 分叉", "柱状图 图表", "星星 奖章",
           "分层 堆叠", "放大镜审查", "文档报告", "箭头向右", "菜单 列表", "禁止 停用"]
for q in queries:
    p = subprocess.run(["python", "scripts/iconpark_tool.py", "search", "--query", q, "--limit", "3"],
                       cwd=SKILL, capture_output=True, text=True, encoding="utf-8", errors="replace")
    lines = []
    import json as J
    try:
        arr = J.loads(p.stdout)
        for it in arr:
            lines.append(it["iconType"])
    except Exception:
        lines = [p.stdout[:200]]
    print(q, "=>", lines)
