# -*- coding: utf-8 -*-
import subprocess, sys
SKILL = r"C:\Users\zane\AppData\Local\Doubao\User Data\Default\.doubao\agent_mode\workspace\.skills\ppt"
queries = ["安全防护 盾牌", "目标 靶心", "数据 数据库", "代码 编程", "工具", "芯片 处理器",
           "浏览器 网页", "插件 扩展", "云 服务器", "锁 加密", "警告 风险", "检查 对勾",
           "关闭 错误", "搜索 放大镜", "漏斗 过滤", "流程 工作流", "火箭", "团队",
           "文件 报告", "时间 历史", "天平 法律", "层级 网络", "闪电 速度", "书本 知识"]
for q in queries:
    p = subprocess.run(["python", "scripts/iconpark_tool.py", "search", "--query", q, "--limit", "4"],
                       cwd=SKILL, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print("###", q)
    print(p.stdout.strip()[:700])
    if p.stderr.strip():
        print("ERR", p.stderr[:200])
