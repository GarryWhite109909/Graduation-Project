#!/usr/bin/env python3
"""
蒸馏数据生成脚本
按《新蒸馏方法论.md》分配表，调用 DeepSeek V4-Flash 和 Kimi K3 API 生成训练样本。
GLM-5.2 部分的 1800 条由 GLM-5.2 模型直接生成，不走此脚本。

用法：
  # 先跑 5 条测试格式
  python generate_distill_data.py --provider deepseek --category c_memory --limit 5

  # 跑完整类别
  python generate_distill_data.py --provider deepseek --category c_memory

  # 跑该 provider 的所有类别
  python generate_distill_data.py --provider deepseek --all
  python generate_distill_data.py --provider kimi --all

环境变量：
  export DEEPSEEK_API_KEY="sk-xxx"
  export MOONSHOT_API_KEY="sk-xxx"
"""

import os
import re
import json
import time
import random
import argparse
from pathlib import Path
from openai import OpenAI

# ============================================================
# 路径配置
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # 毕业设计/
PROMPTS_DIR = PROJECT_ROOT / "docs" / "prompts"
OUTPUT_DIR = PROJECT_ROOT / "experiments" / "exp_06_finetune" / "data" / "distill_raw"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# API 配置（三模型均 OpenAI 兼容）
# ============================================================
PROVIDERS = {
    "deepseek": {
        "client_factory": lambda: OpenAI(
            api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            base_url="https://api.deepseek.com",
        ),
        "model": "deepseek-v4-flash",
        "temperature": 0.7,
        "max_tokens": 1024,
        "env_var": "DEEPSEEK_API_KEY",
    },
    "kimi": {
        "client_factory": lambda: OpenAI(
            api_key=os.environ.get("MOONSHOT_API_KEY", ""),
            base_url="https://api.moonshot.ai/v1",
        ),
        "model": "kimi-k3",
        "temperature": 0.5,
        "max_tokens": 1024,
        "env_var": "MOONSHOT_API_KEY",
    },
}

# ============================================================
# 从提示词文件提取 system prompt
# ============================================================
def load_system_prompt(provider: str) -> str:
    """从 docs/prompts/{provider}_prompt.md 提取系统提示词（第一个 ``` 代码块）"""
    prompt_file = PROMPTS_DIR / f"{provider}_prompt.md"
    text = prompt_file.read_text(encoding="utf-8")
    # 找 "## 系统提示词" 后面的第一个 ``` 代码块
    match = re.search(r"## 系统提示词.*?```\n(.*?)```", text, re.DOTALL)
    if not match:
        raise ValueError(f"未在 {prompt_file} 中找到系统提示词代码块")
    return match.group(1).strip()


# ============================================================
# 任务定义：按方法论分配表
# ============================================================
# DeepSeek: 7700 条 = C内存1000 + 渗透1800 + Web2500 + Shell1200 + 修复1200
# Kimi:     2000 条 = C内存重构800 + 跨文件1200
# GLM:      1800 条（由 GLM-5.2 模型直接生成，不走此脚本）

C_MEMORY_CWES = [
    ("CWE-416", "UAF"), ("CWE-415", "Double Free"), ("CWE-120", "Buffer Overflow"),
    ("CWE-122", "Heap Overflow"), ("CWE-121", "Stack Overflow"), ("CWE-476", "Null Deref"),
    ("CWE-367", "TOCTOU"), ("CWE-190", "Integer Overflow"), ("CWE-787", "Out-of-bounds Write"),
    ("CWE-125", "Out-of-bounds Read"),
]
C_SCENES = ["网络协议解析", "文件系统操作", "内存管理", "多线程同步", "设备驱动", "嵌入式固件"]

PENTEST_CWES = [
    ("CWE-78", "OS Command Injection"), ("CWE-77", "Command Injection"),
    ("CWE-88", "Argument Injection"), ("CWE-134", "Format String"),
    ("CWE-918", "SSRF"), ("CWE-912", "Hidden Functionality"), ("CWE-749", "Exposed Dangerous Method"),
]
PENTEST_LANGS = ["Python", "Shell", "Go", "JavaScript"]
PENTEST_SCENES = ["运维脚本", "API服务", "定时任务", "容器入口", "CI/CD流水线", "日志处理"]

WEB_CWES = [
    ("CWE-89", "SQLi"), ("CWE-79", "XSS"), ("CWE-22", "Path Traversal"),
    ("CWE-502", "反序列化"), ("CWE-611", "XXE"), ("CWE-352", "CSRF"),
    ("CWE-1336", "SSTI"), ("CWE-643", "XPath"), ("CWE-943", "NoSQL"),
    ("CWE-90", "LDAP"), ("CWE-441", "信任边界"), ("CWE-639", "IDOR"),
    ("CWE-862", "缺失授权"), ("CWE-306", "缺失认证"), ("CWE-601", "开放重定向"),
    ("CWE-117", "日志注入"), ("CWE-798", "硬编码凭证"),
]
WEB_LANGS = ["Java", "Python", "JavaScript", "PHP"]
WEB_FRAMEWORKS = ["Spring", "Flask", "Django", "Express", "FastAPI", "原生"]
WEB_SCENES = ["用户认证", "订单查询", "文件上传", "模板渲染", "API网关", "数据导出"]

SHELL_TYPES = ["Shell脚本", "Dockerfile", "nginx配置", "systemd unit", "CI/CD yaml"]
SHELL_SCENES = ["部署脚本", "反向代理", "容器构建", "定时任务", "环境初始化"]

KIMI_C_MEMORY_CWES = [
    ("CWE-416", "UAF"), ("CWE-415", "Double Free"), ("CWE-122", "Heap Overflow"),
    ("CWE-367", "TOCTOU"), ("CWE-190", "Integer Overflow"), ("CWE-787", "Out-of-bounds Write"),
]
KIMI_C_SCENES = ["协议解析", "内存池", "对象生命周期", "多线程同步", "文件系统驱动"]

CROSSFILE_CWES = [
    ("CWE-441", "信任边界绕过"), ("CWE-639", "IDOR"), ("CWE-862", "缺失授权"),
    ("CWE-918", "SSRF"), ("CWE-89", "跨文件SQL注入"),
]
CROSSFILE_SCENES = ["微服务API", "模块化后端", "前后端分离", "RPC服务", "事件驱动架构"]


def _expand_tasks(cwe_list, n, **field_options):
    """生成 n 条任务，随机组合字段值"""
    tasks = []
    for _ in range(n):
        cwe, name = random.choice(cwe_list)
        task = {"cwe": f"{cwe} {name}"}
        for k, choices in field_options.items():
            task[k] = random.choice(choices)
        tasks.append(task)
    return tasks


def build_task_list(provider: str, category: str) -> list[dict]:
    """按分配表构建任务列表，每条任务是一个占位符字典"""
    random.seed(42)  # 可复现
    tasks = []

    if provider == "deepseek":
        if category == "c_memory":
            # 1000 条：漏洞 250 + 安全 750
            vuln = _expand_tasks(C_MEMORY_CWES, 250, lang=["C", "C++"],
                                 difficulty=["简单", "中等", "困难"], has_vuln=["是"], scene=C_SCENES)
            safe = _expand_tasks(C_MEMORY_CWES, 750, lang=["C", "C++"],
                                 difficulty=["简单", "中等", "困难"], has_vuln=["否"], scene=C_SCENES)
            tasks = vuln + safe

        elif category == "pentest":
            # 1800 条：漏洞 450 + 安全 1350
            vuln = _expand_tasks(PENTEST_CWES, 450, lang=PENTEST_LANGS,
                                 has_vuln=["是"], scene=PENTEST_SCENES)
            safe = _expand_tasks(PENTEST_CWES, 1350, lang=PENTEST_LANGS,
                                 has_vuln=["否"], scene=PENTEST_SCENES)
            tasks = vuln + safe

        elif category == "web":
            # 2500 条：漏洞 625 + 安全 1875
            vuln = _expand_tasks(WEB_CWES, 625, lang=WEB_LANGS, framework=WEB_FRAMEWORKS,
                                 has_vuln=["是"], scene=WEB_SCENES,
                                 difficulty=["典型", "防御迷惑", "注意力分散", "框架代码"])
            safe = _expand_tasks(WEB_CWES, 1875, lang=WEB_LANGS, framework=WEB_FRAMEWORKS,
                                 has_vuln=["否"], scene=WEB_SCENES,
                                 difficulty=["典型", "防御迷惑", "注意力分散", "框架代码"])
            tasks = vuln + safe

        elif category == "shell":
            # 1200 条：漏洞 300 + 安全 900
            # shell 类没有固定 CWE，用类型名（Shell脚本/Dockerfile 等）作为任务字段
            vuln = [{"type": random.choice(SHELL_TYPES), "has_vuln": "是", "scene": random.choice(SHELL_SCENES)}
                    for _ in range(300)]
            safe = [{"type": random.choice(SHELL_TYPES), "has_vuln": "否", "scene": random.choice(SHELL_SCENES)}
                    for _ in range(900)]
            tasks = vuln + safe

        elif category == "fix":
            # 1200 条修复样例：需要先有漏洞代码，这里生成占位任务
            # 实际使用时需要从已生成的漏洞样本中提取代码填入
            tasks = [{"index": i, "note": "修复样例需手动提供漏洞代码"} for i in range(1200)]

    elif provider == "kimi":
        if category == "c_memory":
            # 800 条：漏洞 200 + 安全 600
            vuln = _expand_tasks(KIMI_C_MEMORY_CWES, 200, lang=["C", "C++"],
                                 difficulty=["中等", "困难"], has_vuln=["是"], scene=KIMI_C_SCENES)
            safe = _expand_tasks(KIMI_C_MEMORY_CWES, 600, lang=["C", "C++"],
                                 difficulty=["中等", "困难"], has_vuln=["否"], scene=KIMI_C_SCENES)
            tasks = vuln + safe

        elif category == "crossfile":
            # 1200 条：漏洞 300 + 安全 900
            vuln = _expand_tasks(CROSSFILE_CWES, 300,
                                 has_vuln=["是"], scene=CROSSFILE_SCENES,
                                 file_role=["入口文件", "中间处理", "数据访问层"],
                                 upstream=["未做认证", "已做认证但未授权", "已做完整认证授权"])
            safe = _expand_tasks(CROSSFILE_CWES, 900,
                                 has_vuln=["否"], scene=CROSSFILE_SCENES,
                                 file_role=["入口文件", "中间处理", "数据访问层"],
                                 upstream=["已做完整认证授权"])
            tasks = vuln + safe

    random.shuffle(tasks)
    return tasks


# ============================================================
# User Prompt 模板
# ============================================================
USER_TEMPLATES = {
    "deepseek": {
        "c_memory": (
            "请生成 1 条 {cwe} 的训练样本：\n"
            "- 语言：{lang}\n"
            "- 难度：{difficulty}（困难 = 涉及跨函数调用或宏定义）\n"
            "- 是否有漏洞：{has_vuln}\n"
            "- 代码场景：{scene}\n\n"
            "要求：\n"
            "1. 代码必须是真实可编译的 C/C++ 片段（20-80 行），模拟真实项目结构\n"
            "2. 漏洞样本必须能被静态分析识别，但不能太明显\n"
            "3. 安全样本必须包含有效防御（free 后置 NULL、RAII、边界检查、智能指针）\n"
            "4. 每个漏洞锚定具体行号\n\n"
            "输出严格三段式格式。"
        ),
        "pentest": (
            "请生成 1 条 {cwe} 的训练样本：\n"
            "- 语言：{lang}\n"
            "- 场景：{scene}\n"
            "- 是否有漏洞：{has_vuln}\n\n"
            "要求：\n"
            "1. 场景真实：CI/CD 脚本、运维自动化、容器配置、API 网关、日志处理\n"
            "2. 命令注入样本含 shell=True + 用户输入拼接、os.system + 字符串拼接\n"
            "3. 安全样本含有效防御：subprocess 列表参数 + shell=False、shlex.quote、白名单\n"
            "4. 区分「shell=True + shlex.quote 是有效防御」vs「shell=True + 字符串拼接是漏洞」\n\n"
            "输出严格三段式格式。"
        ),
        "web": (
            "请生成 1 条 {cwe} 的训练样本：\n"
            "- 语言：{lang}\n"
            "- 框架：{framework}\n"
            "- 场景：{scene}\n"
            "- 是否有漏洞：{has_vuln}\n"
            "- 难度：{difficulty}\n\n"
            "要求：\n"
            "1. 模拟真实 Web 框架代码\n"
            "2. 漏洞样本含真实业务逻辑，不要教科书式 demo\n"
            "3. 防御迷惑样本：含部分防御但不充分\n"
            "4. 注意力分散样本：含无关安全措施\n\n"
            "输出严格三段式格式。"
        ),
        "shell": (
            "请生成 1 条 Shell/配置文件安全的训练样本：\n"
            "- 类型：{type}\n"
            "- 场景：{scene}\n"
            "- 是否有漏洞：{has_vuln}\n\n"
            "CWE 覆盖：CWE-78 命令注入 / CWE-798 硬编码凭证 / CWE-276 不安全文件权限 / "
            "CWE-326 弱加密 / CWE-1188 不安全默认初始化 / CWE-732 不安全资源权限\n\n"
            "要求：\n"
            "1. 真实 Shell 脚本（bash/sh）、Dockerfile、docker-compose.yml、nginx.conf、systemd unit、CI/CD yaml\n"
            "2. 漏洞模式：eval 用户输入、硬编码密码、chmod 777、弱 TLS 配置、容器以 root 运行\n"
            "3. 安全样本：环境变量引用凭证、最小权限、TLS 1.2+、容器非 root 用户\n"
            "4. 配置文件要真实可解析\n\n"
            "输出严格三段式格式。"
        ),
        "fix": (
            "请针对以下漏洞代码生成修复样例：\n"
            "```{lang}\n"
            "{vuln_code}\n"
            "```\n"
            "漏洞类型：{cwe}\n\n"
            "要求：\n"
            "1. 给出修复后的完整代码\n"
            "2. 说明修复原理（1-2 句话）\n"
            "3. 确认修复不引入新漏洞\n\n"
            "输出三段式，fix_suggestion 字段给出完整修复代码块（而非简单建议）。"
        ),
    },
    "kimi": {
        "c_memory": (
            "请生成 1 条 {cwe} 的训练样本：\n"
            "- 语言：{lang}\n"
            "- 场景：{scene}\n"
            "- 难度：{difficulty}（必须跨函数或跨文件）\n"
            "- 是否有漏洞：{has_vuln}\n\n"
            "要求：\n"
            "1. 代码场景真实：网络协议解析、文件系统驱动、内存池、对象生命周期管理\n"
            "2. 漏洞必须涉及跨函数或跨文件的调用链，但输出必须压扁为 ≤5 步\n"
            "3. 安全样本：使用 RAII、智能指针、free 后置 NULL、边界检查、原子操作\n"
            "4. CoT 必须压成以下格式：\n"
            "   [漏洞类型] {{CWE-XXX}}\n"
            "   [位置] file.c:{{行号}}\n"
            "   [关键证据] {{1 句话核心}}\n"
            "   [3-5 步推理] 1) ... 2) ... 3) ...\n"
            "   [修复] {{1 句话}}\n\n"
            "【关键】输出必须压成 ≤5 步，不要展开调用链细节。8B 模型学不会数万 token 的追踪。\n\n"
            "输出严格三段式格式。"
        ),
        "crossfile": (
            "请生成 1 条跨文件分块审计样本：\n"
            "- 漏洞类型：{cwe}\n"
            "- 场景：{scene}\n"
            "- 文件角色：{file_role}\n"
            "- 上游调用方：{upstream}\n\n"
            "【这是新增类别——模拟文件切割工具的产出】\n"
            "8B 模型上下文有限，无法处理长文件。本类样本教模型：\n"
            "1. 在单个文件块（≤4K token）内识别漏洞\n"
            "2. 结合「上游调用方摘要」判断跨文件风险\n"
            "3. 标注「需结合上游 X 函数验证」的待确认项\n\n"
            "【输入格式特殊】\n"
            "请在代码片段前用注释标注上游调用方摘要（200 token 内），如：\n"
            "// 【上游调用方摘要】server.js 第 45 行调用此模块的 handleRequest(req)，req 来自 HTTP 请求，未做认证\n\n"
            "【输出格式特殊】\n"
            "分析过程必须包含：\n"
            "1. 本块内的数据流分析（≤3 步）\n"
            "2. 跨文件风险标注：「需结合上游 {{X 函数}} 验证 {{Y 条件}}」\n"
            "3. 待确认项（如有）\n\n"
            "输出严格三段式格式，CoT ≤5 步。"
        ),
    },
}


# ============================================================
# API 调用 + 重试
# ============================================================
def call_api(provider: str, system_prompt: str, user_prompt: str,
             max_retries: int = 3) -> str:
    """调用 API 生成一条样本，带指数退避重试"""
    cfg = PROVIDERS[provider]
    client = cfg["client_factory"]()

    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=cfg["model"],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=cfg["temperature"],
                max_tokens=cfg["max_tokens"],
            )
            # K3 的思考链在 message.reasoning_content，训练数据只取 content
            content = resp.choices[0].message.content
            if not content or len(content.strip()) < 20:
                raise ValueError(f"响应过短（{len(content) if content else 0} 字符），可能被截断")
            return content
        except Exception as e:
            wait = 2 ** attempt
            print(f"    [重试 {attempt+1}/{max_retries}] {type(e).__name__}: {e}，{wait}s 后重试")
            time.sleep(wait)

    raise RuntimeError(f"API 调用失败，已达最大重试次数 {max_retries}")


# ============================================================
# 断点续传
# ============================================================
def load_checkpoint(output_file: Path) -> int:
    """读取已完成的条数"""
    if not output_file.exists():
        return 0
    count = 0
    with open(output_file, "r", encoding="utf-8") as f:
        for _ in f:
            count += 1
    return count


def append_result(output_file: Path, record: dict):
    """追加一条结果到 JSONL"""
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ============================================================
# 主流程
# ============================================================
DEEPSEEK_CATEGORIES = ["c_memory", "pentest", "web", "shell", "fix"]
KIMI_CATEGORIES = ["c_memory", "crossfile"]


def run(provider: str, category: str, limit: int | None = None):
    """生成指定 provider + category 的数据"""
    cfg = PROVIDERS[provider]
    env_var = cfg["env_var"]
    if not os.environ.get(env_var):
        print(f"错误：未设置环境变量 {env_var}")
        print(f"  export {env_var}=\"sk-你的key\"")
        return

    system_prompt = load_system_prompt(provider)
    tasks = build_task_list(provider, category)
    template = USER_TEMPLATES[provider][category]

    output_file = OUTPUT_DIR / f"distill_{provider}_{category}.jsonl"
    done = load_checkpoint(output_file)
    total = len(tasks) if limit is None else min(limit, len(tasks))

    if done >= total:
        print(f"[{provider}/{category}] 已完成 {done}/{total}，跳过")
        return

    print(f"[{provider}/{category}] 从第 {done+1} 条开始，共 {total} 条")
    print(f"  输出文件：{output_file}")
    print(f"  模型：{cfg['model']}，温度：{cfg['temperature']}")

    success = 0
    fail = 0
    for i in range(done, total):
        task = tasks[i]
        try:
            user_prompt = template.format(**task)
        except KeyError as e:
            print(f"  [{i+1}/{total}] 模板填充失败，缺少字段 {e}，跳过")
            fail += 1
            continue

        try:
            result = call_api(provider, system_prompt, user_prompt)
            record = {
                "index": i,
                "category": category,
                "provider": provider,
                "task": task,
                "output": result,
            }
            append_result(output_file, record)
            success += 1
            if (i + 1) % 10 == 0 or i + 1 == total:
                print(f"  [{i+1}/{total}] 成功 {success}，失败 {fail}")
        except Exception as e:
            print(f"  [{i+1}/{total}] 失败: {e}")
            fail += 1
            # 失败也记录，避免重复尝试
            append_result(output_file, {
                "index": i,
                "category": category,
                "provider": provider,
                "task": task,
                "output": None,
                "error": str(e),
            })

        # 限速：避免 API 速率限制
        time.sleep(0.5)

    print(f"\n[{provider}/{category}] 完成：成功 {success}，失败 {fail}")
    print(f"  结果保存在：{output_file}")


def main():
    parser = argparse.ArgumentParser(description="蒸馏数据生成脚本")
    parser.add_argument("--provider", choices=["deepseek", "kimi"], required=True,
                        help="数据生成模型")
    parser.add_argument("--category", help="数据类别")
    parser.add_argument("--all", action="store_true", help="生成该 provider 的所有类别")
    parser.add_argument("--limit", type=int, help="只跑前 N 条（测试用）")
    args = parser.parse_args()

    if args.all:
        categories = DEEPSEEK_CATEGORIES if args.provider == "deepseek" else KIMI_CATEGORIES
        for cat in categories:
            if cat == "fix":
                print("\n[fix] 修复样例需要先从漏洞样本中提取代码，请手动处理或单独运行")
                continue
            run(args.provider, cat, args.limit)
    else:
        if not args.category:
            parser.error("必须指定 --category 或 --all")
        run(args.provider, args.category, args.limit)


if __name__ == "__main__":
    main()
