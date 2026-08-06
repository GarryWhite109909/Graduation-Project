#!/usr/bin/env python3
"""针对性补充训练数据生成 —— 基于 v8 评估诊断的弱项 CWE。

诊断发现的问题：
  1. CWE-90 LDAP Injection: 100% 漏报（模型看到 LdapEncoder 就认为安全）
  2. CWE-95 Code Injection: 100% 漏报（eval(expression) 作为 RPC 参数）
  3. CWE-441 Untrusted Search Path: 50% 漏报
  4. CWE-117 Log Injection: 仅 5 条训练数据
  5. CWE-330 Weak Random: 仅 5 条训练数据
  6. FPR 26.9%: 无对抗性安全样本
  7. strict_recall 45.9%: CWE 归因能力差

总计补充 ~160 条（90 漏洞 + 70 安全），用 DeepSeek V4-Flash 生成。

用法：
  cd <project_root>
  DEEPSEEK_API_KEY=sk-xxx PYTHONPATH=. python3 \
      experiments/exp_06_finetune/scripts/gen_targeted_supplement.py

  # 限制条数（调试用）
  DEEPSEEK_API_KEY=sk-xxx PYTHONPATH=. python3 \
      experiments/exp_06_finetune/scripts/gen_targeted_supplement.py --limit 5
"""

import argparse
import json
import os
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

# 导入 distill_v2 模块
_DISTILL_V2 = Path(__file__).resolve().parent / "distill_v2"
sys.path.insert(0, str(_DISTILL_V2))

from prompts.deepseek import (
    DEEPSEEK_DISTILL_POSITIVE,
    DEEPSEEK_DISTILL_NEGATIVE,
    STUDENT_SYSTEM,
)
from validate_sample import parse_assistant, validate, build_chatml

import requests

# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).resolve().parents[1] / "data"
OUTPUT_FILE = DATA_DIR / "distill_targeted_supplement.jsonl"

# ---------------------------------------------------------------------------
# API 配置
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
BASE_URL = "https://api.deepseek.com"
CHAT_URL = f"{BASE_URL}/v1/chat/completions"
MODEL = "deepseek-chat"
CONCURRENCY = 6
TEMPERATURE = 0.7
MAX_TOKENS = 4096
TIMEOUT = 90
MAX_RETRIES = 3

# ---------------------------------------------------------------------------
# 针对性任务规格
# 格式: (cwe, has_vuln, lang, scene, key_pattern, difficulty)
# key_pattern: 针对评估中发现的失败模式
# ---------------------------------------------------------------------------
TARGETED_TASKS = []

def _add(cwe, has_vuln, lang, scene, key_pattern, difficulty="典型"):
    TARGETED_TASKS.append({
        "cwe": cwe,
        "has_vuln": has_vuln,
        "lang": lang,
        "scene": scene,
        "key_pattern": key_pattern,
        "difficulty": difficulty,
    })

# === 1. CWE-90 LDAP Injection（20 漏洞 + 10 安全 = 30 条）===
# 评估发现: 模型看到 LdapEncoder.nameEncode 就认为安全，100% 漏报
ldap_vuln_patterns = [
    "用户输入直接拼接到 LDAP filter 字符串（如 f\"(uid={username})\"），未经编码",
    "LdapEncoder.nameEncode 只编码部分特殊字符，* 和 () 仍可注入",
    "Spring LDAP 的 filterEncode 被误用为只编码值未编码 filter 模板",
    "JNDI lookup() 接受用户可控的 URL 参数",
    "Python ldap3 的 search_s 使用 format 字符串拼接 filter",
]
ldap_safe_patterns = [
    "使用 LDAP 参数化查询（LdapTemplate.search with filter parameters，占位符绑定）",
    "对用户输入做严格白名单校验（只允许字母数字），再拼入 filter",
    "使用 ldap3 的 abstractConnection.search 且 filter 参数化",
]
for i, pat in enumerate(ldap_vuln_patterns):
    for lang in ["Java", "Python", "JavaScript", "Java", "Python"]:
        _add("CWE-90", True, lang, "用户认证/目录服务", pat, "防御迷惑" if i >= 1 else "典型")
for pat in ldap_safe_patterns:
    for lang in ["Java", "Python", "JavaScript"]:
        _add("CWE-90", False, lang, "用户认证/目录服务", pat, "典型")

# === 2. CWE-95 Code Injection（20 漏洞 + 10 安全 = 30 条）===
# 评估发现: eval(expression) 中 expression 是 RPC 参数，模型不认为用户可控
ci_vuln_patterns = [
    "eval(expression) 中 expression 是 RPC/API 参数（如 calculate(expression) 工具），攻击者直接传入恶意代码",
    "exec(user_input) 在插件/工具系统中执行用户提供的字符串",
    "Jinja2 SSTI: render_template_string(user_input) 导致模板注入",
    "eval with incomplete character filtering（只过滤 import/exec 但可用 __builtins__）",
    "new Function(user_input)() 在 JavaScript 中执行用户代码",
]
ci_safe_patterns = [
    "使用 ast.literal_eval 替代 eval，只允许字面量",
    "使用安全的沙箱执行（RestrictedPython）+ 白名单操作",
    "使用数值解析（float/int）替代 eval 做数学计算",
]
for i, pat in enumerate(ci_vuln_patterns):
    for lang in ["Python", "JavaScript", "Python", "Java", "Python"]:
        _add("CWE-95", True, lang, "计算器工具/模板渲染/插件系统", pat, "注意力分散" if i == 0 else "典型")
for pat in ci_safe_patterns:
    for lang in ["Python", "JavaScript", "Python"]:
        _add("CWE-95", False, lang, "计算器工具/模板渲染", pat, "典型")

# === 3. CWE-441 Untrusted Search Path（10 漏洞 + 5 安全 = 15 条）===
# 评估发现: 不理解信任边界，loopback URL 被当作可信
usp_vuln_patterns = [
    "loopback URL（127.0.0.1）被当作可信来源，未校验来源",
    "subprocess 不使用完整路径，依赖 PATH 环境变量（可被劫持）",
    "动态加载模块时使用用户可控的路径",
]
usp_safe_patterns = [
    "显式指定可执行文件的完整路径（/usr/bin/xxx）",
    "校验来源 IP + 使用白名单 + 完整路径",
]
for i, pat in enumerate(usp_vuln_patterns):
    for lang in ["Python", "Shell", "Go", "Python"]:
        _add("CWE-441", True, lang, "API 网关/CI-CD/运维脚本", pat, "注意力分散")
for pat in usp_safe_patterns:
    for lang in ["Python", "Go", "Python"]:
        _add("CWE-441", False, lang, "API 网关/运维脚本", pat, "典型")

# === 4. CWE-117 Log Injection（15 漏洞 + 5 安全 = 20 条）===
# 评估发现: 仅 5 条训练数据，严重不足
li_vuln_patterns = [
    "用户输入直接写入日志（logging.info(user_input)），\\n 可注入伪造日志行",
    "日志中的 CRLF 注入（\r\n\r\n 伪造 HTTP 头/日志分隔）",
    "log.error(f\"Failed: {user_input}\") 中用户输入含换行符",
    "JSON 日志注入（用户输入含 \\n 破坏 JSON 结构）",
    "日志中的 ANSI 转义序列注入",
]
li_safe_patterns = [
    "对日志输入做净化（移除 \\n\\r，或用 repr() 转义）",
    "使用结构化日志（JSON logging with proper escaping）",
]
for i, pat in enumerate(li_vuln_patterns):
    for lang in ["Python", "Java", "Python", "JavaScript", "Python"]:
        _add("CWE-117", True, lang, "日志查询接口/API 网关", pat, "典型")
for pat in li_safe_patterns:
    for lang in ["Python", "Java", "Python"]:
        _add("CWE-117", False, lang, "日志查询接口", pat, "典型")

# === 5. CWE-330 Weak Random（15 漏洞 + 5 安全 = 20 条）===
# 评估发现: 仅 5 条训练数据，严重不足
wr_vuln_patterns = [
    "random.random() 生成密码重置 token",
    "random.randint 生成验证码",
    "Math.random 生成 session ID（JavaScript）",
    "java.util.Random 生成安全令牌（可预测种子）",
    "random.choice 从固定字符集生成密码",
]
wr_safe_patterns = [
    "使用 secrets.token_hex() / secrets.token_urlsafe() 生成 token",
    "使用 java.security.SecureRandom 生成安全随机数",
]
for i, pat in enumerate(wr_vuln_patterns):
    for lang in ["Python", "JavaScript", "Java", "Python", "Python"]:
        _add("CWE-330", True, lang, "密码重置/会话管理/验证码", pat, "典型")
for pat in wr_safe_patterns:
    for lang in ["Python", "Java", "Python"]:
        _add("CWE-330", False, lang, "密码重置/会话管理", pat, "典型")

# === 6. 对抗性安全样本（30 条）===
# 评估发现: FPR 26.9%，模型把安全代码误判为漏洞
# 这些样本"看起来危险但实际安全"，教会模型不要误报
adversarial_safe = [
    # SQL 注入误报
    ("CWE-89", "Python", "参数化查询 cur.execute('SELECT * FROM users WHERE id = %s', (uid,))，但变量名包含 'sql' 或 'query' 关键词"),
    ("CWE-89", "Java", "PreparedStatement 参数化查询，但 SQL 语句中包含字符串拼接的表名（白名单校验过）"),
    ("CWE-89", "Python", "Django ORM 的 raw query 使用参数化，但代码中有 execute 关键词"),
    # 命令注入误报
    ("CWE-78", "Python", "subprocess.run(['ls', '-la', path], shell=False)，但 path 来自用户输入且做了白名单校验"),
    ("CWE-78", "Python", "subprocess.run(cmd, shell=True) 但 cmd 是硬编码列表拼接，不含用户输入"),
    ("CWE-78", "Shell", "eval 命令但变量来自受信任的配置文件（非用户输入）"),
    # XSS 误报
    ("CWE-79", "JavaScript", "res.send(userInput) 但已设置 Content-Type: text/plain（非 HTML）"),
    ("CWE-79", "Python", "Django 模板自动转义 {{ user_input }}，但代码中有 innerHTML 关键词（在注释中）"),
    ("CWE-79", "JavaScript", "DOMPurify.sanitize(html) 清洗后插入 DOM，但代码中有 innerHTML"),
    # 反序列化误报
    ("CWE-502", "Python", "json.loads(user_input) 是安全的 JSON 解析（非 pickle）"),
    ("CWE-502", "Java", "ObjectInputStream 但已有类型白名单（resolveClass 检查）"),
    # 硬编码凭证误报
    ("CWE-798", "Python", "os.getenv('API_KEY') 从环境变量获取（非硬编码），但变量名包含 'password'"),
    ("CWE-798", "Java", "配置文件中的占位符 ${DB_PASSWORD}（Spring 注入，非硬编码）"),
    # 弱密码学误报
    ("CWE-327", "Python", "hashlib.sha256 用于非安全用途（如文件校验和），非密码哈希"),
    ("CWE-327", "Java", "MD5 用于 ETag 缓存校验（非密码存储）"),
    # 路径穿越误报
    ("CWE-22", "Python", "open(os.path.join(base_dir, filename)) 但已校验 realpath 不超出 base_dir"),
    ("CWE-22", "Java", "Path.normalize() + startsWith(baseDir) 校验后的文件访问"),
    # 认证误报
    ("CWE-306", "Python", "API 端点无认证但已在网关层统一处理（装饰器 @public_api 标记）"),
    ("CWE-306", "Java", "Servlet 无认证检查但已在 Filter 层统一拦截"),
    # 授权误报
    ("CWE-862", "Python", "Django view 无 @login_required 但已在 URL 层配置 LOGIN_REQUIRED_MIDDLEWARE"),
    ("CWE-862", "Java", "方法无授权注解但已在 Spring Security 配置中统一拦截"),
    # CSRF 误报
    ("CWE-352", "Python", "Django 表单无 csrf_token 但这是 API 端点（使用 Bearer token 认证）"),
    ("CWE-352", "JavaScript", "fetch 请求无 CSRF token 但使用 SameSite=Strict cookie"),
    # 开放重定向误报
    ("CWE-601", "Python", "redirect(url) 但 url 来自白名单校验"),
    ("CWE-601", "Java", "response.sendRedirect 但目标 URL 从数据库读取且已校验"),
    # XXE 误报
    ("CWE-611", "Java", "DocumentBuilderFactory 但已设置 FEATURE_SECURE_PROCESSING 和禁用外部实体"),
    ("CWE-611", "Python", "xml.etree.ElementTree.parse 但使用 defusedxml 替代"),
    # SSTI 误报
    ("CWE-1336", "Python", "render_template_string 但模板字符串是硬编码的（非用户输入）"),
    ("CWE-1336", "Python", "Jinja2 Environment 但 autoescape=True 且模板来自文件（非用户输入）"),
    # 综合误报
    ("CWE-79", "Python", "Flask jsonify 返回 JSON 数据（Content-Type: application/json），用户输入在值中（非 HTML 注入）"),
]
for cwe, lang, pattern in adversarial_safe:
    _add(cwe, False, lang, "对抗性安全样本（看起来危险但实际安全）", pattern, "防御迷惑")

# === 7. CWE 边界对比样本（15 条）===
# 评估发现: strict_recall 45.9%，31/61 错标 CWE
boundary_tasks = [
    # CWE-89 SQL vs CWE-943 NoSQL
    ("CWE-89", True, "Python", "SQL vs NoSQL 边界", "MySQL/PostgreSQL 的 SQL 注入（cursor.execute 拼接），需归因为 CWE-89 而非 CWE-943"),
    ("CWE-943", True, "JavaScript", "SQL vs NoSQL 边界", "MongoDB 的 NoSQL 注入（collection.find 拼接），需归因为 CWE-943 而非 CWE-89"),
    ("CWE-89", True, "PHP", "SQL vs NoSQL 边界", "MySQLi 的 SQL 注入，需归因为 CWE-89"),
    ("CWE-943", True, "Python", "SQL vs NoSQL 边界", "PyMongo 的 NoSQL 注入（$where 拼接），需归因为 CWE-943"),
    # CWE-78 命令注入 vs CWE-95 代码注入
    ("CWE-78", True, "Python", "命令注入 vs 代码注入边界", "os.system(user_input) 执行系统命令，归因为 CWE-78 而非 CWE-95"),
    ("CWE-95", True, "Python", "命令注入 vs 代码注入边界", "eval(user_input) 执行 Python 代码，归因为 CWE-95 而非 CWE-78"),
    ("CWE-78", True, "Java", "命令注入 vs 代码注入边界", "Runtime.exec(user_input) 执行系统命令，归因为 CWE-78"),
    ("CWE-95", True, "JavaScript", "命令注入 vs 代码注入边界", "eval(user_input) 执行 JS 代码，归因为 CWE-95"),
    # CWE-502 反序列化 vs CWE-915 属性注入
    ("CWE-502", True, "Java", "反序列化 vs 属性注入边界", "ObjectInputStream.readObject() 反序列化用户数据，归因为 CWE-502"),
    ("CWE-915", True, "Python", "反序列化 vs 属性注入边界", "Django ModelForm 中用户可控字段导致属性注入（非反序列化），归因为 CWE-915"),
    ("CWE-502", True, "Python", "反序列化 vs 属性注入边界", "pickle.loads(user_data) 反序列化，归因为 CWE-502"),
    ("CWE-915", True, "Java", "反序列化 vs 属性注入边界", "Spring @ModelAttribute 自动绑定用户字段（非反序列化），归因为 CWE-915"),
    # CWE-89 SQL vs CWE-643 XPath
    ("CWE-89", True, "Python", "SQL vs XPath 边界", "SQL cursor.execute 拼接注入，归因为 CWE-89"),
    ("CWE-643", True, "Python", "SQL vs XPath 边界", "lxml etree.XPath 拼接注入，归因为 CWE-643"),
    ("CWE-79", True, "JavaScript", "XSS vs SSTI 边界", "innerHTML = userInput 导致 DOM XSS，归因为 CWE-79 而非 CWE-1336"),
]
for cwe, has_vuln, lang, scene, pattern in boundary_tasks:
    _add(cwe, has_vuln, lang, scene, pattern, "注意力分散")


# ---------------------------------------------------------------------------
# user prompt 构建器
# ---------------------------------------------------------------------------
def build_user_prompt(task):
    """构建 DeepSeek 出题指令。"""
    cwe = task["cwe"]
    has_vuln = task["has_vuln"]
    lang = task["lang"]
    scene = task["scene"]
    pattern = task["key_pattern"]
    difficulty = task["difficulty"]

    vuln_str = "是" if has_vuln else "否"
    return (
        f"请生成 1 条 {cwe} 漏洞样本并分析其安全性：\n"
        f"- 语言：{lang}\n"
        f"- 场景：{scene}\n"
        f"- 是否有漏洞：{vuln_str}\n"
        f"- 难度：{difficulty}\n"
        f"- 关键模式要求：{pattern}\n\n"
        f"要求：代码真实可编译（20-80行），漏洞锚定行号。"
        + ("安全样本必须包含有效防御，分析时用否定推理确认安全。" if not has_vuln else "")
    )


# ---------------------------------------------------------------------------
# API 调用
# ---------------------------------------------------------------------------
def call_deepseek(task, task_id):
    """调用 DeepSeek API 生成一条样本。"""
    system = DEEPSEEK_DISTILL_POSITIVE if task["has_vuln"] else DEEPSEEK_DISTILL_NEGATIVE
    user = build_user_prompt(task)

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(CHAT_URL, json=payload, headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            return content, usage, None
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                time.sleep(3 * (attempt + 1))
                continue
            return None, None, f"超时（{MAX_RETRIES}次重试后）"
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 * (attempt + 1))
                continue
            return None, None, str(e)

    return None, None, "重试耗尽"


# ---------------------------------------------------------------------------
# 处理单条任务
# ---------------------------------------------------------------------------
def process_task(task, task_id, output_path, write_lock):
    """处理一条任务：调 API → 解析 → 校验 → 写入。"""
    content, usage, error = call_deepseek(task, task_id)
    if error:
        print(f"  [FAIL] {task_id}: API 错误: {error}", flush=True)
        return None, 0

    # 解析 + 校验
    parsed, parse_err = parse_assistant(content)
    if not parsed:
        print(f"  [FAIL] {task_id}: 解析失败: {parse_err}", flush=True)
        return None, 0

    ok, val_err = validate(parsed, task["has_vuln"])
    if not ok:
        print(f"  [FAIL] {task_id}: 校验失败: {val_err}", flush=True)
        return None, 0

    # 组装 ChatML（build_chatml 返回 {"messages": [...]} 格式）
    record = build_chatml(STUDENT_SYSTEM, parsed)

    # 提取代码文件名
    cwe = task["cwe"]
    has_vuln = task["has_vuln"]
    lang = task["lang"].lower()
    fname = f"targeted_{cwe.lower()}_{task_id.replace('-','_')}.{lang if lang != 'javascript' else 'js'}"

    # 添加 meta
    record["_meta"] = {
        "task_id": task_id,
        "cwe": cwe,
        "lang": task["lang"],
        "has_vuln": has_vuln,
        "scene": task["scene"],
        "pack": "targeted_supplement",
        "source": "deepseek-v4-flash",
        "difficulty": task["difficulty"],
        "key_pattern": task["key_pattern"],
        "filename": fname,
    }

    # 写入文件
    with write_lock:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    tokens = usage.get("total_tokens", 0)
    tag = "VULN" if has_vuln else "SAFE"
    print(f"  [OK]   {task_id}: {cwe} {tag} ({task['lang']}, {len(content)} chars, {tokens} tokens)", flush=True)
    return record, tokens


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="针对性补充训练数据生成（基于 v8 评估诊断）")
    parser.add_argument("--limit", type=int, default=0, help="只生成前 N 条（0=全部）")
    parser.add_argument("--workers", type=int, default=CONCURRENCY, help="并发数")
    parser.add_argument("--output", type=str, default=str(OUTPUT_FILE), help="输出文件")
    args = parser.parse_args()

    if not API_KEY:
        print("[错误] 未设置 DEEPSEEK_API_KEY 环境变量", file=sys.stderr)
        return 1

    tasks = TARGETED_TASKS
    if args.limit > 0:
        tasks = tasks[: args.limit]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 统计
    vuln_count = sum(1 for t in tasks if t["has_vuln"])
    safe_count = len(tasks) - vuln_count
    cwe_dist = {}
    for t in tasks:
        cwe_dist[t["cwe"]] = cwe_dist.get(t["cwe"], 0) + 1

    print(f"[信息] 针对性补充数据生成")
    print(f"  总任务: {len(tasks)}（{vuln_count} 漏洞 + {safe_count} 安全）")
    print(f"  CWE 分布: {dict(sorted(cwe_dist.items(), key=lambda x: int(x[0].split('-')[1])))}")
    print(f"  并发: {args.workers}")
    print(f"  输出: {output_path}")
    print(f"  模型: {MODEL}")

    # 已完成任务（断点续传）
    done_ids = set()
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    tid = obj.get("_meta", {}).get("task_id", "")
                    if tid:
                        done_ids.add(tid)
                except json.JSONDecodeError:
                    pass
        print(f"  已完成: {len(done_ids)} 条（断点续传）")

    # 生成 task_id
    task_list = []
    for i, task in enumerate(tasks, 1):
        tid = f"targeted-{i:04d}"
        if tid not in done_ids:
            task_list.append((task, tid))

    print(f"  待生成: {len(task_list)} 条")
    print()

    # 并发生成
    write_lock = Lock()
    total_tokens = 0
    success = 0
    fail = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_task, task, tid, output_path, write_lock): tid
            for task, tid in task_list
        }
        for future in as_completed(futures):
            tid = futures[future]
            try:
                record, tokens = future.result()
                if record:
                    success += 1
                    total_tokens += tokens
                else:
                    fail += 1
            except Exception as e:
                print(f"  [EXCEPTION] {tid}: {e}", flush=True)
                fail += 1

    elapsed = time.time() - start_time

    # 统计
    print(f"\n{'='*60}")
    print(f"[完成] 成功 {success} / 失败 {fail} / 总计 {success + fail}")
    print(f"  Token 用量: {total_tokens:,}")
    print(f"  估算费用: ¥{total_tokens / 1_000_000 * 1.0:.2f}")
    print(f"  耗时: {elapsed:.0f}s（{elapsed/60:.1f} 分钟）")
    print(f"  输出: {output_path}")

    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f:
            total_lines = sum(1 for _ in f)
        print(f"  文件总行数: {total_lines}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
