#!/usr/bin/env python3
"""缺失 CWE + 边界对比样本生成。

补充内容：
1. 缺失 CWE：CWE-91, CWE-610, CWE-797（测试集需要但训练数据无）
2. CWE 边界对比样本（解决 strict 准确率瓶颈）：
   - CWE-22 路径穿越 vs CWE-732 不安全文件路径（混淆 4 次）
   - CWE-943 NoSQL vs CWE-89 SQL（混淆 1 次但常见）
   - CWE-502 反序列化 vs CWE-98（混淆）
   - CWE-384 会话固定 vs CWE-352 CSRF（混淆）
   - CWE-329 硬编码 IV vs CWE-798 硬编码凭证（混淆）
   - CWE-295 证书验证 vs CWE-759（混淆）
   - CWE-94 代码注入 vs CWE-78 命令注入（混淆）
   - CWE-643 XPath 注入 vs CWE-89 SQL（混淆）
   - CWE-917 SpEL 注入 vs CWE-79 XSS（混淆）
   - CWE-347 JWT vs CWE-287 认证绕过（混淆）

每个边界对生成 4 条（2 漏洞对比 + 2 安全），总计约 40 条。
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

_DISTILL_V2 = Path(__file__).resolve().parent / "distill_v2"
sys.path.insert(0, str(_DISTILL_V2))

from prompts.deepseek import (
    DEEPSEEK_DISTILL_POSITIVE,
    DEEPSEEK_DISTILL_NEGATIVE,
    STUDENT_SYSTEM,
)
from validate_sample import parse_assistant, validate, build_chatml
import requests

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
OUTPUT_FILE = DATA_DIR / "distill_cwe_boundary_supplement.jsonl"

API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
CHAT_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"
CONCURRENCY = 6
TEMPERATURE = 0.7
MAX_TOKENS = 4096
TIMEOUT = 90
MAX_RETRIES = 3

# ===========================================================================
# 任务定义
# ===========================================================================
TASKS = []

def _add(cwe, has_vuln, lang, scene, key_pattern, boundary_note=""):
    TASKS.append({
        "cwe": cwe, "has_vuln": has_vuln, "lang": lang,
        "scene": scene, "key_pattern": key_pattern,
        "boundary_note": boundary_note, "difficulty": "注意力分散",
    })

# --- 1. 缺失 CWE（测试集需要但训练数据无）---
# CWE-91: XML Injection
_add("CWE-91", True, "Java", "XML 配置解析", "XML 属性注入，用户输入拼入 XML 节点属性值", "CWE-91 vs CWE-611（XXE 是外部实体，XML注入是属性/内容注入）")
_add("CWE-91", True, "Python", "API 数据解析", "xml.etree.ElementTree 构造 XML 时用户输入未转义", "")
_add("CWE-91", False, "Java", "XML 配置解析", "使用 XML 转义库对属性值做净化", "")

# CWE-610: Externally Controlled Reference
_add("CWE-610", True, "Python", "外部资源加载", "动态加载外部 URL 资源（非 XXE，是外部引用可控）", "CWE-610 vs CWE-611（610 是外部引用，611 是实体扩展）")
_add("CWE-610", True, "Java", "配置加载", "System.getProperty 加载外部可控配置路径", "")
_add("CWE-610", False, "Python", "外部资源加载", "使用白名单校验外部资源引用", "")

# CWE-797: Improper Filtering of Special Elements
_add("CWE-797", True, "Python", "输入过滤", "过滤不完整，只过滤了 < > 但未过滤 ' \" 导致注入", "CWE-797 vs CWE-79（797 是过滤缺陷，79 是 XSS）")
_add("CWE-797", True, "JavaScript", "输入过滤", "正则过滤不全，特殊字符可绕过", "")
_add("CWE-797", False, "Python", "输入过滤", "使用完整白名单过滤，覆盖所有特殊字符", "")

# --- 2. CWE-22 路径穿越 vs CWE-732 不安全文件路径（混淆 4 次，最高频）---
_add("CWE-22", True, "Python", "文件读取", "open(user_input) 直接拼接路径，../ 可穿越", "CWE-22 路径穿越：source 是用户输入，sink 是 open()，特征是 ../ 穿越")
_add("CWE-22", True, "Java", "文件下载", "new FileInputStream(userPath) 无校验", "CWE-22 路径穿越：特征是路径分隔符 ../ 或 ..\\")
_add("CWE-732", True, "Python", "文件权限", "os.chmod(path, 0o777) 文件权限过宽", "CWE-732 不安全文件权限：不是路径穿越，是权限配置不当")
_add("CWE-732", True, "Java", "文件权限", "Files.setPosixFilePermissions 设置过于宽松", "CWE-732 不安全文件权限：关注权限位而非路径")
_add("CWE-22", False, "Python", "文件读取", "os.path.realpath + startswith(base_dir) 校验", "安全：路径穿越防御")
_add("CWE-732", False, "Python", "文件权限", "os.chmod(path, 0o644) 最小权限", "安全：权限最小化")

# --- 3. CWE-943 NoSQL vs CWE-89 SQL（注入类型边界）---
_add("CWE-943", True, "JavaScript", "MongoDB 查询", "collection.find({user: req.body.user}) 直接拼接", "CWE-943 NoSQL 注入：sink 是 MongoDB 的 find/aggregate")
_add("CWE-943", True, "Python", "PyMongo 查询", "db.users.find({'name': user_input}) 无参数化", "CWE-943 NoSQL 注入：特征是 $where/$gt 等 NoSQL 操作符注入")
_add("CWE-89", True, "Python", "MySQL 查询", "cursor.execute('SELECT * FROM users WHERE id=' + uid)", "CWE-89 SQL 注入：sink 是 SQL execute，特征是 SQL 语法")
_add("CWE-89", True, "Java", "PostgreSQL 查询", "Statement.executeQuery(sql) 拼接", "CWE-89 SQL 注入：sink 是 JDBC executeQuery")
_add("CWE-943", False, "JavaScript", "MongoDB 查询", "使用 mongoose schema 校验 + 参数化查询", "安全：NoSQL 参数化")
_add("CWE-89", False, "Python", "MySQL 查询", "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))", "安全：SQL 参数化")

# --- 4. CWE-502 反序列化 vs CWE-98（PHP 对象注入）/ 其他 ---
_add("CWE-502", True, "Java", "数据传输", "ObjectInputStream.readObject() 反序列化用户数据", "CWE-502 反序列化：sink 是 readObject()/pickle.loads/yaml.unsafe_load")
_add("CWE-502", True, "Python", "缓存处理", "pickle.loads(user_data) 反序列化", "CWE-502 反序列化：Python pickle")
_add("CWE-98", True, "PHP", "文件包含", "include($_GET['page']) PHP 文件包含漏洞", "CWE-98 PHP 对象注入/文件包含：sink 是 include/require，非反序列化")
_add("CWE-502", False, "Java", "数据传输", "使用 JSON 解析 + 类型白名单（resolveClass 检查）", "安全：反序列化白名单")
_add("CWE-98", False, "PHP", "文件包含", "白名单校验 include 参数", "安全：文件包含白名单")

# --- 5. CWE-384 会话固定 vs CWE-352 CSRF（会话安全边界）---
_add("CWE-384", True, "Java", "登录处理", "登录成功后未重新生成 session ID", "CWE-384 会话固定：特征是登录后未重新生成 session")
_add("CWE-384", True, "Python", "登录处理", "Flask session permanent=True 且未 rotate", "CWE-384 会话固定：sink 是 session 管理")
_add("CWE-352", True, "Python", "表单提交", "POST 请求无 CSRF token 校验", "CWE-352 CSRF：特征是跨站请求伪造，sink 是状态变更操作")
_add("CWE-352", True, "Java", "表单提交", "无 CSRF token + 无 SameSite cookie", "CWE-352 CSRF：sink 是状态变更")
_add("CWE-384", False, "Java", "登录处理", "登录后 request.changeSessionId()", "安全：会话重新生成")
_add("CWE-352", False, "Python", "表单提交", "Django CSRF middleware + {% csrf_token %}", "安全：CSRF 防御")

# --- 6. CWE-329 硬编码 IV vs CWE-798 硬编码凭证（硬编码边界）---
_add("CWE-329", True, "Java", "加密", "AES 加密使用硬编码 IV（非随机生成）", "CWE-329 硬编码 IV：关注加密算法的 IV 是否随机")
_add("CWE-329", True, "Python", "加密", "AES.new(key, IV=b'1234567890123456') 硬编码 IV", "CWE-329 硬编码 IV：IV 是固定字节")
_add("CWE-798", True, "Python", "数据库连接", "password='admin123' 硬编码在代码中", "CWE-798 硬编码凭证：关注凭证（密码/API key）字面量")
_add("CWE-798", True, "Java", "API 配置", "apiKey = 'sk-xxx' 硬编码", "CWE-798 硬编码凭证：凭证是字面量")
_add("CWE-329", False, "Java", "加密", "SecureRandom 生成 IV，每次加密不同", "安全：随机 IV")
_add("CWE-798", False, "Python", "数据库连接", "os.getenv('DB_PASSWORD') 从环境变量获取", "安全：凭证外部化")

# --- 7. CWE-295 证书验证 vs CWE-759（TLS 边界）---
_add("CWE-295", True, "Python", "HTTPS 请求", "requests.get(url, verify=False) 禁用证书验证", "CWE-295 证书验证缺失：verify=False 或 SSLContext 不校验")
_add("CWE-295", True, "Java", "HTTPS 请求", "TrustManager 实现返回空数组，不校验证书", "CWE-295 证书验证缺失")
_add("CWE-759", True, "Python", "密码哈希", "使用 bcrypt 但 salt 固定（非随机）", "CWE-759 缺少盐值：关注密码哈希的 salt")
_add("CWE-295", False, "Python", "HTTPS 请求", "verify=True 使用系统 CA 证书", "安全：证书验证启用")
_add("CWE-759", False, "Python", "密码哈希", "bcrypt.gensalt() 随机盐值", "安全：随机盐")

# --- 8. CWE-94 代码注入 vs CWE-78 命令注入（执行边界）---
_add("CWE-94", True, "Python", "动态执行", "eval(user_input) 执行 Python 表达式", "CWE-94 代码注入：sink 是 eval/exec，执行语言本身代码")
_add("CWE-94", True, "JavaScript", "动态执行", "new Function(user_input)() 执行 JS 代码", "CWE-94 代码注入：sink 是 eval/new Function")
_add("CWE-78", True, "Python", "命令执行", "os.system(user_input) 执行系统命令", "CWE-78 命令注入：sink 是 os.system/subprocess，执行 OS 命令")
_add("CWE-78", True, "Java", "命令执行", "Runtime.getRuntime().exec(user_input)", "CWE-78 命令注入：sink 是 Runtime.exec")
_add("CWE-94", False, "Python", "动态执行", "ast.literal_eval 替代 eval（只允许字面量）", "安全：安全替代")
_add("CWE-78", False, "Python", "命令执行", "subprocess.run(['ls', path], shell=False) 列表参数", "安全：列表参数 + shell=False")

# --- 9. CWE-643 XPath 注入 vs CWE-89 SQL（查询注入边界）---
_add("CWE-643", True, "Python", "XML 查询", "etree.XPath('//user[name=\"' + user_input + '\"]') 拼接", "CWE-643 XPath 注入：sink 是 XPath 查询")
_add("CWE-643", True, "Java", "XML 查询", "XPathExpression eval 拼接用户输入", "CWE-643 XPath 注入：sink 是 XPath 编译/执行")
_add("CWE-643", False, "Python", "XML 查询", "参数化 XPath 查询（变量绑定）", "安全：XPath 参数化")

# --- 10. CWE-917 SpEL 注入 vs CWE-79 XSS（表达式边界）---
_add("CWE-917", True, "Java", "Spring 表达式", "SpelExpressionParser.parseExpression(user_input).getValue()", "CWE-917 SpEL 注入：sink 是 SpEL 解析器")
_add("CWE-917", True, "Java", "Thymeleaf 模板", "__${user_input}__ 表达式注入", "CWE-917 SpEL 注入：特征是 __${}__ 表达式")
_add("CWE-917", False, "Java", "Spring 表达式", "SimpleEvaluationContext 限制允许的操作", "安全：SpEL 沙箱")

# --- 11. CWE-347 JWT 签名验证 vs CWE-287 认证绕过（认证边界）---
_add("CWE-347", True, "JavaScript", "JWT 验证", "jwt.verify(token, secret, {algorithms: ['none']}) 允许 none 算法", "CWE-347 JWT 签名验证：关注算法是否允许 none")
_add("CWE-347", True, "Python", "JWT 验证", "jwt.decode(token, verify=False) 禁用签名验证", "CWE-347 JWT 签名验证：verify=False")
_add("CWE-287", True, "Python", "认证检查", "if user.role == 'admin' 字符串比较但未校验认证", "CWE-287 认证绕过：关注认证逻辑是否完整")
_add("CWE-347", False, "JavaScript", "JWT 验证", "jwt.verify(token, secret, {algorithms: ['HS256']}) 限定算法", "安全：JWT 算法白名单")
_add("CWE-287", False, "Python", "认证检查", "@login_required 装饰器 + session 校验", "安全：认证检查")


def build_user_prompt(task):
    cwe = task["cwe"]
    has_vuln = task["has_vuln"]
    lang = task["lang"]
    scene = task["scene"]
    pattern = task["key_pattern"]
    boundary = task.get("boundary_note", "")
    difficulty = task["difficulty"]
    vuln_str = "是" if has_vuln else "否"

    prompt = (
        f"请生成 1 条 {cwe} 漏洞样本并分析其安全性：\n"
        f"- 语言：{lang}\n"
        f"- 场景：{scene}\n"
        f"- 是否有漏洞：{vuln_str}\n"
        f"- 难度：{difficulty}\n"
        f"- 关键模式要求：{pattern}\n"
    )
    if boundary:
        prompt += f"- CWE 归因提示：{boundary}\n"
    prompt += "\n要求：代码真实可编译（20-80行），漏洞锚定行号。"
    if not has_vuln:
        prompt += "安全样本必须包含有效防御，分析时用否定推理确认安全。"
    prompt += "\n重要：vulnerability_type 字段必须以正确的 CWE 编号开头（如 \"CWE-22 路径穿越\"）。"
    return prompt


def call_deepseek(task, task_id):
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


def process_task(task, task_id, output_path, write_lock):
    content, usage, error = call_deepseek(task, task_id)
    if error:
        print(f"  [FAIL] {task_id}: API 错误: {error}", flush=True)
        return None, 0
    parsed, parse_err = parse_assistant(content)
    if not parsed:
        print(f"  [FAIL] {task_id}: 解析失败: {parse_err}", flush=True)
        return None, 0
    ok, val_err = validate(parsed, task["has_vuln"])
    if not ok:
        print(f"  [FAIL] {task_id}: 校验失败: {val_err}", flush=True)
        return None, 0
    record = build_chatml(STUDENT_SYSTEM, parsed)
    cwe = task["cwe"]
    lang = task["lang"].lower()
    fname = f"boundary_{cwe.lower()}_{task_id.replace('-','_')}.{lang if lang != 'javascript' else 'js'}"
    record["_meta"] = {
        "task_id": task_id,
        "cwe": cwe,
        "lang": task["lang"],
        "has_vuln": task["has_vuln"],
        "scene": task["scene"],
        "pack": "cwe_boundary_supplement",
        "source": "deepseek-v4-flash",
        "difficulty": task["difficulty"],
        "key_pattern": task["key_pattern"],
        "boundary_note": task.get("boundary_note", ""),
        "filename": fname,
    }
    with write_lock:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    tokens = usage.get("total_tokens", 0)
    tag = "VULN" if task["has_vuln"] else "SAFE"
    print(f"  [OK]   {task_id}: {cwe} {tag} ({task['lang']}, {len(content)} chars, {tokens} tokens)", flush=True)
    return record, tokens


def main():
    parser = argparse.ArgumentParser(description="CWE 边界对比样本生成")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=CONCURRENCY)
    parser.add_argument("--output", type=str, default=str(OUTPUT_FILE))
    args = parser.parse_args()

    if not API_KEY:
        print("[错误] 未设置 DEEPSEEK_API_KEY", file=sys.stderr)
        return 1

    tasks = TASKS
    if args.limit > 0:
        tasks = tasks[: args.limit]

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    vuln_count = sum(1 for t in tasks if t["has_vuln"])
    safe_count = len(tasks) - vuln_count
    cwe_dist = {}
    for t in tasks:
        cwe_dist[t["cwe"]] = cwe_dist.get(t["cwe"], 0) + 1

    print(f"[信息] CWE 边界对比样本生成")
    print(f"  总任务: {len(tasks)}（{vuln_count} 漏洞 + {safe_count} 安全）")
    print(f"  CWE 分布: {dict(sorted(cwe_dist.items(), key=lambda x: int(x[0].split('-')[1])))}")
    print(f"  输出: {output_path}\n")

    done_ids = set()
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    obj = json.loads(line)
                    tid = obj.get("_meta", {}).get("task_id", "")
                    if tid: done_ids.add(tid)
                except: pass
        print(f"  已完成: {len(done_ids)} 条")

    task_list = []
    for i, task in enumerate(tasks, 1):
        tid = f"boundary-{i:04d}"
        if tid not in done_ids:
            task_list.append((task, tid))
    print(f"  待生成: {len(task_list)} 条\n")

    write_lock = Lock()
    total_tokens = 0
    success = fail = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_task, t, tid, output_path, write_lock): tid
                   for t, tid in task_list}
        for future in as_completed(futures):
            try:
                rec, tokens = future.result()
                if rec: success += 1; total_tokens += tokens
                else: fail += 1
            except Exception as e:
                print(f"  [EXCEPTION] {e}", flush=True)
                fail += 1

    elapsed = time.time() - start
    print(f"\n{'='*60}")
    print(f"[完成] 成功 {success} / 失败 {fail} / 总计 {success+fail}")
    print(f"  Token: {total_tokens:,}  费用: ¥{total_tokens/1e6*1.0:.2f}  耗时: {elapsed:.0f}s")
    if output_path.exists():
        with open(output_path) as f:
            print(f"  文件行数: {sum(1 for _ in f)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
