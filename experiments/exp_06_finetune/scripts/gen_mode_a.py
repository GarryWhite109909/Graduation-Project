#!/usr/bin/env python3
"""模式 A 训练样本生成：多候选漏洞 → 选出真主漏洞。

生成 60 条训练样本，训练模型在一段代码同时存在多个安全问题时，正确选出
最严重的主漏洞作为 vulnerability_type，而不是报告次要问题（如硬编码密钥）。

样本类型分布：
  1. 硬编码 key + 命令注入（CWE-78）        10 条
  2. 硬编码 key + SQL 注入（CWE-89）         10 条
  3. 硬编码 key + 反序列化（CWE-502）         8 条
  4. 硬编码 key + SSTI（CWE-1336）            8 条
  5. 硬编码 key + XSS（CWE-79）               8 条
  6. 硬编码 key + 路径穿越（CWE-22）           6 条
  7. 多注入点选主（两种漏洞，选更严重者）     10 条

约 20% 样本包含"防御迷惑"代码（看似有防御但实际无效）。
语言覆盖：Python, JavaScript, Java, PHP, Go。

输出：
  experiments/exp_06_finetune/data/supplement_mode_a.jsonl

用法：
  python experiments/exp_06_finetune/scripts/gen_mode_a.py
"""

import json
import re
from pathlib import Path
from collections import Counter

# ===========================================================================
# 路径与常量
# ===========================================================================
SCRIPT_DIR = Path(__file__).resolve().parent          # scripts/
EXP_DIR = SCRIPT_DIR.parent                            # exp_06_finetune/
OUTPUT_FILE = EXP_DIR / "data" / "supplement_mode_a.jsonl"

SYSTEM_PROMPT = (
    "你是一名安全研究员，分析给定代码的安全漏洞。\n"
    "\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，"
    "字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），"
    "格式如 'CWE-编号 漏洞名'，例如 'CWE-89 SQL Injection'、"
    "'CWE-79 Cross-site Scripting (XSS)'；无漏洞填 'none'\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填 'None'\n"
    "   - source: str, 污染来源（用户可控输入点）。必须锚定行号，"
    "如 'line 12: request.args.get(\"id\")'；无漏洞填 'N/A'\n"
    "   - sink: str, 危险函数或触发点。必须锚定行号，"
    "如 'line 18: cursor.execute(query)'；无漏洞填 'N/A'\n"
    "   - explanation: str, 漏洞或安全现状说明（数据流/成因，用 -> 箭头描述）\n"
    "   - fix_suggestion: str, 可执行的修复建议。必须锚定行号，"
    "格式 'line N: 应改为 ...'；无漏洞填 'no fix needed'"
)


# ===========================================================================
# 辅助函数
# ===========================================================================
def _ln(code, marker):
    """返回 code 中第一个包含 marker 的行的 1-based 行号。"""
    for i, line in enumerate(code.split("\n"), 1):
        if marker in line:
            return i
    raise ValueError(f"代码中未找到标记: {marker!r}")


def make_verdict(code, *, has_vuln, vuln_type, risk,
                 source_marker=None, source_desc=None,
                 sink_marker=None, sink_desc=None,
                 explanation, fix_marker=None, fix_desc=None):
    """构造 verdict dict，行号从 code 中自动解析。"""
    if not has_vuln:
        return {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": explanation,
            "fix_suggestion": "no fix needed",
        }
    src_line = _ln(code, source_marker)
    sink_line = _ln(code, sink_marker)
    fix_line = _ln(code, fix_marker) if fix_marker else sink_line
    fix_suggestion = f"line {fix_line}: 应改为 {fix_desc}"
    fix_suggestion = fix_suggestion.replace("\n", " ")
    if len(fix_suggestion) > 500:
        fix_suggestion = fix_suggestion[:497] + "..."
    return {
        "has_vulnerability": True,
        "vulnerability_type": vuln_type,
        "risk_level": risk,
        "source": f"line {src_line}: {source_desc}",
        "sink": f"line {sink_line}: {sink_desc}",
        "explanation": explanation,
        "fix_suggestion": fix_suggestion,
    }


def make_sample(lang, code, analysis, verdict):
    """构造 ChatML JSON 记录。"""
    user_content = (
        f"代码片段（语言: {lang}）：\n"
        f"```{lang}\n{code}\n```"
    )
    json_str = json.dumps(verdict, ensure_ascii=False)
    assistant_content = f"{analysis}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def _spec(lang, code, analysis, **verdict_kw):
    """快捷构造样本规格 dict。"""
    return {
        "lang": lang,
        "code": code,
        "analysis": analysis,
        "verdict": make_verdict(code, **verdict_kw),
    }


def validate_spec(spec):
    """校验单条样本规格，返回错误列表（空列表表示通过）。"""
    errors = []
    code = spec["code"]
    verdict = spec["verdict"]
    lines = code.split("\n")
    num_lines = len(lines)

    for field in ("has_vulnerability", "vulnerability_type", "risk_level",
                  "source", "sink", "explanation", "fix_suggestion"):
        if field not in verdict:
            errors.append(f"缺少字段: {field}")

    if verdict.get("has_vulnerability") is True:
        vt = verdict.get("vulnerability_type", "")
        if not vt.startswith("CWE-"):
            errors.append(f"vulnerability_type '{vt}' 不以 'CWE-' 开头")
        if verdict.get("risk_level") not in ("Critical", "High", "Medium", "Low"):
            errors.append(f"risk_level '{verdict.get('risk_level')}' 不合法")

        for field in ("source", "sink", "fix_suggestion"):
            val = verdict.get(field, "")
            m = re.search(r"line (\d+)", val)
            if not m:
                errors.append(f"{field} 缺少行号引用: {val[:60]}")
            else:
                ln = int(m.group(1))
                if ln < 1 or ln > num_lines:
                    errors.append(f"{field} 行号 {ln} 超出范围 (1-{num_lines})")

        fix = verdict.get("fix_suggestion", "")
        if "\n" in fix:
            errors.append("fix_suggestion 含换行符")
        if len(fix) > 500:
            errors.append(f"fix_suggestion 过长 ({len(fix)} 字符)")
    return errors


# ===========================================================================
# 1. 硬编码 key + 命令注入（CWE-78）— 10 条
# ===========================================================================
def gen_key_plus_cmd():
    S = []

    # --- 1. Python os.system ---
    code = r'''import os

API_KEY = "sk-abc123def456ghi789"

def ping_host(hostname):
    cmd = "ping -c 1 " + hostname
    os.system(cmd)
    return "done"
'''
    k = _ln(code, 'API_KEY')
    c = _ln(code, 'os.system')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥 API_KEY（CWE-798），属于次要问题，需攻击者已获取源码才能利用。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 hostname 经字符串拼接进 os.system，无任何转义。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用（如注入 ; id），"
        f"虽然存在硬编码密钥（CWE-798），但主漏洞为命令注入，因其可被远程攻击者直接利用。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="def ping_host", source_desc="ping_host(hostname) 参数 hostname 用户可控",
        sink_marker="os.system", sink_desc="os.system(cmd) 执行拼接命令",
        explanation=f"line {_ln(code,'def ping_host')} hostname 用户输入 -> line {_ln(code,'cmd =')} 字符串拼接无转义 -> line {_ln(code,'os.system')} os.system 执行 -> 命令注入（硬编码密钥 CWE-798 为次要问题）",
        fix_marker="os.system", fix_desc="使用 subprocess.run(['ping','-c','1',hostname]) 传列表参数不经 shell"))

    # --- 2. Python subprocess shell=True（防御迷惑：仅过滤 |） ---
    code = r'''import subprocess

DB_PASSWORD = "admin_pass_2024"

def lookup_domain(domain):
    safe = domain.replace("|", "")
    result = subprocess.run("nslookup " + safe, shell=True, capture_output=True)
    return result.stdout.decode()
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'subprocess.run')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码 DB_PASSWORD（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 domain 拼接进 subprocess.run(shell=True)。\n"
        f"3. 防御迷惑：仅过滤 | 字符，未过滤 ; & $() \\n 等命令分隔符，防御无效。\n"
        f"4. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="def lookup_domain", source_desc="lookup_domain(domain) 参数 domain 用户可控",
        sink_marker="subprocess.run", sink_desc="subprocess.run(shell=True) 执行拼接命令",
        explanation=f"line {_ln(code,'def lookup_domain')} domain 用户输入 -> line {_ln(code,'safe =')} 仅过滤|（防御迷惑） -> line {_ln(code,'subprocess.run')} shell=True 执行 -> 命令注入（; & $() 未过滤）",
        fix_marker="subprocess.run", fix_desc="使用 subprocess.run(['nslookup',domain]) 传列表参数，设 shell=False"))

    # --- 3. JavaScript child_process.exec ---
    code = r'''const { exec } = require('child_process');

const JWT_SECRET = "my_super_secret_key_2024";

function checkFile(filename) {
    exec('file ' + filename, (err, stdout) => {
        console.log(stdout);
    });
}
'''
    k = _ln(code, 'JWT_SECRET')
    c = _ln(code, 'exec(')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 JWT 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 filename 拼接进 exec()，无转义。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用"
        f"（如注入 ; cat /etc/passwd），远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="function checkFile", source_desc="checkFile(filename) 参数 filename 用户可控",
        sink_marker="exec('file '", sink_desc="exec('file ' + filename) 执行拼接命令",
        explanation=f"line {_ln(code,'function checkFile')} filename 用户输入 -> line {c} 字符串拼接 -> exec 执行 -> 命令注入（硬编码 JWT 密钥为次要问题）",
        fix_marker="exec('file '", fix_desc="使用 execFile('file',[filename]) 不经 shell 执行"))

    # --- 4. Java ProcessBuilder sh -c ---
    code = r'''import java.io.*;

public class NetworkTool {
    private static final String SECRET_KEY = "hardcoded_secret_12345";

    public static String traceroute(String host) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "traceroute " + host);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }
}
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'ProcessBuilder')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥 SECRET_KEY（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 host 拼接进 sh -c 命令。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="public static String traceroute", source_desc="traceroute(String host) 参数 host 用户可控",
        sink_marker="new ProcessBuilder", sink_desc="ProcessBuilder(/bin/sh,-c, traceroute+host) shell 执行",
        explanation=f"line {_ln(code,'public static String traceroute')} host 用户输入 -> line {_ln(code,'new ProcessBuilder')} 拼接 sh -c -> shell 执行 -> 命令注入（硬编码密钥为次要问题）",
        fix_marker="new ProcessBuilder", fix_desc="使用 new ProcessBuilder(\"traceroute\",host) 不经 shell 执行"))

    # --- 5. PHP shell_exec ---
    code = r'''<?php
$DB_PASSWORD = "root_pass_123";

function convert_image($file) {
    $output = shell_exec("convert " . $file . " output.png");
    return $output;
}
?>
'''
    k = _ln(code, '$DB_PASSWORD')
    c = _ln(code, 'shell_exec')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 file 拼接进 shell_exec。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用"
        f"（如注入 ; rm -rf /tmp），远比硬编码密码（High）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="function convert_image", source_desc="convert_image($file) 参数 $file 用户可控",
        sink_marker="shell_exec", sink_desc='shell_exec("convert " . $file ...) 执行拼接命令',
        explanation=f"line {_ln(code,'function convert_image')} $file 用户输入 -> line {_ln(code,'shell_exec')} 字符串拼接 shell_exec -> 命令注入（硬编码密码为次要问题）",
        fix_marker="shell_exec", fix_desc="使用 escapeshellarg($file) 转义参数后再拼接，或用 proc_open 传数组"))

    # --- 6. Go exec.Command sh -c ---
    code = r'''package main

import (
    "os/exec"
)

var APIKey = "ghp_abcdef1234567890abcdef1234567890"

func runDig(domain string) string {
    cmd := exec.Command("sh", "-c", "dig "+domain)
    out, _ := cmd.Output()
    return string(out)
}
'''
    k = _ln(code, 'var APIKey')
    c = _ln(code, 'exec.Command')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 domain 拼接进 sh -c 命令。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("go", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="func runDig", source_desc="runDig(domain string) 参数 domain 用户可控",
        sink_marker="exec.Command", sink_desc='exec.Command("sh","-c","dig "+domain) shell 执行',
        explanation=f"line {_ln(code,'func runDig')} domain 用户输入 -> line {_ln(code,'exec.Command')} 拼接 sh -c -> shell 执行 -> 命令注入（硬编码密钥为次要问题）",
        fix_marker="exec.Command", fix_desc="使用 exec.Command(\"dig\",domain) 传参数列表不经 shell"))

    # --- 7. Python os.popen（防御迷惑：仅去除 < >） ---
    code = r'''import os

SECRET_TOKEN = "token_abc123xyz789"

def get_user_info(username):
    cleaned = username.replace("<", "").replace(">", "")
    return os.popen("id " + cleaned).read()
'''
    k = _ln(code, 'SECRET_TOKEN')
    c = _ln(code, 'os.popen')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入拼接进 os.popen。\n"
        f"3. 防御迷惑：仅去除 < > 字符，未过滤 ; | & $() 等命令分隔符，防御无效。\n"
        f"4. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="def get_user_info", source_desc="get_user_info(username) 参数 username 用户可控",
        sink_marker="os.popen", sink_desc='os.popen("id " + cleaned) 执行拼接命令',
        explanation=f"line {_ln(code,'def get_user_info')} username 用户输入 -> line {_ln(code,'cleaned =')} 仅去< >（防御迷惑） -> line {_ln(code,'os.popen')} os.popen 执行 -> 命令注入（; | & 未过滤）",
        fix_marker="os.popen", fix_desc="使用 subprocess.run(['id',username]) 传列表参数，设 shell=False"))

    # --- 8. Node.js execSync ---
    code = r'''const { execSync } = require('child_process');
const API_TOKEN = "tok_live_abc123def456";

function compressFile(path) {
    const out = execSync('gzip ' + path);
    return out.toString();
}
'''
    k = _ln(code, 'API_TOKEN')
    c = _ln(code, 'execSync(')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 令牌（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 path 拼接进 execSync。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码令牌（High）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="function compressFile", source_desc="compressFile(path) 参数 path 用户可控",
        sink_marker="execSync('gzip '", sink_desc="execSync('gzip ' + path) 执行拼接命令",
        explanation=f"line {_ln(code,'function compressFile')} path 用户输入 -> line {c} 字符串拼接 -> execSync 执行 -> 命令注入（硬编码令牌为次要问题）",
        fix_marker="execSync('gzip '", fix_desc="使用 execFileSync('gzip',[path]) 不经 shell 执行"))

    # --- 9. Python subprocess.check_output（防御迷惑：黑名单不全） ---
    code = r'''import subprocess

DB_PASS = "secret_db_password"

def fetch_url(url):
    blocked = [";", "|", "&"]
    safe = url
    for ch in blocked:
        safe = safe.replace(ch, "")
    return subprocess.check_output("curl " + safe, shell=True).decode()
'''
    k = _ln(code, 'DB_PASS')
    c = _ln(code, 'subprocess.check_output')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 url 拼接进 shell=True 命令。\n"
        f"3. 防御迷惑：黑名单仅过滤 ; | &，未过滤 $() 反引号 \\n 等，可被 $(id) 绕过。\n"
        f"4. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="def fetch_url", source_desc="fetch_url(url) 参数 url 用户可控",
        sink_marker="subprocess.check_output", sink_desc="subprocess.check_output(shell=True) 执行拼接命令",
        explanation=f"line {_ln(code,'def fetch_url')} url 用户输入 -> line {_ln(code,'for ch')} 黑名单过滤; | &（防御迷惑） -> line {_ln(code,'subprocess.check_output')} shell=True -> 命令注入（$() 反引号未过滤）",
        fix_marker="subprocess.check_output", fix_desc="使用 subprocess.check_output(['curl',url]) 传列表参数 shell=False"))

    # --- 10. Java Runtime.exec sh -c ---
    code = r'''import java.io.*;

public class FileInspector {
    private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

    public static String inspect(String path) throws IOException {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "stat " + path});
        return new String(p.getInputStream().readAllBytes());
    }
}
'''
    k = _ln(code, 'ACCESS_KEY')
    c = _ln(code, 'Runtime.getRuntime')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 AWS 访问密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现命令注入（CWE-78），用户输入 path 拼接进 sh -c 命令。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="public static String inspect", source_desc="inspect(String path) 参数 path 用户可控",
        sink_marker="Runtime.getRuntime", sink_desc='Runtime.exec({"/bin/sh","-c","stat "+path}) shell 执行',
        explanation=f"line {_ln(code,'public static String inspect')} path 用户输入 -> line {_ln(code,'Runtime.getRuntime')} 拼接 sh -c -> shell 执行 -> 命令注入（硬编码密钥为次要问题）",
        fix_marker="Runtime.getRuntime", fix_desc='使用 Runtime.getRuntime().exec(new String[]{"stat",path}) 不经 shell'))

    return S


# ===========================================================================
# 2. 硬编码 key + SQL 注入（CWE-89）— 10 条
# ===========================================================================
def gen_key_plus_sqli():
    S = []

    # --- 1. Python sqlite3 f-string ---
    code = r'''import sqlite3

DB_PASSWORD = "admin123"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'cursor.execute')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 username 经 f-string 拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用"
        f"（如注入 ' OR '1'='1 绕过认证），远比硬编码密码（High，需源码访问）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="def get_user", source_desc="get_user(username) 参数 username 用户可控",
        sink_marker="cursor.execute(query)", sink_desc="cursor.execute(f'SELECT ... {username}') 执行拼接 SQL",
        explanation=f"line {_ln(code,'def get_user')} username 用户输入 -> line {_ln(code,'query = f')} f-string 拼接 SQL -> line {_ln(code,'cursor.execute')} 执行 -> SQL 注入（硬编码密码为次要问题）",
        fix_marker="query = f", fix_desc='cursor.execute("SELECT * FROM users WHERE username = ?",(username,)) 使用参数化查询'))

    # --- 2. PHP mysqli_query ---
    code = r'''<?php
$DB_PASS = "root_secret_2024";

function find_user($name) {
    $conn = mysqli_connect("localhost", "root", $DB_PASS, "appdb");
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
    $result = mysqli_query($conn, $sql);
    return mysqli_fetch_assoc($result);
}
?>
'''
    k = _ln(code, '$DB_PASS')
    c = _ln(code, 'mysqli_query')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 name 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密码（High，需源码访问）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function find_user", source_desc="find_user($name) 参数 $name 用户可控",
        sink_marker="mysqli_query", sink_desc='mysqli_query($conn, "SELECT ... " . $name) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function find_user')} $name 用户输入 -> line {_ln(code,'$sql =')} 字符串拼接 SQL -> line {_ln(code,'mysqli_query')} 执行 -> SQL 注入（硬编码密码为次要问题）",
        fix_marker="$sql =", fix_desc='$stmt = mysqli_prepare($conn,"SELECT * FROM users WHERE name = ?"); mysqli_stmt_bind_param($stmt,"s",$name)'))

    # --- 3. Java Statement ---
    code = r'''import java.sql.*;

public class UserDao {
    private static final String DB_PASSWORD = "mysql_admin_2024";

    public User findByName(String name) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/appdb", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM users WHERE name = '" + name + "'");
        return rs.next() ? new User(rs) : null;
    }
}
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'stmt.executeQuery')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 name 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密码（High，需源码访问）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="public User findByName", source_desc="findByName(String name) 参数 name 用户可控",
        sink_marker="stmt.executeQuery", sink_desc='stmt.executeQuery("SELECT ... " + name) 执行拼接 SQL',
        explanation=f"line {_ln(code,'public User findByName')} name 用户输入 -> line {_ln(code,'stmt.executeQuery')} 字符串拼接 SQL -> Statement 执行 -> SQL 注入（硬编码密码为次要问题）",
        fix_marker="stmt.executeQuery", fix_desc='使用 PreparedStatement 并 setString(1, name) 参数化查询'))

    # --- 4. JavaScript mysql.query ---
    code = r'''const mysql = require('mysql');
const JWT_SECRET = "jwt_secret_key_abc123";

const pool = mysql.createPool({
    host: 'localhost', user: 'root',
    password: 'db_pass_2024', database: 'appdb'
});

function searchProducts(keyword) {
    const sql = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
    pool.query(sql, (err, rows) => {
        return rows;
    });
}
'''
    k = _ln(code, 'JWT_SECRET')
    c = _ln(code, 'pool.query')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 JWT 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 keyword 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function searchProducts", source_desc="searchProducts(keyword) 参数 keyword 用户可控",
        sink_marker="pool.query(sql", sink_desc='pool.query("SELECT ... " + keyword) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function searchProducts')} keyword 用户输入 -> line {_ln(code,'const sql =')} 字符串拼接 SQL -> line {_ln(code,'pool.query')} 执行 -> SQL 注入（硬编码密钥为次要问题）",
        fix_marker="const sql =", fix_desc='pool.query("SELECT * FROM products WHERE name LIKE ?",["%"+keyword+"%"]) 使用占位符'))

    # --- 5. Python psycopg2（防御迷惑：仅替换单引号） ---
    code = r'''import psycopg2

DB_PASS = "postgres_admin_2024"

def search_log(keyword):
    conn = psycopg2.connect(dbname="appdb", user="admin", password=DB_PASS)
    cursor = conn.cursor()
    safe = keyword.replace("'", "''")
    cursor.execute("SELECT * FROM logs WHERE msg LIKE '%" + safe + "%'")
    return cursor.fetchall()
'''
    k = _ln(code, 'DB_PASS')
    c = _ln(code, 'cursor.execute')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 keyword 拼接进 SQL。\n"
        f"3. 防御迷惑：仅替换单引号为双单引号，但反斜杠 \\ 未处理，"
        f"攻击者可用 \\' 绕过转义注入单引号。\n"
        f"4. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="def search_log", source_desc="search_log(keyword) 参数 keyword 用户可控",
        sink_marker="cursor.execute", sink_desc='cursor.execute("SELECT ... " + safe) 执行拼接 SQL',
        explanation=f"line {_ln(code,'def search_log')} keyword 用户输入 -> line {_ln(code,'safe =')} 仅替换单引号（防御迷惑，\\ 未处理） -> line {_ln(code,'cursor.execute')} 拼接 SQL -> SQL 注入（\\' 绕过）",
        fix_marker="cursor.execute", fix_desc='cursor.execute("SELECT * FROM logs WHERE msg LIKE %s",("%"+keyword+"%",)) 使用参数化查询'))

    # --- 6. Go database/sql ---
    code = r'''package main

import (
    "database/sql"
    _ "github.com/lib/pq"
)

var APIKey = "api_key_xyz_123456789"

func getUser(db *sql.DB, email string) (*User, error) {
    query := "SELECT id, email FROM users WHERE email = '" + email + "'"
    row := db.QueryRow(query)
    var u User
    err := row.Scan(&u.ID, &u.Email)
    return &u, err
}
'''
    k = _ln(code, 'var APIKey')
    c = _ln(code, 'db.QueryRow')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 email 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("go", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="func getUser", source_desc="getUser(db, email) 参数 email 用户可控",
        sink_marker="db.QueryRow", sink_desc='db.QueryRow("SELECT ... " + email) 执行拼接 SQL',
        explanation=f"line {_ln(code,'func getUser')} email 用户输入 -> line {_ln(code,'query :=')} 字符串拼接 SQL -> line {_ln(code,'db.QueryRow')} 执行 -> SQL 注入（硬编码密钥为次要问题）",
        fix_marker="query :=", fix_desc='db.QueryRow("SELECT id, email FROM users WHERE email = $1",email) 使用占位符'))

    # --- 7. PHP PDO query（非预处理） ---
    code = r'''<?php
$SECRET_KEY = "flask_secret_abc123";

function get_orders($pdo, $user_id) {
    $sql = "SELECT * FROM orders WHERE user_id = " . $user_id;
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
'''
    k = _ln(code, '$SECRET_KEY')
    c = _ln(code, '$pdo->query')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 user_id 直接拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用"
        f"（如注入 1 OR 1=1 获取全部订单），远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function get_orders", source_desc="get_orders($pdo, $user_id) 参数 $user_id 用户可控",
        sink_marker="$pdo->query", sink_desc='$pdo->query("SELECT ... " . $user_id) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function get_orders')} $user_id 用户输入 -> line {_ln(code,'$sql =')} 字符串拼接 SQL -> line {_ln(code,'$pdo->query')} query 非预处理执行 -> SQL 注入（硬编码密钥为次要问题）",
        fix_marker="$sql =", fix_desc='$stmt = $pdo->prepare("SELECT * FROM orders WHERE user_id = ?"); $stmt->execute([$user_id])'))

    # --- 8. Java JdbcTemplate ---
    code = r'''import org.springframework.jdbc.core.JdbcTemplate;

public class ProductDao {
    private static final String API_SECRET = "api_secret_456789";
    private final JdbcTemplate jdbc;

    public ProductDao(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Product> search(String keyword) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'";
        return jdbc.queryForList(sql, Product.class);
    }
}
'''
    k = _ln(code, 'API_SECRET')
    c = _ln(code, 'jdbc.queryForList')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 keyword 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="public List<Product> search", source_desc="search(String keyword) 参数 keyword 用户可控",
        sink_marker="jdbc.queryForList", sink_desc='jdbc.queryForList("SELECT ... " + keyword) 执行拼接 SQL',
        explanation=f"line {_ln(code,'public List<Product> search')} keyword 用户输入 -> line {_ln(code,'String sql =')} 字符串拼接 SQL -> line {_ln(code,'jdbc.queryForList')} 执行 -> SQL 注入（硬编码密钥为次要问题）",
        fix_marker="String sql =", fix_desc='jdbc.queryForList("SELECT * FROM products WHERE name LIKE ?",new Object[]{"%"+keyword+"%"})'))

    # --- 9. Python MySQLdb（防御迷惑：addslashes） ---
    code = r'''import MySQLdb

DB_PASSWORD = "mysql_root_pass"

def login(username, password):
    conn = MySQLdb.connect(host="localhost", user="root", passwd=DB_PASSWORD, db="app")
    cursor = conn.cursor()
    safe_user = username.replace("\\", "\\\\").replace("'", "\\'")
    safe_pass = password.replace("\\", "\\\\").replace("'", "\\'")
    sql = f"SELECT * FROM users WHERE username='{safe_user}' AND password='{safe_pass}'"
    cursor.execute(sql)
    return cursor.fetchone()
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'cursor.execute')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入拼接进 SQL。\n"
        f"3. 防御迷惑：手动转义反斜杠和单引号（类似 addslashes），但在 GBK 等多字节编码下"
        f"可被多字节字符绕过（如 0xbf27 被吃掉反斜杠）。\n"
        f"4. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="def login", source_desc="login(username, password) 参数用户可控",
        sink_marker="cursor.execute(sql)", sink_desc="cursor.execute(f'SELECT ... {safe_user}') 执行拼接 SQL",
        explanation=f"line {_ln(code,'def login')} username/password 用户输入 -> line {_ln(code,'safe_user =')} 手动转义（防御迷惑，多字节编码可绕过） -> line {_ln(code,'sql = f')} f-string 拼接 -> line {_ln(code,'cursor.execute(sql)')} 执行 -> SQL 注入",
        fix_marker="cursor.execute(sql)", fix_desc='cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",(username,password)) 参数化'))

    # --- 10. Node.js pg ---
    code = r'''const { Pool } = require('pg');
const SECRET = "app_secret_key_2024";

const pool = new Pool({
    user: 'admin', host: 'localhost',
    database: 'appdb', password: 'pg_pass_2024', port: 5432
});

function findAccount(owner) {
    const sql = "SELECT * FROM accounts WHERE owner = '" + owner + "'";
    pool.query(sql, (err, res) => {
        return res.rows;
    });
}
'''
    k = _ln(code, "const SECRET")
    c = _ln(code, 'pool.query(sql')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SQL 注入（CWE-89），用户输入 owner 字符串拼接进 SQL。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function findAccount", source_desc="findAccount(owner) 参数 owner 用户可控",
        sink_marker="pool.query(sql", sink_desc='pool.query("SELECT ... " + owner) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function findAccount')} owner 用户输入 -> line {_ln(code,'const sql =')} 字符串拼接 SQL -> line {_ln(code,'pool.query(sql')} 执行 -> SQL 注入（硬编码密钥为次要问题）",
        fix_marker="const sql =", fix_desc='pool.query("SELECT * FROM accounts WHERE owner = $1",[owner]) 使用占位符'))

    return S


# ===========================================================================
# 3. 硬编码 key + 反序列化（CWE-502）— 8 条
# ===========================================================================
def gen_key_plus_deser():
    S = []

    # --- 1. Python pickle.loads ---
    code = r'''import pickle
import base64

SECRET_KEY = "django_secret_key_abc123"

def load_session(session_data):
    raw = base64.b64decode(session_data)
    data = pickle.loads(raw)
    return data["user_id"]
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'pickle.loads')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），用户输入 session_data 经 base64 解码后"
        f"直接 pickle.loads，可构造恶意 pickle 实现 RCE。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用实现 RCE，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="def load_session", source_desc="load_session(session_data) 参数 session_data 用户可控",
        sink_marker="pickle.loads", sink_desc="pickle.loads(raw) 反序列化用户数据",
        explanation=f"line {_ln(code,'def load_session')} session_data 用户输入 -> line {_ln(code,'raw =')} base64 解码 -> line {_ln(code,'pickle.loads')} pickle.loads 反序列化 -> RCE（硬编码密钥为次要问题）",
        fix_marker="pickle.loads", fix_desc="使用 JSON 替代 pickle，或 json.loads(base64.b64decode(session_data))"))

    # --- 2. Python yaml.load ---
    code = r'''import yaml

API_KEY = "sk_live_abc123def456ghi789"

def parse_config(config_text):
    config = yaml.load(config_text, Loader=yaml.Loader)
    return config.get("timeout", 30)
'''
    k = _ln(code, 'API_KEY')
    c = _ln(code, 'yaml.load')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），yaml.load 使用不安全的 Loader，"
        f"可注入 !!python/object/apply 构造恶意对象实现 RCE。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="def parse_config", source_desc="parse_config(config_text) 参数 config_text 用户可控",
        sink_marker="yaml.load", sink_desc="yaml.load(config_text, Loader=yaml.Loader) 不安全反序列化",
        explanation=f"line {_ln(code,'def parse_config')} config_text 用户输入 -> line {_ln(code,'yaml.load')} yaml.load(不安全 Loader) -> !!python/object/apply -> RCE（硬编码密钥为次要问题）",
        fix_marker="yaml.load", fix_desc="使用 yaml.safe_load(config_text) 仅加载基础 YAML 类型"))

    # --- 3. Java ObjectInputStream ---
    code = r'''import java.io.*;

public class SessionManager {
    private static final String SECRET_KEY = "java_secret_key_2024";

    public static Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'readObject')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），ObjectInputStream.readObject 直接反序列化"
        f"用户数据，可利用 Commons Collections 等 gadget 链实现 RCE。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="public static Object deserialize", source_desc="deserialize(byte[] data) 参数 data 用户可控",
        sink_marker="readObject", sink_desc="ObjectInputStream.readObject() 反序列化用户数据",
        explanation=f"line {_ln(code,'public static Object deserialize')} data 用户输入 -> line {_ln(code,'ObjectInputStream')} ObjectInputStream 构造 -> line {_ln(code,'readObject')} readObject -> gadget 链 RCE（硬编码密钥为次要问题）",
        fix_marker="readObject", fix_desc="使用 ObjectInputFilter 白名单限制可反序列化的类"))

    # --- 4. Python pickle（防御迷惑：检查 magic bytes 但仍加载） ---
    code = r'''import pickle
import hmac
import hashlib

SECRET_KEY = b"hmac_secret_key_2024"

def load_data(token):
    payload = bytes.fromhex(token)
    if not payload.startswith(b"\\x80"):
        raise ValueError("invalid format")
    return pickle.loads(payload)
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'pickle.loads')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），pickle.loads 反序列化用户数据。\n"
        f"3. 防御迷惑：仅检查 magic bytes \\x80 前缀，不校验 HMAC 签名，"
        f"攻击者可构造合法前缀的恶意 pickle。\n"
        f"4. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="def load_data", source_desc="load_data(token) 参数 token 用户可控",
        sink_marker="pickle.loads(payload)", sink_desc="pickle.loads(payload) 反序列化用户数据",
        explanation=f"line {_ln(code,'def load_data')} token 用户输入 -> line {_ln(code,'if not payload')} 仅检查 magic bytes（防御迷惑） -> line {_ln(code,'pickle.loads(payload)')} pickle.loads -> RCE（无 HMAC 校验）",
        fix_marker="pickle.loads(payload)", fix_desc="先 HMAC 校验签名，再使用 json.loads 替代 pickle"))

    # --- 5. Node.js node-serialize ---
    code = r'''const serialize = require('node-serialize');
const API_TOKEN = "api_token_live_abc123";

function restoreSession(cookieValue) {
    const obj = serialize.unserialize(cookieValue);
    return obj.userId;
}
'''
    k = _ln(code, 'API_TOKEN')
    c = _ln(code, 'serialize.unserialize')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 令牌（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），node-serialize.unserialize 可执行"
        f"IIFE payload（如 _$$ND_FUNC$$_function(){...}()）实现 RCE。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码令牌（High）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="function restoreSession", source_desc="restoreSession(cookieValue) 参数 cookieValue 用户可控",
        sink_marker="serialize.unserialize", sink_desc="serialize.unserialize(cookieValue) 反序列化用户数据",
        explanation=f"line {_ln(code,'function restoreSession')} cookieValue 用户输入 -> line {_ln(code,'serialize.unserialize')} unserialize -> IIFE payload -> RCE（硬编码令牌为次要问题）",
        fix_marker="serialize.unserialize", fix_desc="改用 JSON.parse，禁用 node-serialize 的函数反序列化"))

    # --- 6. PHP unserialize ---
    code = r'''<?php
$DB_PASSWORD = "mysql_pass_2024";

function restore_cart($cookie) {
    $data = unserialize($cookie);
    return $data['items'];
}
?>
'''
    k = _ln(code, '$DB_PASSWORD')
    c = _ln(code, 'unserialize')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），unserialize 直接反序列化用户 cookie，"
        f"可利用 __wakeup/__destruct 魔术方法链实现 RCE。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="function restore_cart", source_desc="restore_cart($cookie) 参数 $cookie 用户可控",
        sink_marker="unserialize", sink_desc="unserialize($cookie) 反序列化用户数据",
        explanation=f"line {_ln(code,'function restore_cart')} $cookie 用户输入 -> line {_ln(code,'unserialize')} unserialize -> __wakeup/__destruct 魔术方法 -> POP 链 RCE（硬编码密码为次要问题）",
        fix_marker="unserialize", fix_desc="改用 json_decode，如需 unserialize 使用 allowed_classes 选项限制"))

    # --- 7. Python marshal.loads ---
    code = r'''import marshal
import base64

SECRET = "app_secret_abc123xyz"

def load_plugin(code_b64):
    raw = base64.b64decode(code_b64)
    func = marshal.loads(raw)
    return func()
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 'marshal.loads')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），marshal.loads 反序列化用户数据为"
        f"代码对象并执行，可直接实现任意代码执行。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="def load_plugin", source_desc="load_plugin(code_b64) 参数 code_b64 用户可控",
        sink_marker="marshal.loads", sink_desc="marshal.loads(raw) 反序列化用户数据为代码对象",
        explanation=f"line {_ln(code,'def load_plugin')} code_b64 用户输入 -> line {_ln(code,'raw =')} base64 解码 -> line {_ln(code,'marshal.loads')} marshal.loads 代码对象 -> line {_ln(code,'func()')} 执行 -> RCE",
        fix_marker="marshal.loads", fix_desc="禁止从用户输入加载 marshal 代码对象，改用 JSON 配置加载"))

    # --- 8. Java XMLDecoder（防御迷惑：检查类名但允许） ---
    code = r'''import java.beans.XMLDecoder;
import java.io.*;

public class ConfigLoader {
    private static final String SECRET = "config_secret_456";

    public static Object load(String xml) {
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes());
        XMLDecoder decoder = new XMLDecoder(bais);
        Object obj = decoder.readObject();
        decoder.close();
        return obj;
    }
}
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 'readObject()')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现不安全反序列化（CWE-502），XMLDecoder.readObject 可通过"
        f"<java> 标签构造任意对象并调用方法（如 ProcessBuilder.start）实现 RCE。\n"
        f"3. 防御迷惑：代码无任何过滤，XMLDecoder 本身不限制可创建的类。\n"
        f"4. 主漏洞判定：反序列化风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="public static Object load", source_desc="load(String xml) 参数 xml 用户可控",
        sink_marker="readObject()", sink_desc="XMLDecoder.readObject() 反序列化用户 XML",
        explanation=f"line {_ln(code,'public static Object load')} xml 用户输入 -> line {_ln(code,'XMLDecoder')} XMLDecoder 构造 -> line {_ln(code,'readObject()')} readObject -> <java> 标签构造 ProcessBuilder -> RCE",
        fix_marker="readObject()", fix_desc="禁用 XMLDecoder 解析用户输入，改用 JAXB 或 Jackson 配合白名单"))

    return S


# ===========================================================================
# 4. 硬编码 key + SSTI（CWE-1336）— 8 条
# ===========================================================================
def gen_key_plus_ssti():
    S = []

    # --- 1. Python Flask render_template_string ---
    code = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded_flask_secret_123'

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = '<h1>Hello ' + name + '</h1>'
    return render_template_string(template)
'''
    k = _ln(code, "app.config['SECRET_KEY']")
    c = _ln(code, 'render_template_string')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 Flask secret_key（CWE-798），属于次要问题。"
        f"这是最常见的误判场景，模型容易把硬编码 secret_key 当主漏洞。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 name 拼接进模板字符串后"
        f"render_template_string 编译执行，可注入 {{config}} 泄露密钥或 {{7*7}} 验证。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用实现 RCE，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="request.args.get", source_desc="request.args.get('name') 用户可控",
        sink_marker="render_template_string", sink_desc="render_template_string(template) 编译执行用户模板",
        explanation=f"line {_ln(code,'request.args.get')} name 用户输入 -> line {_ln(code,'template =')} 字符串拼接进模板 -> line {_ln(code,'render_template_string')} render_template_string 编译执行 -> SSTI RCE（硬编码 secret_key 为次要问题）",
        fix_marker="render_template_string", fix_desc="使用 render_template('greet.html', name=name) 加载预定义模板，用户输入仅作 context"))

    # --- 2. Python Jinja2 Template（防御迷惑：HTML escape 无效） ---
    code = r'''from jinja2 import Template
from markupsafe import escape

SECRET_KEY = "jinja_secret_abc123"

def render_msg(user_input):
    safe = escape(user_input)
    tmpl = Template("Welcome: " + str(safe))
    return tmpl.render()
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'tmpl.render')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入经 escape 后拼接进 Jinja2 模板"
        f"字符串并编译执行。\n"
        f"3. 防御迷惑：markupsafe.escape 仅转义 HTML 实体，不移除 Jinja2 {{ }} 语法，"
        f"攻击者可注入 {{{{config}}}} 泄露密钥。\n"
        f"4. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="def render_msg", source_desc="render_msg(user_input) 参数 user_input 用户可控",
        sink_marker="tmpl.render", sink_desc="Template(...).render() 编译执行用户模板",
        explanation=f"line {_ln(code,'def render_msg')} user_input 用户输入 -> line {_ln(code,'safe =')} escape 仅转义 HTML（防御迷惑，不移除 {{{{}}}}） -> line {_ln(code,'tmpl =')} Template 拼接编译 -> line {_ln(code,'tmpl.render')} render 执行 -> SSTI",
        fix_marker="tmpl = Template", fix_desc="使用 Environment 从文件加载模板，用户输入仅作 render() 的 context 变量"))

    # --- 3. Java Freemarker new Template ---
    code = r'''import freemarker.template.*;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

public class MsgRenderer {
    private static final String SECRET = "freemarker_secret_123";
    private final Configuration cfg;

    public MsgRenderer() throws Exception {
        cfg = new Configuration(Configuration.VERSION_2_3_31);
        cfg.setDefaultEncoding("UTF-8");
    }

    public String render(String userTemplate, Map<String, Object> data) throws Exception {
        Template t = new Template("userTpl", userTemplate, cfg);
        StringWriter sw = new StringWriter();
        t.process(data, sw);
        return sw.toString();
    }
}
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 't.process')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 userTemplate 经 new Template 编译"
        "为 Freemarker 模板并执行，可注入 ${'freemarker.template.utility.Execute'?new()('id')}。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="String userTemplate", source_desc="render(String userTemplate, ...) 参数用户可控",
        sink_marker="t.process", sink_desc="new Template(userTemplate).process() 编译执行用户模板",
        explanation=f"line {_ln(code,'String userTemplate')} userTemplate 用户输入 -> line {_ln(code,'new Template')} new Template 编译 -> line {_ln(code,'t.process')} process 执行 -> Freemarker SSTI RCE（硬编码密钥为次要问题）",
        fix_marker="new Template", fix_desc="使用 cfg.getTemplate('msg.html') 加载预定义模板，禁止从用户输入构造 Template"))

    # --- 4. Node.js ejs.render ---
    code = r'''const express = require('express');
const ejs = require('ejs');
const SECRET_KEY = 'express_secret_abc123';

const app = express();

app.get('/preview', (req, res) => {
    const tpl = req.query.tpl || '<p><%= title %></p>';
    const html = ejs.render(tpl, { title: req.query.title || '' });
    res.send(html);
});
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'ejs.render')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 tpl 经 ejs.render 编译执行，"
        f"可注入 <%- global.process.mainModule.require('child_process').execSync('id') %> 实现 RCE。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="req.query.tpl", source_desc="req.query.tpl 用户可控模板字符串",
        sink_marker="ejs.render(tpl", sink_desc="ejs.render(tpl, ...) 编译执行用户模板",
        explanation=f"line {_ln(code,'req.query.tpl')} tpl 用户输入 -> line {_ln(code,'ejs.render(tpl')} ejs.render 编译执行 -> 注入 require('child_process') -> SSTI RCE（硬编码密钥为次要问题）",
        fix_marker="ejs.render(tpl", fix_desc="使用 res.render('preview', { title }) 加载预定义 EJS 模板文件"))

    # --- 5. PHP Twig createTemplate ---
    code = r'''<?php
require_once 'vendor/autoload.php';
$API_KEY = "api_key_php_abc123";

$loader = new \Twig\Loader\ArrayLoader([]);
$twig = new \Twig\Environment($loader);

function render_page($twig, $template_src) {
    $template = $twig->createTemplate($template_src);
    return $template->render(['user' => 'guest']);
}
?>
'''
    k = _ln(code, '$API_KEY')
    c = _ln(code, 'createTemplate')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 template_src 经 createTemplate 编译"
        "为 Twig 模板并执行，可注入 {{_self.env.registerUndefinedFilterCallback('exec')}} 等。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="$template_src", source_desc="render_page($twig, $template_src) 参数用户可控",
        sink_marker="createTemplate", sink_desc="$twig->createTemplate($template_src) 编译用户模板",
        explanation=f"line {_ln(code,'$template_src')} template_src 用户输入 -> line {_ln(code,'createTemplate')} createTemplate 编译 -> line {_ln(code,'render(')} render 执行 -> Twig SSTI RCE（硬编码密钥为次要问题）",
        fix_marker="createTemplate", fix_desc="使用 $twig->load('page.html') 加载预定义模板，用户输入仅作 context 变量"))

    # --- 6. Python Mako Template ---
    code = r'''from mako.template import Template
from mako.lookup import TemplateLookup

SECRET_KEY = "mako_secret_key_456"

def render_email(template_str, context):
    tmpl = Template(template_str)
    return tmpl.render(**context)
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'tmpl.render')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 template_str 经 Template 编译"
        f"并执行，Mako 可注入 ${{__import__('os').popen('id').read()}} 实现 RCE。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="def render_email", source_desc="render_email(template_str, ...) 参数 template_str 用户可控",
        sink_marker="tmpl.render", sink_desc="Template(template_str).render() 编译执行用户模板",
        explanation=f"line {_ln(code,'def render_email')} template_str 用户输入 -> line {_ln(code,'tmpl = Template')} Template 编译 -> line {_ln(code,'tmpl.render')} render 执行 -> Mako SSTI RCE（硬编码密钥为次要问题）",
        fix_marker="tmpl = Template", fix_desc="使用 TemplateLookup 从文件加载预定义模板，用户输入仅作 render context"))

    # --- 7. Java Velocity evaluate ---
    code = r'''import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import java.io.StringWriter;

public class NotifService {
    private static final String SECRET = "velocity_secret_123";
    private final VelocityEngine ve;

    public NotifService() {
        ve = new VelocityEngine();
        ve.init();
    }

    public String render(String userTemplate) throws Exception {
        VelocityContext ctx = new VelocityContext();
        StringWriter sw = new StringWriter();
        ve.evaluate(ctx, sw, "notif", userTemplate);
        return sw.toString();
    }
}
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 've.evaluate')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 userTemplate 经 ve.evaluate 编译执行，"
        f"可注入 ${{__import__('os').popen('id').read()}} 等反射调用实现 RCE。\n"
        f"3. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="String userTemplate", source_desc="render(String userTemplate) 参数用户可控",
        sink_marker="ve.evaluate", sink_desc="ve.evaluate(ctx, sw, 'notif', userTemplate) 编译执行用户模板",
        explanation=f"line {_ln(code,'String userTemplate')} userTemplate 用户输入 -> line {_ln(code,'ve.evaluate')} evaluate 编译执行 -> 反射调用 Runtime -> Velocity SSTI RCE（硬编码密钥为次要问题）",
        fix_marker="ve.evaluate", fix_desc="使用 ve.getTemplate('notif.vm') 加载预定义模板，用户输入仅作 context"))

    # --- 8. Python Flask（防御迷惑：strip_tags 不移除 Jinja 语法） ---
    code = r'''from flask import Flask, request, render_template_string
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'flask_hardcoded_789'

def strip_tags(text):
    return re.sub(r'<[^>]+>', '', text)

@app.route('/wiki')
def wiki():
    content = request.args.get('content', '')
    safe = strip_tags(content)
    return render_template_string('<div>{{{ content }}}</div>'.replace('{{{', '{{').replace('}}}', '}}').replace('{{ content }}', safe))
'''
    k = _ln(code, "app.config['SECRET_KEY']")
    c = _ln(code, 'render_template_string')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 Flask secret_key（CWE-798），属于次要问题。"
        f"这是最常见的误判场景。\n"
        f"2. 第{c}行：发现 SSTI（CWE-1336），用户输入 content 拼接进模板字符串。\n"
        f"3. 防御迷惑：strip_tags 仅去除 HTML 标签，不移除 Jinja2 {{{{}}}} 语法，"
        f"攻击者可注入 {{{{config}}}} 泄露 SECRET_KEY 或实现 RCE。\n"
        f"4. 主漏洞判定：SSTI 风险等级为 Critical，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="request.args.get", source_desc="request.args.get('content') 用户可控",
        sink_marker="render_template_string", sink_desc="render_template_string(拼接含用户输入的模板) 编译执行",
        explanation=f"line {_ln(code,'request.args.get')} content 用户输入 -> line {_ln(code,'safe =')} strip_tags 仅去 HTML（防御迷惑，不移除 {{{{}}}}） -> line {_ln(code,'render_template_string')} 拼接模板并编译执行 -> SSTI RCE",
        fix_marker="render_template_string", fix_desc="使用 render_template('wiki.html', content=safe) 加载预定义模板，用户输入仅作 context 变量"))

    return S


# ===========================================================================
# 5. 硬编码 key + XSS（CWE-79）— 8 条
# ===========================================================================
def gen_key_plus_xss():
    S = []

    # --- 1. Python Flask |safe ---
    code = r'''from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'flask_xss_secret_123'

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return render_template_string('<p>Results for: {{ q|safe }}</p>', q=q)
'''
    k = _ln(code, "app.config['SECRET_KEY']")
    c = _ln(code, 'render_template_string')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 Flask secret_key（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 q 经 |safe 过滤器标记为安全后输出，"
        f"未转义 HTML 特殊字符，可注入 <script>alert(1)</script>。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用窃取用户会话，"
        f"远比硬编码密钥（High，需源码访问）更严重，因为 XSS 可被直接远程利用。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="request.args.get", source_desc="request.args.get('q') 用户可控",
        sink_marker="render_template_string", sink_desc='render_template_string("... {{ q|safe }}") 输出未转义',
        explanation=f"line {_ln(code,'request.args.get')} q 用户输入 -> line {_ln(code,'render_template_string')} |safe 标记为不转义 -> 输出 <script> -> XSS（硬编码密钥为次要问题）",
        fix_marker="render_template_string", fix_desc="移除 |safe 过滤器，使用 {{ q }} 让 Jinja2 自动转义 HTML"))

    # --- 2. PHP echo ---
    code = r'''<?php
$API_KEY = "php_api_key_abc123";

function show_comment() {
    $comment = $_GET['comment'] ?? '';
    echo "<div>" . $comment . "</div>";
}
?>
'''
    k = _ln(code, '$API_KEY')
    c = _ln(code, 'echo')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 $_GET['comment'] 直接 echo 输出，无转义。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="$_GET['comment']", source_desc="$_GET['comment'] 用户可控",
        sink_marker='echo', sink_desc='echo "<div>" . $comment . "</div>" 输出未转义',
        explanation=f"line {_ln(code,'$_GET')} comment 用户输入 -> line {_ln(code,'echo')} echo 直接输出无转义 -> 注入 <script> -> XSS（硬编码密钥为次要问题）",
        fix_marker="echo", fix_desc='echo "<div>" . htmlspecialchars($comment, ENT_QUOTES, "UTF-8") . "</div>" 转义输出'))

    # --- 3. JavaScript innerHTML ---
    code = r'''const API_TOKEN = "js_api_token_abc123";

function displayMessage(msg) {
    const div = document.getElementById('msg');
    div.innerHTML = '<p>' + msg + '</p>';
}
'''
    k = _ln(code, 'API_TOKEN')
    c = _ln(code, 'innerHTML')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 令牌（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 msg 经 innerHTML 写入 DOM，无转义，"
        f"可注入 <img src=x onerror=alert(1)>。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码令牌（High，需源码访问）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="function displayMessage", source_desc="displayMessage(msg) 参数 msg 用户可控",
        sink_marker="innerHTML", sink_desc="div.innerHTML = '<p>' + msg + '</p>' 写入未转义 HTML",
        explanation=f"line {_ln(code,'function displayMessage')} msg 用户输入 -> line {_ln(code,'innerHTML')} innerHTML 拼接写入 -> 注入 <img onerror> -> XSS（硬编码令牌为次要问题）",
        fix_marker="innerHTML", fix_desc="使用 div.textContent = msg 或 div.innerText 替代 innerHTML"))

    # --- 4. Java HttpServletResponse ---
    code = r'''import java.io.*;
import javax.servlet.http.*;

public class EchoServlet extends HttpServlet {
    private static final String DB_PASSWORD = "java_db_pass_2024";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String name = req.getParameter("name");
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Welcome " + name + "</h1>");
    }
}
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'out.println')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 name 直接拼入 HTML 输出，无转义。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密码（High，需源码访问）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="req.getParameter", source_desc='req.getParameter("name") 用户可控',
        sink_marker="out.println", sink_desc='out.println("<h1>Welcome " + name + "</h1>") 输出未转义',
        explanation=f"line {_ln(code,'req.getParameter')} name 用户输入 -> line {_ln(code,'out.println')} 字符串拼接 HTML 输出 -> 注入 <script> -> XSS（硬编码密码为次要问题）",
        fix_marker="out.println", fix_desc='使用 org.apache.commons.text.StringEscapeUtils.escapeHtml4(name) 转义后再输出'))

    # --- 5. Python Django（防御迷惑：strip_tags 不完整） ---
    code = r'''from django.http import HttpResponse
from django.utils.html import strip_tags

SECRET_KEY = "django_secret_xyz_789"

def show_profile(request):
    bio = request.GET.get('bio', '')
    safe = strip_tags(bio)
    return HttpResponse('<div>' + safe + '</div>')
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'HttpResponse')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 bio 输出到 HTTP 响应。\n"
        f"3. 防御迷惑：strip_tags 仅去除 HTML 标签，但不转义属性中的特殊字符。"
        f"攻击者可用 <svg/onload=alert(1)> 等变形标签绕过 strip_tags，"
        f"或利用未闭合标签绕过。\n"
        f"4. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="request.GET.get", source_desc="request.GET.get('bio') 用户可控",
        sink_marker="HttpResponse", sink_desc="HttpResponse('<div>' + safe + '</div>') 输出未转义",
        explanation=f"line {_ln(code,'request.GET.get')} bio 用户输入 -> line {_ln(code,'safe =')} strip_tags（防御迷惑，可被变形标签绕过） -> line {_ln(code,'HttpResponse')} HttpResponse 输出 -> XSS",
        fix_marker="HttpResponse", fix_desc="使用 django.utils.html.escape(safe) 或 render(request, 'profile.html', {'bio': bio}) 自动转义"))

    # --- 6. PHP htmlspecialchars（防御迷惑：编码错误） ---
    code = r'''<?php
$DB_PASS = "mysql_pass_2024";

function show_search() {
    $q = $_GET['q'] ?? '';
    echo '<p>Search: ' . htmlspecialchars($q, ENT_QUOTES, 'ISO-8859-1') . '</p>';
}
?>
'''
    k = _ln(code, '$DB_PASS')
    c = _ln(code, 'echo')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 q 经 htmlspecialchars 输出。\n"
        f"3. 防御迷惑：htmlspecialchars 使用 ISO-8859-1 编码而非 UTF-8，"
        f"在 UTF-8 页面环境下可被多字节字符绕过（如 0xc0aa 注入标签）。\n"
        f"4. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="$_GET['q']", source_desc="$_GET['q'] 用户可控",
        sink_marker="echo", sink_desc="echo htmlspecialchars($q, ENT_QUOTES, 'ISO-8859-1') 编码错误",
        explanation=f"line {_ln(code,'$_GET')} q 用户输入 -> line {_ln(code,'echo')} htmlspecialchars 用 ISO-8859-1（防御迷惑，UTF-8 页面可绕过） -> XSS",
        fix_marker="echo", fix_desc='将 htmlspecialchars 编码参数改为 "UTF-8"：htmlspecialchars($q, ENT_QUOTES, "UTF-8")'))

    # --- 7. Node.js res.send ---
    code = r'''const express = require('express');
const SECRET = 'express_xss_secret_456';

const app = express();

app.get('/profile', (req, res) => {
    const name = req.query.name || 'anonymous';
    res.send('<h1>Profile: ' + name + '</h1>');
});
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 'res.send')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 name 直接拼入 HTML 响应，无转义。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker="req.query.name", source_desc="req.query.name 用户可控",
        sink_marker="res.send", sink_desc="res.send('<h1>Profile: ' + name + '</h1>') 输出未转义",
        explanation=f"line {_ln(code,'req.query.name')} name 用户输入 -> line {_ln(code,'res.send')} 字符串拼接 HTML -> 注入 <script> -> XSS（硬编码密钥为次要问题）",
        fix_marker="res.send", fix_desc="使用 escape-html 模块转义：res.send('<h1>Profile: ' + escape(name) + '</h1>')"))

    # --- 8. Go template.HTML ---
    code = r'''package main

import (
    "html/template"
    "net/http"
)

var APIKey = "go_api_key_abc123"

func handler(w http.ResponseWriter, r *http.Request) {
    msg := r.URL.Query().Get("msg")
    tmpl := template.Must(template.New("page").Parse(
        "<div>" + template.HTML(msg) + "</div>"))
    tmpl.Execute(w, nil)
}
'''
    k = _ln(code, 'var APIKey')
    c = _ln(code, 'template.HTML')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现 XSS（CWE-79），用户输入 msg 经 template.HTML() 标记为安全后"
        f"拼入模板，绕过 Go 模板自动转义。\n"
        f"3. 主漏洞判定：XSS 风险等级为 Medium，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("go", code, analysis,
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="Medium",
        source_marker='Query().Get("msg")', source_desc='r.URL.Query().Get("msg") 用户可控',
        sink_marker="template.HTML", sink_desc="template.HTML(msg) 标记为不转义后拼入模板",
        explanation=f"line {_ln(code,'Query().Get')} msg 用户输入 -> line {_ln(code,'template.HTML')} template.HTML 绕过转义 -> 注入 <script> -> XSS（硬编码密钥为次要问题）",
        fix_marker="template.HTML", fix_desc="移除 template.HTML() 类型转换，将 msg 作为模板变量 {{.Msg}} 传入让模板自动转义"))

    return S


# ===========================================================================
# 6. 硬编码 key + 路径穿越（CWE-22）— 6 条
# ===========================================================================
def gen_key_plus_path():
    S = []

    # --- 1. Python open() ---
    code = r'''import os

SECRET_KEY = "file_secret_abc123"

def read_file(filename):
    base = "/var/www/uploads"
    filepath = os.path.join(base, filename)
    with open(filepath, "r") as f:
        return f.read()
'''
    k = _ln(code, 'SECRET_KEY')
    c = _ln(code, 'open(filepath')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 filename 经 os.path.join 拼接，"
        f"未过滤 ../，可注入 ../../etc/passwd 读取任意文件。\n"
        f"3. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="def read_file", source_desc="read_file(filename) 参数 filename 用户可控",
        sink_marker="open(filepath", sink_desc='open(os.path.join(base, filename)) 读取拼接路径文件',
        explanation=f"line {_ln(code,'def read_file')} filename 用户输入 -> line {_ln(code,'filepath =')} os.path.join 无过滤 -> line {_ln(code,'open(filepath')} open 读取 -> ../../etc/passwd 路径穿越（硬编码密钥为次要问题）",
        fix_marker="filepath =", fix_desc="使用 os.path.realpath 校验 filepath.startswith(os.path.realpath(base)) 防止穿越"))

    # --- 2. PHP include ---
    code = r'''<?php
$API_KEY = "php_path_key_abc123";

function load_page($page) {
    $path = "/var/www/pages/" . $page . ".php";
    include($path);
}
?>
'''
    k = _ln(code, '$API_KEY')
    c = _ln(code, 'include($path)')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 API 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 page 直接拼接路径并 include，"
        f"可注入 ../../etc/passwd%00 截断读取任意文件。\n"
        f"3. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="function load_page", source_desc="load_page($page) 参数 $page 用户可控",
        sink_marker="include($path)", sink_desc='include("/var/www/pages/" . $page . ".php") 包含拼接路径',
        explanation=f"line {_ln(code,'function load_page')} page 用户输入 -> line {_ln(code,'$path =')} 字符串拼接路径 -> line {_ln(code,'include($path)')} include 加载 -> ../../ 路径穿越（硬编码密钥为次要问题）",
        fix_marker="$path =", fix_desc="使用 basename($page) 仅取文件名，或白名单校验 page 值"))

    # --- 3. Node.js fs.readFile ---
    code = r'''const fs = require('fs');
const path = require('path');
const JWT_SECRET = "node_jwt_secret_456";

function getFile(filename, callback) {
    const base = path.join(__dirname, 'uploads');
    const filepath = path.join(base, filename);
    fs.readFile(filepath, 'utf8', callback);
}
'''
    k = _ln(code, 'JWT_SECRET')
    c = _ln(code, 'fs.readFile')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码 JWT 密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 filename 经 path.join 拼接，"
        f"未过滤 ../，可读取任意文件。\n"
        f"3. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="function getFile", source_desc="getFile(filename, callback) 参数 filename 用户可控",
        sink_marker="fs.readFile", sink_desc="fs.readFile(path.join(base, filename)) 读取拼接路径",
        explanation=f"line {_ln(code,'function getFile')} filename 用户输入 -> line {_ln(code,'filepath =')} path.join 无过滤 -> line {_ln(code,'fs.readFile')} readFile -> ../../ 路径穿越（硬编码密钥为次要问题）",
        fix_marker="filepath =", fix_desc="使用 path.resolve 后校验 filepath.startsWith(base + path.sep) 防止穿越"))

    # --- 4. Java new File ---
    code = r'''import java.io.*;
import java.nio.file.*;

public class FileService {
    private static final String SECRET = "java_file_secret_123";

    public static String readFile(String name) throws IOException {
        Path base = Paths.get("/var/www/uploads");
        Path file = base.resolve(name);
        return Files.readString(file);
    }
}
'''
    k = _ln(code, 'SECRET')
    c = _ln(code, 'Files.readString')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 name 经 base.resolve 拼接，"
        f"未校验是否在 base 目录内，可注入 ../../etc/passwd。\n"
        f"3. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High，需源码访问）更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="public static String readFile", source_desc="readFile(String name) 参数 name 用户可控",
        sink_marker="Files.readString", sink_desc="Files.readString(base.resolve(name)) 读取拼接路径",
        explanation=f"line {_ln(code,'public static String readFile')} name 用户输入 -> line {_ln(code,'Path file =')} base.resolve 无校验 -> line {_ln(code,'Files.readString')} readString -> ../../ 路径穿越（硬编码密钥为次要问题）",
        fix_marker="Path file =", fix_desc="校验 file.normalize().startsWith(base.normalize()) 防止路径穿越"))

    # --- 5. Go os.Open（防御迷惑：仅替换 .. 字面量） ---
    code = r'''package main

import (
    "os"
    "strings"
)

var SecretKey = "go_secret_key_abc123"

func readFile(filename string) ([]byte, error) {
    safe := strings.ReplaceAll(filename, "..", "")
    path := "/var/www/uploads/" + safe
    return os.ReadFile(path)
}
'''
    k = _ln(code, 'var SecretKey')
    c = _ln(code, 'os.ReadFile')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码密钥（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 filename 拼接路径。\n"
        f"3. 防御迷惑：仅替换 .. 字面量，可被 ....// 或 URL 编码 %2e%2e 绕过。\n"
        f"4. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密钥（High）更严重。"
    )
    S.append(_spec("go", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="func readFile", source_desc="readFile(filename string) 参数 filename 用户可控",
        sink_marker="os.ReadFile", sink_desc="os.ReadFile(path) 读取拼接路径",
        explanation=f"line {_ln(code,'func readFile')} filename 用户输入 -> line {_ln(code,'safe :=')} ReplaceAll .. （防御迷惑，可被 ....// 绕过） -> line {_ln(code,'os.ReadFile')} ReadFile -> 路径穿越",
        fix_marker="path :=", fix_desc="使用 filepath.Clean+filepath.Join 后校验 strings.HasPrefix(abs, base) 防止穿越"))

    # --- 6. Python open（防御迷惑：basename 仅部分场景） ---
    code = r'''import os

DB_PASSWORD = "db_pass_for_file_2024"

def get_avatar(user_id, ext="png"):
    if ext not in ("png", "jpg"):
        ext = "png"
    filename = user_id + "." + ext
    filepath = os.path.join("/var/www/avatars", filename)
    return open(filepath, "rb").read()
'''
    k = _ln(code, 'DB_PASSWORD')
    c = _ln(code, 'open(filepath')
    analysis = (
        f"分析过程：\n"
        f"1. 第{k}行：发现硬编码数据库密码（CWE-798），属于次要问题。\n"
        f"2. 第{c}行：发现路径穿越（CWE-22），用户输入 user_id 直接拼接文件名，"
        f"未使用 basename 或校验，可注入 ../../etc/passwd.png。\n"
        f"3. 防御迷惑：仅校验 ext 白名单，但 user_id 无任何过滤，防御不完整。\n"
        f"4. 主漏洞判定：路径穿越风险等级为 High，可被远程攻击者直接利用，"
        f"远比硬编码密码（High）更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-22 Path Traversal", risk="High",
        source_marker="def get_avatar", source_desc="get_avatar(user_id, ext) 参数 user_id 用户可控",
        sink_marker="open(filepath", sink_desc='open(os.path.join(base, user_id + "." + ext)) 读取拼接路径',
        explanation=f"line {_ln(code,'def get_avatar')} user_id 用户输入 -> line {_ln(code,'filename =')} 直接拼接无 basename（防御迷惑，仅校验 ext） -> line {_ln(code,'open(filepath')} open -> ../../etc/passwd 路径穿越",
        fix_marker="filename =", fix_desc="使用 os.path.basename(user_id) 仅取文件名，并校验不含路径分隔符"))

    return S


# ===========================================================================
# 7. 多注入点选主（两种漏洞，选更严重者）— 10 条
# ===========================================================================
def gen_multi_inject():
    S = []

    # --- 1. 命令注入(Critical) + SQL注入(High) → 命令注入 ---
    code = r'''import os
import sqlite3

def run_report(host, db_path):
    os.system("ping -c 1 " + host)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE host = '" + host + "'")
    return cursor.fetchone()
'''
    cmd_ln = _ln(code, 'os.system')
    sqli_ln = _ln(code, 'cursor.execute')
    analysis = (
        f"分析过程：\n"
        f"1. 第{cmd_ln}行：发现命令注入（CWE-78），用户输入 host 拼接进 os.system。\n"
        f"2. 第{sqli_ln}行：发现 SQL 注入（CWE-89），用户输入 host 拼接进 SQL 查询。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，SQL 注入为 High。"
        f"根据优先级 RCE > SQLi，命令注入可直接执行系统命令，比 SQL 注入更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="def run_report", source_desc="run_report(host, db_path) 参数 host 用户可控",
        sink_marker="os.system", sink_desc='os.system("ping -c 1 " + host) 执行拼接命令',
        explanation=f"line {_ln(code,'def run_report')} host 用户输入 -> line {_ln(code,'os.system')} os.system 拼接 -> 命令注入(Critical)；line {_ln(code,'cursor.execute')} SQL 注入(High) 为次要问题；主漏洞选命令注入因 RCE > SQLi",
        fix_marker="os.system", fix_desc="使用 subprocess.run(['ping','-c','1',host]) 传列表参数，并参数化 SQL 查询"))

    # --- 2. SQL注入(High) + XSS(Medium) → SQL注入 ---
    code = r'''<?php
function search_products($pdo, $keyword) {
    $sql = "SELECT * FROM products WHERE name LIKE '%" . $keyword . "%'";
    $stmt = $pdo->query($sql);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo "<h2>Search results for: " . $keyword . "</h2>";
    return $results;
}
?>
'''
    sqli_ln = _ln(code, '$pdo->query')
    xss_ln = _ln(code, 'echo')
    analysis = (
        f"分析过程：\n"
        f"1. 第{sqli_ln}行：发现 SQL 注入（CWE-89），用户输入 keyword 拼接进 SQL。\n"
        f"2. 第{xss_ln}行：发现 XSS（CWE-79），用户输入 keyword 直接 echo 输出无转义。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，XSS 为 Medium。"
        f"根据优先级 SQLi > XSS，SQL 注入可窃取/篡改数据库，比 XSS 更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function search_products", source_desc="search_products($pdo, $keyword) 参数 $keyword 用户可控",
        sink_marker="$pdo->query", sink_desc='$pdo->query("SELECT ... " . $keyword) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function search_products')} keyword 用户输入 -> line {_ln(code,'$pdo->query')} SQL 注入(High)；line {_ln(code,'echo')} XSS(Medium) 为次要问题；主漏洞选 SQL 注入因 SQLi > XSS",
        fix_marker="$sql =", fix_desc='使用 $pdo->prepare("SELECT * FROM products WHERE name LIKE ?") 并 bindParam 参数化'))

    # --- 3. 命令注入(Critical) + XSS(Medium) → 命令注入 ---
    code = r'''const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/check', (req, res) => {
    const url = req.query.url;
    exec('curl ' + url, (err, stdout) => {
        res.send('<pre>' + stdout + '</pre>');
    });
});
'''
    cmd_ln = _ln(code, 'exec(')
    xss_ln = _ln(code, 'res.send')
    analysis = (
        f"分析过程：\n"
        f"1. 第{cmd_ln}行：发现命令注入（CWE-78），用户输入 url 拼接进 exec。\n"
        f"2. 第{xss_ln}行：发现 XSS（CWE-79），stdout 直接 res.send 输出无转义。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，XSS 为 Medium。"
        f"根据优先级 RCE > XSS，命令注入可执行任意系统命令，远比 XSS 严重。"
    )
    S.append(_spec("javascript", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="req.query.url", source_desc="req.query.url 用户可控",
        sink_marker="exec('curl '", sink_desc="exec('curl ' + url) 执行拼接命令",
        explanation=f"line {_ln(code,'req.query.url')} url 用户输入 -> line {cmd_ln} exec 拼接 -> 命令注入(Critical)；line {_ln(code,'res.send')} XSS(Medium) 为次要问题；主漏洞选命令注入因 RCE > XSS",
        fix_marker="exec('curl '", fix_desc="使用 execFile('curl',[url]) 不经 shell，并对 stdout 做 HTML 转义"))

    # --- 4. 反序列化(Critical) + SQL注入(High) → 反序列化 ---
    code = r'''import pickle
import base64
import psycopg2

def process_data(session_b64, keyword):
    raw = base64.b64decode(session_b64)
    data = pickle.loads(raw)
    conn = psycopg2.connect("dbname=appdb")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '" + keyword + "'")
    return data, cursor.fetchone()
'''
    deser_ln = _ln(code, 'pickle.loads')
    sqli_ln = _ln(code, 'cursor.execute')
    analysis = (
        f"分析过程：\n"
        f"1. 第{deser_ln}行：发现不安全反序列化（CWE-502），pickle.loads 用户数据可 RCE。\n"
        f"2. 第{sqli_ln}行：发现 SQL 注入（CWE-89），keyword 拼接进 SQL。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，SQL 注入为 High。"
        f"根据优先级 RCE > SQLi，反序列化可直接执行任意代码，比 SQL 注入更严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker="def process_data", source_desc="process_data(session_b64, keyword) 参数 session_b64 用户可控",
        sink_marker="pickle.loads", sink_desc="pickle.loads(base64.b64decode(session_b64)) 反序列化用户数据",
        explanation=f"line {_ln(code,'def process_data')} session_b64 用户输入 -> line {_ln(code,'pickle.loads')} pickle.loads -> 反序列化 RCE(Critical)；line {_ln(code,'cursor.execute')} SQL 注入(High) 为次要问题；主漏洞选反序列化因 RCE > SQLi",
        fix_marker="pickle.loads", fix_desc="使用 json.loads 替代 pickle，并参数化 SQL 查询"))

    # --- 5. SSTI(Critical) + XSS(Medium) → SSTI（防御迷惑：strip_tags） ---
    code = r'''from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

@app.route('/render')
def render():
    tpl = request.args.get('tpl', '<p>{{ name }}</p>')
    name = request.args.get('name', 'guest')
    safe_name = re.sub(r'<[^>]+>', '', name)
    return render_template_string(tpl.replace('{{ name }}', safe_name))
'''
    ssti_ln = _ln(code, 'render_template_string')
    xss_ln = _ln(code, 'safe_name =')
    analysis = (
        f"分析过程：\n"
        f"1. 第{ssti_ln}行：发现 SSTI（CWE-1336），用户输入 tpl 经 render_template_string 编译执行。\n"
        f"2. 第{xss_ln}行：发现 XSS（CWE-79），name 输出到模板，但 strip_tags 不完整。\n"
        f"3. 防御迷惑：strip_tags 仅去 HTML 标签，不阻止 Jinja2 {{ }} 语法。\n"
        f"4. 主漏洞判定：SSTI 风险等级为 Critical，XSS 为 Medium。"
        f"根据优先级 RCE > XSS，SSTI 可实现 RCE，远比 XSS 严重。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-1336 Server-Side Template Injection (SSTI)", risk="Critical",
        source_marker="request.args.get('tpl'", source_desc="request.args.get('tpl') 用户可控模板",
        sink_marker="render_template_string", sink_desc="render_template_string(tpl...) 编译执行用户模板",
        explanation=f"line {_ln(code,'request.args.get')} tpl 用户输入 -> line {_ln(code,'safe_name =')} strip_tags（防御迷惑） -> line {_ln(code,'render_template_string')} SSTI(Critical)；XSS(Medium) 为次要问题；主漏洞选 SSTI 因 RCE > XSS",
        fix_marker="render_template_string", fix_desc="使用 render_template('render.html', name=name) 加载预定义模板"))

    # --- 6. SQL注入(High) + SSRF(High) → SQL注入 ---
    code = r'''import sqlite3
import requests

def fetch_resource(url, tag):
    resp = requests.get(url)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM resources WHERE tag = '" + tag + "'")
    return resp.text, cursor.fetchone()
'''
    sqli_ln = _ln(code, 'cursor.execute')
    ssrf_ln = _ln(code, 'requests.get')
    analysis = (
        f"分析过程：\n"
        f"1. 第{sqli_ln}行：发现 SQL 注入（CWE-89），用户输入 tag 拼接进 SQL。\n"
        f"2. 第{ssrf_ln}行：发现 SSRF（CWE-918），用户输入 url 直接 requests.get 请求。\n"
        f"3. 主漏洞判定：两者风险等级均为 High。根据漏洞类型优先级 SQLi > SSRF，"
        f"SQL 注入可直接窃取/篡改数据库全部数据，比 SSRF 影响面更广。"
    )
    S.append(_spec("python", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="def fetch_resource", source_desc="fetch_resource(url, tag) 参数 tag 用户可控",
        sink_marker="cursor.execute", sink_desc='cursor.execute("SELECT ... " + tag) 执行拼接 SQL',
        explanation=f"line {_ln(code,'def fetch_resource')} tag 用户输入 -> line {_ln(code,'cursor.execute')} SQL 注入(High)；line {_ln(code,'requests.get')} SSRF(High) 为次要问题；主漏洞选 SQL 注入因 SQLi > SSRF",
        fix_marker="cursor.execute", fix_desc='cursor.execute("SELECT * FROM resources WHERE tag = ?",(tag,)) 参数化，并对 url 做白名单校验'))

    # --- 7. 命令注入(Critical) + SSRF(High) → 命令注入 ---
    code = r'''import java.io.*;
import java.net.*;
import java.util.*;

public class HealthChecker {
    public static String check(String host, String url) throws Exception {
        Process p = Runtime.getRuntime().exec(
            new String[]{"/bin/sh", "-c", "curl -s " + url});
        String body = new String(p.getInputStream().readAllBytes());

        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.getResponseCode();
        return body;
    }
}
'''
    cmd_ln = _ln(code, 'Runtime.getRuntime')
    ssrf_ln = _ln(code, 'u.openConnection')
    analysis = (
        f"分析过程：\n"
        f"1. 第{cmd_ln}行：发现命令注入（CWE-78），用户输入 url 拼接进 sh -c 命令。\n"
        f"2. 第{ssrf_ln}行：发现 SSRF（CWE-918），用户输入 url 直接 openConnection 请求。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，SSRF 为 High。"
        f"根据优先级 RCE > SSRF，命令注入可执行任意系统命令，比 SSRF 更严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="public static String check", source_desc="check(String host, String url) 参数 url 用户可控",
        sink_marker="Runtime.getRuntime", sink_desc='Runtime.exec({"/bin/sh","-c","curl "+url}) shell 执行',
        explanation=f"line {_ln(code,'public static String check')} url 用户输入 -> line {_ln(code,'Runtime.getRuntime')} sh -c 拼接 -> 命令注入(Critical)；line {_ln(code,'u.openConnection')} SSRF(High) 为次要问题；主漏洞选命令注入因 RCE > SSRF",
        fix_marker="Runtime.getRuntime", fix_desc='使用 ProcessBuilder("curl","-s",url) 不经 shell，并对 url 做协议+域名白名单校验'))

    # --- 8. 反序列化(Critical) + XSS(Medium) → 反序列化 ---
    code = r'''import java.io.*;
import javax.servlet.http.*;

public class CacheServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String data = req.getParameter("data");
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(data.getBytes()));
        Object obj = null;
        try { obj = ois.readObject(); } catch (Exception e) {}
        resp.setContentType("text/html");
        resp.getWriter().println("<div>" + obj + "</div>");
    }
}
'''
    deser_ln = _ln(code, 'readObject')
    xss_ln = _ln(code, 'println')
    analysis = (
        f"分析过程：\n"
        f"1. 第{deser_ln}行：发现不安全反序列化（CWE-502），ObjectInputStream.readObject"
        f" 反序列化用户数据，可利用 gadget 链 RCE。\n"
        f"2. 第{xss_ln}行：发现 XSS（CWE-79），obj 直接输出到 HTML 无转义。\n"
        f"3. 主漏洞判定：反序列化风险等级为 Critical，XSS 为 Medium。"
        f"根据优先级 RCE > XSS，反序列化可实现 RCE，远比 XSS 严重。"
    )
    S.append(_spec("java", code, analysis,
        has_vuln=True, vuln_type="CWE-502 Deserialization of Untrusted Data", risk="Critical",
        source_marker='req.getParameter("data")', source_desc='req.getParameter("data") 用户可控',
        sink_marker="readObject", sink_desc="ObjectInputStream.readObject() 反序列化用户数据",
        explanation=f"line {_ln(code,'req.getParameter')} data 用户输入 -> line {_ln(code,'readObject')} readObject -> 反序列化 RCE(Critical)；line {_ln(code,'println')} XSS(Medium) 为次要问题；主漏洞选反序列化因 RCE > XSS",
        fix_marker="readObject", fix_desc="禁用 ObjectInputStream 解析用户输入，改用 JSON，并对输出做 HTML 转义"))

    # --- 9. SQL注入(High) + 信息泄露(Medium) → SQL注入 ---
    code = r'''<?php
function debug_search($pdo, $keyword) {
    $sql = "SELECT * FROM users WHERE email LIKE '%" . $keyword . "%'";
    try {
        $stmt = $pdo->query($sql);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        echo "SQL Error: " . $e->getMessage() . " in: " . $sql;
        return [];
    }
}
?>
'''
    sqli_ln = _ln(code, '$pdo->query')
    leak_ln = _ln(code, 'echo "SQL Error')
    analysis = (
        f"分析过程：\n"
        f"1. 第{sqli_ln}行：发现 SQL 注入（CWE-89），用户输入 keyword 拼接进 SQL。\n"
        f"2. 第{leak_ln}行：发现信息泄露（CWE-209），异常时输出 SQL 错误和完整语句。\n"
        f"3. 主漏洞判定：SQL 注入风险等级为 High，信息泄露为 Medium。"
        f"根据优先级 SQLi > 信息泄露，SQL 注入可窃取全部数据库数据，比信息泄露更严重。"
    )
    S.append(_spec("php", code, analysis,
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="function debug_search", source_desc="debug_search($pdo, $keyword) 参数 $keyword 用户可控",
        sink_marker="$pdo->query", sink_desc='$pdo->query("SELECT ... " . $keyword) 执行拼接 SQL',
        explanation=f"line {_ln(code,'function debug_search')} keyword 用户输入 -> line {_ln(code,'$pdo->query')} SQL 注入(High)；line {_ln(code,'echo')} 信息泄露(Medium) 为次要问题；主漏洞选 SQL 注入因 SQLi > 信息泄露",
        fix_marker="$sql =", fix_desc='使用 $pdo->prepare + bindParam 参数化，并在 catch 中仅记录日志不输出详细错误'))

    # --- 10. 命令注入(Critical) + 路径穿越(High) → 命令注入 ---
    code = r'''package main

import (
    "os/exec"
    "os"
)

func processFile(filename string) string {
    cmd := exec.Command("sh", "-c", "file "+filename)
    out, _ := cmd.Output()

    path := "/var/www/uploads/" + filename
    data, _ := os.ReadFile(path)
    return string(out) + string(data)
}
'''
    cmd_ln = _ln(code, 'exec.Command')
    path_ln = _ln(code, 'os.ReadFile')
    analysis = (
        f"分析过程：\n"
        f"1. 第{cmd_ln}行：发现命令注入（CWE-78），用户输入 filename 拼接进 sh -c 命令。\n"
        f"2. 第{path_ln}行：发现路径穿越（CWE-22），用户输入 filename 拼接路径未过滤 ../。\n"
        f"3. 主漏洞判定：命令注入风险等级为 Critical，路径穿越为 High。"
        f"根据优先级 RCE > 路径穿越，命令注入可执行任意系统命令，比路径穿越更严重。"
    )
    S.append(_spec("go", code, analysis,
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="func processFile", source_desc="processFile(filename string) 参数 filename 用户可控",
        sink_marker="exec.Command", sink_desc='exec.Command("sh","-c","file "+filename) shell 执行',
        explanation=f"line {_ln(code,'func processFile')} filename 用户输入 -> line {_ln(code,'exec.Command')} sh -c 拼接 -> 命令注入(Critical)；line {_ln(code,'os.ReadFile')} 路径穿越(High) 为次要问题；主漏洞选命令注入因 RCE > 路径穿越",
        fix_marker="exec.Command", fix_desc='使用 exec.Command("file",filename) 不经 shell，并校验 filename 不含路径分隔符'))

    return S


# ===========================================================================
# 主函数
# ===========================================================================
def main():
    """组合所有生成器，校验样本，写入 JSONL，打印统计。"""
    generators = [
        ("硬编码 key + 命令注入", gen_key_plus_cmd),
        ("硬编码 key + SQL 注入", gen_key_plus_sqli),
        ("硬编码 key + 反序列化", gen_key_plus_deser),
        ("硬编码 key + SSTI", gen_key_plus_ssti),
        ("硬编码 key + XSS", gen_key_plus_xss),
        ("硬编码 key + 路径穿越", gen_key_plus_path),
        ("多注入点选主", gen_multi_inject),
    ]

    all_specs = []
    print("=" * 70)
    print("模式 A 训练样本生成：多候选漏洞 → 选出真主漏洞")
    print("=" * 70)

    for name, gen_func in generators:
        specs = gen_func()
        print(f"  [{name}] 生成 {len(specs)} 条")
        all_specs.extend(specs)

    total = len(all_specs)
    print(f"\n总样本数: {total}")

    if total != 60:
        print(f"[警告] 预期 60 条，实际 {total} 条")

    # --- 校验所有样本 ---
    print("\n--- 校验样本 ---")
    has_error = False
    for i, spec in enumerate(all_specs, 1):
        errors = validate_spec(spec)
        if errors:
            has_error = True
            print(f"  [FAIL] 样本 #{i} ({spec['lang']}):")
            for err in errors:
                print(f"         - {err}")

    if has_error:
        print("\n[错误] 存在校验失败的样本，请修复后再运行。")
        return 1

    print("  所有样本校验通过。")

    # --- 写入 JSONL ---
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for spec in all_specs:
            record = make_sample(spec["lang"], spec["code"], spec["analysis"], spec["verdict"])
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\n--- 输出 ---")
    print(f"  文件: {OUTPUT_FILE}")
    print(f"  行数: {total}")

    # --- 统计 ---
    print(f"\n--- 统计 ---")
    lang_counter = Counter(spec["lang"] for spec in all_specs)
    vuln_counter = Counter(
        spec["verdict"]["vulnerability_type"] for spec in all_specs
        if spec["verdict"]["has_vulnerability"]
    )
    risk_counter = Counter(
        spec["verdict"]["risk_level"] for spec in all_specs
        if spec["verdict"]["has_vulnerability"]
    )
    safe_count = sum(1 for spec in all_specs if not spec["verdict"]["has_vulnerability"])
    vuln_count = total - safe_count

    print(f"  漏洞/安全: {vuln_count} 漏洞 + {safe_count} 安全")
    print(f"  语言分布: {dict(sorted(lang_counter.items(), key=lambda x: -x[1]))}")
    print(f"  风险分布: {dict(sorted(risk_counter.items(), key=lambda x: -x[1]))}")
    print(f"  CWE 分布:")
    for cwe, count in sorted(vuln_counter.items(), key=lambda x: -x[1]):
        print(f"    {cwe}: {count}")

    print(f"\n[完成] 已生成 {total} 条样本到 {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
