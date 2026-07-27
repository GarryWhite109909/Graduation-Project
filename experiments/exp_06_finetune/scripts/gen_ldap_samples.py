#!/usr/bin/env python3
"""
LDAP 注入（CWE-90）训练样本生成。

背景：
  当前训练数据 train_chatml_v3.jsonl 中 LDAP 注入样本严重不足（仅 1 条），
  导致模型在 CVE-fix 真实集上 LDAP 注入样本从 TP 变 FN。本脚本生成 9 条
  高质量 LDAP 样本（5 漏洞 + 4 安全），覆盖 Python python-ldap / ldap3、
  Node.js ldapauth、Java JNDI、PHP ldap_search 等主流 LDAP 库与场景。

  漏洞样本 CoT 包含具体 LDAP 注入 payload（如 *)(uid=*)），
  安全样本 CoT 解释防御机制为何有效（转义了哪些字符 / 白名单为何能阻止注入）。

输出：
  追加 9 行到 data/train_chatml_v3.jsonl

用法：
  python3 \
      experiments/exp_06_finetune/scripts/gen_ldap_samples.py
"""

import json
import re
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/train_chatml_v3.jsonl"


# ===========================================================================
# 9 条样本定义（5 漏洞 + 4 安全）
# code 和 cot 使用 raw string 以避免反斜杠转义问题
# ===========================================================================
SAMPLES = [
    # =====================================================================
    # 漏洞样本 1: Python python-ldap search_s 拼接 filter
    # =====================================================================
    {
        "filename": "vuln_ldap_python_search.py",
        "language": "python",
        "code": r'''import ldap

def login(username, password):
    conn = ldap.initialize('ldap://ldap.example.com')
    conn.simple_bind_s('cn=admin,dc=example,dc=com', 'admin_secret')
    base = 'dc=example,dc=com'
    results = conn.search_s(base, ldap.SCOPE_SUBTREE, f'(uid={username})')
    if results:
        return verify_password(results[0][1], password)
    return False''',
        "cot": r'''分析过程：
1. 污染源识别：函数参数 username 来自用户登录输入，完全可控。
2. 危险 sink 定位：conn.search_s 的第三个参数 filter，即 LDAP 搜索过滤器。
3. 数据流追踪：username 通过 f-string 直接嵌入 f'(uid={username})'，中间无任何转义或校验。
4. 防御检查：代码未调用 ldap.escape_filter_chars，也未做白名单校验。
5. 攻击验证：若 username 传入 *)(uid=*)，filter 变为 (uid=*)(uid=*)，匹配所有条目，可绕过认证。
6. 结论：存在 CWE-90 LDAP注入，风险等级 High。''',
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "source": "username 函数参数",
            "sink": "conn.search_s(base, ldap.SCOPE_SUBTREE, f'(uid={username})')",
            "explanation": "username 经 f-string 拼入 LDAP filter，无转义；攻击者传入 *)(uid=*) 可篡改 filter 语义绕过认证",
            "fix_suggestion": "使用 ldap.escape_filter_chars(username) 转义 LDAP filter 特殊字符后再拼接",
        },
    },
    # =====================================================================
    # 漏洞样本 2: Python ldap3 search 拼接 filter
    # =====================================================================
    {
        "filename": "vuln_ldap3_filter.py",
        "language": "python",
        "code": r'''from ldap3 import Server, Connection, SUBTREE

def search_user(user_input):
    server = Server('ldap://ldap.example.com')
    conn = Connection(server, user='cn=admin,dc=example,dc=com', password='admin_secret')
    conn.bind()
    base = 'dc=example,dc=com'
    conn.search(base, f'(cn={user_input}*)', SUBTREE)
    return conn.entries''',
        "cot": r'''分析过程：
1. 首先定位输入源：user_input 作为查询参数，攻击者可任意构造。
2. sink 识别：conn.search(base, filter, SUBTREE) 的 filter 参数决定 LDAP 查询语义。
3. 数据流：user_input 经 f-string 拼成 (cn={user_input}*)，星号 * 本身是 LDAP 通配符，括号 ( 是 filter 元字符，均未转义。
4. 防御确认：未使用 ldap3.utils.conv.escape_filter_chars，无输入校验。
5. 利用举例：user_input=admin)(uid=* 可让 filter 变为 (cn=admin)(uid=*)，改变查询逻辑返回非预期条目。
6. 结论：存在 CWE-90 LDAP注入，风险等级 High。''',
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "source": "user_input 函数参数",
            "sink": "conn.search(base, f'(cn={user_input}*)', SUBTREE)",
            "explanation": "user_input 经 f-string 拼入 LDAP filter，星号和括号未转义；攻击者可注入 )( 改变 filter 结构",
            "fix_suggestion": "使用 ldap3.utils.conv.escape_filter_chars 转义用户输入后再拼接 filter",
        },
    },
    # =====================================================================
    # 漏洞样本 3: Node.js ldapauth searchFilter replace（类似 CVE-2015-7294）
    # =====================================================================
    {
        "filename": "vuln_ldap_js_filter.js",
        "language": "javascript",
        "code": r'''var ldapauth = require('ldapauth-fork');

var opts = {
    url: 'ldap://ldap.example.com',
    bindDN: 'cn=admin,dc=example,dc=com',
    bindCredentials: 'admin_secret',
    searchBase: 'dc=example,dc=com',
    searchFilter: '(uid={{username}})'
};

function authenticate(username, password, callback) {
    var searchFilter = opts.searchFilter.replace(/{{username}}/g, username);
    opts.searchFilter = searchFilter;
    var auth = new ldapauth(opts);
    auth.authenticate(username, password, callback);
}''',
        "cot": r'''分析过程：
1. 污染源：authenticate 函数的 username 参数，来自 HTTP 请求。
2. 危险 sink：searchFilter 字符串作为 LDAP 搜索过滤器传入认证逻辑。
3. 数据流：opts.searchFilter.replace(/{{username}}/g, username) 将 username 原样替换进过滤器模板，String.replace 不做任何 LDAP 转义。
4. 防御检查：代码中无 escape/编码逻辑，类似 CVE-2015-7294 的模式。
5. 攻击场景：username=* 可使过滤器变为 (uid=*)，匹配任意用户从而绕过认证。
6. 结论：存在 CWE-90 LDAP注入，风险等级 High。''',
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "source": "authenticate 函数的 username 参数",
            "sink": "opts.searchFilter.replace(/{{username}}/g, username)",
            "explanation": "username 经 String.replace 原样拼入 LDAP searchFilter，无转义；攻击者传入 * 可使 filter 匹配所有用户绕过认证",
            "fix_suggestion": "对 username 调用 LDAP filter 转义函数处理星号、括号、反斜杠、NUL 等特殊字符后再替换",
        },
    },
    # =====================================================================
    # 漏洞样本 4: Java JNDI ctx.search 拼接 filter
    # =====================================================================
    {
        "filename": "vuln_ldap_java_jndi.java",
        "language": "java",
        "code": r'''import javax.naming.*;
import javax.naming.directory.*;

public class LdapAuthService {
    private final DirContext ctx;

    public LdapAuthService(DirContext ctx) {
        this.ctx = ctx;
    }

    public SearchResult findUser(String uid) throws NamingException {
        String base = "dc=example,dc=com";
        String filter = "(uid=" + uid + ")";
        NamingEnumeration<SearchResult> results = ctx.search(base, filter, null);
        if (results.hasMore()) {
            return results.next();
        }
        return null;
    }
}''',
        "cot": r'''分析过程：
1. 源分析：uid 参数通常来自 HTTP 请求参数，用户可控。
2. sink 识别：ctx.search(base, filter, null) 中 filter 为 LDAP 查询过滤器。
3. 数据流追踪：uid 经字符串拼接 "(uid=" + uid + ")" 构成 filter，Java 字符串拼接不转义 LDAP 元字符。
4. 防御评估：代码无正则校验、无白名单、无转义调用。
5. 注入验证：uid=admin)(uid=* 使 filter 变为 (uid=admin)(uid=*)，SearchControls 未限制，可枚举目录条目。
6. 结论：存在 CWE-90 LDAP注入，风险等级 High。''',
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "source": "findUser 方法的 uid 参数",
            "sink": "ctx.search(base, filter, null)",
            "explanation": "uid 经字符串拼接构成 LDAP filter，无转义；攻击者传入 admin)(uid=* 可改变 filter 逻辑枚举目录",
            "fix_suggestion": "对 uid 做白名单校验或使用 spring-ldap 的 LdapEncoder.filterEncode 转义",
        },
    },
    # =====================================================================
    # 漏洞样本 5: PHP ldap_search 拼接 filter
    # =====================================================================
    {
        "filename": "vuln_ldap_php_search.php",
        "language": "php",
        "code": r'''<?php
function ldap_auth($username, $password) {
    $conn = ldap_connect('ldap://ldap.example.com');
    ldap_bind($conn, 'cn=admin,dc=example,dc=com', 'admin_secret');
    $base_dn = 'dc=example,dc=com';
    $filter = "(uid=" . $_POST['username'] . ")";
    $result = ldap_search($conn, $base_dn, $filter);
    $entries = ldap_get_entries($conn, $result);
    if ($entries['count'] > 0) {
        return verify_password($entries[0], $password);
    }
    return false;
}
?>''',
        "cot": r'''分析过程：
1. 输入源：$_POST['username'] 直接来自表单 POST，攻击者完全可控。
2. sink 定位：ldap_search($conn, $base_dn, $filter) 的第三个参数 $filter。
3. 数据流：$_POST['username'] 经 PHP 字符串拼接 "(uid=" . $_POST['username'] . ")" 构成 $filter，无中间过滤。
4. 防御检查：未调用 ldap_escape，未做输入校验。
5. 攻击演示：提交 username=*)(uid=* 使 filter 为 (uid=*)(uid=*)，ldap_search 返回全部条目。
6. 结论：存在 CWE-90 LDAP注入，风险等级 High。''',
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "source": "$_POST['username']",
            "sink": "ldap_search($conn, $base_dn, $filter)",
            "explanation": "$_POST['username'] 经字符串拼接构成 LDAP filter，无转义；攻击者可注入 )( 篡改 filter 返回全部条目",
            "fix_suggestion": "使用 ldap_escape($username, '', LDAP_ESCAPE_FILTER) 转义后再拼接 filter",
        },
    },
    # =====================================================================
    # 安全样本 6: Python python-ldap escape_filter_chars
    # =====================================================================
    {
        "filename": "safe_ldap_python_escape.py",
        "language": "python",
        "code": r'''import ldap

def login(username, password):
    conn = ldap.initialize('ldap://ldap.example.com')
    conn.simple_bind_s('cn=admin,dc=example,dc=com', 'admin_secret')
    base = 'dc=example,dc=com'
    safe_username = ldap.escape_filter_chars(username)
    results = conn.search_s(base, ldap.SCOPE_SUBTREE, f'(uid={safe_username})')
    if results:
        return verify_password(results[0][1], password)
    return False''',
        "cot": r'''分析过程：
1. 污染源：username 来自用户登录输入。
2. sink 识别：conn.search_s 的 filter 参数。
3. 数据流：username → ldap.escape_filter_chars(username) → f-string 拼接 → search_s。
4. 防御评估：ldap.escape_filter_chars 会将 * ( ) \ 和 NUL 等 LDAP filter 特殊字符转义为 \2a \28 \29 \5c \00 形式，攻击者无法注入括号改变 filter 结构。
5. 结论：防御有效，无 LDAP 注入风险。''',
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "ldap.escape_filter_chars 转义了 LDAP filter 特殊字符，用户输入无法改变 filter 结构",
            "fix_suggestion": "no fix needed",
        },
    },
    # =====================================================================
    # 安全样本 7: Python ldap3 escape_filter_chars
    # =====================================================================
    {
        "filename": "safe_ldap3_template.py",
        "language": "python",
        "code": r'''from ldap3 import Server, Connection, SUBTREE
from ldap3.utils.conv import escape_filter_chars

def search_user(user_input):
    server = Server('ldap://ldap.example.com')
    conn = Connection(server, user='cn=admin,dc=example,dc=com', password='admin_secret')
    conn.bind()
    base = 'dc=example,dc=com'
    safe_input = escape_filter_chars(user_input)
    conn.search(base, f'(cn={safe_input})', SUBTREE)
    return conn.entries''',
        "cot": r'''分析过程：
1. 源识别：user_input 来自用户搜索请求。
2. sink 定位：conn.search 的 filter 参数。
3. 数据流追踪：user_input → escape_filter_chars(user_input) → f-string 拼入 (cn={safe_input}) → conn.search。
4. 防御确认：ldap3.utils.conv.escape_filter_chars 按 RFC 4515 规则转义 * ( ) \ 和 NUL 字符，转义后即使输入含 )( 也被当作字面量匹配。
5. 结论：转义有效，不存在 LDAP 注入。''',
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "ldap3 的 escape_filter_chars 按 RFC 4515 转义特殊字符，防御有效",
            "fix_suggestion": "no fix needed",
        },
    },
    # =====================================================================
    # 安全样本 8: Java JNDI 白名单校验
    # =====================================================================
    {
        "filename": "safe_ldap_java_whitelist.java",
        "language": "java",
        "code": r'''import javax.naming.*;
import javax.naming.directory.*;

public class LdapAuthService {
    private final DirContext ctx;

    public LdapAuthService(DirContext ctx) {
        this.ctx = ctx;
    }

    public SearchResult findUser(String uid) throws NamingException {
        if (!uid.matches("[a-zA-Z0-9_-]+")) {
            throw new IllegalArgumentException("Invalid uid format");
        }
        String base = "dc=example,dc=com";
        String filter = "(uid=" + uid + ")";
        NamingEnumeration<SearchResult> results = ctx.search(base, filter, null);
        if (results.hasMore()) {
            return results.next();
        }
        return null;
    }
}''',
        "cot": r'''分析过程：
1. 污染源：uid 参数，来自 HTTP 请求。
2. sink 识别：ctx.search 的 filter 参数。
3. 数据流：uid → 正则白名单校验 → 字符串拼接 → ctx.search。
4. 防御评估：uid.matches("[a-zA-Z0-9_-]+") 只允许字母、数字、下划线、横线，LDAP filter 特殊字符（* ( ) \ 和 NUL）均无法通过；不匹配时直接抛异常，阻断数据流。
5. 结论：白名单有效，无 LDAP 注入风险。''',
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "白名单正则 [a-zA-Z0-9_-]+ 阻止了 LDAP filter 特殊字符注入",
            "fix_suggestion": "no fix needed",
        },
    },
    # =====================================================================
    # 安全样本 9: Node.js 自定义转义函数
    # =====================================================================
    {
        "filename": "safe_ldap_js_escape.js",
        "language": "javascript",
        "code": r'''var ldapauth = require('ldapauth-fork');

function escapeLDAP(input) {
    return input.replace(/[*()\\\x00]/g, '\\$&');
}

var opts = {
    url: 'ldap://ldap.example.com',
    bindDN: 'cn=admin,dc=example,dc=com',
    bindCredentials: 'admin_secret',
    searchBase: 'dc=example,dc=com',
    searchFilter: '(uid={{username}})'
};

function authenticate(username, password, callback) {
    var safeUsername = escapeLDAP(username);
    var searchFilter = opts.searchFilter.replace(/{{username}}/g, safeUsername);
    opts.searchFilter = searchFilter;
    var auth = new ldapauth(opts);
    auth.authenticate(username, password, callback);
}''',
        "cot": r'''分析过程：
1. 源分析：username 来自 HTTP 认证请求。
2. sink 定位：searchFilter 字符串用于 LDAP 查询。
3. 数据流：username → escapeLDAP(username) → replace 拼入 filter → 认证查询。
4. 防御确认：escapeLDAP 用正则 /[*()\\\x00]/g 匹配 * ( ) \ 和 NUL 字符，替换为反斜杠前缀形式（如 * → \*），符合 RFC 4515 转义规则，攻击者无法改变 filter 语义。
5. 结论：自定义转义有效，不存在 LDAP 注入。''',
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": "自定义 escapeLDAP 函数转义了 * ( ) \\ 和 NUL 字符，符合 RFC 4515",
            "fix_suggestion": "no fix needed",
        },
    },
]


# ===========================================================================
# 构建与追加逻辑
# ===========================================================================
def load_system_prompt(filepath):
    """从现有 JSONL 第一行读取 system prompt，确保与现有样本完全一致。"""
    with open(filepath, encoding="utf-8") as f:
        first_line = f.readline()
    obj = json.loads(first_line)
    return obj["messages"][0]["content"]


def build_user_prompt(filename, language, code):
    """构建 user prompt，格式与现有样本一致。"""
    return (
        f"代码片段（文件名: {filename}，语言: {language}）：\n"
        f"```{language}\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )


def build_sample(sample, system_prompt):
    """构建一条 ChatML 样本。"""
    user_prompt = build_user_prompt(
        sample["filename"], sample["language"], sample["code"]
    )
    json_str = json.dumps(sample["verdict"], ensure_ascii=False, indent=2)
    assistant_content = f"{sample['cot']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def verify_new_samples(filepath, start_line):
    """验证追加的样本：合法 JSON、3 条消息、json 块可解析、CWE 归因正确。"""
    print("\n=== 验证新增样本 ===")
    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()

    for idx in range(start_line, len(lines)):
        line_no = idx + 1
        line = lines[idx]

        # 1. 合法 JSON
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {line_no}: JSON 解析失败 - {e}")
            continue

        # 2. messages 有 3 条
        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {line_no}: messages 数量为 {len(messages)}，期望 3")
            continue

        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {line_no}: roles 为 {roles}")
            continue

        # 3. assistant content 包含可解析的 ```json 块
        assistant_content = messages[2]["content"]
        json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
        if not json_blocks:
            errors.append(f"行 {line_no}: 未找到 ```json 块")
            continue

        verdict = None
        for block in json_blocks:
            try:
                verdict = json.loads(block)
                break
            except json.JSONDecodeError:
                continue
        if verdict is None:
            errors.append(f"行 {line_no}: JSON 块无法解析")
            continue

        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")

        # 4. 漏洞样本的 vulnerability_type 包含 "CWE-90"
        if has_vuln is True:
            if "CWE-90" not in vuln_type:
                errors.append(f"行 {line_no}: 漏洞样本 vulnerability_type 为 '{vuln_type}'，缺少 'CWE-90'")
            cwe_counter[vuln_type] += 1
        elif has_vuln is False:
            if vuln_type != "none":
                errors.append(f"行 {line_no}: 安全样本 vulnerability_type 为 '{vuln_type}'，期望 'none'")
            cwe_counter["none（安全）"] += 1
        else:
            errors.append(f"行 {line_no}: has_vulnerability 为 {has_vuln}，非布尔值")

    if errors:
        print(f"发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        print("所有验证通过：")
        print(f"  - 新增 {len(lines) - start_line} 条样本均为合法 JSON")
        print(f"  - 每条 messages 数组有 3 条（system/user/assistant）")
        print(f"  - assistant content 的 ```json 块均可解析")
        print(f"  - 漏洞样本 vulnerability_type 均包含 'CWE-90'")
        print(f"  - 安全样本 has_vulnerability 均为 false")

    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    return len(errors) == 0


def main():
    print("=" * 60)
    print("LDAP 注入（CWE-90）训练样本生成")
    print("=" * 60)

    # 1. 从现有文件读取 system prompt（确保完全一致）
    system_prompt = load_system_prompt(OUTPUT_FILE)
    print(f"已从 {OUTPUT_FILE.name} 读取 system prompt")

    # 2. 读取现有行数
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        existing_lines = [l for l in f if l.strip()]
    before_count = len(existing_lines)
    print(f"现有样本数: {before_count}")

    # 3. 追加 9 条样本
    vuln_count = sum(1 for s in SAMPLES if s["verdict"]["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"\n准备追加 {len(SAMPLES)} 条样本（漏洞 {vuln_count} + 安全 {safe_count}）")

    # 检查文件末尾是否有换行符
    needs_newline = False
    if OUTPUT_FILE.stat().st_size > 0:
        with open(OUTPUT_FILE, "rb") as f:
            f.seek(-1, 2)
            last_byte = f.read(1)
            if last_byte != b"\n":
                needs_newline = True

    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        if needs_newline:
            f.write("\n")
        for sample in SAMPLES:
            chatml = build_sample(sample, system_prompt)
            f.write(json.dumps(chatml, ensure_ascii=False) + "\n")

    # 4. 确认写入数量
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        all_lines = [l for l in f if l.strip()]
    after_count = len(all_lines)
    added = after_count - before_count

    print(f"\n追加后样本数: {after_count}")
    print(f"新增样本数: {added}")

    # 5. 验证新增样本
    ok = verify_new_samples(OUTPUT_FILE, before_count)

    print("\n" + "=" * 60)
    if ok and added == len(SAMPLES):
        print(f"成功：{added} 条 LDAP 样本已追加到 {OUTPUT_FILE.name}")
    else:
        print(f"警告：追加或验证存在问题，请检查上方输出")
    print("=" * 60)


if __name__ == "__main__":
    main()
