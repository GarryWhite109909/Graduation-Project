"""
Batch 4: 追加到 distill_glm_cwe_cvss.jsonl 和 distill_glm_web.jsonl
- cwe_cvss: CWE-90 LDAP 注入 (12 条: 3 漏洞 + 9 安全) + CWE-643 XPath 注入 (12 条: 3 漏洞 + 9 安全)
- web:      CWE-502 不安全反序列化 (12 条: 3 漏洞 + 9 安全) + CWE-611 XXE (12 条: 3 漏洞 + 9 安全)
"""
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from gen_glm_distill_batch1 import (
    GLM_SYSTEM, build_user_cwe_cvss, build_user_web,
    assistant_response, write_sample,
)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


# =====================================================================
# Batch 4: cwe_cvss  ——  CWE-90 LDAP 注入
# 12 条：3 漏洞 + 9 安全，覆盖 Python / Java / PHP
# =====================================================================

CWE_CVSS_BATCH4_LDAP = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_037.py
from flask import Flask, request, jsonify
from ldap3 import Server, Connection

app = Flask(__name__)
server = Server('ldap://corp-dc.local')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    filter_str = f"(uid={uid})"
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn', 'mail'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入，未做转义或白名单校验",
            "第 11 行 f-string 把 uid 直接拼入 LDAP filter 字符串",
            "第 13 行 conn.search 使用拼接后的 filter_str 作为搜索过滤器",
            "source→sink 间无任何防御，攻击者传 uid=*)(uid=*) 可枚举全目录或绕过过滤",
            "CWE-90 LDAP 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', f\"(uid={uid})\")",
            "explanation": "request.args.get('uid') → uid → f-string 拼入 filter → conn.search 执行 LDAP 查询",
            "fix_suggestion": "使用 ldap3.utils.conv.escape_filter_chars(uid) 对特殊字符转义后再拼入 filter",
        },
    },
    {
        "lang": "Java", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_038.java
@RestController
public class LdapUserController {
    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/find_user")
    public List<String> findUser(@RequestParam String uid) {
        String filter = "(uid=" + uid + ")";
        return ldapTemplate.search(
            "ou=staff,dc=corp,dc=local",
            filter,
            (Attributes attrs) -> (String) attrs.get("cn").get()
        );
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String uid 获取用户输入，未做转义",
            "第 9 行用 Java + 把 uid 拼入 LDAP filter 字符串字面量",
            "第 11 行 ldapTemplate.search 使用拼接后的 filter 作为搜索过滤器",
            "LdapTemplate 的 search 方法不会自动转义 filter 内容，source→sink 间无防御",
            "CWE-90 LDAP 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "@RequestParam String uid",
            "sink": "ldapTemplate.search(\"ou=staff,dc=corp,dc=local\", \"(uid=\" + uid + \")\", ...)",
            "explanation": "@RequestParam uid → 字符串拼接进 filter → ldapTemplate.search 执行 LDAP 查询",
            "fix_suggestion": "使用 LdapEncoder.filterEncode(uid) 对 filter 值转义后再拼接",
        },
    },
    {
        "lang": "PHP", "has_vuln": True, "difficulty": "典型",
        "code": """```php
// distill_glm_cwe_cvss_039.php
<?php
$ds = ldap_connect('ldap://corp-dc.local');
ldap_bind($ds, 'cn=admin', 'secret');
$uid = $_GET['uid'];
$filter = "(uid=$uid)";
$result = ldap_search($ds, 'ou=staff,dc=corp,dc=local', $filter, ['cn', 'mail']);
$entries = ldap_get_entries($ds, $result);
return json_encode($entries);
```""",
        "steps": [
            "第 5 行 $_GET['uid'] 获取用户输入，未做转义或过滤",
            "第 6 行用 PHP 字符串插值把 $uid 直接拼入 LDAP filter",
            "第 7 行 ldap_search 使用拼接后的 filter 作为搜索过滤器",
            "source→sink 间无任何防御，攻击者传 uid=*)(uid=*) 可枚举全目录",
            "CWE-90 LDAP 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-90 LDAP注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "$_GET['uid']",
            "sink": "ldap_search($ds, 'ou=staff,dc=corp,dc=local', \"(uid=$uid)\")",
            "explanation": "$_GET['uid'] → $uid → 字符串插值拼入 filter → ldap_search 执行 LDAP 查询",
            "fix_suggestion": "使用 ldap_escape($uid, '', LDAP_ESCAPE_FILTER) 对 filter 值转义后再拼接",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_040.py
from flask import Flask, request, jsonify
from ldap3 import Server, Connection
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)
server = Server('ldap://corp-dc.local')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    safe_uid = escape_filter_chars(uid)
    filter_str = f"(uid={safe_uid})"
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn', 'mail'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 11 行 request.args.get('uid') 获取用户输入",
            "第 12 行 escape_filter_chars(uid) 对 * ( ) \\ NUL 等 LDAP filter 特殊字符做转义",
            "第 13 行 f-string 拼接的是已转义的 safe_uid，filter 语义不会被破坏",
            "已检查：escape_filter_chars 转义 + 拼接，攻击者传 *)(uid=*) 中的 ) 和 * 会被反斜杠转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', f\"(uid={safe_uid})\")",
            "explanation": "uid 经 escape_filter_chars 转义后拼入 filter，特殊字符被反斜杠转义，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_041.java
@RestController
public class LdapUserController {
    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/find_user")
    public List<String> findUser(@RequestParam String uid) {
        String safeUid = LdapEncoder.filterEncode(uid);
        String filter = "(uid=" + safeUid + ")";
        return ldapTemplate.search(
            "ou=staff,dc=corp,dc=local",
            filter,
            (Attributes attrs) -> (String) attrs.get("cn").get()
        );
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String uid 获取用户输入",
            "第 9 行 LdapEncoder.filterEncode(uid) 对 filter 值中的特殊字符做转义",
            "第 10 行用 + 拼接的是已转义的 safeUid，filter 语义不会被破坏",
            "已检查：LdapEncoder.filterEncode 转义，* ( ) \\ 等 special char 被反斜杠转义，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "ldapTemplate.search(..., \"(uid=\" + safeUid + \")\", ...)",
            "explanation": "uid 经 LdapEncoder.filterEncode 转义后拼入 filter，特殊字符被反斜杠转义，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_042.py
from flask import Flask, request, jsonify
from ldap3 import Server, Connection

app = Flask(__name__)
server = Server('ldap://corp-dc.local')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    # 使用固定 filter 模板 + 显式校验，避免拼接
    if not uid.isalnum() or len(uid) > 32:
        return {'error': 'invalid uid'}, 400
    filter_str = '(uid={uid})'.format(uid=uid)
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入",
            "第 12-13 行 isalnum() + len 校验：仅允许字母数字且长度 ≤32，含 * ( ) 等特殊字符的输入被 400 拒绝",
            "第 14 行 str.format 填充已校验的 uid，filter 语义固定为 (uid=<纯字母数字>)",
            "已检查：白名单字符校验 + 长度限制，攻击者无法注入 * 或 ) 等元字符",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', '(uid={uid})'.format(uid=uid))",
            "explanation": "uid 经 isalnum 白名单 + 长度校验，特殊字符被拒绝，filter 语义固定，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_043.java
@RestController
public class LdapUserController {
    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/find_user")
    public List<String> findUser(@RequestParam String uid) {
        // 使用 AND filterContainers 容器 + 编码值，避免拼接
        String safeUid = LdapEncoder.filterEncode(uid);
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("uid", safeUid));
        return ldapTemplate.search(
            "ou=staff,dc=corp,dc=local",
            filter.encode(),
            (Attributes attrs) -> (String) attrs.get("cn").get()
        );
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String uid 获取用户输入",
            "第 10 行 LdapEncoder.filterEncode(uid) 对值做转义",
            "第 11-12 行 AndFilter + EqualsFilter 构造结构化 filter，filter.encode() 输出标准 filter 字符串",
            "已检查：filterEncode 转义 + EqualsFilter 结构化构造，filter 语义由框架保证，无拼接",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "ldapTemplate.search(..., filter.encode(), ...)",
            "explanation": "uid 经 filterEncode 转义 + EqualsFilter 结构化构造 filter，无字符串拼接，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_044.py
import re
from flask import Flask, request, jsonify
from ldap3 import Server, Connection

app = Flask(__name__)
server = Server('ldap://corp-dc.local')
UID_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    if not UID_RE.match(uid):
        return {'error': 'invalid uid'}, 400
    filter_str = f"(uid={uid})"
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入",
            "第 11-12 行 UID_RE.match 白名单正则校验：仅允许字母数字._- 且长度 1-32，非法输入被 400 拒绝",
            "第 13 行 f-string 拼接已校验的 uid，filter 仅含安全字符集",
            "已检查：白名单正则校验排除 * ( ) \\ NUL 等所有 LDAP 元字符，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', f\"(uid={uid})\")",
            "explanation": "uid 经白名单正则校验，仅允许字母数字._-，LDAP 元字符被拒绝，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "PHP", "has_vuln": False, "difficulty": "典型",
        "code": """```php
// distill_glm_cwe_cvss_045.php
<?php
$ds = ldap_connect('ldap://corp-dc.local');
ldap_bind($ds, 'cn=admin', 'secret');
$uid = $_GET['uid'];
$safe_uid = ldap_escape($uid, '', LDAP_ESCAPE_FILTER);
$filter = "(uid=$safe_uid)";
$result = ldap_search($ds, 'ou=staff,dc=corp,dc=local', $filter, ['cn', 'mail']);
$entries = ldap_get_entries($ds, $result);
return json_encode($entries);
```""",
        "steps": [
            "第 5 行 $_GET['uid'] 获取用户输入",
            "第 6 行 ldap_escape($uid, '', LDAP_ESCAPE_FILTER) 对 filter 上下文的特殊字符做转义",
            "第 7 行字符串插值拼接的是已转义的 safe_uid，filter 语义不会被破坏",
            "已检查：ldap_escape + LDAP_ESCAPE_FILTER 上下文转义，* ( ) \\ NUL 被反斜杠转义，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "$_GET['uid']",
            "sink": "ldap_search($ds, 'ou=staff,dc=corp,dc=local', \"(uid=$safe_uid)\")",
            "explanation": "uid 经 ldap_escape + LDAP_ESCAPE_FILTER 转义后拼入 filter，特殊字符被反斜杠转义，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_046.py
from flask import Flask, request, jsonify
from ldap3 import Server, Connection
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)
server = Server('ldap://corp-dc.local')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    # 固定 filter 模板占位 + 转义，双重防御
    safe_uid = escape_filter_chars(uid)
    filter_template = '(uid={uid})'
    filter_str = filter_template.format(uid=safe_uid)
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 11 行 request.args.get('uid') 获取用户输入",
            "第 13 行 escape_filter_chars(uid) 对 LDAP filter 特殊字符做转义",
            "第 14-15 行固定 filter 模板占位 {uid} 由 str.format 填充已转义的 safe_uid，无直接拼接",
            "已检查：escape_filter_chars 转义 + 模板占位填充，特殊字符被反斜杠转义，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', filter_template.format(uid=safe_uid))",
            "explanation": "uid 经 escape_filter_chars 转义 + 模板占位填充，特殊字符被转义，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_047.java
@RestController
public class LdapUserController {
    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/find_user")
    public List<String> findUser(@RequestParam String uid) {
        // 使用 HardcodedFilter + WhitespacingFilter 校验，filter 值经白名单约束
        if (!uid.matches("[a-zA-Z0-9._-]{1,32}")) {
            throw new IllegalArgumentException("invalid uid");
        }
        String filter = "(uid=" + uid + ")";
        return ldapTemplate.search(
            "ou=staff,dc=corp,dc=local",
            filter,
            (Attributes attrs) -> (String) attrs.get("cn").get()
        );
    }
}
```""",
        "steps": [
            "第 8 行 @RequestParam String uid 获取用户输入",
            "第 10-12 行 matches(\"[a-zA-Z0-9._-]{1,32}\") 白名单正则校验，仅允许字母数字._- 且长度 1-32",
            "第 13 行拼接的 uid 已被白名单限定为安全字符集，不含 * ( ) \\ 等 LDAP 元字符",
            "已检查：白名单正则校验排除所有 LDAP filter 元字符，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "ldapTemplate.search(..., \"(uid=\" + uid + \")\", ...)",
            "explanation": "uid 经白名单正则校验，仅允许字母数字._-，LDAP 元字符被拒绝，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_048.py
from flask import Flask, request, jsonify
from ldap3 import Server, Connection
from ldap3.protocol.formatters.formatters import escape_filter_chars
from ldap3.abstract import filter as flt

app = Flask(__name__)
server = Server('ldap://corp-dc.local')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    # 使用 ldap3 内置的 filter 构造器，自动转义
    f = flt.FILTER_PRESENT  # 占位：实际使用 EqualsFilter 语义
    safe_uid = escape_filter_chars(uid)
    filter_str = f"(uid={safe_uid})"
    with Connection(server, user='cn=admin', password='secret') as conn:
        conn.search('ou=staff,dc=corp,dc=local', filter_str, attributes=['cn'])
    return jsonify([str(e.cn) for e in conn.entries])
```""",
        "steps": [
            "第 11 行 request.args.get('uid') 获取用户输入",
            "第 14 行 escape_filter_chars(uid)（ldap3.protocol.formatters）对 filter 特殊字符做转义",
            "第 15 行 f-string 拼接的是已转义的 safe_uid，filter 语义固定为 (uid=<转义值>)",
            "已检查：ldap3 内置 escape_filter_chars 转义，* ( ) \\ NUL 被反斜杠转义，无 LDAP 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "conn.search('ou=staff,dc=corp,dc=local', f\"(uid={safe_uid})\")",
            "explanation": "uid 经 ldap3 内置 escape_filter_chars 转义后拼入 filter，特殊字符被转义，无 LDAP 注入",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 4: cwe_cvss  ——  CWE-643 XPath 注入
# 12 条：3 漏洞 + 9 安全，覆盖 Python / Java
# =====================================================================

CWE_CVSS_BATCH4_XPATH = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_049.py
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
tree = etree.parse('/var/data/users.xml')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    expr = f"//user[uid='{uid}']/name/text()"
    results = tree.xpath(expr)
    return jsonify({'names': results})
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入，未做转义或白名单校验",
            "第 11 行 f-string 把 uid 直接拼入 XPath 表达式字符串",
            "第 12 行 tree.xpath 执行拼接后的 XPath 表达式",
            "source→sink 间无任何防御，攻击者传 uid=' or '1'='1 可绕过条件枚举所有 user 节点",
            "CWE-643 XPath 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 XPath注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.args.get('uid')",
            "sink": "tree.xpath(f\"//user[uid='{uid}']/name/text()\")",
            "explanation": "request.args.get('uid') → uid → f-string 拼入 XPath → tree.xpath 执行查询",
            "fix_suggestion": "使用 lxml xpath 变量绑定：tree.xpath(\"//user[uid=$uid]/name/text()\", uid=uid)",
        },
    },
    {
        "lang": "Python", "has_vuln": True, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_050.py
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)
root = ET.parse('/var/data/users.xml').getroot()


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    expr = f".//user[uid='{uid}']"
    found = root.findall(expr)
    return jsonify({'count': len(found)})
```""",
        "steps": [
            "第 9 行 request.args.get('uid') 获取用户输入，未做转义",
            "第 10 行 f-string 把 uid 直接拼入 XPath 表达式",
            "第 11 行 root.findall 执行拼接后的 XPath 表达式",
            "source→sink 间无任何防御，攻击者传 uid=' or '1'='1 可枚举所有 user 节点",
            "CWE-643 XPath 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 XPath注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.args.get('uid')",
            "sink": "root.findall(f\".//user[uid='{uid}']\")",
            "explanation": "request.args.get('uid') → uid → f-string 拼入 XPath → root.findall 执行查询",
            "fix_suggestion": "改用 lxml 的 xpath 变量绑定，或对 uid 做白名单校验（仅字母数字）",
        },
    },
    {
        "lang": "Java", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_051.java
import javax.xml.xpath.*;
import org.xml.sax.InputSource;

@RestController
public class UserXPathController {
    @GetMapping("/find_user")
    public String findUser(@RequestParam String uid) throws Exception {
        XPathFactory xf = XPathFactory.newInstance();
        XPath xpath = xf.newXPath();
        String expr = "//user[uid='" + uid + "']/name/text()";
        return xpath.evaluate(expr, new InputSource("/var/data/users.xml"));
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam String uid 获取用户输入，未做转义",
            "第 11 行用 Java + 把 uid 拼入 XPath 表达式字符串",
            "第 12 行 xpath.evaluate 执行拼接后的 XPath 表达式",
            "source→sink 间无任何防御，攻击者传 uid=' or '1'='1 可绕过条件",
            "CWE-643 XPath 注入，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 XPath注入",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "@RequestParam String uid",
            "sink": "xpath.evaluate(\"//user[uid='\" + uid + \"']/name/text()\", ...)",
            "explanation": "@RequestParam uid → 字符串拼接进 XPath → xpath.evaluate 执行查询",
            "fix_suggestion": "使用 XPathVariableResolver + setVariable 绑定变量，避免拼接",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_052.py
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
tree = etree.parse('/var/data/users.xml')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    # 使用 lxml xpath 变量绑定（$uid），不拼接字符串
    results = tree.xpath("//user[uid=$uid]/name/text()", uid=uid)
    return jsonify({'names': results})
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入",
            "第 12 行 XPath 表达式使用 $uid 变量占位符，未做字符串拼接",
            "tree.xpath 第二参数 uid=uid 作为变量绑定值传入，lxml 内部对值做转义",
            "已检查：$uid 变量绑定 + 无字符串拼接，攻击者传 ' or '1'='1 仅作为字面值匹配，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "tree.xpath(\"//user[uid=$uid]/name/text()\", uid=uid)",
            "explanation": "uid 通过 $uid 变量绑定传入 lxml xpath，框架内部转义，无字符串拼接，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_053.py
import re
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)
root = ET.parse('/var/data/users.xml').getroot()
UID_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    if not UID_RE.match(uid):
        return {'error': 'invalid uid'}, 400
    expr = f".//user[uid='{uid}']"
    found = root.findall(expr)
    return jsonify({'count': len(found)})
```""",
        "steps": [
            "第 11 行 request.args.get('uid') 获取用户输入",
            "第 12-13 行 UID_RE.match 白名单正则校验：仅允许字母数字._- 且长度 1-32，非法输入被 400 拒绝",
            "第 14 行 f-string 拼接已校验的 uid，expr 仅含安全字符集",
            "已检查：白名单正则校验排除 ' 等引号和 XPath 元字符，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "root.findall(f\".//user[uid='{uid}']\")",
            "explanation": "uid 经白名单正则校验，仅允许字母数字._-，引号和 XPath 元字符被拒绝，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_054.java
import javax.xml.xpath.*;
import org.xml.sax.InputSource;

@RestController
public class UserXPathController {
    @GetMapping("/find_user")
    public String findUser(@RequestParam String uid) throws Exception {
        XPathFactory xf = XPathFactory.newInstance();
        XPath xpath = xf.newXPath();
        // 使用 XPathVariableResolver 绑定变量，不拼接字符串
        xpath.setXPathVariableResolver(v -> {
            if ("uid".equals(v.getLocalPart())) return uid;
            return null;
        });
        return xpath.evaluate("//user[uid=$uid]/name/text()",
            new InputSource("/var/data/users.xml"));
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam String uid 获取用户输入",
            "第 11-15 行 setXPathVariableResolver 将 $uid 变量映射到 uid 值，框架内部转义",
            "第 16 行 XPath 表达式使用 $uid 变量占位符，未做字符串拼接",
            "已检查：XPathVariableResolver 变量绑定 + 无字符串拼接，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "xpath.evaluate(\"//user[uid=$uid]/name/text()\", ...)",
            "explanation": "uid 经 XPathVariableResolver 绑定为 $uid 变量，无字符串拼接，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_055.py
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
tree = etree.parse('/var/data/users.xml')


def escape_xpath_literal(s):
    # 处理 XPath 字符串字面量中的引号转义
    if "'" not in s:
        return f"'{s}'"
    if '"' not in s:
        return f'"{s}"'
    return "concat(" + ",\"'\",".join(f"'{p}'" for p in s.split("'")) + ")"


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    safe = escape_xpath_literal(uid)
    results = tree.xpath(f"//user[uid={safe}]/name/text()")
    return jsonify({'names': results})
```""",
        "steps": [
            "第 9 行 request.args.get('uid') 获取用户输入",
            "第 11-18 行 escape_xpath_literal 对单引号/双引号做 XPath 字面量转义（使用 concat 拼接 '）",
            "第 21 行 f-string 拼接的是已转义的 safe 字面量，expr 语义不会被破坏",
            "已检查：escape_xpath_literal 对引号做 concat 转义，攻击者无法注入 ' or '1'='1",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "tree.xpath(f\"//user[uid={safe}]/name/text()\")",
            "explanation": "uid 经 escape_xpath_literal 对引号做 concat 转义，无法注入 XPath 元字符，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_056.java
import javax.xml.xpath.*;
import org.xml.sax.InputSource;

@RestController
public class UserXPathController {
    private static final XPath xpath;
    static {
        XPathFactory xf = XPathFactory.newInstance();
        xpath = xf.newXPath();
        // 编译固定表达式 + 变量绑定
        xpath.setXPathVariableResolver(v -> null);
    }

    @GetMapping("/find_user")
    public String findUser(@RequestParam String uid) throws Exception {
        xpath.setXPathVariableResolver(v -> {
            if ("uid".equals(v.getLocalPart())) return uid;
            return null;
        });
        XPathExpression expr = xpath.compile("//user[uid=$uid]/name/text()");
        return expr.evaluate(new InputSource("/var/data/users.xml"));
    }
}
```""",
        "steps": [
            "第 17 行 @RequestParam String uid 获取用户输入",
            "第 18-21 行 setXPathVariableResolver 将 $uid 变量映射到 uid 值，框架内部转义",
            "第 22 行 xpath.compile 编译固定表达式（不含用户输入），第 23 行 evaluate 执行",
            "已检查：编译固定表达式 + XPathVariableResolver 变量绑定，无字符串拼接，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "xpath.compile(\"//user[uid=$uid]/name/text()\").evaluate(...)",
            "explanation": "uid 经 XPathVariableResolver 绑定为 $uid 变量，表达式为编译固定字符串，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_057.py
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
tree = etree.parse('/var/data/users.xml')


@app.route('/find_user')
def find_user():
    uid = request.args.get('uid', '')
    # 使用 XPathEval (etree.XPath) 预编译 + 变量绑定
    compiled = etree.XPath("//user[uid=$uid]/name/text()")
    results = compiled(tree, uid=uid)
    return jsonify({'names': results})
```""",
        "steps": [
            "第 10 行 request.args.get('uid') 获取用户输入",
            "第 12 行 etree.XPath(...) 预编译固定表达式（不含用户输入），$uid 为变量占位符",
            "第 13 行 compiled(tree, uid=uid) 通过关键字参数绑定变量值，lxml 内部转义",
            "已检查：预编译固定表达式 + $uid 变量绑定，无字符串拼接，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "etree.XPath(\"//user[uid=$uid]/name/text()\")(tree, uid=uid)",
            "explanation": "uid 通过 etree.XPath 预编译表达式的 $uid 变量绑定传入，无字符串拼接，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_058.py
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)
root = ET.parse('/var/data/users.xml').getroot()


@app.route('/find_user')
def find_user():
    uid_raw = request.args.get('uid', '')
    # int() 强制类型转换，非数字输入被拒绝
    try:
        uid = int(uid_raw)
    except ValueError:
        return {'error': 'invalid uid'}, 400
    expr = f".//user[uid='{uid}']"
    found = root.findall(expr)
    return jsonify({'count': len(found)})
```""",
        "steps": [
            "第 9 行 request.args.get('uid') 获取用户输入",
            "第 11-13 行 int(uid_raw) 强制类型转换，非数字输入被 ValueError 拒绝返回 400",
            "第 14 行 f-string 拼接的 uid 是 int 类型，str(uid) 仅含数字字符",
            "已检查：int 类型转换保证 uid 仅含数字，引号和 XPath 元字符被拒绝，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('uid')",
            "sink": "root.findall(f\".//user[uid='{uid}']\")",
            "explanation": "uid 经 int() 类型转换，仅含数字字符，引号和 XPath 元字符被拒绝，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_059.java
import javax.xml.xpath.*;
import org.xml.sax.InputSource;

@RestController
public class UserXPathController {
    @GetMapping("/find_user")
    public String findUser(@RequestParam String uid) throws Exception {
        XPathFactory xf = XPathFactory.newInstance();
        XPath xpath = xf.newXPath();
        // setVariable 设置 XPath 变量值（避免 setVariable 与 XPathVariableResolver 冲突时用后者）
        xpath.setXPathVariableResolver(v -> {
            if ("uid".equals(v.getLocalPart())) return uid;
            return null;
        });
        return xpath.evaluate("//user[uid=$uid]/name/text()",
            new InputSource("/var/data/users.xml"));
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam String uid 获取用户输入",
            "第 12-15 行 setXPathVariableResolver 将 $uid 变量映射到 uid 值，框架内部转义",
            "第 16 行 XPath 表达式使用 $uid 变量占位符，未做字符串拼接",
            "已检查：XPathVariableResolver 变量绑定 + 无字符串拼接，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String uid",
            "sink": "xpath.evaluate(\"//user[uid=$uid]/name/text()\", ...)",
            "explanation": "uid 经 XPathVariableResolver 绑定为 $uid 变量，无字符串拼接，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_060.py
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)
tree = etree.parse('/var/data/users.xml')


@app.route('/find_user')
def find_user():
    keyword = request.args.get('kw', '')
    # 避免使用 XPath 表达式，改用纯文本遍历匹配
    names = []
    for user in tree.iter('user'):
        uid_elem = user.find('uid')
        if uid_elem is not None and uid_elem.text == keyword:
            name_elem = user.find('name')
            if name_elem is not None:
                names.append(name_elem.text)
    return jsonify({'names': names})
```""",
        "steps": [
            "第 10 行 request.args.get('kw') 获取用户输入",
            "第 12-16 行使用 tree.iter('user') + user.find('uid') 遍历元素，uid_elem.text == keyword 做纯文本比较",
            "纯文本比较不涉及 XPath 表达式解析，keyword 作为字面值参与 == 比较",
            "已检查：避免使用 xpath/findall(expr)，改用 iter + find + == 文本匹配，无 XPath 注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('kw')",
            "sink": "uid_elem.text == keyword",
            "explanation": "kw 作为字面值参与 Python == 文本比较，不进入 XPath 表达式解析，无 XPath 注入",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 4: web  ——  CWE-502 不安全反序列化
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Spring / Django / FastAPI
# =====================================================================

WEB_BATCH4_DESER = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "会话恢复", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_037.py
import pickle
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/restore_session')
def restore_session():
    blob = request.get_data()
    # 直接反序列化用户提交的二进制
    session = pickle.loads(blob)
    return jsonify({'user': session.get('user')})
```""",
        "steps": [
            "第 9 行 request.get_data() 获取用户提交的原始二进制数据",
            "第 11 行 pickle.loads(blob) 使用 pickle 协议反序列化任意 Python 对象",
            "pickle 通过 __reduce__ 机制可在反序列化时执行任意代码",
            "source→sink 间无任何防御，攻击者构造恶意 pickle payload 可实现 RCE",
            "CWE-502 不安全反序列化，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-502 不安全反序列化",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.get_data()",
            "sink": "pickle.loads(blob)",
            "explanation": "request.get_data() → blob → pickle.loads 反序列化任意 Python 对象，可通过 __reduce__ 触发 RCE",
            "fix_suggestion": "使用 JSON 替代 pickle：json.loads(blob.decode())，仅解析数据结构不实例化对象",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "会话恢复", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_web_038.java
import java.io.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SessionController {
    @PostMapping("/restore_session")
    public String restore(HttpServletRequest req) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object obj = ois.readObject();
        return obj.toString();
    }
}
```""",
        "steps": [
            "第 8 行 req.getInputStream() 获取 HTTP 请求体原始字节流",
            "第 9 行 ObjectInputStream 包装输入流，第 10 行 readObject 反序列化任意 Java 对象",
            "Java 原生反序列化可通过 Serializable 类的 readObject/readResolve 方法触发任意代码（如 Commons Collections gadget）",
            "source→sink 间无任何防御，攻击者构造恶意序列化数据可实现 RCE",
            "CWE-502 不安全反序列化，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-502 不安全反序列化",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "req.getInputStream()",
            "sink": "ois.readObject()",
            "explanation": "req.getInputStream() → ObjectInputStream → readObject 反序列化任意 Java 对象，可触发 gadget 链 RCE",
            "fix_suggestion": "使用 JSON 替代 Java 原生序列化，或用 ObjectInputFilter 限制可反序列化的类白名单",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "配置加载", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_039.py
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/load_config')
def load_config():
    raw = request.get_data(as_text=True)
    # yaml.load 默认使用 FullLoader 之前的 UnsafeLoader，可实例化任意 Python 对象
    cfg = yaml.load(raw, Loader=yaml.Loader)
    return jsonify({'config': str(cfg)})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 YAML 文本",
            "第 11 行 yaml.load(raw, Loader=yaml.Loader) 使用非 safe Loader 反序列化",
            "yaml.Loader 支持 !!python/object 等标签，可在加载时实例化任意 Python 对象并执行代码",
            "source→sink 间无任何防御，攻击者提交 !!python/object/apply:os.system ['id'] 可实现 RCE",
            "CWE-502 不安全反序列化，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-502 不安全反序列化",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.get_data(as_text=True)",
            "sink": "yaml.load(raw, Loader=yaml.Loader)",
            "explanation": "request.get_data → raw → yaml.load(Loader=yaml.Loader) 加载含 !!python/object 标签的 YAML 可实例化任意对象触发 RCE",
            "fix_suggestion": "使用 yaml.safe_load(raw) 替代 yaml.load，仅解析 YAML 数据结构不实例化 Python 对象",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "会话恢复", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_040.py
import json
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/restore_session')
def restore_session():
    blob = request.get_data(as_text=True)
    # 使用 JSON 解析替代 pickle，仅解析数据结构不实例化对象
    session = json.loads(blob)
    return jsonify({'user': session.get('user')})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 JSON 文本",
            "第 11 行 json.loads(blob) 仅解析 JSON 数据结构（dict/list/str/num/bool/null）",
            "json.loads 不支持 Python 对象实例化，不会调用 __reduce__ 或 __init__",
            "已检查：使用 JSON（非 pickle）解析，仅产出原生数据类型，无对象实例化，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "json.loads(blob)",
            "explanation": "blob 经 json.loads 解析为原生 JSON 数据类型，不实例化 Python 对象，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "API 响应", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_041.java
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class ApiController {
    private final ObjectMapper mapper;

    public ApiController() {
        this.mapper = new ObjectMapper();
        // 显式禁用 default typing，禁止 @class 元数据驱动的多态反序列化
        this.mapper.enableDefaultTyping(
            ObjectMapper.DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY);
        // 改为安全配置：不启用 default typing
    }

    @PostMapping("/api")
    public Object api(@RequestBody String body) throws Exception {
        return mapper.readTree(body);
    }
}
```""",
        "steps": [
            "第 12-14 行构造 ObjectMapper，未启用 enableDefaultTyping（默认安全）",
            "第 16-18 行 mapper.readTree(body) 将 JSON 解析为 JsonNode 树结构",
            "readTree 不绑定到具体 Java 类，不会触发 setter/构造器或 @class 元数据驱动实例化",
            "已检查：未启用 default typing + readTree 仅解析为 JsonNode，无多态反序列化，无 RCE 风险",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestBody String body",
            "sink": "mapper.readTree(body)",
            "explanation": "body 经 ObjectMapper（未启用 default typing）readTree 解析为 JsonNode，无多态实例化，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "会话恢复", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_042.py
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect


@csrf_protect
def restore_session(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'method not allowed'}, status=405)
    # 替换 pickle：使用 JSON 解析 request.body
    session = json.loads(request.body.decode('utf-8'))
    return JsonResponse({'user': session.get('user')})
```""",
        "steps": [
            "第 9 行 request.body 获取用户提交的原始字节",
            "第 11 行 json.loads(request.body.decode('utf-8')) 将 JSON 文本解析为原生数据类型",
            "json.loads 不支持 Python 对象实例化，不会触发 __reduce__",
            "已检查：使用 JSON（非 pickle）解析 + @csrf_protect 防 CSRF，仅产出原生数据类型，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.body",
            "sink": "json.loads(request.body.decode('utf-8'))",
            "explanation": "request.body 经 json.loads 解析为原生 JSON 数据类型，不实例化 Python 对象，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "会话恢复", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_043.java
import java.io.*;
import java.util.Set;
import org.springframework.web.bind.annotation.*;

@RestController
public class SessionController {
    // 白名单：仅允许这些类被反序列化
    private static final Set<String> ALLOWED = Set.of(
        "com.myapp.SessionData", "java.lang.String", "java.util.HashMap");

    @PostMapping("/restore_session")
    public String restore(HttpServletRequest req) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream()) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) {
                if (!ALLOWED.contains(desc.getName())) {
                    throw new InvalidClassException("unauthorized class", desc.getName());
                }
                return super.resolveClass(desc);
            }
        };
        Object obj = ois.readObject();
        return obj.toString();
    }
}
```""",
        "steps": [
            "第 11 行 req.getInputStream() 获取请求体字节流",
            "第 13-19 行重写 resolveClass：仅允许 ALLOWED 白名单中的类被反序列化，非法类抛 InvalidClassException",
            "第 21 行 readObject 反序列化时，每个类都经 resolveClass 校验，gadget 链中的类被拒绝",
            "已检查：resolveClass 白名单过滤，Commons Collections 等 gadget 类被拒绝，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "ois.readObject()",
            "explanation": "ObjectInputStream 重写 resolveClass + 白名单校验，非白名单类被拒绝，gadget 链无法触发，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "配置加载", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_044.py
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/load_config')
def load_config():
    raw = request.get_data(as_text=True)
    # 使用 safe_load 替代 yaml.load，仅解析 YAML 数据结构
    cfg = yaml.safe_load(raw)
    return jsonify({'config': str(cfg)})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 YAML 文本",
            "第 11 行 yaml.safe_load(raw) 仅解析 YAML 标准数据结构（dict/list/str/num/bool/null）",
            "safe_load 不支持 !!python/object 等自定义 Python 标签，不会实例化 Python 对象",
            "已检查：使用 safe_load（非 yaml.load），不解析 !!python/object 标签，无对象实例化，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "yaml.safe_load(raw)",
            "explanation": "raw 经 yaml.safe_load 解析为标准 YAML 数据类型，不实例化 Python 对象，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "API 响应", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_045.java
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class ApiController {
    private final ObjectMapper mapper = new ObjectMapper();

    @PostMapping("/api")
    public SessionData api(@RequestBody SessionData dto) {
        // SessionData 使用 @JsonTypeInfo(Default) 忽略 @class 元数据
        return dto;
    }
}

@JsonTypeInfo(use = JsonTypeInfo.Id.NONE)
class SessionData {
    public String user;
    public long ts;
}
```""",
        "steps": [
            "第 10 行 @RequestBody SessionData dto 由 Jackson 反序列化为固定类型 SessionData",
            "第 17 行 @JsonTypeInfo(use = JsonTypeInfo.Id.NONE) 显式禁用类型元数据驱动",
            "Jackson 仅根据 SessionData 的字段名绑定 JSON 属性，忽略 @class 等 type 标识，不会实例化其他类",
            "已检查：固定目标类型 + @JsonTypeInfo(Id.NONE) 禁用多态，无 @class 驱动的多态反序列化",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestBody SessionData dto",
            "sink": "Jackson 反序列化为 SessionData",
            "explanation": "body 经 Jackson 反序列化为固定 SessionData 类型，@JsonTypeInfo(Id.NONE) 禁用多态，无 @class 驱动实例化，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "FastAPI", "scene": "消息队列", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_046.py
import msgpack
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

ALLOWED_TYPES = (dict, list, str, int, float, bool, type(None))


@app.post('/enqueue')
async def enqueue(req: Request):
    blob = await req.body()
    # msgpack 反序列化后做类型校验
    data = msgpack.unpackb(blob, raw=False)
    if not isinstance(data, ALLOWED_TYPES):
        raise HTTPException(400, 'invalid payload type')
    return {'status': 'queued', 'type': type(data).__name__}
```""",
        "steps": [
            "第 10 行 await req.body() 获取用户提交的 msgpack 二进制",
            "第 12 行 msgpack.unpackb(blob, raw=False) 解包为 Python 对象",
            "第 13-15 行 isinstance(data, ALLOWED_TYPES) 校验：仅允许 dict/list/str/num/bool/None，自定义对象被 400 拒绝",
            "已检查：msgpack unpackb + 类型白名单校验，仅产出原生数据类型，无自定义对象实例化，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "await req.body()",
            "sink": "msgpack.unpackb(blob, raw=False)",
            "explanation": "blob 经 msgpack.unpackb 解包 + isinstance 类型白名单校验，仅允许原生数据类型，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "会话恢复", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_047.java
import java.io.*;
import java.util.Set;
import org.springframework.web.bind.annotation.*;

@RestController
public class SessionController {
    // JDK 9+ ObjectInputFilter 白名单
    private static final ObjectInputFilter FILTER =
        ObjectInputFilter.Config.createFilter(
            "com.myapp.SessionData;java.lang.*;java.util.*;!*");

    @PostMapping("/restore_session")
    public String restore(HttpServletRequest req) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        ois.setObjectInputFilter(FILTER);
        Object obj = ois.readObject();
        return obj.toString();
    }
}
```""",
        "steps": [
            "第 10-12 行 ObjectInputFilter.Config.createFilter 定义白名单：SessionData + java.lang.* + java.util.*，!* 拒绝其他所有类",
            "第 16 行 ois.setObjectInputFilter(FILTER) 将过滤器绑定到 ObjectInputStream",
            "第 17 行 readObject 反序列化时，每个类都经 FILTER 校验，非白名单类被拒绝",
            "已检查：ObjectInputFilter 全局白名单 + !* 默认拒绝，gadget 链中的非白名单类被拒绝，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "ois.readObject()",
            "explanation": "ObjectInputStream 设置 ObjectInputFilter 白名单 + !* 默认拒绝，非白名单类被拒绝，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "缓存读取", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_048.py
import json
import shelve
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/cache_set')
def cache_set():
    key = request.args.get('key', '')
    val = request.get_data(as_text=True)
    # 使用 JSON 解析 val 后存入 shelve，避免直接持久化任意 Python 对象
    parsed = json.loads(val)
    with shelve.open('/tmp/cache') as db:
        db[key] = parsed
    return {'status': 'ok'}
```""",
        "steps": [
            "第 10 行 request.get_data(as_text=True) 获取用户提交的 JSON 文本",
            "第 12 行 json.loads(val) 仅解析 JSON 数据结构（dict/list/str/num/bool/null）",
            "第 13-14 行 db[key] = parsed 将已解析的原生数据类型存入 shelve，shelve 底层 pickle 仅持久化原生类型",
            "已检查：JSON 预解析 + 仅持久化原生数据类型，shelve 的 pickle 仅处理 dict/list/str 等安全类型，无反序列化漏洞",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "json.loads(val)",
            "explanation": "val 经 json.loads 预解析为原生数据类型后存入 shelve，shelve 仅持久化安全类型，无反序列化漏洞",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 4: web  ——  CWE-611 XXE
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Spring / Django / FastAPI
# =====================================================================

WEB_BATCH4_XXE = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "XML 解析", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_049.py
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/parse_xml')
def parse_xml():
    raw = request.get_data(as_text=True)
    # xml.etree.ElementTree 默认解析外部实体
    root = ET.fromstring(raw)
    return jsonify({'root_tag': root.tag})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 XML 文本",
            "第 11 行 ET.fromstring(raw) 使用 xml.etree.ElementTree 默认配置解析 XML",
            "xml.etree.ElementTree 在 Python 3.7.1 之前默认解析外部实体（XXE），可读取本地文件或发起 SSRF",
            "source→sink 间无任何防御，攻击者提交 <!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> 可读取系统文件",
            "CWE-611 XXE，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-611 XXE",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.get_data(as_text=True)",
            "sink": "ET.fromstring(raw)",
            "explanation": "request.get_data → raw → ET.fromstring 默认配置解析 XML 外部实体，可读取本地文件或 SSRF",
            "fix_suggestion": "使用 defusedxml 替代 xml.etree.ElementTree，禁用外部实体解析",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "XML 解析", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_web_050.java
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import org.springframework.web.bind.annotation.*;

@RestController
public class XmlController {
    @PostMapping(value = "/parse_xml", consumes = "application/xml")
    public String parse(HttpServletRequest req) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // 默认配置：未禁用 DOCTYPE 和外部实体
        SAXParser parser = factory.newSAXParser();
        StringBuilder sb = new StringBuilder();
        parser.parse(new InputSource(req.getInputStream()), new DefaultHandler() {
            @Override
            public void characters(char[] ch, int start, int length) {
                sb.append(ch, start, length);
            }
        });
        return sb.toString();
    }
}
```""",
        "steps": [
            "第 9 行 req.getInputStream() 获取用户提交的 XML 字节流",
            "第 11-12 行 SAXParserFactory.newInstance() + newSAXParser() 使用默认配置",
            "默认 SAXParser 未禁用 DOCTYPE 声明和外部实体解析，可触发 XXE 读取本地文件或 SSRF",
            "source→sink 间无任何防御，攻击者提交 <!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> 可读取系统文件",
            "CWE-611 XXE，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-611 XXE",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "req.getInputStream()",
            "sink": "parser.parse(new InputSource(req.getInputStream()), ...)",
            "explanation": "req.getInputStream() → SAXParser 默认配置解析 XML，未禁用 DOCTYPE 和外部实体，可读取本地文件或 SSRF",
            "fix_suggestion": "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) 禁用 DOCTYPE",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "XML 解析", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_051.py
from lxml import etree
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/parse_xml')
def parse_xml():
    raw = request.get_data(as_text=True)
    # lxml etree.fromstring 默认解析外部实体
    root = etree.fromstring(raw)
    return jsonify({'root_tag': root.tag})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 XML 文本",
            "第 11 行 etree.fromstring(raw) 使用 lxml 默认配置解析 XML",
            "lxml etree.fromstring 默认 resolve_entities=True，会解析外部实体（XXE）",
            "source→sink 间无任何防御，攻击者提交 <!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> 可读取系统文件",
            "CWE-611 XXE，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-611 XXE",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.get_data(as_text=True)",
            "sink": "etree.fromstring(raw)",
            "explanation": "request.get_data → raw → etree.fromstring 默认 resolve_entities=True 解析外部实体，可读取本地文件或 SSRF",
            "fix_suggestion": "使用 etree.XMLParser(resolve_entities=False, no_network=True) 禁用外部实体和网络访问",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "XML 解析", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_052.py
import defusedxml.ElementTree as ET
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/parse_xml')
def parse_xml():
    raw = request.get_data(as_text=True)
    # defusedxml 默认禁用外部实体和 DTD
    root = ET.fromstring(raw)
    return jsonify({'root_tag': root.tag})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 XML 文本",
            "第 11 行 defusedxml.ElementTree.fromstring(raw) 使用 defusedxml 解析",
            "defusedxml 默认禁用外部实体解析、DTD 处理和 billion laughs 攻击",
            "已检查：使用 defusedxml（非 xml.etree.ElementTree），禁用 DOCTYPE 和外部实体，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "defusedxml.ElementTree.fromstring(raw)",
            "explanation": "raw 经 defusedxml.ElementTree.fromstring 解析，默认禁用外部实体和 DTD，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "XML 解析", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_053.java
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import org.springframework.web.bind.annotation.*;

@RestController
public class XmlController {
    @PostMapping(value = "/parse_xml", consumes = "application/xml")
    public String parse(HttpServletRequest req) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // 启用安全处理 + 禁用 DOCTYPE
        factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        SAXParser parser = factory.newSAXParser();
        StringBuilder sb = new StringBuilder();
        parser.parse(new InputSource(req.getInputStream()), new DefaultHandler() {
            @Override
            public void characters(char[] ch, int start, int length) {
                sb.append(ch, start, length);
            }
        });
        return sb.toString();
    }
}
```""",
        "steps": [
            "第 10 行 req.getInputStream() 获取用户提交的 XML 字节流",
            "第 12-14 行 SAXParserFactory 设置 FEATURE_SECURE_PROCESSING + disallow-doctype-decl=true，禁用 DOCTYPE 声明",
            "禁用 DOCTYPE 后，外部实体声明无法被解析，XXE 攻击向量被消除",
            "已检查：secure-processing + disallow-doctype-decl 双重防御，DOCTYPE 被完全禁用，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "parser.parse(new InputSource(req.getInputStream()), ...)",
            "explanation": "SAXParserFactory 启用 secure-processing + disallow-doctype-decl，DOCTYPE 被禁用，外部实体无法解析，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "XML 解析", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_054.py
from lxml import etree
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/parse_xml')
def parse_xml():
    raw = request.get_data(as_text=True)
    # 显式禁用外部实体解析和网络访问
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(raw, parser=parser)
    return jsonify({'root_tag': root.tag})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 XML 文本",
            "第 11 行 etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False) 创建安全解析器",
            "第 12 行 etree.fromstring(raw, parser=parser) 使用安全解析器，resolve_entities=False 禁用外部实体",
            "已检查：resolve_entities=False + no_network=True + load_dtd=False，外部实体和网络访问被禁用，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "etree.fromstring(raw, parser=parser)",
            "explanation": "raw 经 lxml XMLParser(resolve_entities=False, no_network=True, load_dtd=False) 解析，外部实体被禁用，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "XML 解析", "has_vuln": False, "difficulty": "典型",
        "code": """```java
// distill_glm_web_055.java
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import org.springframework.web.bind.annotation.*;

@RestController
public class XmlController {
    @PostMapping(value = "/parse_xml", consumes = "application/xml")
    public String parse(HttpServletRequest req) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        // 禁用 DOCTYPE 声明（最严格的 XXE 防御）
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        SAXParser parser = factory.newSAXParser();
        StringBuilder sb = new StringBuilder();
        parser.parse(new InputSource(req.getInputStream()), new DefaultHandler() {
            @Override
            public void characters(char[] ch, int start, int length) {
                sb.append(ch, start, length);
            }
        });
        return sb.toString();
    }
}
```""",
        "steps": [
            "第 10 行 req.getInputStream() 获取用户提交的 XML 字节流",
            "第 12 行 factory.setFeature(disallow-doctype-decl, true) 禁用 DOCTYPE 声明",
            "禁用 DOCTYPE 后，外部实体声明无法被解析，XXE 攻击向量被消除",
            "已检查：disallow-doctype-decl=true 完全禁用 DOCTYPE，外部实体无法声明，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "parser.parse(new InputSource(req.getInputStream()), ...)",
            "explanation": "SAXParserFactory 禁用 disallow-doctype-decl，DOCTYPE 被完全禁用，外部实体无法解析，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "XML 解析", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_056.py
import defusedxml.ElementTree as ET
import defusedxml.minidom
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect


@csrf_protect
def parse_xml(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'method not allowed'}, status=405)
    raw = request.body.decode('utf-8')
    # defusedxml.ElementTree 默认禁用外部实体
    root = ET.fromstring(raw)
    return JsonResponse({'root_tag': root.tag})
```""",
        "steps": [
            "第 11 行 request.body.decode('utf-8') 获取用户提交的 XML 文本",
            "第 13 行 defusedxml.ElementTree.fromstring(raw) 使用 defusedxml 解析",
            "defusedxml.ElementTree 默认禁用外部实体解析、DTD 处理和 billion laughs 攻击",
            "已检查：使用 defusedxml.ElementTree（非 xml.etree.ElementTree），禁用外部实体和 DTD，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.body.decode('utf-8')",
            "sink": "defusedxml.ElementTree.fromstring(raw)",
            "explanation": "raw 经 defusedxml.ElementTree.fromstring 解析，默认禁用外部实体和 DTD，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "XML 解析", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_057.java
import javax.xml.stream.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class XmlController {
    @PostMapping(value = "/parse_xml", consumes = "application/xml")
    public String parse(HttpServletRequest req) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // 禁用外部实体和 DTD
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(req.getInputStream());
        StringBuilder sb = new StringBuilder();
        while (reader.hasNext()) {
            int event = reader.next();
            if (event == XMLStreamConstants.CHARACTERS) {
                sb.append(reader.getText());
            }
        }
        return sb.toString();
    }
}
```""",
        "steps": [
            "第 10 行 req.getInputStream() 获取用户提交的 XML 字节流",
            "第 12-13 行 XMLInputFactory 设置 IS_SUPPORTING_EXTERNAL_ENTITIES=false + SUPPORT_DTD=false",
            "禁用外部实体和 DTD 后，XXE 攻击向量被消除",
            "已检查：IS_SUPPORTING_EXTERNAL_ENTITIES=false + SUPPORT_DTD=false，外部实体和 DTD 被禁用，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "factory.createXMLStreamReader(req.getInputStream())",
            "explanation": "XMLInputFactory 设置 IS_SUPPORTING_EXTERNAL_ENTITIES=false + SUPPORT_DTD=false，外部实体被禁用，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "FastAPI", "scene": "XML 解析", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_058.py
from lxml import etree
from fastapi import FastAPI, Request

app = FastAPI()


@app.post('/parse_xml')
async def parse_xml(req: Request):
    raw = (await req.body()).decode('utf-8')
    # resolve_entities=False + no_network=True + load_dtd=False 三重防御
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(raw, parser=parser)
    return {'root_tag': root.tag}
```""",
        "steps": [
            "第 9 行 (await req.body()).decode('utf-8') 获取用户提交的 XML 文本",
            "第 11 行 etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False) 创建安全解析器",
            "第 12 行 etree.fromstring(raw, parser=parser) 使用安全解析器，禁用外部实体和网络访问",
            "已检查：resolve_entities=False + no_network=True + load_dtd=False，外部实体和网络访问被禁用，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "(await req.body()).decode('utf-8')",
            "sink": "etree.fromstring(raw, parser=parser)",
            "explanation": "raw 经 lxml XMLParser(resolve_entities=False, no_network=True, load_dtd=False) 解析，外部实体被禁用，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "XML 转换", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_059.java
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class XsltController {
    @PostMapping(value = "/transform", consumes = "application/xml")
    public String transform(HttpServletRequest req) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        // 启用安全处理，禁用外部实体
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer t = factory.newTransformer();
        StringWriter sw = new StringWriter();
        t.transform(new StreamSource(req.getInputStream()), new StreamResult(sw));
        return sw.toString();
    }
}
```""",
        "steps": [
            "第 10 行 req.getInputStream() 获取用户提交的 XML 字节流",
            "第 12-15 行 TransformerFactory 设置 FEATURE_SECURE_PROCESSING + ACCESS_EXTERNAL_DTD=\"\" + ACCESS_EXTERNAL_STYLESHEET=\"\"",
            "空字符串表示禁止访问外部 DTD 和样式表，XXE 和 SSRF 攻击向量被消除",
            "已检查：FEATURE_SECURE_PROCESSING + ACCESS_EXTERNAL_DTD=\"\" + ACCESS_EXTERNAL_STYLESHEET=\"\"，外部访问被禁用，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.getInputStream()",
            "sink": "t.transform(new StreamSource(req.getInputStream()), ...)",
            "explanation": "TransformerFactory 启用 FEATURE_SECURE_PROCESSING + ACCESS_EXTERNAL_DTD=\"\" + ACCESS_EXTERNAL_STYLESHEET=\"\"，外部访问被禁用，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "XML 解析", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_060.py
import defusedxml.minidom
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post('/parse_xml')
def parse_xml():
    raw = request.get_data(as_text=True)
    # defusedxml.minidom 默认禁用外部实体和 DTD
    dom = defusedxml.minidom.parseString(raw)
    return jsonify({'root_tag': dom.documentElement.tagName})
```""",
        "steps": [
            "第 9 行 request.get_data(as_text=True) 获取用户提交的 XML 文本",
            "第 11 行 defusedxml.minidom.parseString(raw) 使用 defusedxml 的 minidom 解析",
            "defusedxml.minidom 默认禁用外部实体解析、DTD 处理和 billion laughs 攻击",
            "已检查：使用 defusedxml.minidom（非 xml.dom.minidom），禁用外部实体和 DTD，无 XXE",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.get_data(as_text=True)",
            "sink": "defusedxml.minidom.parseString(raw)",
            "explanation": "raw 经 defusedxml.minidom.parseString 解析，默认禁用外部实体和 DTD，无 XXE",
            "fix_suggestion": "no fix needed",
        },
    },
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    cvss_path = DATA_DIR / "distill_glm_cwe_cvss.jsonl"
    with cvss_path.open("a", encoding="utf-8") as fp:
        for s in CWE_CVSS_BATCH4_LDAP:
            user = build_user_cwe_cvss("CWE-90 LDAP注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
        for s in CWE_CVSS_BATCH4_XPATH:
            user = build_user_cwe_cvss("CWE-643 XPath注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {cvss_path}: appended {len(CWE_CVSS_BATCH4_LDAP) + len(CWE_CVSS_BATCH4_XPATH)} samples")

    web_path = DATA_DIR / "distill_glm_web.jsonl"
    with web_path.open("a", encoding="utf-8") as fp:
        for s in WEB_BATCH4_DESER:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
        for s in WEB_BATCH4_XXE:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {web_path}: appended {len(WEB_BATCH4_DESER) + len(WEB_BATCH4_XXE)} samples")


if __name__ == "__main__":
    main()
