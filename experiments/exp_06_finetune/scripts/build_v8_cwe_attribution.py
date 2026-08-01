#!/usr/bin/env python3
"""
构建 v8 CWE 归因改进训练数据。

背景：
  v7 模型在 87 合成测试集上 recall 达 0.967，但 strict_accuracy 仅 0.728——
  即 27% 的检测因 CWE 编号错误而误导用户。v8 必须提升 CWE 归因准确性。

策略：
  以 train_chatml_v7_realworld.jsonl（799 条）为基底，新增 24 条「对比 CoT」样本：
    A. 注入混淆判别（5 条）：XPath / NoSQL(Node) / NoSQL(Py) / LDAP / Header
    B. 认证与访问控制混淆（4 条）：IDOR / 缺失授权 / 缺失认证 / Session Fixation
    C. 密码学混淆（3 条）：硬编码 IV / JWT none / 弱算法 MD5
    D. 模板与表达式注入混淆（4 条）：SSTI Jinja2 / SSTI Twig / SpEL / OGNL
    E. 其他高频误判 CWE（8 条）：Race / Mass Assignment / 原型链污染 / 类型混淆 /
       时序攻击 / YAML 反序列化 / 信息泄露 / CSRF

关键创新：
  每条样本 CoT 包含「对比 CoT」段，显式写出「为什么不是 CWE-Y？因为...」，
  教模型在易混 CWE 之间做出正确判别。

用法：
    PYTHONPATH=../../.. python3 build_v8_cwe_attribution.py
输出：
    experiments/exp_06_finetune/data/train_chatml_v8_cwe_attribution.jsonl
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "experiments/exp_06_finetune/data"
V7_FILE = DATA_DIR / "train_chatml_v7_realworld.jsonl"
OUT_FILE = DATA_DIR / "train_chatml_v8_cwe_attribution.jsonl"

SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，判断其中是否存在安全漏洞。"
    "分析范围包括但不限于：SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、硬编码敏感信息"
    "（密钥/密码/Token）、不安全的反序列化、日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、SSTI、XXE、开放重定向、"
    "LDAP 注入（CWE-90）、信任边界绕过（CWE-441）、整数溢出（CWE-190）、缺失认证/授权、"
    "XPath 注入（CWE-643）、NoSQL 注入（CWE-943）、IDOR（CWE-639）、Session Fixation（CWE-384）、"
    "硬编码 IV（CWE-329）、JWT 签名缺陷（CWE-347）、竞态条件（CWE-362）、Mass Assignment（CWE-915）、"
    "原型链污染（CWE-1321）、OGNL 注入（CWE-917）、SpEL 注入（CWE-94）、类型混淆（CWE-843）、"
    "时序攻击（CWE-208）、HTTP 头注入（CWE-113）、信息泄露（CWE-200）等。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，不要降级为「敏感但非漏洞」。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。\n"
    "7. 【强制】vulnerability_type 必须以 CWE-XXX 编号开头，如「CWE-89 SQL注入」；"
    "禁止只写漏洞名不写编号；多 CWE 用分号分隔如「CWE-1336; CWE-94 SSTI模板注入」。\n"
    "8. CWE 归因判别（按 sink 类型与漏洞本质区分，禁止混淆）：\n"
    "   - 注入类按 sink 区分：SQL execute → CWE-89；shell/os.system → CWE-78；"
    "eval/exec → CWE-95/94；LDAP search → CWE-90；template render → CWE-1336/CWE-94；"
    "XPath evaluate → CWE-643；NoSQL find → CWE-943；HTTP header → CWE-113；"
    "OGNL → CWE-917；SpEL parseExpression → CWE-94。\n"
    "   - 访问控制类按缺陷本质区分：IDOR/越权访问 → CWE-639；缺失授权（有认证无授权）→ CWE-862；"
    "缺失认证（无认证机制）→ CWE-306；信任源误判 → CWE-441；Session Fixation → CWE-384。\n"
    "   - 密码学类按缺陷区分：硬编码 IV → CWE-329；JWT 签名验证不严 → CWE-347；"
    "弱算法 MD5/SHA1 → CWE-327；硬编码凭证 → CWE-798；弱随机数 → CWE-330。\n"
    "   - 并发与逻辑类：Race Condition/TOCTOU → CWE-362；Mass Assignment → CWE-915；"
    "原型链污染 → CWE-1321；PHP 类型混淆（strcmp null == 0）→ CWE-843；"
    "时序攻击（== 比较密钥）→ CWE-208。\n"
    "   - 其他常见类：信任边界绕过 → CWE-441；反序列化 → CWE-502；XXE → CWE-611；"
    "SSRF → CWE-918；信息泄露 → CWE-200；开放重定向 → CWE-601；路径穿越 → CWE-22；"
    "XSS → CWE-79；CSRF → CWE-352；日志注入 → CWE-117。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "   - has_vulnerability: bool, true 表示存在漏洞，false 表示未发现漏洞\n"
    "   - vulnerability_type: str, 单个字符串（禁止拆成多个逗号分隔的值），必须以 CWE-XXX 编号开头，"
    "格式如「CWE-89 SQL注入」；多 CWE 用分号分隔如「CWE-1336; CWE-94 SSTI模板注入」；无漏洞填「none」\n"
    "   - risk_level: str, Critical/High/Medium/Low；无漏洞填「None」\n"
    "   - source: str, 污染来源（用户可控输入点）；无漏洞填「N/A」\n"
    "   - sink: str, 危险函数或触发点；无漏洞填「N/A」\n"
    "   - explanation: str, 漏洞或安全现状说明\n"
    "   - fix_suggestion: str, 修复建议；无漏洞填「no fix needed」\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


def build_sample(code: str, language: str, filename: str, cot: str, json_block: str) -> dict:
    """构建一条 ChatML 训练样本。"""
    user_prompt = (
        f"请分析以下代码片段是否存在安全漏洞。\n\n"
        f"语言：{language}\n文件名：{filename}\n\n```\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
    )
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": cot + "\n\n```json\n" + json_block + "\n```"},
        ]
    }


def vuln_json(cwe: str, name: str, risk: str, source: str, sink: str,
              explanation: str, fix: str) -> str:
    return json.dumps({
        "has_vulnerability": True,
        "vulnerability_type": f"{cwe} {name}",
        "risk_level": risk,
        "source": source,
        "sink": sink,
        "explanation": explanation,
        "fix_suggestion": fix,
    }, ensure_ascii=False, indent=2)


def safe_json(explanation: str) -> str:
    return json.dumps({
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": explanation,
        "fix_suggestion": "no fix needed",
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# A. 注入混淆判别（5 条）
# ===========================================================================
# 关键教学点：注入类漏洞按 sink 类型区分，不要见到查询就判 CWE-89

INJECTION_SAMPLES = []

# A1: XPath 注入（Python lxml）— 对比 CWE-89
INJECTION_SAMPLES.append(build_sample(
    code='''from lxml import etree
from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    user = request.args.get("user", "")
    tree = etree.parse("users.xml")
    # 用户输入直接拼接到 XPath 表达式
    expr = "//user[name='" + user + "']"
    results = tree.xpath(expr)
    return {"count": len(results)}
''',
    language="python", filename="xpath_inject_01_lxml.py",
    cot="分析过程：\n"
        "1. 用户可控输入：user 来自 request.args。\n"
        "2. 危险 sink：tree.xpath(expr)，expr = //user[name=' + user + '] 直接拼接。\n"
        "3. 防御检查：无转义。user 中的 ' 可闭合 XPath 字符串，'] | //user 可枚举全部用户。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为 sink 是 lxml tree.xpath 而非 SQL execute，"
        "注入目标是 XPath 表达式而非 SQL 语句，故为 CWE-643 XPath 注入。\n"
        "5. 综合来看，存在 XPath 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-643", "XPath注入", "High",
        source="request.args.get('user')",
        sink="tree.xpath(expr) 其中 expr 拼接 user",
        explanation="user 直接拼接到 XPath 表达式，' 可闭合字符串注入任意 XPath 查询枚举用户",
        fix="用参数化 XPath 或对 user 中的 ' 进行转义（替换为 &apos;）；用 lxml.etree.xpath 的变量绑定"
    )
))

# A2: NoSQL 注入（Node.js MongoDB）— 对比 CWE-89
INJECTION_SAMPLES.append(build_sample(
    code='''const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const app = express();
app.use(express.json());

app.post('/find', async (req, res) => {
    const user = req.body.user;
    const client = await MongoClient.connect('mongodb://localhost:27017');
    const db = client.db('app');
    // 用户输入直接作为查询条件，可注入 { $ne: null }
    const results = await db.collection('users').find({ user: user }).toArray();
    res.json(results);
});
app.listen(3000);
''',
    language="javascript", filename="nosql_inject_01_mongo.js",
    cot="分析过程：\n"
        "1. 用户可控输入：user 来自 req.body（JSON），类型未校验。\n"
        "2. 危险 sink：db.collection.find({ user: user })，user 可为对象而非字符串。\n"
        "3. 防御检查：无类型校验。攻击者发送 user={\"$ne\":null} 匹配所有用户，绕过查询限制。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为 sink 是 MongoDB find 而非 SQL execute，"
        "注入载体是 NoSQL 查询操作符（$ne/$gt/$regex）而非 SQL 语法，故为 CWE-943 NoSQL 注入。\n"
        "5. 综合来看，存在 NoSQL 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-943", "NoSQL注入", "High",
        source="req.body.user（JSON，类型未校验）",
        sink="db.collection.find({ user: user })",
        explanation="user 可为对象注入 $ne 等操作符，匹配所有用户绕过查询限制",
        fix="校验 typeof user === 'string'；用 mongo-sanitize 过滤 $ 开头的键；或显式构造查询对象"
    )
))

# A3: NoSQL 注入（Python PyMongo）— 对比 CWE-89
INJECTION_SAMPLES.append(build_sample(
    code='''from flask import Flask, request
from pymongo import MongoClient
app = Flask(__name__)

@app.route("/find", methods=["POST"])
def find():
    # 直接接受 JSON body 作为查询条件
    query = request.get_json()
    client = MongoClient("mongodb://localhost:27017")
    db = client.app
    # 用户可注入 {"user": {"$ne": null}} 匹配所有用户
    results = list(db.users.find(query))
    return {"count": len(results)}
''',
    language="python", filename="nosql_inject_02_pymongo.py",
    cot="分析过程：\n"
        "1. 用户可控输入：整个 JSON body 作为 query，无任何字段白名单或类型校验。\n"
        "2. 危险 sink：db.users.find(query)，query 完全用户可控。\n"
        "3. 攻击路径：发送 {\"password\":{\"$gt\":\"\"}} 可匹配所有有密码的用户，绕过认证查询。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为 sink 是 PyMongo find 而非 SQL execute，"
        "注入载体是 MongoDB 查询操作符而非 SQL 语法，故为 CWE-943 NoSQL 注入。\n"
        "5. 综合来看，存在 NoSQL 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-943", "NoSQL注入", "High",
        source="request.get_json()（整个 body 作为查询条件）",
        sink="db.users.find(query)",
        explanation="整个 JSON body 直接作为 MongoDB 查询条件，可注入 $ne/$gt 等操作符绕过查询限制",
        fix="白名单提取查询字段并强制类型校验；用 mongosanitize 或手动过滤 $ 开头的键"
    )
))

# A4: LDAP 注入（Java Servlet）— 对比 CWE-89 和 CWE-78
INJECTION_SAMPLES.append(build_sample(
    code='''import javax.naming.*;
import javax.naming.directory.*;
import javax.servlet.http.*;

public class UserSearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws Exception {
        String username = req.getParameter("user");
        InitialDirContext ctx = new InitialDirContext();
        // filter 直接拼接用户输入，未转义
        String filter = "(uid=" + username + ")";
        SearchControls ctrls = new SearchControls();
        ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> results = ctx.search(
            "ldap://corp.local:389/ou=users,dc=corp,dc=local", filter, ctrls);
        resp.getWriter().println("found: " + results.hasMore());
    }
}
''',
    language="java", filename="ldap_inject_01_servlet.java",
    cot="分析过程：\n"
        "1. 用户可控输入：username 来自 req.getParameter（HTTP 请求）。\n"
        "2. 危险 sink：ctx.search(filter)，filter = (uid= + username + ) 直接拼接。\n"
        "3. 防御检查：无转义。username 中的 *)(uid=* 可使 filter 匹配所有用户绕过查询限制。\n"
        "4. 对比 CoT：为什么不是 CWE-89？因为 sink 是 LDAP search 而非 SQL execute，"
        "注入目标是 LDAP filter 语法而非 SQL 语句；为什么不是 CWE-78？因为不是 shell 命令，"
        "ctx.search 是目录服务查询不是 os.system。故为 CWE-90 LDAP 注入。\n"
        "5. 综合来看，存在 LDAP 注入漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-90", "LDAP注入", "High",
        source="req.getParameter('user')",
        sink="ctx.search(filter) 其中 filter 拼接 username",
        explanation="username 直接拼接到 LDAP filter，* ( ) 等可改变 filter 结构绕过查询限制",
        fix="用 LdapEncoder.escapeForSearchFilter(username) 转义后再拼接 filter"
    )
))

# A5: HTTP 头注入（PHP header）— 对比 CWE-79
INJECTION_SAMPLES.append(build_sample(
    code='''<?php
function do_redirect($url) {
    // 用户输入直接传给 header()，可注入 \\r\\n 设置任意响应头
    header("Location: " . $url);
    exit;
}

if (isset($_GET['url'])) {
    do_redirect($_GET['url']);
}
?>
''',
    language="php", filename="header_inject_01_php.php",
    cot="分析过程：\n"
        "1. 用户可控输入：$_GET['url']。\n"
        "2. 危险 sink：header('Location: ' . $url)，url 直接拼接到 HTTP 响应头。\n"
        "3. 防御检查：无 \\r\\n 过滤。攻击者注入 url=xxx%0d%0aSet-Cookie:evil=1 可设置任意响应头。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为 sink 是 HTTP header 而非 HTML body，"
        "注入载体是 CRLF（\\r\\n）分隔的响应头字段而非 HTML 标签，"
        "攻击发生在 HTTP 响应头层而非浏览器 DOM 层，故为 CWE-113 HTTP 头注入。\n"
        "5. 综合来看，存在 HTTP 头注入漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-113", "HTTP头注入", "Medium",
        source="$_GET['url']",
        sink="header('Location: ' . $url)",
        explanation="url 直接拼接到 HTTP 响应头，\\r\\n 可注入任意响应头（如 Set-Cookie）实现会话固定或 XSS",
        fix="用 header('Location: ' . $url, true, 302) 并过滤 url 中的 \\r\\n 字符；或校验 url 为相对路径"
    )
))


# ===========================================================================
# B. 认证与访问控制混淆（4 条）
# ===========================================================================
# 关键教学点：区分 CWE-639 / CWE-862 / CWE-306 / CWE-384 的边界

AUTH_SAMPLES = []

# B1: IDOR（Python Flask）— 对比 CWE-79
AUTH_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    if "user_id" not in session:
        return "unauthorized", 401
    # 未校验 order 是否属于当前用户，可越权访问他人订单
    order = db.execute(
        "SELECT * FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    return dict(order)
''',
    language="python", filename="idor_01_flask.py",
    cot="分析过程：\n"
        "1. 用户可控输入：order_id 来自 URL 路径参数。\n"
        "2. 访问控制分析：检查了 session.user_id（认证），但未校验该 order 是否属于当前用户。\n"
        "3. 攻击路径：用户 A 登录后访问 /api/orders/2 可查看用户 B 的订单，水平越权。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为问题不是 HTML 输出未转义，"
        "而是水平越权访问他人资源——SQL 用了参数化无注入，缺陷在授权逻辑缺失，故为 CWE-639 IDOR。\n"
        "5. 综合来看，存在 IDOR 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-639", "IDOR越权访问", "High",
        source="URL 路径参数 order_id",
        sink="db.execute 查询 orders 表未校验 owner",
        explanation="查询订单时未校验 order 是否属于当前 session 用户，可遍历 ID 访问他人订单",
        fix="SQL 加 AND user_id = ? 条件：SELECT * FROM orders WHERE id = ? AND user_id = ?"
    )
))

# B2: 缺失授权（Python Flask）— 对比 CWE-798
AUTH_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/admin/users/delete", methods=["POST"])
def delete_user():
    # 有认证但无授权检查——任何登录用户都能删除
    if "user_id" not in session:
        return "unauthorized", 401
    uid = request.form.get("uid")
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    return "deleted"
''',
    language="python", filename="missing_authz_01_flask.py",
    cot="分析过程：\n"
        "1. 访问控制分析：检查了 session.user_id（认证存在），但未检查用户是否为 admin。\n"
        "2. 攻击路径：任意登录用户（含普通用户）可调用 /admin/users/delete 删除任意账户。\n"
        "3. 防御缺失：缺少 @require_admin 装饰器或 role 校验。\n"
        "4. 对比 CoT：为什么不是 CWE-798？因为没有硬编码凭证，secret_key 来自环境变量无泄露，"
        "问题是认证通过后缺少授权检查（有认证无授权），故为 CWE-862 缺失授权而非 CWE-798。\n"
        "5. 综合来看，存在缺失授权漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-862", "缺失授权", "High",
        source="session.user_id（任意登录用户）",
        sink="db.execute DELETE FROM users 未校验 admin 角色",
        explanation="有认证但无授权检查，任意登录用户可调用管理员端点删除用户",
        fix="加 @require_admin 装饰器或 if session.get('role') != 'admin': return 403"
    )
))

# B3: 缺失认证（Node.js Express）— 对比 CWE-862
AUTH_SAMPLES.append(build_sample(
    code='''const express = require('express');
const app = express();
app.use(express.json());

// 管理端点完全没有任何认证机制
app.post('/admin/shutdown', (req, res) => {
    shutdownServer();
    res.json({ status: 'shutting down' });
});

app.post('/admin/config', (req, res) => {
    const newConfig = req.body;
    updateConfig(newConfig);
    res.json({ status: 'updated' });
});

app.listen(3000);
''',
    language="javascript", filename="missing_authn_01_express.js",
    cot="分析过程：\n"
        "1. 访问控制分析：/admin/* 端点没有任何认证或授权检查，任何人可直接访问。\n"
        "2. 攻击路径：攻击者直接 POST /admin/shutdown 即可关闭服务器，无需任何凭证。\n"
        "3. 防御缺失：完全没有认证中间件（无 token、无 session、无 basic auth）。\n"
        "4. 对比 CoT：为什么不是 CWE-862？因为 CWE-862 是有认证但授权不严，"
        "本例是完全没有认证机制（连登录都没有），属于更根本的缺陷，故为 CWE-306 缺失认证。\n"
        "5. 综合来看，存在缺失认证漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-306", "缺失认证", "Critical",
        source="公网请求直接访问 /admin/* 端点",
        sink="/admin/shutdown 和 /admin/config 端点无认证",
        explanation="管理端点完全没有认证机制，任何人可直接关闭服务器或修改配置",
        fix="加认证中间件：app.use('/admin/*', requireAuth); 校验 JWT token 或 session"
    )
))

# B4: Session Fixation（Python Flask）— 对比 CWE-200
AUTH_SAMPLES.append(build_sample(
    code='''import os
from flask import Flask, request, session
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    pwd = request.form.get("pwd")
    if check_credentials(user, pwd):
        # 登录成功后未重新生成 session id
        session["user"] = user
        return "logged in"
    return "denied", 401
''',
    language="python", filename="session_fixation_01_flask.py",
    cot="分析过程：\n"
        "1. 认证流程：用户提交 user/pwd，check_credentials 通过后设置 session。\n"
        "2. 缺陷识别：登录成功后未调用 session.regenerate() 或清旧 session id，"
        "攻击者可预设 session id 诱导受害者登录后用同一 id 劫持会话。\n"
        "3. 防御检查：secret_key 来自环境变量（无硬编码），但缺少登录后 session 重新生成。\n"
        "4. 对比 CoT：为什么不是 CWE-200？因为问题不是信息泄露（不涉及返回敏感数据），"
        "而是登录后不更换 session ID 导致会话固定攻击，属于会话管理缺陷，故为 CWE-384 Session Fixation。\n"
        "5. 综合来看，存在 Session Fixation 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-384", "Session Fixation", "High",
        source="攻击者预设的 session id",
        sink="登录后 session['user']=user 未重新生成 session id",
        explanation="登录成功后未重新生成 session id，攻击者可预设 id 诱导受害者登录后劫持会话",
        fix="登录成功后 session.clear() 并重新生成 session id；Flask 用 session.regenerate() 或自定义"
    )
))


# ===========================================================================
# C. 密码学混淆（3 条）
# ===========================================================================
# 关键教学点：区分 CWE-329 / CWE-347 / CWE-327 / CWE-798 / CWE-200 的边界

CRYPTO_SAMPLES = []

# C1: 硬编码 IV（Python cryptography）— 对比 CWE-200
CRYPTO_SAMPLES.append(build_sample(
    code='''import os
from flask import request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

@app.route("/encrypt")
def encrypt():
    plaintext = request.args.get("data", "")
    key = os.environ["AES_KEY"].encode()
    # 硬编码 IV，每次加密用同一 IV
    iv = b"0123456789abcdef"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ct.hex()
''',
    language="python", filename="hardcoded_iv_01_aes.py",
    cot="分析过程：\n"
        "1. 密码学分析：AES-CBC 加密，key 来自环境变量（无硬编码），但 iv = b'0123456789abcdef' 硬编码。\n"
        "2. 缺陷：固定 IV 使相同明文产生相同密文，攻击者可识别重复明文模式，泄露信息。\n"
        "3. 防御检查：CBC 模式要求 IV 不可预测且唯一，当前 IV 固定不满足。\n"
        "4. 对比 CoT：为什么不是 CWE-200？因为固定 IV 导致密文可预测，"
        "是密码学缺陷（IV 未随机化）而非信息泄露（不涉及直接返回敏感数据），故为 CWE-329 硬编码 IV。\n"
        "5. 综合来看，存在硬编码 IV 漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-329", "硬编码IV", "Medium",
        source="硬编码的 iv = b'0123456789abcdef'",
        sink="Cipher(algorithms.AES(key), modes.CBC(iv))",
        explanation="AES-CBC 使用固定 IV，相同明文产生相同密文，泄露明文模式信息",
        fix="每次加密用 os.urandom(16) 生成随机 IV，并将 IV 与密文一起存储/传输"
    )
))

# C2: JWT none 算法（Node.js）— 对比 CWE-200
CRYPTO_SAMPLES.append(build_sample(
    code='''const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.get('/admin', (req, res) => {
    const auth = req.headers.authorization || '';
    const token = auth.split(' ')[1];
    try {
        // 未指定 algorithms 白名单，可能接受 alg: none
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        if (payload.role === 'admin') {
            return res.json({ data: 'admin panel' });
        }
        res.status(403).json({ error: 'forbidden' });
    } catch (e) {
        res.status(401).json({ error: 'invalid token' });
    }
});
app.listen(3000);
''',
    language="javascript", filename="jwt_none_01_node.js",
    cot="分析过程：\n"
        "1. 认证流程：从 Authorization 头取 JWT，jwt.verify 校验后检查 role 字段。\n"
        "2. 缺陷识别：jwt.verify 未指定 algorithms 参数（如 ['HS256']），"
        "jsonwebtoken 旧版本会接受 alg:none 的无签名 token。\n"
        "3. 攻击路径：攻击者构造 header={alg:none}, payload={role:admin} 的 token，"
        "verify 不校验签名直接信任 payload，绕过认证。\n"
        "4. 对比 CoT：为什么不是 CWE-200？因为问题是签名验证不严（接受 none 算法），"
        "不是信息泄露（不涉及返回敏感数据），属于签名验证缺陷，故为 CWE-347 JWT 签名验证不当。\n"
        "5. 综合来看，存在 JWT 签名验证缺陷，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-347", "JWT签名验证缺陷", "Critical",
        source="客户端构造的 alg:none JWT",
        sink="jwt.verify(token, secret) 未指定 algorithms 白名单",
        explanation="未限制 algorithms 白名单，攻击者可用 alg:none 构造无签名 token 伪造 admin 身份",
        fix="jwt.verify(token, secret, { algorithms: ['HS256'] }) 显式指定算法白名单"
    )
))

# C3: 弱算法 MD5（Java）— 对比 CWE-798
CRYPTO_SAMPLES.append(build_sample(
    code='''import java.security.MessageDigest;
import java.util.Base64;

public class PasswordStore {
    public String hashPassword(String raw) throws Exception {
        // 用 MD5 哈希密码（无 salt，无迭代）
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(raw.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(digest);
    }
}
''',
    language="java", filename="weak_crypto_01_md5.java",
    cot="分析过程：\n"
        "1. 密码学分析：用 MessageDigest.getInstance(\"MD5\") 哈希密码，无 salt、无迭代。\n"
        "2. 缺陷：MD5 已被破解（碰撞攻击），且速度快使暴力破解可行，无 salt 使彩虹表攻击有效。\n"
        "3. 防御检查：无 per-user salt、无慢哈希（如 bcrypt/Argon2）。\n"
        "4. 对比 CoT：为什么不是 CWE-798？因为没有硬编码凭证（rawPassword 来自用户输入），"
        "问题是用了已破解的 MD5 算法做密码哈希，属于弱密码学缺陷，故为 CWE-327 弱密码学。\n"
        "5. 综合来看，存在弱密码学漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-327", "弱密码学", "High",
        source="raw 参数（用户密码）",
        sink="MessageDigest.getInstance('MD5')",
        explanation="MD5 已破解且速度过快，无 salt 使彩虹表攻击可行，密码可被暴力破解",
        fix="改用 bcrypt/Argon2id（per-user salt + 适当 cost factor）；废弃 MD5 密码哈希"
    )
))


# ===========================================================================
# D. 模板与表达式注入混淆（4 条）
# ===========================================================================
# 关键教学点：区分 SSTI (CWE-1336/94) vs XSS (CWE-79) vs SSRF (CWE-918)

TEMPLATE_SAMPLES = []

# D1: SSTI Jinja2（Python）— 对比 CWE-79
TEMPLATE_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # 用户输入拼接进模板字符串后渲染
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
''',
    language="python", filename="ssti_01_jinja2.py",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 request.args。\n"
        "2. 危险 sink：render_template_string(template)，template 拼接了 name。\n"
        "3. 攻击路径：name={{config}} 泄露 Flask 配置；name={{''.__class__.__mro__[1].__subclasses__()}} 可 RCE。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为 sink 是 render_template_string 模板渲染，"
        "用户输入作为模板内容（含 {{ }} 语法）而非 HTML 输出，"
        "Jinja2 在服务端解析执行模板语法，可 RCE，比浏览器侧 XSS 更危险，故为 CWE-1336; CWE-94 SSTI。\n"
        "5. 综合来看，存在 SSTI 漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-1336; CWE-94", "SSTI模板注入", "Critical",
        source="request.args.get('name')",
        sink="render_template_string(template) 其中 template 拼接 name",
        explanation="name 拼接到模板字符串后由 Jinja2 渲染，{{ }} 语法可执行任意 Python 代码导致 RCE",
        fix="用 render_template 引用固定模板文件 + context 传入 name（Jinja2 自动转义）；禁止拼接用户输入到模板"
    )
))

# D2: SSTI Twig（PHP）— 对比 CWE-79
TEMPLATE_SAMPLES.append(build_sample(
    code='''<?php
require_once 'vendor/autoload.php';
use Twig\\Environment;
use Twig\\Loader\\FilesystemLoader;

$loader = new FilesystemLoader('/tmp/templates');
$twig = new Environment($loader);

$name = $_GET['name'];
// 用户输入直接作为模板内容渲染
$template = $twig->createTemplate("<h1>Hello " . $name . "</h1>");
echo $template->render([]);
?>
''',
    language="php", filename="ssti_02_twig.php",
    cot="分析过程：\n"
        "1. 用户可控输入：name 来自 $_GET。\n"
        "2. 危险 sink：twig.createTemplate(...).render()，模板内容拼接了 name。\n"
        "3. 攻击路径：name={{_self.env.registerUndefinedFilterCallback('exec')}} 可调用 PHP exec 实现 RCE。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为 sink 是 Twig render 模板渲染，"
        "用户输入作为模板内容（含 {{ }} 语法）而非 HTML 输出，"
        "Twig 在服务端解析执行模板语法，可 RCE，故为 CWE-1336; CWE-94 SSTI。\n"
        "5. 综合来看，存在 SSTI 漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-1336; CWE-94", "SSTI模板注入", "Critical",
        source="$_GET['name']",
        sink="twig->createTemplate(...)->render()",
        explanation="name 拼接到模板内容后由 Twig 渲染，{{ }} 语法可执行任意 PHP 代码导致 RCE",
        fix="用固定模板文件 $twig->render('hello.html', ['name' => $name])；Twig 自动转义 name"
    )
))

# D3: SpEL 注入（Java Spring）— 对比 CWE-918
TEMPLATE_SAMPLES.append(build_sample(
    code='''import org.springframework.expression.*;
import org.springframework.expression.spel.standard.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SpelController {
    @GetMapping("/eval")
    public String eval(@RequestParam String expr) {
        // 用户输入直接传给 SpEL 解析执行
        SpelExpressionParser parser = new SpelExpressionParser();
        Expression expression = parser.parseExpression(expr);
        Object result = expression.getValue();
        return String.valueOf(result);
    }
}
''',
    language="java", filename="spel_inject_01_spring.java",
    cot="分析过程：\n"
        "1. 用户可控输入：expr 来自 @RequestParam（HTTP 请求）。\n"
        "2. 危险 sink：parser.parseExpression(expr).getValue()，SpEL 表达式引擎直接执行用户输入。\n"
        "3. 攻击路径：expr=T(java.lang.Runtime).getRuntime().exec('id') 可执行任意系统命令 RCE。\n"
        "4. 对比 CoT：为什么不是 CWE-918 SSRF？因为 sink 是 SpEL parseExpression 表达式引擎，"
        "不是 HTTP 请求（如 HttpClient.execute(new URL(url))），"
        "注入目标是 Spring 表达式语言而非 HTTP 请求，故为 CWE-94 代码注入（SpEL）。\n"
        "5. 综合来看，存在 SpEL 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-94", "SpEL注入", "Critical",
        source="@RequestParam String expr",
        sink="parser.parseExpression(expr).getValue()",
        explanation="expr 直接传给 SpEL 表达式引擎执行，可调用 Runtime.exec 实现任意命令 RCE",
        fix="禁止用户输入直接进入 SpEL；用 SimpleEvaluationContext 限制功能；或用白名单校验表达式"
    )
))

# D4: OGNL 注入（Java）— 对比 CWE-918
TEMPLATE_SAMPLES.append(build_sample(
    code='''import ognl.Ognl;
import ognl.OgnlContext;
import org.springframework.web.bind.annotation.*;

@RestController
public class OgnlController {
    @GetMapping("/parse")
    public String parse(@RequestParam String expr) throws Exception {
        // 用户输入直接传给 OGNL 解析执行
        OgnlContext context = new OgnlContext();
        Object tree = Ognl.parseExpression(expr);
        Object result = Ognl.getValue(tree, context, new Object());
        return String.valueOf(result);
    }
}
''',
    language="java", filename="ognl_inject_01_struts.java",
    cot="分析过程：\n"
        "1. 用户可控输入：expr 来自 @RequestParam（HTTP 请求）。\n"
        "2. 危险 sink：Ognl.parseExpression(expr) + Ognl.getValue(tree, context, ...)，OGNL 表达式引擎执行用户输入。\n"
        "3. 攻击路径：expr=@java.lang.Runtime@getRuntime().exec('id') 可执行任意命令 RCE（Struts2 经典漏洞模式）。\n"
        "4. 对比 CoT：为什么不是 CWE-918 SSRF？因为 sink 是 OGNL 表达式引擎，"
        "不是 HTTP 请求（如 RestTemplate.getForObject(url)），"
        "注入目标是 OGNL 表达式语言而非 HTTP 请求，故为 CWE-917 OGNL 注入。\n"
        "5. 综合来看，存在 OGNL 注入漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-917", "OGNL注入", "Critical",
        source="@RequestParam String expr",
        sink="Ognl.parseExpression(expr) + Ognl.getValue(...)",
        explanation="expr 直接传给 OGNL 表达式引擎执行，可调用 Runtime.exec 实现任意命令 RCE",
        fix="禁止用户输入直接进入 OGNL；用 OgnlContext 设置严格权限；或用白名单校验表达式"
    )
))


# ===========================================================================
# E. 其他高频误判 CWE（8 条）
# ===========================================================================
# 关键教学点：区分 CWE-362 / CWE-915 / CWE-1321 / CWE-843 / CWE-208 /
#             CWE-502 / CWE-200 / CWE-352 的边界

OTHER_SAMPLES = []

# E1: 竞态条件（Python Flask）— 对比 CWE-89/79
OTHER_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/withdraw", methods=["POST"])
def withdraw():
    amount = int(request.form.get("amount", 0))
    user_id = session["user_id"]
    # check-then-act 之间无锁
    balance = db.execute(
        "SELECT balance FROM accounts WHERE uid = ?", (user_id,)
    ).fetchone()[0]
    if balance < amount:
        return "insufficient", 400
    db.execute(
        "UPDATE accounts SET balance = balance - ? WHERE uid = ?",
        (amount, user_id)
    )
    return "ok"
''',
    language="python", filename="race_01_toctou.py",
    cot="分析过程：\n"
        "1. 并发场景：多线程并发调用 /withdraw，accounts 表被并发读写。\n"
        "2. 危险模式：检查余额（SELECT balance）与扣款（UPDATE balance）非原子，"
        "两个并发请求可能同时通过 balance < amount 检查后都扣款，导致余额为负。\n"
        "3. 防御检查：无锁、无事务隔离、无乐观锁（version 字段）。\n"
        "4. 对比 CoT：为什么不是 CWE-89/79？因为问题不是注入（SQL 用了参数化无注入），"
        "而是 check-then-act 之间无锁导致 TOCTOU（Time-Of-Check-Time-Of-Use），故为 CWE-362 竞态条件。\n"
        "5. 综合来看，存在竞态条件漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-362", "竞态条件", "High",
        source="并发请求触发 TOCTOU",
        sink="SELECT balance 与 UPDATE balance 非原子",
        explanation="检查余额与扣款非原子操作，并发请求可同时通过检查导致超额扣款（余额为负）",
        fix="用事务 + SELECT FOR UPDATE 行锁；或用乐观锁 UPDATE accounts SET balance=balance-? WHERE uid=? AND balance>=?"
    )
))

# E2: Mass Assignment（Python Flask + SQLAlchemy）— 对比 CWE-862
OTHER_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/api/profile/update", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return "unauthorized", 401
    # 直接把所有 JSON 字段赋值给用户对象
    data = request.get_json()
    user = User.query.get(session["user_id"])
    for key, value in data.items():
        setattr(user, key, value)
    db.session.commit()
    return "updated"
''',
    language="python", filename="mass_assign_01_sqlalchemy.py",
    cot="分析过程：\n"
        "1. 用户可控输入：整个 JSON body 通过 data.items() 遍历赋值给 user 对象。\n"
        "2. 危险模式：setattr(user, key, value) 无字段白名单，攻击者可提交 {\"is_admin\": true} 提权。\n"
        "3. 防御检查：有认证（session.user_id），但未限制可修改的字段。\n"
        "4. 对比 CoT：为什么不是 CWE-862？因为有认证（session 校验存在），"
        "问题是批量赋值允许修改 is_admin 字段（非授权检查缺失），"
        "属于对象属性不受控修改，故为 CWE-915 Mass Assignment。\n"
        "5. 综合来看，存在 Mass Assignment 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-915", "Mass Assignment", "High",
        source="request.get_json() 的所有字段",
        sink="setattr(user, key, value) 无字段白名单",
        explanation="遍历 JSON 所有字段赋值给 user 对象，攻击者可提交 is_admin=true 实现权限提升",
        fix="用字段白名单：allowed = ['name', 'email']; for k in allowed: setattr(user, k, data[k])"
    )
))

# E3: 原型链污染（Node.js）— 对比 CWE-862
OTHER_SAMPLES.append(build_sample(
    code='''const express = require('express');
const app = express();
app.use(express.json());

function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/config', (req, res) => {
    const defaults = { theme: 'light', lang: 'en' };
    merge(defaults, req.body);
    res.json(defaults);
});
app.listen(3000);
''',
    language="javascript", filename="proto_pollution_01_merge.js",
    cot="分析过程：\n"
        "1. 用户可控输入：req.body（JSON）传入 merge 函数。\n"
        "2. 危险 sink：merge 递归赋值，未过滤 __proto__ 和 constructor 键。\n"
        "3. 攻击路径：发送 {\"__proto__\":{\"isAdmin\":true}} 污染 Object.prototype，"
        "后续所有对象继承 isAdmin=true，可绕过权限检查。\n"
        "4. 对比 CoT：为什么不是 CWE-862？因为问题是递归 merge 污染原型链，"
        "不是权限缺失（权限检查在别处），属于对象原型不受控修改，故为 CWE-1321; CWE-915 原型链污染。\n"
        "5. 综合来看，存在原型链污染漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-1321; CWE-915", "原型链污染", "High",
        source="req.body 含 __proto__ 键",
        sink="merge 函数递归赋值未过滤 __proto__",
        explanation="递归 merge 未过滤 __proto__，攻击者可污染 Object.prototype 注入任意属性影响全局对象",
        fix="merge 中过滤 __proto__ 和 constructor 键；或用 Object.create(null) 创建无原型对象"
    )
))

# E4: PHP 类型混淆（strcmp）— 对比 CWE-287
OTHER_SAMPLES.append(build_sample(
    code='''<?php
session_start();
function check_password($input, $stored) {
    // strcmp 返回 0 表示相等，但出错（如传入数组）返回 null
    // null == 0 在 PHP 松散比较中为 true
    if (strcmp($input, $stored) == 0) {
        return true;
    }
    return false;
}

if (isset($_POST['password']) && isset($_POST['user'])) {
    $stored = fetch_password($_POST['user']);
    if (check_password($_POST['password'], $stored)) {
        $_SESSION['authed'] = true;
        echo "logged in";
    } else {
        echo "denied";
    }
}
?>
''',
    language="php", filename="type_juggling_01_strcmp.php",
    cot="分析过程：\n"
        "1. 认证流程：用 strcmp 比较用户密码与存储密码，== 0 判定相等。\n"
        "2. 缺陷识别：strcmp 传入数组参数时返回 null（PHP 5.x），null == 0 在松散比较中为 true。\n"
        "3. 攻击路径：攻击者用 password[]=x 使 $_POST['password'] 为数组，strcmp 返回 null，== 0 通过，绕过认证。\n"
        "4. 对比 CoT：为什么不是 CWE-287？因为有认证机制（strcmp 密码校验存在），"
        "问题是 strcmp 返回 null 被 == 0 松散比较通过（类型混淆），不是认证完全缺失，故为 CWE-843 类型混淆。\n"
        "5. 综合来看，存在类型混淆漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-843", "类型混淆", "Critical",
        source="$_POST['password'] 可为数组",
        sink="strcmp($input, $stored) == 0 松散比较",
        explanation="strcmp 传入数组返回 null，null == 0 在 PHP 松散比较中为 true，可绕过密码校验",
        fix="用 === 严格比较：strcmp(...) === 0；或校验 is_string($input) 后再比较"
    )
))

# E5: 时序攻击（Python Flask）— 对比 CWE-798
OTHER_SAMPLES.append(build_sample(
    code='''import os
from flask import Flask, request, session
app = Flask(__name__)

@app.route("/api/admin", methods=["POST"])
def admin_action():
    token = request.headers.get("X-Admin-Token", "")
    expected = db.execute(
        "SELECT token FROM admin_tokens WHERE uid = 1"
    ).fetchone()[0]
    # 用 == 比较 token，存在时序泄露
    if token == expected:
        session["admin"] = True
        return "admin access"
    return "forbidden", 403
''',
    language="python", filename="timing_01_token_compare.py",
    cot="分析过程：\n"
        "1. 认证流程：从请求头取 X-Admin-Token，与数据库中 expected 用 == 比较。\n"
        "2. 缺陷识别：== 比较字符串时逐字符短路返回，字符匹配越多耗时越长，"
        "攻击者可通过测量响应时间逐字符爆破 token。\n"
        "3. 防御检查：token 存数据库（非硬编码），但比较方式不安全。\n"
        "4. 对比 CoT：为什么不是 CWE-798？因为没有硬编码密码（token 在数据库中），"
        "是用了 == 而非 hmac.compare_digest 导致时序泄露，属于时序侧信道缺陷，故为 CWE-208 时序攻击。\n"
        "5. 综合来看，存在时序攻击漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-208", "时序攻击", "Medium",
        source="X-Admin-Token 请求头",
        sink="token == expected 逐字符短路比较",
        explanation="用 == 比较密钥逐字符短路返回，攻击者可通过响应时间逐字符爆破 token",
        fix="用 hmac.compare_digest(token, expected) 恒定时间比较；或用 hash 等值比较"
    )
))

# E6: YAML 反序列化（Python）— 对比 CWE-918
OTHER_SAMPLES.append(build_sample(
    code='''import yaml
from flask import Flask, request
app = Flask(__name__)

@app.route("/config/load", methods=["POST"])
def load_config():
    raw = request.get_data(as_text=True)
    # 用 yaml.load 而非 safe_load，可反序列化任意 Python 对象
    config = yaml.load(raw, Loader=yaml.Loader)
    return {"theme": config.get("theme", "default")}
''',
    language="python", filename="yaml_deser_01_load.py",
    cot="分析过程：\n"
        "1. 用户可控输入：raw 来自 request.get_data（POST body）。\n"
        "2. 危险 sink：yaml.load(raw, Loader=yaml.Loader)，yaml.Loader 支持反序列化任意 Python 对象。\n"
        "3. 攻击路径：发送 !!python/object/apply:os.system ['id'] 可在反序列化时执行系统命令 RCE。\n"
        "4. 对比 CoT：为什么不是 CWE-918 SSRF？因为 sink 是 yaml.load 反序列化，"
        "不是 HTTP 请求（如 requests.get(url)），"
        "注入载体是 YAML 标签（!!python/object）而非 URL，故为 CWE-502 不安全反序列化。\n"
        "5. 综合来看，存在反序列化漏洞，风险等级 Critical。",
    json_block=vuln_json(
        "CWE-502", "不安全反序列化", "Critical",
        source="request.get_data()（POST YAML body）",
        sink="yaml.load(raw, Loader=yaml.Loader)",
        explanation="yaml.Loader 支持反序列化任意 Python 对象，可构造恶意 YAML 在加载时执行系统命令 RCE",
        fix="用 yaml.safe_load(raw) 替代 yaml.load；safe_load 不支持 !!python/object 等危险标签"
    )
))

# E7: 信息泄露（Python Flask）— 对比 CWE-89
OTHER_SAMPLES.append(build_sample(
    code='''import traceback
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/users/<uid>")
def get_user(uid):
    try:
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if not user:
            return {"error": "not found"}, 404
        return dict(user)
    except Exception as e:
        # 返回完整堆栈信息，泄露内部路径和数据库结构
        return {"error": traceback.format_exc()}, 500
''',
    language="python", filename="info_disclosure_01_traceback.py",
    cot="分析过程：\n"
        "1. 错误处理分析：except 捕获异常后返回 traceback.format_exc() 给客户端。\n"
        "2. 缺陷识别：堆栈信息含文件路径、SQL 语句、数据库结构、库版本等内部信息，"
        "攻击者可据此构造后续攻击。\n"
        "3. 防御检查：SQL 用了参数化（无注入），但错误响应泄露敏感信息。\n"
        "4. 对比 CoT：为什么不是 CWE-89 SQL注入？因为虽然查询了数据库，"
        "但 SQL 用了 ? 参数化无注入风险，漏洞是返回了堆栈信息和内部路径（错误处理不当），"
        "属于信息泄露，故为 CWE-200 信息泄露。\n"
        "5. 综合来看，存在信息泄露漏洞，风险等级 Medium。",
    json_block=vuln_json(
        "CWE-200", "信息泄露", "Medium",
        source="异常触发后的 traceback.format_exc()",
        sink="return {'error': traceback.format_exc()}, 500",
        explanation="异常堆栈返回给客户端，泄露文件路径、SQL 结构、库版本等内部信息",
        fix="生产环境返回通用错误消息 {'error': 'internal error'}；堆栈仅记录到服务端日志"
    )
))

# E8: CSRF（Python Flask）— 对比 CWE-79
OTHER_SAMPLES.append(build_sample(
    code='''from flask import Flask, request, session
app = Flask(__name__)

@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return "unauthorized", 401
    # 状态变更操作无 CSRF token 校验
    to = request.form.get("to")
    amount = int(request.form.get("amount", 0))
    db.execute(
        "UPDATE accounts SET balance = balance - ? WHERE uid = ?",
        (amount, session["user_id"])
    )
    db.execute(
        "UPDATE accounts SET balance = balance + ? WHERE uid = ?",
        (amount, to)
    )
    return "transferred"
''',
    language="python", filename="csrf_01_transfer.py",
    cot="分析过程：\n"
        "1. 操作分析：/transfer 是状态变更操作（修改账户余额），需 CSRF 防护。\n"
        "2. 防御检查：有认证（session.user_id），但无 CSRF token 校验、无 Origin/Referer 检查。\n"
        "3. 攻击路径：攻击者构造恶意页面 <form action='/transfer' method='POST'>，"
        "诱导已登录用户访问后自动提交转账请求。\n"
        "4. 对比 CoT：为什么不是 CWE-79？因为没有 XSS（不涉及注入恶意脚本到页面），"
        "问题是状态变更操作缺少 CSRF token，攻击者借助受害者浏览器的 session cookie 伪造请求，"
        "故为 CWE-352 CSRF。\n"
        "5. 综合来看，存在 CSRF 漏洞，风险等级 High。",
    json_block=vuln_json(
        "CWE-352", "CSRF", "High",
        source="攻击者构造的跨站表单请求",
        sink="/transfer 端点无 CSRF token 校验执行转账",
        explanation="状态变更操作无 CSRF token，攻击者可构造跨站表单诱导已登录用户提交转账请求",
        fix="用 Flask-WTF CSRFProtect 或自定义 CSRF token 校验；校验 Origin/Referer 头"
    )
))


# ===========================================================================
# 主函数
# ===========================================================================

def extract_code(user_content: str) -> str:
    """从 user 消息中提取代码块内容用于去重。"""
    parts = user_content.split("```")
    if len(parts) >= 3:
        return parts[1].strip()
    return user_content


def main():
    print("=" * 60)
    print("v8 CWE 归因改进训练数据构建")
    print("=" * 60)

    # 加载 v7_realworld 基底
    print(f"\n[1] 加载基底: {V7_FILE}")
    records = []
    with open(V7_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"    v7_realworld 样本数: {len(records)}")

    # 收集所有新样本
    new_samples = (
        INJECTION_SAMPLES +    # 5 条注入混淆
        AUTH_SAMPLES +         # 4 条认证/访问控制混淆
        CRYPTO_SAMPLES +       # 3 条密码学混淆
        TEMPLATE_SAMPLES +     # 4 条模板/表达式注入混淆
        OTHER_SAMPLES          # 8 条其他高频误判
    )
    print(f"\n[2] 新增样本数: {len(new_samples)}")
    print(f"    - 注入混淆 (A): {len(INJECTION_SAMPLES)}")
    print(f"    - 认证/访问控制混淆 (B): {len(AUTH_SAMPLES)}")
    print(f"    - 密码学混淆 (C): {len(CRYPTO_SAMPLES)}")
    print(f"    - 模板/表达式注入混淆 (D): {len(TEMPLATE_SAMPLES)}")
    print(f"    - 其他高频误判 (E): {len(OTHER_SAMPLES)}")

    # 合并
    all_records = records + new_samples
    print(f"\n[3] 合并后总数: {len(all_records)} "
          f"(v7 {len(records)} + 新增 {len(new_samples)})")

    # 去重（按 user prompt 中的代码内容 hash）
    seen_codes = set()
    deduped = []
    dup_count = 0
    for rec in all_records:
        user_content = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "user":
                user_content = msg.get("content", "")
                break
        code = extract_code(user_content)
        key = hash(code)
        if key in seen_codes:
            dup_count += 1
            continue
        seen_codes.add(key)
        deduped.append(rec)
    if dup_count:
        print(f"\n[4] 去重: 移除 {dup_count} 条重复样本")
    else:
        print(f"\n[4] 去重: 无重复样本")
    print(f"    最终样本数: {len(deduped)}")

    # 保存
    print(f"\n[5] 保存到: {OUT_FILE}")
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for rec in deduped:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # CWE 分布统计（从 assistant 消息中提取 vulnerability_type 字段的 CWE 编号）
    cwe_dist = {}
    for rec in deduped:
        assistant_msg = ""
        for msg in rec.get("messages", []):
            if msg.get("role") == "assistant":
                assistant_msg = msg.get("content", "")
                break
        # 提取 JSON 块中的 vulnerability_type
        json_match = re.search(r'"vulnerability_type"\s*:\s*"([^"]*)"', assistant_msg)
        if json_match:
            vuln_type = json_match.group(1)
            if vuln_type == "none":
                cwe_dist["none"] = cwe_dist.get("none", 0) + 1
                continue
            for m in re.finditer(r"CWE-\d+", vuln_type):
                cwe = m.group(0)
                cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1
        elif "CWE-" in assistant_msg:
            for m in re.finditer(r"CWE-\d+", assistant_msg):
                cwe = m.group(0)
                cwe_dist[cwe] = cwe_dist.get(cwe, 0) + 1

    print(f"\n[6] CWE 分布:")
    for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: (-x[1], x[0])):
        print(f"    {cwe}: {cnt}")

    print(f"\n{'=' * 60}")
    print(f"v8 训练数据构建完成: {len(deduped)} 条样本")
    print(f"输出: {OUT_FILE}")
    print(f"{'=' * 60}")
    print(f"\n下一步：Jaccard 泄漏审计 + v8 课程学习训练")


if __name__ == "__main__":
    main()
