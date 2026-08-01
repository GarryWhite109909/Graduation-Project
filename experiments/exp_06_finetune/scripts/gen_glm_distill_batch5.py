"""
Batch 5: 追加到 distill_glm_cwe_cvss.jsonl 和 distill_glm_web.jsonl
- cwe_cvss: CWE-943 NoSQL 注入 (12 条: 3 漏洞 + 9 安全) + CWE-639 IDOR (12 条: 3 漏洞 + 9 安全)
- web:      CWE-352 CSRF (12 条: 3 漏洞 + 9 安全) + CWE-1336 SSTI (12 条: 3 漏洞 + 9 安全)

复用 batch1 的系统提示词和辅助函数。
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
# Batch 5: cwe_cvss  ——  CWE-943 NoSQL 注入
# 12 条：3 漏洞 + 9 安全，覆盖 Python / JavaScript
# CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N（9.1 Critical）
# =====================================================================

CWE_CVSS_BATCH5_NOSQL = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_061.py
import json
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.post('/login')
def login():
    raw = request.get_data(as_text=True)
    # 用户提交的 JSON 字符串直接 parse 为 query 字典，无字段白名单
    try:
        query = json.loads(raw)
    except json.JSONDecodeError:
        return jsonify({'error': 'invalid json'}), 400
    user = db.users.find_one(query)
    if user:
        return jsonify({'token': issue_token(str(user['_id']))})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10 行 request.get_data(as_text=True) 获取用户提交的 JSON 字符串",
            "第 13 行 json.loads(raw) 将用户可控字符串 parse 为 query 字典，未做字段白名单或操作符过滤",
            "第 16 行 db.users.find_one(query) 直接用用户控制的字典作为 MongoDB query",
            "source→sink 间无任何防御，攻击者传 {\"username\":\"admin\",\"password\":{\"$ne\":\"\"}} 可绕过密码校验",
            "CWE-943 NoSQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-943 NoSQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "request.get_data(as_text=True)",
            "sink": "db.users.find_one(json.loads(raw))",
            "explanation": "request.get_data → raw → json.loads → query 字典 → find_one 执行 NoSQL 查询，$ne 操作符可绕过条件",
            "fix_suggestion": "显式提取已知字段并做类型校验：username = data.get('username', '')；isinstance(username, str) 拒绝 dict 类型的 $ 操作符",
        },
    },
    {
        "lang": "Python", "has_vuln": True, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_062.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.route('/user')
def find_user():
    name = request.args.get('name', '')
    # $where 接收 JS 表达式，f-string 直接拼接用户输入
    query = {"$where": f"this.username == '{name}'"}
    user = db.users.find_one(query)
    return jsonify({'user': str(user)})
```""",
        "steps": [
            "第 10 行 request.args.get('name') 获取用户输入，未做转义或白名单",
            "第 12 行 f-string 把 name 直接拼入 $where 的 JS 表达式字符串",
            "第 13 行 db.users.find_one 执行含用户输入的 $where 表达式",
            "source→sink 间无任何防御，攻击者传 name=' || '1'=='1 可构造恒真表达式匹配所有文档",
            "CWE-943 NoSQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-943 NoSQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "request.args.get('name')",
            "sink": "db.users.find_one({\"$where\": f\"this.username == '{name}'\"})",
            "explanation": "request.args.get('name') → name → f-string 拼入 $where JS 表达式 → find_one 执行，攻击者可构造恒真条件",
            "fix_suggestion": "避免使用 $where；改用字段查询 db.users.find_one({\"username\": name})，name 经类型校验为字符串",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": True, "difficulty": "典型",
        "code": """```javascript
// distill_glm_cwe_cvss_063.js
const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());
const client = new MongoClient('mongodb://db:27017');

app.post('/login', async (req, res) => {
    // express.json() 已将 body parse 为对象，直接作为 query 传入
    const user = await client.db('appdb')
        .collection('users')
        .findOne(req.body);
    if (user) {
        res.json({ token: issueToken(user._id) });
    } else {
        res.status(401).json({ error: 'invalid credentials' });
    }
});
```""",
        "steps": [
            "第 7 行 app.use(express.json()) 将 JSON body 自动 parse 为对象挂到 req.body",
            "第 12 行 findOne(req.body) 直接用用户控制的 JS 对象作为 MongoDB query",
            "express.json() 会把 {\"password\":{\"$ne\":\"\"}} 解析为 {password: {$ne: ''}}，$ne 操作符被 MongoDB 执行",
            "source→sink 间无任何防御，攻击者传 {\"username\":\"admin\",\"password\":{\"$ne\":\"\"}} 可绕过密码校验",
            "CWE-943 NoSQL 注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-943 NoSQL注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": 9.1,
            "source": "req.body (express.json() parsed)",
            "sink": "client.db('appdb').collection('users').findOne(req.body)",
            "explanation": "express.json() → req.body 对象 → findOne(req.body) 直接用用户控制对象作为 query，$ne 操作符可绕过条件",
            "fix_suggestion": "显式提取已知字段并做类型校验：const {username, password} = req.body; if (typeof username !== 'string') return 400;",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_064.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.route('/users')
def list_users():
    name = request.args.get('name', '')
    # 显式构造 query 字典，字段值来自 request.args.get() 返回的字符串
    query = {"name": name} if name else {}
    users = list(db.users.find(query, {"_id": 0, "name": 1, "email": 1}).limit(20))
    return jsonify({'users': users})
```""",
        "steps": [
            "第 9 行 request.args.get('name') 获取用户输入，Flask 的 args.get 始终返回字符串",
            "第 11 行显式构造 query 字典，仅含已知字段 name，字段值为字符串",
            "request.args 不会将 ?name[$ne]= 解析为嵌套对象，$ 操作符无法通过 querystring 注入",
            "已检查：显式字典构造 + 字符串字段值 + request.args 不解析嵌套对象，无 $ 操作符注入路径",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "db.users.find({\"name\": name})",
            "explanation": "name 经 request.args.get() 返回字符串，显式构造 query 字典仅含已知字段，$ 操作符无法注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_065.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.post('/login')
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    # $eq 强制相等匹配，值作为字面量而非操作符字典
    query = {
        "username": {"$eq": username},
        "password": {"$eq": password},
    }
    user = db.users.find_one(query)
    if user:
        return jsonify({'token': issue_token(str(user['_id']))})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10-11 行 data.get 提取 username/password，用户可能传入 dict 类型的 {\"$ne\":\"\"}",
            "第 13-16 行 query 使用 $eq 操作符强制相等匹配，$eq 的值作为字面量比较",
            "即使 password 是 {\"$ne\":\"\"}，{\"$eq\":{\"$ne\":\"\"}} 表示 password 等于该 dict 字面值，无文档匹配",
            "已检查：$eq 强制字面量比较，$ne 等操作符被包装为 $eq 的字面值参数而非执行操作符",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.json.get('username')",
            "sink": "db.users.find_one({\"username\": {\"$eq\": username}, ...})",
            "explanation": "username/password 经 $eq 包装为字面量比较，$ne 等操作符被作为 $eq 的值而非执行操作符，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_066.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.post('/login')
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    # 类型校验：仅允许字符串值，拒绝 dict/list 等 $ 操作符载体
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'invalid input type'}), 400
    query = {"username": username, "password": password}
    user = db.users.find_one(query)
    if user:
        return jsonify({'token': issue_token(str(user['_id']))})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10-11 行 data.get 提取 username/password",
            "第 13-14 行 isinstance 校验：仅允许 str 类型，dict 类型的 {\"$ne\":\"\"} 被拒绝返回 400",
            "第 15 行 query 仅含已校验为字符串的字段值，$ 操作符无法注入",
            "已检查：isinstance 类型校验拒绝 dict/list 类型，$ 操作符载体无法进入 query",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.json.get('username')",
            "sink": "db.users.find_one({\"username\": username, \"password\": password})",
            "explanation": "username/password 经 isinstance(str) 校验，dict 类型的 $ 操作符被拒绝，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": False, "difficulty": "中等",
        "code": """```javascript
// distill_glm_cwe_cvss_067.js
const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());
const client = new MongoClient('mongodb://db:27017');

app.post('/login', async (req, res) => {
    // 仅提取已知字段，用 String() 强制转换为字符串
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');
    const query = { username, password };
    const user = await client.db('appdb').collection('users').findOne(query);
    if (user) {
        res.json({ token: issueToken(user._id) });
    } else {
        res.status(401).json({ error: 'invalid credentials' });
    }
});
```""",
        "steps": [
            "第 10-11 行 String(req.body.username) 将用户输入强制转为字符串",
            "第 12 行构造 query 对象仅含已知字段 username/password，值为字符串",
            "若用户传 password={\"$ne\":\"\"}，String({$ne:''}) 转为 '[object Object]' 字面值，无文档匹配",
            "已检查：String() 类型强制转换 + 显式字段提取，$ 操作符 dict 被转为字符串字面值",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.body.username",
            "sink": "client.db('appdb').collection('users').findOne({username, password})",
            "explanation": "username/password 经 String() 强制转换为字符串，$ne 等 dict 操作符被转为 [object Object] 字面值，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_068.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb
ALLOWED_FIELDS = {'name', 'email', 'status'}


@app.route('/users')
def list_users():
    # 仅允许白名单字段进入 query
    query = {}
    for key, val in request.args.items():
        if key in ALLOWED_FIELDS:
            query[key] = val
    users = list(db.users.find(query, {"_id": 0}).limit(20))
    return jsonify({'users': users})
```""",
        "steps": [
            "第 10 行 request.args.items() 获取查询参数，Flask args 的值始终为字符串",
            "第 11-13 行 key in ALLOWED_FIELDS 白名单校验：仅 name/email/status 字段名可进入 query",
            "$where 等操作符字段名不在白名单中，被过滤；字段值始终为字符串，无法注入 $ne 等 dict 操作符",
            "已检查：白名单字段名 + 字符串字段值，$where 和 $ 操作符字段被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.items()",
            "sink": "db.users.find(query)",
            "explanation": "query 字段名经 ALLOWED_FIELDS 白名单过滤，$where 等操作符字段被拒绝，字段值为字符串，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_069.py
import re
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.route('/users')
def list_users():
    name = request.args.get('name', '')
    if not name:
        return jsonify({'users': []})
    # 转义 regex 特殊字符，防止元字符注入
    safe = re.escape(name)
    query = {"name": {"$regex": safe, "$options": "i"}}
    users = list(db.users.find(query, {"_id": 0}).limit(20))
    return jsonify({'users': users})
```""",
        "steps": [
            "第 11 行 request.args.get('name') 获取用户输入，Flask args 返回字符串",
            "第 14 行 re.escape(name) 转义 . * + ? { } [ ] ( ) \\ | ^ $ 等 regex 元字符",
            "第 15 行 $regex 的值为已转义的字符串，regex 语义不会被破坏",
            "已检查：re.escape 转义 + 字符串字段值，$regex 元字符注入被消除",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "db.users.find({\"name\": {\"$regex\": safe, \"$options\": \"i\"}})",
            "explanation": "name 经 re.escape 转义后作为 $regex 字符串值，regex 元字符被转义，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": False, "difficulty": "中等",
        "code": """```javascript
// distill_glm_cwe_cvss_070.js
const express = require('express');
const { MongoClient, ObjectId } = require('bson');
const app = express();
const client = new MongoClient('mongodb://db:27017');

app.get('/user/:id', async (req, res) => {
    const id = req.params.id;
    // BSON ObjectId 类型校验：非法格式抛异常
    let oid;
    try {
        oid = new ObjectId(id);
    } catch (e) {
        return res.status(400).json({ error: 'invalid id format' });
    }
    const user = await client.db('appdb').collection('users').findOne({ _id: oid });
    res.json({ user });
});
```""",
        "steps": [
            "第 9 行 req.params.id 获取用户输入的 id 字符串",
            "第 12-16 行 new ObjectId(id) 构造 BSON ObjectId，非法格式（含 $ 操作符）抛 TypeError 被捕获返回 400",
            "第 17 行 query 使用已校验的 ObjectId 类型，$ne 等 dict 操作符无法通过 ObjectId 构造",
            "已检查：ObjectId 类型校验 + try/catch 拒绝非法格式，$ 操作符 dict 无法注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.params.id",
            "sink": "client.db('appdb').collection('users').findOne({_id: oid})",
            "explanation": "id 经 new ObjectId() 类型校验，非法格式被拒绝，$ne 等 dict 操作符无法通过 ObjectId 构造，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_071.py
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient('mongodb://db:27017').appdb


@app.post('/login')
def login():
    data = request.json or {}
    # dict() 构造 query，仅含已知字段，str() 强制字符串值
    query = dict(
        username=str(data.get('username', '')),
        password=str(data.get('password', '')),
    )
    user = db.users.find_one(query)
    if user:
        return jsonify({'token': issue_token(str(user['_id']))})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10-11 行 data.get 提取 username/password，用户可能传入 dict 类型的 {\"$ne\":\"\"}",
            "第 10-11 行 str() 强制转换为字符串，{\"$ne\":\"\"} 被转为 \"{\\'$ne\\': \\'\\'}\" 字面值",
            "第 12-13 行 dict() 构造 query 仅含已知字段 username/password，值为字符串",
            "已检查：str() 类型强制 + dict() 已知字段构造，$ 操作符 dict 被转为字符串字面值",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.json.get('username')",
            "sink": "db.users.find_one(dict(username=str(...), password=str(...)))",
            "explanation": "username/password 经 str() 强制转换 + dict() 已知字段构造，$ne dict 被转为字符串字面值，无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_072.py
from flask import Flask, request, jsonify
from motor.motor_asyncio import AsyncIOMotorClient

app = Flask(__name__)
db = AsyncIOMotorClient('mongodb://db:27017').appdb


@app.post('/login')
async def login():
    data = await request.json
    username = data.get('username', '')
    password = data.get('password', '')
    # 类型校验：仅允许字符串值，拒绝 dict/list 类型的 $ 操作符
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'invalid input type'}), 400
    query = {"username": username, "password": password}
    user = await db.users.find_one(query)
    if user:
        return jsonify({'token': issue_token(str(user['_id']))})
    return jsonify({'error': 'invalid credentials'}), 401
```""",
        "steps": [
            "第 10 行 await request.json 异步获取用户提交的 JSON 对象",
            "第 11-12 行 data.get 提取 username/password",
            "第 14-15 行 isinstance(str) 校验：仅允许字符串，dict 类型的 {\"$ne\":\"\"} 被拒绝返回 400",
            "已检查：isinstance 类型校验 + Motor 异步 find_one，$ 操作符 dict 无法进入 query",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "await request.json",
            "sink": "await db.users.find_one({\"username\": username, \"password\": password})",
            "explanation": "username/password 经 isinstance(str) 校验，dict 类型的 $ 操作符被拒绝，Motor 异步查询无 NoSQL 注入",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 5: cwe_cvss  ——  CWE-639 IDOR（不安全的直接对象引用）
# 12 条：3 漏洞 + 9 安全，覆盖 Python / Java
# CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N（6.5 Medium）
# =====================================================================

CWE_CVSS_BATCH5_IDOR = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_073.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route('/profile/<int:user_id>')
def get_profile(user_id):
    # 用户 ID 从 URL 参数获取，未校验是否属于当前登录用户
    conn = sqlite3.connect('app.db')
    row = conn.execute(
        "SELECT id, name, email, phone FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    return jsonify({'profile': row})
```""",
        "steps": [
            "第 8 行 <int:user_id> 从 URL 路径参数获取用户 ID，攻击者可遍历任意 ID",
            "第 10-11 行用 user_id 查询 users 表，未校验 user_id 是否等于当前登录用户的 ID",
            "source→sink 间无授权校验，攻击者修改 URL 为 /profile/2 可读取其他用户的 profile",
            "无 session/token 归属校验，直接对象引用未做权限检查",
            "CWE-639 IDOR，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-639 IDOR",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 6.5,
            "source": "URL path parameter user_id",
            "sink": "conn.execute(\"SELECT ... FROM users WHERE id = ?\", (user_id,))",
            "explanation": "URL 参数 user_id → 直接查询 users 表 → 无归属校验，攻击者可遍历任意用户 ID 读取 profile",
            "fix_suggestion": "从 session 获取当前用户 ID：uid = session['user_id']；校验 user_id == uid 或查询时 WHERE id = ? AND id = session_user_id",
        },
    },
    {
        "lang": "Java", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_074.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private OrderRepository repo;

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId) {
        // orderId 从 URL 获取，未校验该订单是否属于当前用户
        return repo.findById(orderId)
            .orElseThrow(() -> new NotFoundException("order not found"));
    }
}
```""",
        "steps": [
            "第 10 行 @PathVariable Long orderId 从 URL 路径获取订单 ID",
            "第 12 行 repo.findById(orderId) 按 ID 查询订单，未校验订单的 userId 是否等于当前认证用户",
            "source→sink 间无归属校验，攻击者修改 URL 为 /orders/1001 可查看他人订单",
            "无 ownership check，直接对象引用未做权限检查",
            "CWE-639 IDOR，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-639 IDOR",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 6.5,
            "source": "@PathVariable Long orderId",
            "sink": "repo.findById(orderId)",
            "explanation": "@PathVariable orderId → repo.findById 查询订单 → 无 ownership 校验，攻击者可遍历任意 orderId 读取他人订单",
            "fix_suggestion": "校验订单归属：Order o = repo.findById(orderId); if (!o.getUserId().equals(currentUserId)) throw 403；或 repo.findByIdAndUserId(orderId, currentUserId)",
        },
    },
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_075.py
from django.http import JsonResponse
from myapp.models import FileAsset


def download_file(request, file_id):
    # 文件 ID 从 URL 获取，未校验当前用户是否有权访问该文件
    try:
        fid = int(file_id)
    except ValueError:
        return JsonResponse({'error': 'invalid id'}, status=400)
    asset = FileAsset.objects.get(id=fid)
    return JsonResponse({
        'url': asset.signed_url(),
        'name': asset.filename,
    })
```""",
        "steps": [
            "第 7 行 file_id 从 URL 路径参数获取",
            "第 9-10 行 int(file_id) 类型转换，仅防止非数字输入",
            "第 11 行 FileAsset.objects.get(id=fid) 按 ID 查询文件，未校验 file.owner == request.user",
            "source→sink 间无权限校验，攻击者遍历 file_id 可下载他人文件",
            "CWE-639 IDOR，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-639 IDOR",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 6.5,
            "source": "URL path parameter file_id",
            "sink": "FileAsset.objects.get(id=fid)",
            "explanation": "URL 参数 file_id → int 转换 → FileAsset.objects.get 查询 → 无 owner 校验，攻击者可遍历任意 file_id 下载他人文件",
            "fix_suggestion": "查询时加 user 过滤：FileAsset.objects.get(id=fid, owner=request.user)；或 get_object_or_404(FileAsset, id=fid, owner=request.user)",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_076.py
from flask import Flask, session, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = 'secure-random-key'


@app.route('/profile')
def get_profile():
    # 从 session 获取当前用户 ID，不接受 URL 参数
    uid = session.get('user_id')
    if not uid:
        return jsonify({'error': 'unauthorized'}), 401
    conn = sqlite3.connect('app.db')
    row = conn.execute(
        "SELECT id, name, email FROM users WHERE id = ?", (uid,)
    ).fetchone()
    return jsonify({'profile': row})
```""",
        "steps": [
            "第 10 行 session.get('user_id') 从服务端 session 获取当前登录用户 ID",
            "第 11-12 行未登录用户返回 401",
            "第 14-15 行用 session 中的 uid 查询，攻击者无法通过 URL 参数修改 uid",
            "已检查：user_id 来自服务端 session 而非 URL 参数，攻击者无法遍历他人 ID",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "session.get('user_id')",
            "sink": "conn.execute(\"SELECT ... FROM users WHERE id = ?\", (uid,))",
            "explanation": "uid 来自服务端 session 而非 URL 参数，攻击者无法修改 uid 遍历他人 profile，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_077.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private OrderRepository repo;

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId, @AuthenticationPrincipal UserPrincipal principal) {
        Order order = repo.findById(orderId)
            .orElseThrow(() -> new NotFoundException("order not found"));
        // 校验订单属于当前认证用户
        if (!order.getUserId().equals(principal.getUserId())) {
            throw new ForbiddenException("access denied");
        }
        return order;
    }
}
```""",
        "steps": [
            "第 10 行 @PathVariable orderId 从 URL 获取",
            "第 11 行 repo.findById 查询订单后，第 13-15 行校验 order.getUserId() == principal.getUserId()",
            "订单 userId 不等于当前用户 ID 时抛 403 Forbidden",
            "已检查：ownership 校验 order.getUserId().equals(principal.getUserId())，非本人订单返回 403",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@PathVariable Long orderId",
            "sink": "repo.findById(orderId)",
            "explanation": "orderId 查询后校验 order.getUserId().equals(principal.getUserId())，非本人订单返回 403，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_078.py
from django.http import JsonResponse
from myapp.models import FileAsset


def download_file(request, file_id):
    # 查询时附加 user 过滤，确保仅返回当前用户的文件
    asset = FileAsset.objects.filter(id=file_id, owner=request.user).first()
    if asset is None:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse({
        'url': asset.signed_url(),
        'name': asset.filename,
    })
```""",
        "steps": [
            "第 7 行 file_id 从 URL 获取",
            "第 9 行 FileAsset.objects.filter(id=file_id, owner=request.user) 查询时附加 owner=request.user 条件",
            "非当前用户的文件查询结果为 None，第 10-11 行返回 404",
            "已检查：filter(id=file_id, owner=request.user) 在 SQL 层附加 user 过滤，攻击者无法访问他人文件",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "URL path parameter file_id",
            "sink": "FileAsset.objects.filter(id=file_id, owner=request.user)",
            "explanation": "file_id 查询时附加 owner=request.user 过滤，非本人文件返回 404，攻击者无法遍历他人文件，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_079.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private OrderRepository repo;

    @GetMapping("/{orderId}")
    @PreAuthorize("@orderSecurity.isOwner(#orderId, authentication)")
    public Order getOrder(@PathVariable Long orderId) {
        return repo.findById(orderId)
            .orElseThrow(() -> new NotFoundException("order not found"));
    }
}
```""",
        "steps": [
            "第 10 行 @PreAuthorize 注解在方法调用前执行授权检查",
            "第 10 行 @orderSecurity.isOwner(#orderId, authentication) 调用安全 Bean 校验当前用户是否拥有该订单",
            "isOwner 返回 false 时 Spring Security 抛 AccessDeniedException 返回 403",
            "已检查：@PreAuthorize 方法级授权 + isOwner ownership 校验，非本人订单返回 403",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@PathVariable Long orderId",
            "sink": "repo.findById(orderId)",
            "explanation": "orderId 经 @PreAuthorize + @orderSecurity.isOwner 方法级授权校验，非本人订单返回 403，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_080.py
from flask import Flask, session, request, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = 'secure-random-key'


@app.route('/orders/<int:order_id>')
def get_order(order_id):
    uid = session.get('user_id')
    if not uid:
        return jsonify({'error': 'unauthorized'}), 401
    conn = sqlite3.connect('app.db')
    # 查询时附加 user_id 条件，确保仅返回当前用户的订单
    row = conn.execute(
        "SELECT id, total, status FROM orders WHERE id = ? AND user_id = ?",
        (order_id, uid)
    ).fetchone()
    if row is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'order': row})
```""",
        "steps": [
            "第 10 行 session.get('user_id') 从服务端 session 获取当前用户 ID",
            "第 14-16 行 SQL 查询附加 AND user_id = ? 条件，绑定 session 中的 uid",
            "非当前用户的订单查询结果为 None，第 17-18 行返回 404",
            "已检查：session user_id + SQL 层 AND user_id 过滤，攻击者无法访问他人订单",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "session.get('user_id')",
            "sink": "conn.execute(\"SELECT ... WHERE id = ? AND user_id = ?\", (order_id, uid))",
            "explanation": "order_id 查询附加 AND user_id = session uid 条件，非本人订单返回 404，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_081.py
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from myapp.models import FileAsset


def download_file(request, file_id):
    # get_object_or_404 + owner 过滤，非本人文件直接 404
    asset = get_object_or_404(FileAsset, id=file_id, owner=request.user)
    return JsonResponse({
        'url': asset.signed_url(),
        'name': asset.filename,
    })
```""",
        "steps": [
            "第 7 行 file_id 从 URL 获取",
            "第 9 行 get_object_or_404(FileAsset, id=file_id, owner=request.user) 查询时附加 owner=request.user",
            "非当前用户的文件 get_object_or_404 抛 Http404，返回 404 Not Found",
            "已检查：get_object_or_404 + owner=request.user 过滤，非本人文件返回 404",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "URL path parameter file_id",
            "sink": "get_object_or_404(FileAsset, id=file_id, owner=request.user)",
            "explanation": "file_id 经 get_object_or_404 + owner=request.user 过滤，非本人文件返回 404，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_cwe_cvss_082.java
@RestController
@RequestMapping("/orders")
public class OrderController {
    @Autowired
    private OrderRepository repo;

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId, @AuthenticationPrincipal UserPrincipal principal) {
        // 使用派生查询 findByIdAndUserId，SQL 层附加 user 过滤
        return repo.findByIdAndUserId(orderId, principal.getUserId())
            .orElseThrow(() -> new NotFoundException("order not found"));
    }
}
```""",
        "steps": [
            "第 10 行 @PathVariable orderId 从 URL 获取",
            "第 13 行 repo.findByIdAndUserId(orderId, principal.getUserId()) 使用 Spring Data 派生查询",
            "派生查询在 SQL 层附加 WHERE id = ? AND user_id = ? 条件，非本人订单查询结果为空抛 404",
            "已检查：findByIdAndUserId 派生查询 + SQL 层 user 过滤，攻击者无法访问他人订单",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@PathVariable Long orderId",
            "sink": "repo.findByIdAndUserId(orderId, principal.getUserId())",
            "explanation": "orderId 经 findByIdAndUserId 派生查询附加 user_id 过滤，非本人订单返回 404，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_083.py
from flask import Flask, session, request, jsonify
from myapp.models import Order

app = Flask(__name__)
app.secret_key = 'secure-random-key'


@app.route('/orders/<int:order_id>')
def get_order(order_id):
    uid = session.get('user_id')
    if not uid:
        return jsonify({'error': 'unauthorized'}), 401
    # 查询时附加 user_id 过滤，仅返回当前用户的订单
    order = Order.query.filter_by(id=order_id, user_id=uid).first()
    if order is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'order': order.to_dict()})
```""",
        "steps": [
            "第 10 行 session.get('user_id') 从服务端 session 获取当前用户 ID",
            "第 14 行 Order.query.filter_by(id=order_id, user_id=uid) 查询时附加 user_id=session uid",
            "非当前用户的订单查询结果为 None，第 15-16 行返回 404",
            "已检查：session user_id + filter_by user_id 过滤，攻击者无法访问他人订单",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "session.get('user_id')",
            "sink": "Order.query.filter_by(id=order_id, user_id=uid)",
            "explanation": "order_id 查询附加 filter_by(user_id=session uid) 过滤，非本人订单返回 404，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_084.py
from django.http import JsonResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from myapp.models import FileAsset


class FileDownloadView(LoginRequiredMixin, View):
    def get(self, request, file_id):
        # LoginRequiredMixin 要求登录 + filter 附加 owner 过滤
        asset = FileAsset.objects.filter(id=file_id, owner=request.user).first()
        if asset is None:
            return JsonResponse({'error': 'not found'}, status=404)
        return JsonResponse({'url': asset.signed_url(), 'name': asset.filename})
```""",
        "steps": [
            "第 8 行 LoginRequiredMixin 要求用户已登录，未登录重定向到登录页",
            "第 10 行 FileAsset.objects.filter(id=file_id, owner=request.user) 查询附加 owner=request.user",
            "非当前用户的文件查询结果为 None，第 11-12 行返回 404",
            "已检查：LoginRequiredMixin 登录要求 + filter(owner=request.user) 权限过滤，无 IDOR",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "URL path parameter file_id",
            "sink": "FileAsset.objects.filter(id=file_id, owner=request.user)",
            "explanation": "file_id 经 LoginRequiredMixin 登录要求 + filter(owner=request.user) 权限过滤，非本人文件返回 404，无 IDOR",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 5: web  ——  CWE-352 CSRF
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Django / Spring
# CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N（4.3 Medium）
# =====================================================================

WEB_BATCH5_CSRF = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "密码修改", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_061.py
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.post('/change_password')
def change_password():
    # POST 处理无 CSRF token 校验
    old_pwd = request.form.get('old_password', '')
    new_pwd = request.form.get('new_password', '')
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET password = ? WHERE id = 1", (new_pwd,))
    conn.commit()
    return jsonify({'status': 'ok'})
```""",
        "steps": [
            "第 8-9 行 request.form 获取 POST 表单数据，无 CSRF token 字段校验",
            "第 10-12 行直接更新 users 表密码，未校验请求来源",
            "Flask 默认不启用 CSRF 防护，source→sink 间无 token 校验",
            "攻击者构造恶意页面 <form action='/change_password' method='POST'> 诱导用户点击可篡改密码",
            "CWE-352 CSRF，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-352 CSRF",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "cvss_score": 4.3,
            "source": "request.form.get('new_password')",
            "sink": "conn.execute(\"UPDATE users SET password = ?\", (new_pwd,))",
            "explanation": "POST /change_password 无 CSRF token 校验，攻击者构造跨站表单诱导用户点击可篡改密码",
            "fix_suggestion": "使用 Flask-WTF CSRFProtect 全局启用 CSRF 防护，表单含 {% csrf_token %} 并校验 token",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "用户注册", "has_vuln": True, "difficulty": "中等",
        "code": """```python
# distill_glm_web_062.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from myapp.models import User


@csrf_exempt
def register(request):
    # @csrf_exempt 显式禁用 CSRF 防护
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        User.objects.create(username=username, password=password)
        return JsonResponse({'status': 'created'})
    return JsonResponse({'error': 'method not allowed'}, status=405)
```""",
        "steps": [
            "第 6 行 @csrf_exempt 装饰器显式禁用 Django 默认的 CSRF 防护",
            "第 9-11 行 request.POST 获取表单数据并创建用户，无 token 校验",
            "Django 默认启用 CSRF 但被 @csrf_exempt 关闭，source→sink 间无防御",
            "攻击者构造跨站 POST 表单诱导已登录用户提交可批量注册账号",
            "CWE-352 CSRF，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-352 CSRF",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "cvss_score": 4.3,
            "source": "request.POST.get('username')",
            "sink": "User.objects.create(username=username, password=password)",
            "explanation": "@csrf_exempt 禁用 Django CSRF 防护，POST 注册接口无 token 校验，攻击者可构造跨站表单批量注册",
            "fix_suggestion": "移除 @csrf_exempt 装饰器，使用 @csrf_protect 启用 CSRF 防护，表单含 {% csrf_token %}",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "转账", "has_vuln": True, "difficulty": "典型",
        "code": """```java
// distill_glm_web_063.java
@RestController
@RequestMapping("/transfer")
public class TransferController {
    @Autowired
    private AccountService accountService;

    @PostMapping
    public Map<String, Object> transfer(@RequestParam String to, @RequestParam Double amount) {
        // POST 处理无 CSRF token 校验
        accountService.transfer(1L, Long.parseLong(to), amount);
        return Map.of("status", "ok");
    }
}
```""",
        "steps": [
            "第 10-11 行 @PostMapping + @RequestParam 接收转账参数，无 CSRF token 校验",
            "第 12 行 accountService.transfer 执行转账，未校验请求来源",
            "Spring 默认不启用 CSRF 防护（需显式配置 CsrfFilter），source→sink 间无防御",
            "攻击者构造恶意页面 <form action='/transfer' method='POST'> 诱导用户点击可转账",
            "CWE-352 CSRF，Medium",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-352 CSRF",
            "risk_level": "Medium",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "cvss_score": 4.3,
            "source": "@RequestParam String to",
            "sink": "accountService.transfer(1L, Long.parseLong(to), amount)",
            "explanation": "POST /transfer 无 CSRF token 校验，Spring 未配置 CsrfFilter，攻击者构造跨站表单可转账",
            "fix_suggestion": "在 Spring Security 配置中启用 .csrf() 并在前端表单/header 中携带 CSRF token",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Django", "scene": "密码修改", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_064.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from myapp.models import User


@csrf_protect
def change_password(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'method not allowed'}, status=405)
    # @csrf_protect 校验 POST 中的 csrfmiddlewaretoken
    old_pwd = request.POST.get('old_password', '')
    new_pwd = request.POST.get('new_password', '')
    request.user.set_password(new_pwd)
    request.user.save()
    return JsonResponse({'status': 'ok'})
```""",
        "steps": [
            "第 6 行 @csrf_protect 装饰器启用 Django CSRF 防护",
            "第 10-11 行 request.POST 获取表单数据，Django 校验 csrfmiddlewaretoken 字段与 cookie 中的 token 匹配",
            "前端表单含 {% csrf_token %} 生成隐藏 input，token 不匹配时返回 403",
            "已检查：@csrf_protect + {% csrf_token %} 双重提交 cookie 模式，跨站请求无法伪造 token",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.POST.get('new_password')",
            "sink": "request.user.set_password(new_pwd)",
            "explanation": "@csrf_protect 校验 csrfmiddlewaretoken 与 cookie token 匹配，前端 {% csrf_token %} 生成 token，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "表单提交", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_065.py
from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect
import sqlite3

app = Flask(__name__)
app.secret_key = 'secure-random-key'
csrf = CSRFProtect(app)


@app.post('/change_password')
def change_password():
    # CSRFProtect 全局校验 csrf_token 字段
    old_pwd = request.form.get('old_password', '')
    new_pwd = request.form.get('new_password', '')
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET password = ? WHERE id = 1", (new_pwd,))
    conn.commit()
    return jsonify({'status': 'ok'})
```""",
        "steps": [
            "第 5 行 CSRFProtect(app) 全局启用 Flask-WTF CSRF 防护",
            "第 10-12 行 POST 请求自动校验 csrf_token 字段与 session 中的 token 匹配",
            "前端表单含 <input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>，token 不匹配时返回 400",
            "已检查：CSRFProtect 全局校验 + 前端 csrf_token() 生成，跨站请求无法伪造 token",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.form.get('new_password')",
            "sink": "conn.execute(\"UPDATE users SET password = ?\", (new_pwd,))",
            "explanation": "CSRFProtect 全局校验 csrf_token 字段与 session token 匹配，前端 csrf_token() 生成 token，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "转账", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_066.java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CsrfTokenRepository.withDefaults());
    }
}

@RestController
@RequestMapping("/transfer")
public class TransferController {
    @Autowired
    private AccountService accountService;

    @PostMapping
    public Map<String, Object> transfer(@RequestParam String to, @RequestParam Double amount) {
        accountService.transfer(1L, Long.parseLong(to), amount);
        return Map.of("status", "ok");
    }
}
```""",
        "steps": [
            "第 7-8 行 http.csrf().csrfTokenRepository(...) 启用 Spring Security CsrfFilter",
            "CsrfFilter 校验请求中的 X-CSRF-Token header 或 _csrf 表单字段与 session 中的 CsrfToken 匹配",
            "token 不匹配时返回 403 Forbidden",
            "已检查：CsrfFilter + CsrfTokenRepository 校验 CSRF token，跨站请求无法伪造 header token",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String to",
            "sink": "accountService.transfer(1L, Long.parseLong(to), amount)",
            "explanation": "Spring Security CsrfFilter 校验 X-CSRF-Token header 与 session CsrfToken 匹配，token 不匹配返回 403，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "用户设置", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_067.py
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST


@require_POST
@ensure_csrf_cookie
def update_settings(request):
    # ensure_csrf_cookie 确保 CSRF cookie 已设置
    theme = request.POST.get('theme', 'light')
    request.user.profile.theme = theme
    request.user.profile.save()
    return JsonResponse({'status': 'ok', 'theme': theme})
```""",
        "steps": [
            "第 7 行 @require_POST 限制仅接受 POST 请求，GET 请求返回 405",
            "第 8 行 @ensure_csrf_cookie 确保 response 设置 csrftoken cookie",
            "Django 默认对 POST 请求校验 csrfmiddlewaretoken 字段（@require_POST 不绕过 CSRF）",
            "已检查：@require_POST 方法限制 + Django 默认 CSRF 校验 + ensure_csrf_cookie 设置 token",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.POST.get('theme')",
            "sink": "request.user.profile.save()",
            "explanation": "@require_POST 限制方法 + Django 默认 CSRF 校验 + ensure_csrf_cookie 设置 token，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "密码修改", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_068.py
import secrets
from flask import Flask, request, jsonify, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'secure-random-key'


@app.post('/change_password')
def change_password():
    # 双重提交 cookie 模式：校验 header 与 cookie 中的 token 匹配
    cookie_token = request.cookies.get('csrf_token', '')
    header_token = request.headers.get('X-CSRF-Token', '')
    if not cookie_token or cookie_token != header_token:
        return jsonify({'error': 'invalid csrf token'}), 403
    new_pwd = request.form.get('new_password', '')
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET password = ? WHERE id = 1", (new_pwd,))
    conn.commit()
    return jsonify({'status': 'ok'})
```""",
        "steps": [
            "第 11 行 request.cookies.get('csrf_token') 获取 cookie 中的 CSRF token",
            "第 12 行 request.headers.get('X-CSRF-Token') 获取 header 中的 CSRF token",
            "第 13-14 行校验 cookie token 与 header token 匹配，不匹配返回 403（双重提交 cookie 模式）",
            "已检查：双重提交 cookie 模式，跨站请求无法读取 cookie 设置 header，token 不匹配返回 403",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.form.get('new_password')",
            "sink": "conn.execute(\"UPDATE users SET password = ?\", (new_pwd,))",
            "explanation": "双重提交 cookie 模式校验 X-CSRF-Token header 与 csrf_token cookie 匹配，跨站请求无法读取 cookie 设置 header",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "会话管理", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_069.java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        // SameSite=Strict 防止跨站请求携带 cookie
        http.sessionManagement().sessionFixation().migrateSession();
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setSameSite("Strict");
        return serializer;
    }
}
```""",
        "steps": [
            "第 12-14 行 DefaultCookieSerializer.setSameSite(\"Strict\") 设置 session cookie 的 SameSite=Strict",
            "SameSite=Strict 防止浏览器在跨站请求中携带 cookie，CSRF 请求无 session cookie 被视为未认证",
            "跨站 POST 请求不携带 session cookie，服务端拒绝执行状态变更操作",
            "已检查：SameSite=Strict cookie 策略，跨站请求不携带 session cookie，无 CSRF",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "HTTP request (no session cookie in cross-site)",
            "sink": "sessionManagement 配置",
            "explanation": "SameSite=Strict cookie 策略防止跨站请求携带 session cookie，CSRF 请求无认证被拒绝",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "表单提交", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_070.py
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from myapp.models import User


@require_POST
def update_email(request):
    # @require_POST 限制方法 + Django 默认 CSRF 校验
    email = request.POST.get('email', '')
    request.user.email = email
    request.user.save()
    return JsonResponse({'status': 'ok', 'email': email})
```""",
        "steps": [
            "第 7 行 @require_POST 限制仅接受 POST 请求，GET 请求返回 405",
            "第 9 行 request.POST 获取表单数据，Django 默认对 POST 校验 csrfmiddlewaretoken",
            "前端表单含 {% csrf_token %} 生成隐藏 input，token 不匹配时返回 403",
            "已检查：@require_POST 方法限制 + Django 默认 CSRF 校验 + {% csrf_token %}",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.POST.get('email')",
            "sink": "request.user.save()",
            "explanation": "@require_POST 限制方法 + Django 默认 CSRF 校验 csrfmiddlewaretoken，前端 {% csrf_token %} 生成 token，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "API 调用", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_071.java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(csrfTokenRepository());
    }

    private CsrfTokenRepository csrfTokenRepository() {
        // 使用 HTTP header 模式校验 X-XSRF-TOKEN
        HttpSessionCsrfTokenRepository repo = new HttpSessionCsrfTokenRepository();
        repo.setHeaderName("X-XSRF-TOKEN");
        return repo;
    }
}
```""",
        "steps": [
            "第 7-8 行 http.csrf().csrfTokenRepository 配置 CSRF token 存储",
            "第 11-14 行 HttpSessionCsrfTokenRepository 设置 header 名为 X-XSRF-TOKEN",
            "前端 JS 从 cookie 读取 token 设置到 X-XSRF-TOKEN header，CsrfFilter 校验 header 与 session token 匹配",
            "已检查：HttpSessionCsrfTokenRepository + X-XSRF-TOKEN header 校验，跨站请求无法伪造 header token",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "HTTP POST request",
            "sink": "http.csrf().csrfTokenRepository(csrfTokenRepository())",
            "explanation": "HttpSessionCsrfTokenRepository 校验 X-XSRF-TOKEN header 与 session token 匹配，跨站请求无法读取 cookie 设置 header",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "用户注册", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_072.py
from flask import Flask, request, jsonify
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-random-key'
app.config['WTF_CSRF_ENABLED'] = True


@app.post('/register')
def register():
    form = FlaskForm()
    # FlaskForm.validate_on_submit 校验 csrf_token 隐藏字段
    if not form.validate_on_submit():
        return jsonify({'error': 'csrf validation failed'}), 403
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return jsonify({'status': 'created', 'username': username})
```""",
        "steps": [
            "第 6-7 行 SECRET_KEY + WTF_CSRF_ENABLED=True 启用 Flask-WTF CSRF 防护",
            "第 11 行 FlaskForm() 创建表单实例，第 13 行 validate_on_submit 校验 csrf_token 隐藏字段",
            "前端表单含 <input type='hidden' name='csrf_token'>，token 不匹配时返回 403",
            "已检查：FlaskForm.validate_on_submit + WTF_CSRF_ENABLED 校验 csrf_token，跨站请求无法伪造",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.form.get('username')",
            "sink": "FlaskForm().validate_on_submit()",
            "explanation": "FlaskForm.validate_on_submit 校验 csrf_token 隐藏字段与 session token 匹配，WTF_CSRF_ENABLED 启用，跨站请求无法伪造",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 5: web  ——  CWE-1336 SSTI（服务端模板注入）
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Jinja2 / Spring
# CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H（9.8 Critical）
# =====================================================================

WEB_BATCH5_SSTI = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "页面渲染", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_073.py
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    # render_template_string + f-string 拼接用户输入
    template = f'<h1>Hello {name}</h1>'
    return render_template_string(template)
```""",
        "steps": [
            "第 9 行 request.args.get('name') 获取用户输入，未做转义或白名单",
            "第 11 行 f-string 把 name 直接拼入模板字符串",
            "第 12 行 render_template_string 渲染拼接后的模板，Jinja2 会执行 {{ }} 和 {% %} 表达式",
            "source→sink 间无任何防御，攻击者传 name={{7*7}} 可执行 Jinja2 表达式，传 {{config}} 可泄露密钥",
            "CWE-1336 SSTI，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-1336 SSTI",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('name')",
            "sink": "render_template_string(f'<h1>Hello {name}</h1>')",
            "explanation": "request.args.get('name') → name → f-string 拼入模板 → render_template_string 渲染，攻击者注入 {{ }} 可执行 Jinja2 表达式",
            "fix_suggestion": "使用 render_template 加载固定模板文件，通过 context 传变量：render_template('greet.html', name=name)",
        },
    },
    {
        "lang": "Python", "framework": "Jinja2", "scene": "邮件模板", "has_vuln": True, "difficulty": "中等",
        "code": """```python
# distill_glm_web_074.py
from jinja2 import Environment, Template
from flask import Flask, request

app = Flask(__name__)


@app.route('/preview')
def preview():
    body = request.args.get('body', 'Hello!')
    # Template() 直接用用户输入作为模板内容
    tpl = Template('Dear user, ' + body)
    return tpl.render()
```""",
        "steps": [
            "第 9 行 request.args.get('body') 获取用户输入，未做转义",
            "第 11 行 Template() 构造函数接收用户输入拼接的字符串作为模板内容",
            "第 12 行 tpl.render() 渲染用户控制的模板，Jinja2 执行 {{ }} 和 {% %}",
            "source→sink 间无任何防御，攻击者传 body={{''.__class__.__mro__[1].__subclasses__()}} 可执行任意 Python 代码",
            "CWE-1336 SSTI，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-1336 SSTI",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('body')",
            "sink": "Template('Dear user, ' + body).render()",
            "explanation": "request.args.get('body') → body → 拼接进 Template 构造函数 → render 渲染用户控制模板，攻击者可执行任意 Python 代码",
            "fix_suggestion": "使用固定模板 + 变量绑定：tpl = Template('Dear user, {{ body }}'); tpl.render(body=body)",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "报告生成", "has_vuln": True, "difficulty": "中等",
        "code": """```java
// distill_glm_web_075.java
import freemarker.template.*;
import java.io.StringReader;
import java.io.StringWriter;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {
    private final Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);

    @GetMapping("/report")
    public String render(@RequestParam String name) throws Exception {
        // 用户输入拼接到模板字符串
        Template tpl = new Template("inline",
            new StringReader("Report: " + name), cfg);
        StringWriter sw = new StringWriter();
        tpl.process(new java.util.HashMap<>(), sw);
        return sw.toString();
    }
}
```""",
        "steps": [
            "第 11 行 @RequestParam String name 获取用户输入，未做转义",
            "第 13-14 行 name 拼接进 FreeMarker 模板字符串，new StringReader 包装",
            "第 16 行 tpl.process 渲染模板，FreeMarker 执行 ${} 和 <#...> 表达式",
            "source→sink 间无任何防御，攻击者传 name=${7*7} 可执行表达式，传 ${\"freemarker.template.utility.Execute\"?new()(\"id\")} 可 RCE",
            "CWE-1336 SSTI，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-1336 SSTI",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "@RequestParam String name",
            "sink": "new Template(\"inline\", new StringReader(\"Report: \" + name), cfg).process(...)",
            "explanation": "@RequestParam name → 拼接进 FreeMarker 模板字符串 → process 渲染，攻击者注入 ${} 可执行表达式或 RCE",
            "fix_suggestion": "使用固定模板 + 变量绑定：模板字符串含 ${name}，通过 context 传 name 值而非拼接模板内容",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "页面渲染", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_076.py
from flask import Flask, request, render_template

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    # render_template 加载固定模板文件，通过 context 传变量
    return render_template('greet.html', name=name)
```""",
        "steps": [
            "第 9 行 request.args.get('name') 获取用户输入",
            "第 11 行 render_template('greet.html', name=name) 加载固定模板文件，name 作为 context 变量传入",
            "模板文件中的 {{ name }} 是变量占位符，Jinja2 将 name 作为字面值渲染而非执行表达式",
            "已检查：固定模板文件 + context 变量绑定，name 不进入模板语法解析，无 SSTI",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "render_template('greet.html', name=name)",
            "explanation": "name 通过 render_template 的 context 传入固定模板文件，Jinja2 作为变量字面值渲染，不进入模板语法解析",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Jinja2", "scene": "邮件模板", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_077.py
from jinja2 import Environment, BaseLoader
from flask import Flask, request

app = Flask(__name__)
# SandboxedEnvironment 限制危险操作（属性访问、内置函数等）
env = Environment(loader=BaseLoader(), autoescape=True)


@app.route('/preview')
def preview():
    body = request.args.get('body', 'Hello!')
    tpl = env.from_string('Dear user, {{ body }}')
    return tpl.render(body=body)
```""",
        "steps": [
            "第 7 行 Environment(loader=BaseLoader(), autoescape=True) 创建安全环境（未使用 SandboxedEnvironment 但 autoescape 启用）",
            "第 12 行 env.from_string('Dear user, {{ body }}') 模板字符串使用 {{ body }} 变量占位符，非拼接用户输入",
            "第 13 行 tpl.render(body=body) body 作为变量值传入，Jinja2 作为字面值渲染",
            "已检查：固定模板 + {{ body }} 变量绑定 + autoescape，body 不进入模板语法解析",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('body')",
            "sink": "env.from_string('Dear user, {{ body }}').render(body=body)",
            "explanation": "body 通过 {{ body }} 变量占位符绑定，autoescape 启用，body 作为字面值渲染而非模板语法解析，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "页面渲染", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_078.java
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class GreetController {
    @GetMapping("/greet")
    public String greet(@RequestParam String name, Model model) {
        // Thymeleaf 变量绑定：model.addAttribute 传变量，非拼接模板
        model.addAttribute("name", name);
        return "greet";  // 固定模板文件 greet.html
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam String name 获取用户输入",
            "第 11 行 model.addAttribute(\"name\", name) 将 name 作为模板变量传入 Model",
            "第 12 行 return \"greet\" 返回固定模板文件名，Thymeleaf 加载 greet.html",
            "已检查：固定模板文件 + model.addAttribute 变量绑定，name 不进入模板语法解析，Thymeleaf 自动转义",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String name",
            "sink": "model.addAttribute(\"name\", name); return \"greet\"",
            "explanation": "name 通过 model.addAttribute 传入固定 Thymeleaf 模板，作为变量字面值渲染，Thymeleaf 自动转义，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "页面渲染", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_079.py
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    # render_template_string + {{ var }} 变量绑定，非 f-string 拼接
    return render_template_string('<h1>Hello {{ name }}</h1>', name=name)
```""",
        "steps": [
            "第 9 行 request.args.get('name') 获取用户输入",
            "第 11 行 render_template_string 模板字符串含 {{ name }} 变量占位符，第二参数 name=name 为 context 绑定",
            "Jinja2 将 {{ name }} 中的 name 作为变量字面值渲染，不执行 {{ }} 表达式",
            "已检查：{{ name }} 变量占位符 + context 绑定，name 不进入模板语法解析",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "render_template_string('<h1>Hello {{ name }}</h1>', name=name)",
            "explanation": "name 通过 {{ name }} 变量占位符 + context 绑定传入，Jinja2 作为字面值渲染，不执行表达式，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Thymeleaf", "scene": "页面渲染", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_080.java
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class GreetController {
    @GetMapping("/greet")
    public String greet(@RequestParam String name, Model model) {
        // Thymeleaf ${var} 表达式：模板文件含 th:text="${name}"
        model.addAttribute("name", name);
        return "greet";  // greet.html: <p th:text="${name}">default</p>
    }
}
```""",
        "steps": [
            "第 9 行 @RequestParam String name 获取用户输入",
            "第 11 行 model.addAttribute(\"name\", name) 将 name 作为模板变量传入",
            "模板文件 greet.html 中 th:text=\"${name}\" 使用 Thymeleaf 变量表达式，name 作为字面值渲染且自动 HTML 转义",
            "已检查：Thymeleaf ${var} 变量表达式 + 固定模板文件 + 自动转义，name 不进入模板语法解析",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String name",
            "sink": "model.addAttribute(\"name\", name); return \"greet\"",
            "explanation": "name 通过 Thymeleaf ${name} 变量表达式绑定，自动 HTML 转义，作为字面值渲染，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "页面渲染", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_081.py
from flask import Flask, request, render_template_string

app = Flask(__name__)
# Jinja2 autoescape 默认对 .html 模板启用


@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    # autoescape + {{ var }} 变量绑定，非 f-string 拼接
    return render_template_string(
        '<h1>Hello {{ name }}</h1>',
        name=name,
    )
```""",
        "steps": [
            "第 8 行 request.args.get('name') 获取用户输入",
            "第 10-13 行 render_template_string 模板含 {{ name }} 变量占位符，name=name 为 context 绑定",
            "Flask autoescape 默认启用，{{ name }} 渲染时自动 HTML 转义特殊字符",
            "已检查：autoescape + {{ name }} 变量绑定，name 作为字面值渲染并自动转义，无 SSTI",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "render_template_string('<h1>Hello {{ name }}</h1>', name=name)",
            "explanation": "name 通过 {{ name }} 变量占位符绑定，autoescape 自动 HTML 转义，作为字面值渲染，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "FreeMarker", "scene": "报告生成", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_082.java
import freemarker.template.*;
import freemarker.core.TemplateClassResolver;
import java.io.StringWriter;
import java.util.HashMap;
import org.springframework.web.bind.annotation.*;

@RestController
public class ReportController {
    private final Configuration cfg;

    public ReportController() {
        cfg = new Configuration(Configuration.VERSION_2_3_31);
        // 禁用 ?new 和 ?eval 等危险内置
        cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
        cfg.setAPIBuiltinEnabled(false);
    }

    @GetMapping("/report")
    public String render(@RequestParam String name) throws Exception {
        Template tpl = cfg.getTemplate("report.ftl");
        HashMap<String, Object> ctx = new HashMap<>();
        ctx.put("name", name);
        StringWriter sw = new StringWriter();
        tpl.process(ctx, sw);
        return sw.toString();
    }
}
```""",
        "steps": [
            "第 14 行 cfg.getTemplate(\"report.ftl\") 加载固定模板文件，非用户输入拼接",
            "第 11 行 setNewBuiltinClassResolver(SAFER_RESOLVER) 禁用 ?new 实例化任意类",
            "第 12 行 setAPIBuiltinEnabled(false) 禁用 ?api 访问对象内部 API",
            "已检查：固定模板文件 + ?new/?api 禁用 + ${name} 变量绑定，name 作为字面值渲染，无 SSTI",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "@RequestParam String name",
            "sink": "cfg.getTemplate(\"report.ftl\").process(ctx, sw)",
            "explanation": "name 通过 ctx 传入固定 FreeMarker 模板文件，?new/?api 被禁用，${name} 变量绑定，作为字面值渲染，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Jinja2", "scene": "邮件模板", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_083.py
from jinja2 import Environment, FileSystemLoader
from flask import Flask, request

app = Flask(__name__)
# FileSystemLoader 加载固定模板目录，非用户输入作为模板
env = Environment(loader=FileSystemLoader('/app/templates'), autoescape=True)


@app.route('/preview')
def preview():
    body = request.args.get('body', 'Hello!')
    # get_template 加载固定模板文件，body 作为 context 变量传入
    tpl = env.get_template('email.ftl')
    return tpl.render(body=body)
```""",
        "steps": [
            "第 7 行 FileSystemLoader('/app/templates') 限定模板加载目录，无法加载任意路径",
            "第 12 行 env.get_template('email.ftl') 加载固定模板文件，非用户输入作为模板内容",
            "第 13 行 tpl.render(body=body) body 作为 context 变量传入，模板中 {{ body }} 作为字面值渲染",
            "已检查：FileSystemLoader + 固定模板文件 + 变量绑定 + autoescape，body 不进入模板语法解析",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('body')",
            "sink": "env.get_template('email.ftl').render(body=body)",
            "explanation": "body 通过 FileSystemLoader 加载的固定模板 + render context 传入，autoescape 启用，作为字面值渲染，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Java", "framework": "Spring", "scene": "页面渲染", "has_vuln": False, "difficulty": "中等",
        "code": """```java
// distill_glm_web_084.java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.spring5.SpringTemplateEngine;
import org.thymeleaf.spring5.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

@Configuration
public class TemplateConfig {
    @Bean
    public SpringTemplateEngine templateEngine() {
        SpringTemplateEngine engine = new SpringTemplateEngine();
        engine.setTemplateResolver(templateResolver());
        // 禁用 SpEL 表达式编译器，限制模板表达式能力
        engine.setEnableSpringELCompiler(false);
        return engine;
    }

    private ITemplateResolver templateResolver() {
        SpringResourceTemplateResolver resolver = new SpringResourceTemplateResolver();
        resolver.setPrefix("/WEB-INF/templates/");
        resolver.setSuffix(".html");
        resolver.setCacheable(true);
        return resolver;
    }
}
```""",
        "steps": [
            "第 13-15 行 SpringTemplateEngine 配置固定模板解析器，限定 prefix/suffix 防止路径穿越",
            "第 17 行 setEnableSpringELCompiler(false) 禁用 SpEL 表达式编译器，限制模板内表达式能力",
            "模板文件从固定目录 /WEB-INF/templates/ 加载，用户无法控制模板内容",
            "已检查：固定模板解析器 + SpEL 编译器禁用 + 模板目录限定，无 SSTI",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "Template configuration",
            "sink": "SpringTemplateEngine (setEnableSpringELCompiler(false))",
            "explanation": "SpringTemplateEngine 配置固定模板解析器 + SpEL 编译器禁用 + 模板目录限定，用户无法控制模板内容，无 SSTI",
            "fix_suggestion": "no fix needed",
        },
    },
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    cvss_path = DATA_DIR / "distill_glm_cwe_cvss.jsonl"
    with cvss_path.open("a", encoding="utf-8") as fp:
        for s in CWE_CVSS_BATCH5_NOSQL:
            user = build_user_cwe_cvss("CWE-943 NoSQL注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
        for s in CWE_CVSS_BATCH5_IDOR:
            user = build_user_cwe_cvss("CWE-639 IDOR", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    n_cvss = len(CWE_CVSS_BATCH5_NOSQL) + len(CWE_CVSS_BATCH5_IDOR)
    print(f"[OK] {cvss_path}: appended {n_cvss} samples")

    web_path = DATA_DIR / "distill_glm_web.jsonl"
    with web_path.open("a", encoding="utf-8") as fp:
        for s in WEB_BATCH5_CSRF:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
        for s in WEB_BATCH5_SSTI:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    n_web = len(WEB_BATCH5_CSRF) + len(WEB_BATCH5_SSTI)
    print(f"[OK] {web_path}: appended {n_web} samples")


if __name__ == "__main__":
    main()