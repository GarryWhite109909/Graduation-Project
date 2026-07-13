"""
NoSQL 注入（CWE-643）CWE 归因推理补充样本生成。

背景：
  微调后模型把 NoSQL 注入误标为 CWE-89（SQL 注入），根因是训练数据 CoT 缺少
  "CWE 归因推理"步骤——模型没学到如何区分 CWE-643 与 CWE-89。本脚本生成
  9 条高质量 NoSQL 样本（7 漏洞 + 2 安全），CoT 第 5 步显式推理"为什么
  是 CWE-643 而不是 CWE-89/78"，覆盖 MongoDB $where/$ne/$regex/aggregate、
  PyMongo 字典注入、Node.js find 注入、Redis EVAL 注入等主流场景。

  漏洞样本的 CoT 必须包含 6 步，第 5 步"CWE 归因"显式排除 CWE-89 和 CWE-78，
  确定 CWE-643；安全样本的 CoT 第 5 步显式说明为何不构成 CWE-643。

输出：
  data/supplement_cwe_attribution_nosql.jsonl（9 条 ChatML 样本）

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python \
      experiments/exp_06_finetune/scripts/supplement_cwe_attribution_nosql.py
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_cwe_attribution_nosql.jsonl"

# ---------------------------------------------------------------------------
# SYSTEM_PROMPT_LITE（固定，每条样本通用）
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LITE = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化、"
    "日志注入（CWE-117）、弱密码学（MD5/SHA1 哈希密码、CWE-327）、"
    "弱随机数（random 模块生成 token、CWE-330）、CSRF、"
    "SSTI、XXE、SSRF、未授权访问、安全配置错误、文件上传、"
    "会话固定、LDAP 注入、NoSQL 注入、XPath 注入、表达式注入（SpEL/OGNL）。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定必须基于代码实际内容，不能凭空臆造 API 参数或行为。\n"
    "4. 用户输入到达 sink 不等于漏洞，必须看 sink 前的防御措施是否有效。\n"
    "5. 硬编码的字面量凭证（key/secret/password/token）本身就是漏洞，"
    "不要降级为“敏感但非漏洞”。\n"
    "6. 结论一致性校验：JSON 的 has_vulnerability 必须与上述分析过程的推理结论一致。"
    "若分析过程中识别出风险（如“弱随机”“不安全”“存在漏洞”），JSON 不得标 false；"
    "若分析过程未识别出风险，JSON 不得标 true。\n\n"
    "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    "- has_vulnerability: boolean\n"
    "- vulnerability_type: string（如 \"CWE-89 SQL注入\" 或 \"none\"）\n"
    "- risk_level: string（\"Critical\"/\"High\"/\"Medium\"/\"Low\"/\"none\"）\n"
    "- source: string（污染源，如 \"request.args.get('id')\"）\n"
    "- sink: string（危险 sink）\n"
    "- taint_path: string（数据流路径）\n"
    "- explanation: string（简要说明）\n\n"
    "请先给出分析过程，然后在最后给出 JSON 结论。"
)


# ===========================================================================
# 样本定义：9 条（7 漏洞 + 2 安全）
# 每条含 code / language / filename / cot / verdict
# CoT 第 5 步为 CWE 归因，显式区分 CWE-643 与 CWE-89/78
# ===========================================================================
SAMPLES = [
    # =====================================================================
    # 漏洞样本 1: MongoDB $where 用户输入直接拼入
    # =====================================================================
    {
        "filename": "nosql_01_mongo_where.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.users


@app.route("/search")
def search():
    name = request.args.get("name", "")
    query = {"$where": "this.name == '" + name + "'"}
    result = db.users.find(query)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：db.users.find(query) 执行含 $where 的 MongoDB 查询，$where 会对传入的 JavaScript 表达式求值。
3. 数据流：name → 字符串拼接到 $where 表达式（"this.name == '" + name + "'"）→ find() 执行 JavaScript 求值。
4. 防御检查：未对 $where 中的用户输入做转义或参数化处理，未禁用 $where 操作符，字符串拼接允许注入任意 JavaScript 表达式。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行（subprocess/os.system），用户输入进入的是 MongoDB 查询而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入直接拼入 $where 查询条件，$where 接受 JavaScript 表达式求值，可注入 `'||'1'=='1` 等载荷篡改查询逻辑
6. 结论：用户输入未经转义拼入 MongoDB $where 表达式，$where 对 JavaScript 求值，可注入任意表达式绕过查询条件，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "Critical",
            "source": "request.args.get('name')",
            "sink": "db.users.find({\"$where\": ...})",
            "taint_path": "name → 字符串拼接到 $where 表达式 → find() 执行 JavaScript 求值",
            "explanation": "用户输入拼入 MongoDB $where 条件，$where 对 JavaScript 表达式求值，攻击者可注入 `'||'1'=='1` 篡改查询逻辑",
        },
    },
    # =====================================================================
    # 漏洞样本 2: MongoDB $ne 用户输入绕过密码验证
    # =====================================================================
    {
        "filename": "nosql_02_mongo_ne.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.auth


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    query = {"username": data.get("username"), "password": data.get("password")}
    user = db.users.find_one(query)
    return "ok" if user else "fail"''',
        "cot": """分析过程：
1. 污染源：request.get_json() 获取 JSON 请求体中的 username 和 password。
2. 危险 sink：db.users.find_one(query) 执行 MongoDB 查询。
3. 数据流：data['password'] → 直接作为 query['password'] 的值 → find_one(query) 执行查询。
4. 防御检查：未对 password 字段做类型校验（应限定为字符串），未禁用查询操作符，JSON 请求体中的 password 可为任意类型（包括字典）。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入进入的是 MongoDB 查询而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入直接作为查询条件值，JSON 请求体可为 {"password": {"$ne": "wrong"}}，使查询变为 {"username":"admin","password":{"$ne":"wrong"}} 匹配任意密码不为 "wrong" 的用户，绕过认证
6. 结论：用户输入直接作为 MongoDB 查询条件值且未做类型约束，攻击者可注入 $ne/$gt 等操作符篡改查询逻辑绕过密码验证，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "Critical",
            "source": "request.get_json()",
            "sink": "db.users.find_one(query)",
            "taint_path": "data['password'] → query['password'] → find_one 执行查询",
            "explanation": "用户输入直接作为查询条件值，可注入 {\"password\":{\"$ne\":\"wrong\"}} 绕过密码验证",
        },
    },
    # =====================================================================
    # 漏洞样本 3: MongoDB $regex 用户输入正则注入
    # =====================================================================
    {
        "filename": "nosql_03_mongo_regex.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.users


@app.route("/lookup")
def lookup():
    email = request.args.get("email", "")
    query = {"email": {"$regex": email}}
    result = db.users.find(query)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args.get('email') 获取用户输入。
2. 危险 sink：db.users.find(query) 执行含 $regex 的 MongoDB 查询。
3. 数据流：email → 作为 $regex 的值传入查询（{"email": {"$regex": email}}）→ find() 执行正则匹配。
4. 防御检查：未对 email 做正则特殊字符转义，未限制正则复杂度，用户可控制完整正则模式进行盲注或 ReDoS。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入进入的是 MongoDB 查询而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入直接作为 $regex 的正则模式，可注入 `^a`、`.*` 等模式逐字符提取数据或进行 ReDoS 攻击
6. 结论：用户输入直接作为 MongoDB $regex 的正则模式，攻击者可构造正则表达式进行盲注提取数据或造成 ReDoS，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "High",
            "source": "request.args.get('email')",
            "sink": "db.users.find({\"email\": {\"$regex\": email}})",
            "taint_path": "email → $regex 正则模式 → find() 执行正则匹配",
            "explanation": "用户输入直接作为 $regex 正则模式，攻击者可注入 ^a 等模式逐字符盲注提取邮箱数据",
        },
    },
    # =====================================================================
    # 漏洞样本 4: PyMongo 用户输入直接拼入查询字典
    # =====================================================================
    {
        "filename": "nosql_04_pymongo_dict.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient
import json

app = Flask(__name__)
client = MongoClient()
db = client.shop


@app.route("/find")
def find():
    raw = request.args.get("filter", "{}")
    query = dict(json.loads(raw))
    result = db.products.find(query)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args.get('filter') 获取用户输入的 JSON 字符串。
2. 危险 sink：db.products.find(query) 执行 MongoDB 查询。
3. 数据流：raw → json.loads 解析为 dict → dict() 复制 → find() 执行查询。
4. 防御检查：未对解析后的字典做键/值白名单校验，未禁用 $ 开头的操作符，用户可控制整个查询文档的结构。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入进入的是 MongoDB 查询而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入经 json.loads 解析为字典后直接作为查询文档，可注入 {"price": {"$gt": 0}} 或 {"$where": "..."} 等操作符篡改查询逻辑
6. 结论：用户输入的 JSON 字符串解析后直接作为 MongoDB 查询文档，攻击者可注入任意查询操作符，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "Critical",
            "source": "request.args.get('filter')",
            "sink": "db.products.find(query)",
            "taint_path": "raw → json.loads 解析为 dict → dict() → find() 执行查询",
            "explanation": "用户输入的 JSON 解析后直接作为查询文档，可注入 {\"price\":{\"$gt\":0}} 或 $where 等操作符",
        },
    },
    # =====================================================================
    # 漏洞样本 5: Node.js MongoDB find() 用户输入直接传入
    # =====================================================================
    {
        "filename": "nosql_05_mongo_find.js",
        "language": "javascript",
        "code": '''const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const app = express();

app.get('/login', async (req, res) => {
    const client = await MongoClient.connect('mongodb://localhost:27017');
    const db = client.db('auth');
    const query = { username: req.query.username, password: req.query.password };
    const user = await db.collection('users').findOne(query);
    res.json({ ok: !!user });
});

app.listen(3000);''',
        "cot": """分析过程：
1. 污染源：req.query.username 和 req.query.password 获取用户输入。
2. 危险 sink：db.collection('users').findOne(query) 执行 MongoDB 查询。
3. 数据流：req.query.password → query.password → findOne(query) 执行查询。
4. 防御检查：未对 password 做类型校验（Express 的 querystring 解析支持嵌套对象），未禁用 $ 开头的操作符，password 可为 {"$ne": "wrong"} 等对象。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行（child_process），用户输入进入的是 MongoDB 查询而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：Express 的 querystring 解析支持嵌套对象，攻击者可传 password[$ne]=wrong 使 query 变为 {password:{"$ne":"wrong"}} 绕过密码验证
6. 结论：用户输入直接作为 MongoDB 查询条件值，Express querystring 嵌套解析允许注入 $ne 等操作符，可绕过认证，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "Critical",
            "source": "req.query.password",
            "sink": "db.collection('users').findOne(query)",
            "taint_path": "req.query.password → query.password → findOne 执行查询",
            "explanation": "Express querystring 嵌套解析允许注入 password[$ne]=wrong 使查询变为 {password:{\"$ne\":\"wrong\"}} 绕过认证",
        },
    },
    # =====================================================================
    # 漏洞样本 6: Redis EVAL 用户输入拼入 Lua 脚本
    # =====================================================================
    {
        "filename": "nosql_06_redis_eval.py",
        "language": "python",
        "code": '''from flask import Flask, request
import redis

app = Flask(__name__)
r = redis.Redis()


@app.route("/get")
def get_key():
    key = request.args.get("key", "")
    script = "return redis.call('GET', '" + key + "')"
    result = r.eval(script, 0)
    return str(result)''',
        "cot": """分析过程：
1. 污染源：request.args.get('key') 获取用户输入。
2. 危险 sink：r.eval(script, 0) 执行 Lua 脚本，Redis EVAL 会对脚本字符串中的 Lua 代码求值。
3. 数据流：key → 字符串拼接到 Lua 脚本（"return redis.call('GET', '" + key + "')"）→ r.eval 执行 Lua 求值。
4. 防御检查：未对 key 做转义处理，未使用 EVALSHA + 参数化（KEYS/ARGV 传递），字符串拼接允许注入任意 Lua 代码。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 Redis 键值型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行（subprocess/os.system），用户输入进入的是 Redis EVAL 的 Lua 脚本而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入拼入 Redis EVAL 的 Lua 脚本，可注入 `'); return redis.call('KEYS','*` 等载荷执行任意 Redis 命令，篡改查询逻辑
6. 结论：用户输入未经转义拼入 Redis EVAL 的 Lua 脚本，可注入任意 Lua 代码执行 Redis 命令，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "Critical",
            "source": "request.args.get('key')",
            "sink": "r.eval(script, 0)",
            "taint_path": "key → 字符串拼接到 Lua 脚本 → r.eval 执行 Lua 求值",
            "explanation": "用户输入拼入 Redis EVAL 的 Lua 脚本，可注入 '); return redis.call('KEYS','* 执行任意 Redis 命令",
        },
    },
    # =====================================================================
    # 漏洞样本 7: MongoDB aggregate pipeline 用户输入
    # =====================================================================
    {
        "filename": "nosql_07_mongo_aggregate.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient
import json

app = Flask(__name__)
client = MongoClient()
db = client.sales


@app.route("/report")
def report():
    raw = request.args.get("match", "{}")
    pipeline = [{"$match": json.loads(raw)}, {"$group": {"_id": "$category", "total": {"$sum": "$amount"}}}]
    result = db.orders.aggregate(pipeline)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args.get('match') 获取用户输入的 JSON 字符串。
2. 危险 sink：db.orders.aggregate(pipeline) 执行 MongoDB 聚合管道。
3. 数据流：raw → json.loads 解析为字典 → 作为 $match 阶段的查询条件 → aggregate 执行管道。
4. 防御检查：未对解析后的 $match 字典做键/值白名单校验，未禁用 $where/$ne 等操作符，用户可控制 $match 阶段的完整查询条件。
5. CWE 归因：
   - 漏洞类型：NoSQL 注入
   - 排除 CWE-89（SQL 注入）：不涉及 SQL 语句和关系型数据库，使用的是 MongoDB 文档型 NoSQL 数据库
   - 排除 CWE-78（命令注入）：不涉及系统命令执行，用户输入进入的是 MongoDB 聚合管道而非 shell
   - 确定 CWE-643（数据中介的 NoSQL 注入）：用户输入解析后直接作为聚合管道 $match 阶段的查询条件，可注入 {"$where": "..."} 或 {"price": {"$gt": 0}} 等操作符篡改聚合逻辑
6. 结论：用户输入的 JSON 解析后直接作为聚合管道 $match 阶段查询条件，攻击者可注入任意操作符篡改聚合逻辑，存在 NoSQL 注入漏洞。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-643 NoSQL注入",
            "risk_level": "High",
            "source": "request.args.get('match')",
            "sink": "db.orders.aggregate(pipeline)",
            "taint_path": "raw → json.loads → $match 查询条件 → aggregate 执行管道",
            "explanation": "用户输入解析后作为聚合管道 $match 查询条件，可注入 $where 或 $gt 等操作符篡改聚合逻辑",
        },
    },
    # =====================================================================
    # 安全样本 8: PyMongo 参数化查询（字面值传入）
    # =====================================================================
    {
        "filename": "safe_nosql_01_pymongo_param.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.users


@app.route("/search")
def search():
    name = request.args.get("name", "")
    query = {"name": name}
    result = db.users.find(query)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：db.users.find(query) 执行 MongoDB 查询。
3. 数据流：name → 作为 query['name'] 的值（{"name": name}）→ find() 执行查询。
4. 防御检查：request.args.get 返回字符串字面值，查询键 "name" 为固定常量，用户输入仅作为字面值传入而非操作符字典，无法注入 $ne/$where 等操作符。
5. CWE 归因：
   - 不构成 CWE-643（NoSQL 注入）：request.args.get 返回字符串字面值，查询键为固定常量 "name"，用户输入仅作为字面值查询条件传入，无法构造 {"$ne": ...} 等操作符字典
6. 结论：安全，用户输入作为字符串字面值传入固定键的查询条件，无法注入 NoSQL 操作符，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "request.args.get 返回字符串字面值，查询键为固定常量，用户输入无法构造操作符字典",
        },
    },
    # =====================================================================
    # 安全样本 9: MongoDB 查询前白名单校验
    # =====================================================================
    {
        "filename": "safe_nosql_02_mongo_whitelist.py",
        "language": "python",
        "code": '''from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client.users

ALLOWED_FIELDS = {"name", "email", "status"}


def build_query(params):
    query = {}
    for key, value in params.items():
        if key in ALLOWED_FIELDS and isinstance(value, str):
            query[key] = value
    return query


@app.route("/search")
def search():
    query = build_query(request.args)
    result = db.users.find(query)
    return str(list(result))''',
        "cot": """分析过程：
1. 污染源：request.args 获取用户输入的查询参数。
2. 危险 sink：db.users.find(query) 执行 MongoDB 查询。
3. 数据流：request.args → build_query 过滤 → query 字典 → find() 执行查询。
4. 防御检查：build_query 对查询键做白名单校验（ALLOWED_FIELDS），对值做 isinstance(value, str) 类型校验，只允许字符串字面值进入查询，拒绝字典/列表等非字符串类型，无法注入 $ne/$where 等操作符。
5. CWE 归因：
   - 不构成 CWE-643（NoSQL 注入）：对查询键做白名单校验且对值做 isinstance(str) 类型校验，只允许字面值查询，不允许 $where/$ne 等操作符字典进入查询
6. 结论：安全，白名单校验键 + 类型校验值，用户输入只能作为字符串字面值查询，无法注入 NoSQL 操作符，未发现漏洞。""",
        "verdict": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "none",
            "source": "none",
            "sink": "none",
            "taint_path": "none",
            "explanation": "白名单校验查询键 + isinstance(str) 校验值，只允许字面值查询，无法注入操作符",
        },
    },
]


# ===========================================================================
# 构建与写入逻辑
# ===========================================================================
def build_sample(sample: dict) -> dict:
    """构建一条 ChatML 样本。"""
    user_prompt = build_user_prompt(
        code=sample["code"], language=sample["language"], filename=sample["filename"]
    )
    json_str = json.dumps(sample["verdict"], ensure_ascii=False, indent=2)
    assistant_content = f"{sample['cot']}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def verify_output(filepath: Path) -> None:
    """验证输出文件：合法 JSON、3 条消息、json 块可解析、CWE 归因正确。"""
    print("\n=== 验证输出文件 ===")
    with open(filepath, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]

    errors = []
    cwe_counter = Counter()

    for i, line in enumerate(lines, 1):
        # 1. 合法 JSON
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"行 {i}: JSON 解析失败 - {e}")
            continue

        # 2. messages 有 3 条
        messages = obj.get("messages", [])
        if len(messages) != 3:
            errors.append(f"行 {i}: messages 数量为 {len(messages)}，期望 3")
            continue

        roles = [m["role"] for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"行 {i}: roles 为 {roles}，期望 [system, user, assistant]")
            continue

        # 3. assistant content 包含可解析的 ```json 块
        assistant_content = messages[2]["content"]
        json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
        if not json_blocks:
            errors.append(f"行 {i}: assistant content 中未找到 ```json 块")
            continue

        verdict = None
        for block in json_blocks:
            try:
                verdict = json.loads(block)
                break
            except json.JSONDecodeError:
                continue
        if verdict is None:
            errors.append(f"行 {i}: JSON 块无法解析")
            continue

        has_vuln = verdict.get("has_vulnerability")
        vuln_type = verdict.get("vulnerability_type", "")

        # 4. 漏洞样本的 vulnerability_type 包含 "CWE-643"
        if has_vuln is True:
            if "CWE-643" not in vuln_type:
                errors.append(f"行 {i}: 漏洞样本 vulnerability_type 为 '{vuln_type}'，缺少 'CWE-643'")
            cwe_counter[vuln_type] += 1
        # 5. 安全样本的 has_vulnerability 为 false
        elif has_vuln is False:
            if vuln_type != "none":
                errors.append(f"行 {i}: 安全样本 vulnerability_type 为 '{vuln_type}'，期望 'none'")
            cwe_counter["none（安全）"] += 1
        else:
            errors.append(f"行 {i}: has_vulnerability 为 {has_vuln}，非布尔值")

    if errors:
        print(f"发现 {len(errors)} 个错误：")
        for e in errors:
            print(f"  [ERROR] {e}")
    else:
        print("所有验证通过：")
        print(f"  - {len(lines)} 条样本均为合法 JSON")
        print(f"  - 每条 messages 数组有 3 条（system/user/assistant）")
        print(f"  - assistant content 的 ```json 块均可解析")
        print(f"  - 漏洞样本 vulnerability_type 均包含 'CWE-643'")
        print(f"  - 安全样本 has_vulnerability 均为 false")

    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")


def main():
    print(f"生成 {len(SAMPLES)} 条 NoSQL 注入（CWE-643）CWE 归因推理补充样本")
    vuln_count = sum(1 for s in SAMPLES if s["verdict"]["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    print(f"  漏洞样本: {vuln_count} 条")
    print(f"  安全样本: {safe_count} 条")
    print(f"输出: {OUTPUT_FILE}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            chatml = build_sample(s)
            f.write(json.dumps(chatml, ensure_ascii=False) + "\n")

    # 确认写入数量
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    print(f"\n已写入 {len(lines)} 条样本")

    # CWE 分布统计
    cwe_counter = Counter()
    for s in SAMPLES:
        v = s["verdict"]
        if v["has_vulnerability"]:
            cwe_counter[v["vulnerability_type"]] += 1
        else:
            cwe_counter["none（安全）"] += 1
    print(f"\nCWE 分布统计：")
    for k, v in cwe_counter.most_common():
        print(f"  {v}  {k}")

    # 验证
    verify_output(OUTPUT_FILE)


if __name__ == "__main__":
    main()
