"""
Batch 3: 追加到 distill_glm_cwe_cvss.jsonl 和 distill_glm_web.jsonl
- cwe_cvss: CWE-95 代码注入 / eval·exec (12 条: 3 漏洞 + 9 安全)
- web:      CWE-22 路径穿越 (12 条: 3 漏洞 + 9 安全)
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
# Batch 3: cwe_cvss  ——  CWE-95 代码注入 (eval/exec)
# 12 条：3 漏洞 + 9 安全，覆盖 Python / JavaScript / PHP
# =====================================================================

CWE_CVSS_BATCH3 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_025.py
from flask import Flask, request

app = Flask(__name__)


@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    result = eval(expr)
    return {'result': result}
```""",
        "steps": [
            "第 8 行 request.args.get('expr') 获取用户输入，未做白名单或格式校验",
            "第 9 行 eval(expr) 将用户输入作为 Python 表达式直接执行",
            "eval 在当前作用域执行，可访问内置函数 __import__、open 等",
            "source→sink 间无任何防御，攻击者传 expr=__import__('os').system('id') 可执行任意系统命令",
            "CWE-95 代码注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-95 代码注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('expr')",
            "sink": "eval(expr)",
            "explanation": "request.args.get('expr') → expr → eval 执行任意 Python 表达式",
            "fix_suggestion": "使用 ast.literal_eval 替代 eval（仅支持字面量），或用安全表达式解析库如 simpleeval",
        },
    },
    {
        "lang": "Python", "has_vuln": True, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_026.py
from flask import Flask, request

app = Flask(__name__)


@app.route('/run')
def run():
    code = request.args.get('code', '')
    # 限制 builtins 为空，但未限制属性访问
    exec(code, {'__builtins__': {}})
    return {'status': 'executed'}
```""",
        "steps": [
            "第 8 行 request.args.get('code') 获取用户输入",
            "第 10 行 exec(code, {'__builtins__': {}}) 看似限制 builtins 为空字典",
            "但未限制属性访问链，攻击者可通过 ().__class__.__base__.__subclasses__() 访问所有模块",
            "限制 builtins 是脆弱防御，Python 对象模型允许通过属性链逃逸沙箱",
            "CWE-95 代码注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-95 代码注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "request.args.get('code')",
            "sink": "exec(code, {'__builtins__': {}})",
            "explanation": "exec 执行用户输入，{'__builtins__': {}} 限制可被属性链逃逸绕过",
            "fix_suggestion": "禁止 exec 用户输入；如需动态执行，使用 RestrictedPython 或独立沙箱进程",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": True, "difficulty": "典型",
        "code": """```javascript
// distill_glm_cwe_cvss_027.js
const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
    const expr = req.query.expr || '';
    // eval 执行用户输入的表达式
    const result = eval(expr);
    res.json({ result });
});
```""",
        "steps": [
            "第 8 行 req.query.expr 获取用户输入",
            "第 10 行 eval(expr) 将用户输入作为 JavaScript 代码执行",
            "JavaScript eval 可访问全局对象 require、process 等",
            "攻击者传 expr=require('child_process').execSync('id').toString() 可执行系统命令",
            "CWE-95 代码注入，Critical",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-95 代码注入",
            "risk_level": "Critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
            "source": "req.query.expr",
            "sink": "eval(expr)",
            "explanation": "req.query.expr → expr → eval 执行任意 JavaScript 代码",
            "fix_suggestion": "使用 JSON.parse 或安全表达式解析库；如需计算器功能，用 mathjs 等专用库",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_028.py
from flask import Flask, request
import ast

app = Flask(__name__)


@app.route('/parse')
def parse():
    data = request.args.get('data', '')
    # ast.literal_eval 仅支持 Python 字面量（数字/字符串/列表/字典/元组/布尔/None）
    result = ast.literal_eval(data)
    return {'result': result}
```""",
        "steps": [
            "第 9 行 request.args.get('data') 获取用户输入",
            "第 11 行 ast.literal_eval(data) 仅解析 Python 字面量表达式",
            "ast.literal_eval 使用 AST 解析器，遇到函数调用、属性访问等非字面量节点会抛 ValueError",
            "已检查：ast.literal_eval 不执行代码，仅解析字面量，__import__ 等会被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('data')",
            "sink": "ast.literal_eval(data)",
            "explanation": "data 经 ast.literal_eval 解析为字面量，不执行代码，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_029.py
from flask import Flask, request
import json

app = Flask(__name__)


@app.route('/parse')
def parse():
    data = request.args.get('data', '')
    # JSON.parse 等价：json.loads 仅解析 JSON 格式，不执行代码
    result = json.loads(data)
    return {'result': result}
```""",
        "steps": [
            "第 9 行 request.args.get('data') 获取用户输入",
            "第 11 行 json.loads(data) 仅解析 JSON 格式字符串",
            "json.loads 使用 JSON 解析器，不支持 Python 表达式、函数调用或属性访问",
            "已检查：json.loads 仅解析 JSON 数据结构，不执行代码，无代码注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('data')",
            "sink": "json.loads(data)",
            "explanation": "data 经 json.loads 解析为 JSON 对象，不执行代码，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_030.py
from flask import Flask, request

app = Flask(__name__)

# 安全的运算符映射，不使用 eval
OPS = {
    'add': lambda a, b: a + b,
    'sub': lambda a, b: a - b,
    'mul': lambda a, b: a * b,
    'div': lambda a, b: a / b if b != 0 else None,
}


@app.route('/calc')
def calc():
    op = request.args.get('op', '')
    a = float(request.args.get('a', 0))
    b = float(request.args.get('b', 0))
    if op not in OPS:
        return {'error': 'invalid op'}, 400
    return {'result': OPS[op](a, b)}
```""",
        "steps": [
            "第 14-16 行 request.args.get 获取用户输入 op/a/b",
            "第 15-16 行 float() 强制类型转换，非数字输入会被 ValueError 拒绝",
            "第 17-18 行白名单 OPS 校验，仅允许 add/sub/mul/div 四个运算符",
            "已检查：白名单运算符 + 类型转换 + 函数映射，无 eval/exec，无代码注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('op')",
            "sink": "OPS[op](a, b)",
            "explanation": "op 经白名单校验 + a/b 经 float 类型转换，使用函数映射而非 eval，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_cwe_cvss_031.js
const express = require('express');
const app = express();

app.get('/parse', (req, res) => {
    const data = req.query.data || '';
    // JSON.parse 仅解析 JSON，不执行代码
    try {
        const result = JSON.parse(data);
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'invalid JSON' });
    }
});
```""",
        "steps": [
            "第 8 行 req.query.data 获取用户输入",
            "第 10 行 JSON.parse(data) 仅解析 JSON 格式字符串",
            "JSON.parse 使用 JSON 解析器，不支持 JavaScript 表达式或函数调用",
            "已检查：JSON.parse 仅解析 JSON 数据结构，不执行代码，try-catch 处理格式错误",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.data",
            "sink": "JSON.parse(data)",
            "explanation": "data 经 JSON.parse 解析为 JSON 对象，不执行代码，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_032.py
from flask import Flask, request
import yaml

app = Flask(__name__)


@app.route('/config')
def config():
    raw = request.args.get('cfg', '')
    # yaml.safe_load 不执行自定义 Python 标签，仅解析 YAML 数据结构
    cfg = yaml.safe_load(raw)
    return {'config': cfg}
```""",
        "steps": [
            "第 9 行 request.args.get('cfg') 获取用户输入",
            "第 11 行 yaml.safe_load(raw) 仅解析 YAML 数据结构",
            "yaml.safe_load 不支持 !!python/object 等自定义 Python 标签，不会实例化 Python 对象",
            "已检查：使用 safe_load（非 yaml.load），不执行自定义标签，无代码注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('cfg')",
            "sink": "yaml.safe_load(raw)",
            "explanation": "raw 经 yaml.safe_load 解析为 YAML 数据，不执行自定义标签，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_033.py
from flask import Flask, request
import ast

app = Flask(__name__)


@app.route('/sum_list')
def sum_list():
    raw = request.args.get('list', '')
    # ast.literal_eval 解析列表字面量，然后求和
    try:
        lst = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return {'error': 'invalid list'}, 400
    if not isinstance(lst, list) or not all(isinstance(x, (int, float)) for x in lst):
        return {'error': 'invalid elements'}, 400
    return {'sum': sum(lst)}
```""",
        "steps": [
            "第 9 行 request.args.get('list') 获取用户输入",
            "第 12 行 ast.literal_eval(raw) 仅解析 Python 字面量",
            "第 15-16 行 isinstance 校验：必须是 list 且元素全为 int/float",
            "已检查：ast.literal_eval + 类型校验，不执行代码，非列表或非数字元素被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('list')",
            "sink": "ast.literal_eval(raw)",
            "explanation": "raw 经 ast.literal_eval 解析 + isinstance 类型校验，不执行代码，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "has_vuln": False, "difficulty": "中等",
        "code": """```javascript
// distill_glm_cwe_cvss_034.js
const express = require('express');
const { evaluate } = require('mathjs');
const app = express();

app.get('/calc', (req, res) => {
    const expr = req.query.expr || '';
    try {
        // mathjs.evaluate 仅支持数学表达式，不能访问 JS 全局对象
        const result = evaluate(expr);
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'invalid expression' });
    }
});
```""",
        "steps": [
            "第 9 行 req.query.expr 获取用户输入",
            "第 12 行 mathjs.evaluate(expr) 使用 mathjs 库解析数学表达式",
            "mathjs 的 evaluate 仅支持数学运算（加减乘除、函数等），不能访问 require、process 等 JS 全局对象",
            "已检查：mathjs 是专用数学表达式库，沙箱化解析，无 eval，无代码注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.expr",
            "sink": "mathjs.evaluate(expr)",
            "explanation": "expr 经 mathjs.evaluate 解析为数学表达式，不能访问 JS 全局对象，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_cwe_cvss_035.py
from flask import Flask, request

app = Flask(__name__)


@app.route('/int_convert')
def int_convert():
    val = request.args.get('val', '')
    # 使用 int() 类型转换而非 eval
    try:
        num = int(val, base=0)  # base=0 自动识别 0x/0o/0b 前缀
    except ValueError:
        return {'error': 'not a valid integer'}, 400
    return {'value': num}
```""",
        "steps": [
            "第 8 行 request.args.get('val') 获取用户输入",
            "第 11 行 int(val, base=0) 使用 Python 内置类型转换函数",
            "int() 仅解析整数格式（含 0x/0o/0b 前缀），不会执行表达式或函数调用",
            "已检查：使用 int() 类型转换（非 eval），非数字输入被 ValueError 拒绝，无代码注入",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('val')",
            "sink": "int(val, base=0)",
            "explanation": "val 经 int() 类型转换，不执行代码，非数字输入被拒绝，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_cwe_cvss_036.py
from flask import Flask, request
import json

app = Flask(__name__)


@app.route('/template_fill')
def template_fill():
    name = request.args.get('name', '')
    # 使用 str.format 或模板字符串替换，而非 eval
    template = "Hello, {name}! You have {count} messages."
    result = template.format(name=name, count=0)
    return {'message': result}
```""",
        "steps": [
            "第 9 行 request.args.get('name') 获取用户输入",
            "第 11-12 行 str.format(name=name, count=0) 使用关键字参数填充模板",
            "str.format 仅做字符串替换，不执行表达式；{name} 被 name 的值替换，不支持 {__import__('os')}",
            "已检查：str.format 关键字参数填充（非 eval），无代码执行",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "template.format(name=name, count=0)",
            "explanation": "name 经 str.format 关键字参数填充模板，不执行代码，无代码注入",
            "fix_suggestion": "no fix needed",
        },
    },
]


# =====================================================================
# Batch 3: web  ——  CWE-22 路径穿越
# 12 条：3 漏洞 + 9 安全，覆盖 Flask / Django / Express / FastAPI
# =====================================================================

WEB_BATCH3 = [
    # ----- 漏洞样本 3 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "文件下载", "has_vuln": True, "difficulty": "典型",
        "code": """```python
# distill_glm_web_025.py
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route('/download')
def download():
    filename = request.args.get('file', '')
    filepath = '/var/www/uploads/' + filename
    return send_file(filepath)
```""",
        "steps": [
            "第 8 行 request.args.get('file') 获取用户输入，未做路径校验",
            "第 9 行用 + 把 filename 拼接到基础路径，未过滤 ../ 序列",
            "第 10 行 send_file 读取拼接后的路径并发送给客户端",
            "攻击者传 file=../../../etc/passwd 可穿越到任意目录读取系统文件",
            "CWE-22 路径穿越，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-22 路径穿越",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.args.get('file')",
            "sink": "send_file('/var/www/uploads/' + filename)",
            "explanation": "request.args.get('file') → filename → + 拼接 → send_file 读取穿越路径",
            "fix_suggestion": "使用 send_from_directory + secure_filename，或校验 realpath 后的路径是否在基础目录内",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "文件读取", "has_vuln": True, "difficulty": "防御迷惑",
        "code": """```python
# distill_glm_web_026.py
from django.http import HttpResponse
import os

BASE_DIR = '/var/www/uploads'


def view_file(request):
    name = request.GET.get('name', '')
    # 防御：检查是否包含 ..
    if '..' in name:
        return HttpResponse('invalid filename', status=400)
    filepath = os.path.join(BASE_DIR, name)
    with open(filepath, 'rb') as f:
        return HttpResponse(f.read())
```""",
        "steps": [
            "第 8 行 request.GET.get('name') 获取用户输入",
            "第 10-11 行 if '..' in name 检查字面量 ..，看似防御路径穿越",
            "但仅检查字面量 ..，未规范化路径；攻击者可用 %2e%2e%2f 或符号链接绕过",
            "第 12 行 os.path.join(BASE_DIR, name) 拼接后未做 realpath 校验",
            "CWE-22 路径穿越，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-22 路径穿越",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "request.GET.get('name')",
            "sink": "open(os.path.join(BASE_DIR, name))",
            "explanation": "if '..' in name 仅检查字面量，未规范化路径，可被编码绕过或符号链接绕过",
            "fix_suggestion": "使用 os.path.realpath 规范化后校验 startswith(BASE_DIR)，或用 secure_filename",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "文件下载", "has_vuln": True, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_026.js
const express = require('express');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
    const file = req.query.file || '';
    const filePath = path.join('/var/www/uploads', file);
    res.sendFile(filePath);
});
```""",
        "steps": [
            "第 8 行 req.query.file 获取用户输入",
            "第 9 行 path.join('/var/www/uploads', file) 拼接路径，未过滤 ../",
            "第 10 行 res.sendFile 读取拼接后的路径并发送给客户端",
            "攻击者传 file=../../../etc/passwd 可穿越到任意目录",
            "CWE-22 路径穿越，High",
        ],
        "json": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-22 路径穿越",
            "risk_level": "High",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "source": "req.query.file",
            "sink": "res.sendFile(path.join('/var/www/uploads', file))",
            "explanation": "req.query.file → file → path.join 拼接 → res.sendFile 读取穿越路径",
            "fix_suggestion": "使用 path.resolve 规范化后校验 startsWith(baseDir)，或用 sanitize-filename",
        },
    },
    # ----- 安全样本 9 条 -----
    {
        "lang": "Python", "framework": "Flask", "scene": "文件下载", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_027.py
from flask import Flask, request, send_from_directory

app = Flask(__name__)

UPLOAD_DIR = '/var/www/uploads'


@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # send_from_directory 内部使用 safe_join 防止路径穿越
    return send_from_directory(UPLOAD_DIR, filename)
```""",
        "steps": [
            "第 8 行 request.args.get('file') 获取用户输入",
            "第 10 行 send_from_directory(UPLOAD_DIR, filename) 使用 Flask 内置安全函数",
            "send_from_directory 内部调用 werkzeug.utils.safe_join，检测到 ../ 会抛 BadRequest",
            "已检查：send_from_directory + safe_join 防止路径穿越，../ 序列会被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('file')",
            "sink": "send_from_directory(UPLOAD_DIR, filename)",
            "explanation": "filename 经 send_from_directory 的 safe_join 校验，../ 会被拒绝，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "文件下载", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_028.py
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

BASE_DIR = os.path.realpath('/var/www/uploads')


@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # secure_filename 过滤路径分隔符和 ..
    safe_name = secure_filename(filename)
    if not safe_name:
        return {'error': 'invalid filename'}, 400
    filepath = os.path.join(BASE_DIR, safe_name)
    return send_file(filepath)
```""",
        "steps": [
            "第 9 行 request.args.get('file') 获取用户输入",
            "第 11 行 secure_filename(filename) 过滤路径分隔符、.. 等危险字符，仅保留文件名部分",
            "第 14 行 os.path.join(BASE_DIR, safe_name) 拼接，safe_name 已不含路径分隔符",
            "已检查：secure_filename 过滤 + realpath 基础目录，文件名被限制为单层，无路径穿越",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('file')",
            "sink": "send_file(os.path.join(BASE_DIR, safe_name))",
            "explanation": "filename 经 secure_filename 过滤路径分隔符 + ..，仅保留文件名，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "文件读取", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_029.py
from flask import Flask, request
import os

app = Flask(__name__)

BASE_DIR = os.path.realpath('/var/www/uploads')


@app.route('/view')
def view():
    name = request.args.get('name', '')
    filepath = os.path.realpath(os.path.join(BASE_DIR, name))
    # 校验规范化后的路径是否在基础目录内
    if not filepath.startswith(BASE_DIR + os.sep):
        return {'error': 'access denied'}, 403
    with open(filepath, 'r') as f:
        return {'content': f.read()}
```""",
        "steps": [
            "第 8 行 request.args.get('name') 获取用户输入",
            "第 9 行 os.path.realpath(os.path.join(BASE_DIR, name)) 规范化路径，解析符号链接和 ../",
            "第 10-11 行 filepath.startswith(BASE_DIR + os.sep) 校验规范化路径是否在基础目录内",
            "已检查：realpath 规范化 + startswith 边界校验，../ 会被 realpath 解析后超出 BASE_DIR 被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('name')",
            "sink": "open(os.path.realpath(os.path.join(BASE_DIR, name)))",
            "explanation": "name 经 realpath 规范化 + startswith(BASE_DIR + sep) 校验，超出边界被 403 拒绝，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "文件下载", "has_vuln": False, "difficulty": "典型",
        "code": """```javascript
// distill_glm_web_030.js
const express = require('express');
const path = require('path');
const app = express();

const BASE_DIR = path.resolve('/var/www/uploads');

app.get('/download', (req, res) => {
    const file = req.query.file || '';
    const filePath = path.resolve(BASE_DIR, file);
    // 校验规范化后的路径是否在基础目录内
    if (!filePath.startsWith(BASE_DIR + path.sep)) {
        return res.status(403).json({ error: 'access denied' });
    }
    res.sendFile(filePath);
});
```""",
        "steps": [
            "第 8 行 req.query.file 获取用户输入",
            "第 9 行 path.resolve(BASE_DIR, file) 规范化路径，解析 ../ 序列",
            "第 10-11 行 filePath.startsWith(BASE_DIR + path.sep) 校验是否在基础目录内",
            "已检查：path.resolve 规范化 + startsWith 边界校验，../ 会被解析后超出 BASE_DIR 被拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.file",
            "sink": "res.sendFile(path.resolve(BASE_DIR, file))",
            "explanation": "file 经 path.resolve 规范化 + startsWith 边界校验，超出边界被 403 拒绝，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "FastAPI", "scene": "文件下载", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_031.py
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
import os

app = FastAPI()
BASE_DIR = os.path.realpath('/var/www/uploads')


@app.get('/download')
def download(file: str = Query(..., max_length=255)):
    # 禁止路径分隔符和 ..
    if '/' in file or '\\\\' in file or '..' in file:
        raise HTTPException(400, 'invalid filename')
    filepath = os.path.join(BASE_DIR, file)
    if not os.path.isfile(filepath):
        raise HTTPException(404, 'file not found')
    return FileResponse(filepath)
```""",
        "steps": [
            "第 10 行 file: str = Query(..., max_length=255) 获取用户输入并限制长度",
            "第 11-12 行校验：禁止 / \\\\ .. 三个路径穿越关键字符",
            "第 13 行 os.path.join(BASE_DIR, file) 拼接，file 已不含路径分隔符或 ..",
            "已检查：路径分隔符 + .. 字符校验 + 长度限制 + isfile 校验，无路径穿越",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "file: str = Query(..., max_length=255)",
            "sink": "FileResponse(os.path.join(BASE_DIR, file))",
            "explanation": "file 经路径分隔符 + .. 字符校验 + 长度限制，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "文件下载", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_032.py
from flask import Flask, request, send_file
import os

app = Flask(__name__)

BASE_DIR = os.path.realpath('/var/www/uploads')

# 白名单：仅允许这些文件被下载
ALLOWED_FILES = {'report.pdf', 'manual.pdf', 'guide.pdf'}


@app.route('/download')
def download():
    filename = request.args.get('file', '')
    if filename not in ALLOWED_FILES:
        return {'error': 'file not available'}, 404
    filepath = os.path.join(BASE_DIR, filename)
    return send_file(filepath)
```""",
        "steps": [
            "第 8 行 request.args.get('file') 获取用户输入",
            "第 9-10 行白名单 ALLOWED_FILES 校验，仅允许 report.pdf/manual.pdf/guide.pdf",
            "第 11 行 os.path.join(BASE_DIR, filename) 拼接，filename 已被白名单限定为固定文件名",
            "已检查：白名单枚举校验，filename 只能是三个固定文件名之一，无路径穿越",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "request.args.get('file')",
            "sink": "send_file(os.path.join(BASE_DIR, filename))",
            "explanation": "filename 经白名单枚举校验，仅允许固定文件名，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Django", "scene": "文件下载", "has_vuln": False, "difficulty": "中等",
        "code": """```python
# distill_glm_web_033.py
from django.http import FileResponse, Http404
import os

BASE_DIR = os.path.realpath('/var/www/uploads')


def download(request, filename):
    filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not filepath.startswith(BASE_DIR + os.sep):
        raise Http404('file not found')
    if not os.path.isfile(filepath):
        raise Http404('file not found')
    return FileResponse(open(filepath, 'rb'))
```""",
        "steps": [
            "第 7 行 filename 来自 URL 路径参数（用户可控）",
            "第 8 行 os.path.realpath(os.path.join(BASE_DIR, filename)) 规范化路径",
            "第 9-10 行 filepath.startswith(BASE_DIR + os.sep) 校验是否在基础目录内",
            "已检查：realpath 规范化 + startswith 边界校验 + isfile 校验，超出边界返回 404，无路径穿越",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "filename（URL 路径参数）",
            "sink": "FileResponse(open(filepath, 'rb'))",
            "explanation": "filename 经 realpath 规范化 + startswith 边界校验，超出边界返回 404，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "JavaScript", "framework": "Express", "scene": "文件下载", "has_vuln": False, "difficulty": "中等",
        "code": """```javascript
// distill_glm_web_034.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

const BASE_DIR = path.resolve('/var/www/uploads');

app.get('/download', (req, res) => {
    const file = req.query.file || '';
    // 禁止路径分隔符和 ..
    if (file.includes('/') || file.includes('\\\\') || file.includes('..')) {
        return res.status(400).json({ error: 'invalid filename' });
    }
    const filePath = path.join(BASE_DIR, file);
    fs.accessSync(filePath, fs.constants.R_OK);
    res.sendFile(filePath);
});
```""",
        "steps": [
            "第 8 行 req.query.file 获取用户输入",
            "第 10-11 行校验：禁止 / \\\\ .. 三个路径穿越关键字符",
            "第 12 行 path.join(BASE_DIR, file) 拼接，file 已不含路径分隔符或 ..",
            "已检查：路径分隔符 + .. 字符校验 + accessSync 权限校验，无路径穿越",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "req.query.file",
            "sink": "res.sendFile(path.join(BASE_DIR, file))",
            "explanation": "file 经路径分隔符 + .. 字符校验，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
    {
        "lang": "Python", "framework": "Flask", "scene": "文件下载", "has_vuln": False, "difficulty": "典型",
        "code": """```python
# distill_glm_web_035.py
from flask import Flask, request, abort
import os

app = Flask(__name__)

BASE_DIR = os.path.realpath('/var/www/uploads')


@app.route('/download/<path:filename>')
def download(filename):
    # <path:filename> 会匹配含 / 的路径，需校验
    filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
    try:
        # os.path.relpath 校验是否在基础目录内
        rel = os.path.relpath(filepath, BASE_DIR)
        if rel.startswith('..'):
            abort(403)
    except ValueError:
        abort(403)
    if not os.path.isfile(filepath):
        abort(404)
    with open(filepath, 'rb') as f:
        return f.read()
```""",
        "steps": [
            "第 9 行 filename 来自 URL 路径参数（用户可控，<path:filename> 匹配含 / 的路径）",
            "第 10 行 os.path.realpath(os.path.join(BASE_DIR, filename)) 规范化路径",
            "第 12-14 行 os.path.relpath(filepath, BASE_DIR) 计算相对路径，若以 .. 开头说明超出基础目录",
            "已检查：realpath 规范化 + relpath 相对路径校验 + isfile 校验，超出边界被 403 拒绝",
            "无漏洞",
        ],
        "json": {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "cvss_vector": "N/A",
            "cvss_score": 0.0,
            "source": "filename（URL path 参数）",
            "sink": "open(os.path.realpath(os.path.join(BASE_DIR, filename)))",
            "explanation": "filename 经 realpath 规范化 + relpath 校验是否在基础目录内，超出边界被 403 拒绝，无路径穿越",
            "fix_suggestion": "no fix needed",
        },
    },
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    cvss_path = DATA_DIR / "distill_glm_cwe_cvss.jsonl"
    with cvss_path.open("a", encoding="utf-8") as fp:
        for s in CWE_CVSS_BATCH3:
            user = build_user_cwe_cvss("CWE-95 代码注入", s["lang"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {cvss_path}: appended {len(CWE_CVSS_BATCH3)} samples (CWE-95)")

    web_path = DATA_DIR / "distill_glm_web.jsonl"
    with web_path.open("a", encoding="utf-8") as fp:
        for s in WEB_BATCH3:
            user = build_user_web(s["lang"], s["framework"], s["scene"], s["has_vuln"], s["difficulty"])
            assistant = assistant_response(s["code"], s["steps"], s["json"])
            write_sample(fp, GLM_SYSTEM, user, assistant)
    print(f"[OK] {web_path}: appended {len(WEB_BATCH3)} samples (CWE-22)")


if __name__ == "__main__":
    main()
