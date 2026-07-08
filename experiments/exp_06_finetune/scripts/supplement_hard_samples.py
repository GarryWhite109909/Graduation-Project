"""
补充训练样本 —— 针对评估中失败的漏洞类型补充对抗性训练数据。

失败类型分析：
  1. hard_longfile（3/3 FN）：长文件中隐藏的漏洞，模型被无关代码分散注意力
  2. noise（5/6 FP）：有危险 API 但已有防护，模型误报
  3. CSRF / session_fixation / integer_overflow / hardcoded_secret：缺失控制类
  4. JWT none alg / NoSQL injection / open redirect：特殊绕过类

样本设计原则：
  1. 每条样本的 CoT 分析必须不同（不用模板）
  2. 安全样本的 explanation 必须描述具体防御措施
  3. 加入"看起来安全但有漏洞"的对抗性样本
  4. 加入"看起来危险但实际安全"的对抗性样本
  5. 不与 exp_04 测试集代码重复

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/supplement_hard_samples.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_chatml.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, taint_path, fix_idea, cot_analysis):
    """添加一条样本。"""
    SAMPLES.append({
        "code": code.strip(),
        "language": language,
        "filename": filename,
        "has_vulnerability": has_vulnerability,
        "vulnerability_type": vuln_type,
        "risk_level": risk_level,
        "source": source,
        "sink": sink,
        "taint_path": taint_path,
        "fix_idea": fix_idea,
        "cot_analysis": cot_analysis,
    })


# ===========================================================================
# 1. 长文件隐藏漏洞（教模型在长代码中找到隐藏的漏洞）
# ===========================================================================

add(
    """
import logging
from flask import Flask, request, jsonify, render_template_string
from models import db, User, Order, Product, Review, Cart, Wishlist, Coupon

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
db.init_app(app)
logger = logging.getLogger(__name__)

@app.route('/health')
def health_check():
    return jsonify({'status': 'ok'})

@app.route('/api/products/<int:product_id>/reviews')
def get_product_reviews(product_id):
    product = Product.query.get_or_404(product_id)
    reviews = Review.query.filter_by(product_id=product_id).all()
    return jsonify([{'user': r.user.name, 'rating': r.rating, 'comment': r.comment} for r in reviews])

@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    cart = Cart.query.filter_by(user_id=request.current_user.id).first()
    if not cart:
        cart = Cart(user_id=request.current_user.id)
        db.session.add(cart)
    cart.add_item(product_id, quantity)
    db.session.commit()
    return jsonify({'message': 'added'})

@app.route('/api/greeting')
def custom_greeting():
    name = request.args.get('name', 'Guest')
    template_str = f'<h1>Hello {name}!</h1><p>Welcome to our store.</p>'
    return render_template_string(template_str)

@app.route('/api/coupon/validate')
def validate_coupon():
    code = request.args.get('code', '')
    coupon = Coupon.query.filter_by(code=code).first()
    if coupon and coupon.is_valid():
        return jsonify({'valid': True, 'discount': coupon.discount_percent})
    return jsonify({'valid': False})
""",
    "python",
    "supplement_longfile_ssti.py",
    True,
    "CWE-94 SSTI",
    "Critical",
    "request.args.get('name')",
    "render_template_string(template_str)",
    "用户输入 name 通过 f-string 嵌入 HTML 模板字符串，再传给 render_template_string，导致模板注入",
    "不要用 render_template_string 处理用户输入；改用固定模板文件 + context 传参",
    """分析过程：
1. 逐函数扫描路由处理函数，关注用户输入如何进入危险操作。
2. /health、/api/products、/api/cart/add 这些路由看起来正常，使用了 ORM 查询。
3. 但 /api/greeting 路由有问题：request.args.get('name') 获取用户输入后，
   通过 f-string 直接拼接到 HTML 字符串中，然后传给 render_template_string。
4. render_template_string 会把字符串当作 Jinja2 模板渲染，f-string 拼接意味着
   用户输入成为模板的一部分。攻击者可注入 {{ }} 或 {% %} 标签执行任意代码。
5. 虽然这段代码被埋在多个正常路由之间，但 SSTI 漏洞确实存在。其他路由的
   正常性不影响这个路由的漏洞判定。"""
)

add(
    """
import os
import logging
import hashlib
from flask import Flask, request, jsonify
from models import db, User, AuditLog, Notification

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db.init_app(app)
logger = logging.getLogger(__name__)

@app.route('/api/user/profile')
def get_profile():
    user_id = request.args.get('user_id', type=int)
    user = User.query.get_or_404(user_id)
    return jsonify({'name': user.name, 'email': user.email})

@app.route('/api/user/export')
def export_user_data():
    user_id = request.args.get('user_id', type=int)
    user = User.query.get_or_404(user_id)
    data = user.to_dict()
    filename = f"user_{user_id}_export.csv"
    export_path = os.path.join('/tmp', filename)
    with open(export_path, 'w') as f:
        f.write(str(data))
    return jsonify({'download_url': f'/download/{filename}'})

@app.route('/api/notification/send')
def send_notification():
    user_id = request.args.get('user_id', type=int)
    message = request.args.get('message', '')
    cmd = f"echo '{message}' | mail -s 'Notification' user{user_id}@localhost"
    os.system(cmd)
    return jsonify({'sent': True})

@app.route('/api/audit/search')
def search_audit():
    action = request.args.get('action', '')
    logs = AuditLog.query.filter(AuditLog.action.like(f'%{action}%')).all()
    return jsonify([{'timestamp': l.timestamp, 'action': l.action} for l in logs])
""",
    "python",
    "supplement_longfile_cmd.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('message')",
    "os.system(cmd)",
    "用户输入 message 通过 f-string 拼接到命令字符串，再传给 os.system，可注入 shell 元字符",
    "用 subprocess.run(['mail', '-s', 'Notification', addr], input=message) 列表形式，不用 shell",
    """分析过程：
1. 扫描所有路由，追踪用户输入到危险操作的数据流。
2. /api/user/profile 和 /api/user/export 看起来安全——用了 ORM 和参数化路径。
3. /api/notification/send 路由有命令注入：request.args.get('message') 获取用户输入后，
   直接拼接到 shell 命令字符串中（f"echo '{message}' | mail ..."），再传给 os.system。
4. 攻击者可通过 message=foo'; rm -rf /; echo ' 注入任意命令。
5. 其他路由的安全性不影响这个路由的漏洞判定。os.system + 用户输入拼接 = 命令注入。"""
)

# ===========================================================================
# 2. Noise 样本（有危险 API 但已有防护 → 安全）
# ===========================================================================

add(
    """
import subprocess
import shlex

def ping_host(hostname):
    if not hostname.replace('.', '').replace('-', '').isalnum():
        return "Invalid hostname"
    result = subprocess.run(['ping', '-c', '1', hostname], capture_output=True, text=True)
    return result.stdout
""",
    "python",
    "supplement_noise_safe_subprocess.py",
    False,
    "none",
    "None",
    "hostname 参数（函数入参）",
    "subprocess.run(['ping', '-c', '1', hostname])",
    "hostname 先经过 isalnum 白名单校验，subprocess 使用列表形式且 shell 默认 False，不触发 shell 解释",
    "no fix needed",
    """分析过程：
1. 输入来源：hostname 是函数参数。
2. sink 评估：subprocess.run 用列表形式传参，shell 参数默认 False。
3. 防御确认：hostname 经过 replace + isalnum 白名单校验，只允许字母数字点号和连字符，
   阻止了 shell 元字符（如 ; | & $ 等）。
4. 列表形式 + shell=False 意味着参数被直接传递给 ping 程序，不经过 shell 解释。
5. 结论：代码安全，未发现漏洞。"""
)

add(
    """
# 注释中有 os.system，但实际代码已被注释掉
# def old_delete(path):
#     os.system(f'rm -rf {path}')

def safe_delete(path):
    import os
    if not os.path.isabs(path) or '..' in path:
        raise ValueError("Invalid path")
    safe_dir = os.path.join(os.getcwd(), 'uploads')
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(safe_dir):
        raise ValueError("Path outside allowed directory")
    os.remove(abs_path)
""",
    "python",
    "supplement_noise_commented_dangerous.py",
    False,
    "none",
    "None",
    "os.remove(abs_path)",
    "注释中的 os.system 已被注释，实际执行的是 os.remove，且有路径校验",
    "abspath + startswith 限定目录，阻止路径穿越",
    "no fix needed",
    """分析过程：
1. 首先注意到注释中有 os.system 调用，但代码已被注释掉（# 开头），不会执行。
2. 实际执行的 safe_delete 函数使用 os.remove，不是 os.system。
3. 路径校验：检查 isabs、禁止 '..'、abspath + startswith 限定在 uploads 目录内。
4. 注释中的危险代码不影响实际安全性，不能因为注释中有 os.system 就判漏洞。
5. 结论：代码安全，未发现漏洞。"""
)

add(
    """
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM products WHERE name LIKE ?", ('%' + keyword + '%',))
        results = cursor.fetchall()
        return {'results': results}
    except Exception as e:
        conn.rollback()
        return {'error': 'search failed'}, 500
    finally:
        conn.close()
""",
    "python",
    "supplement_noise_safe_try_except.py",
    False,
    "none",
    "None",
    "cursor.execute(...) with ?",
    "参数化查询 + try-except 异常处理",
    "使用 ? 占位符参数化查询，try-except 是异常处理不是安全缺陷",
    "no fix needed",
    """分析过程：
1. 输入来源：request.args.get('q') 获取用户搜索关键词。
2. sink 评估：cursor.execute 使用 ? 占位符 + 参数元组 ('%' + keyword + '%',)。
3. 防御确认：? 是 SQL 占位符，参数值由数据库驱动自动转义，不会进入 SQL 语法层。
   这不是字符串拼接 SQL，是标准的参数化查询写法。
4. try-except-finally 是正常的异常处理和资源管理，不是安全缺陷。
5. 结论：代码安全，参数化查询已正确防护。"""
)

# ===========================================================================
# 3. CSRF / session_fixation / missing_authz（缺失控制类漏洞）
# ===========================================================================

add(
    """
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'fixed-secret-key'

@app.route('/transfer', methods=['POST'])
def transfer_money():
    if 'user_id' not in session:
        return redirect('/login')
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    # 执行转账逻辑
    db.transfer(session['user_id'], recipient, amount)
    return {'status': 'transferred'}
""",
    "python",
    "supplement_csrf_missing.py",
    True,
    "CWE-352 CSRF",
    "High",
    "POST /transfer 无 CSRF token",
    "db.transfer(...) 执行资金操作",
    "转账操作只检查了登录状态，未验证 CSRF token，攻击者可构造表单诱导用户点击触发转账",
    "在表单中加入 CSRF token，服务端验证 token 匹配；或使用 SameSite cookie 属性",
    """分析过程：
1. 控制点检查：资金转账操作应具备 CSRF 防护（因为是 state-changing POST 请求）。
2. 控制是否缺失：代码只检查了 session['user_id']（登录状态），没有验证 CSRF token。
   用户可能在被钓鱼网站诱导下，浏览器自动携带 session cookie 发起转账请求。
3. 攻击面：攻击者构造一个自动提交的表单页面，受害者访问时浏览器自动带上 cookie，
   服务端误认为是用户本人操作。
4. 防御检查：未发现 CSRF token 验证、SameSite cookie 设置、Origin/Referer 检查等任何防护。
5. 结论：存在 CSRF 漏洞。此类漏洞不是输入到 sink 的注入，而是缺少安全控制点。"""
)

add(
    """
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'change-me-in-production'

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.authenticate(username, password)
    if user:
        session['user_id'] = user.id
        session['role'] = user.role
        return {'status': 'logged in'}
    return {'error': 'invalid credentials'}, 401
""",
    "python",
    "supplement_session_fixation.py",
    True,
    "CWE-384 Session Fixation",
    "Medium",
    "session['user_id'] = user.id（登录后未重新生成 session）",
    "复用已有 session ID",
    "登录成功后直接设置 session['user_id']，未调用 session.regenerate() 重新生成 session ID",
    "登录成功后调用 session.clear() 或重新生成 session ID，防止攻击者预设的 session ID 被复用",
    """分析过程：
1. 控制点检查：登录成功后应重新生成 session ID（防止 session fixation）。
2. 控制是否缺失：代码在登录成功后直接设置 session['user_id']，
   没有先调用 session.regenerate() 或 session.clear() 来重新生成 session ID。
3. 攻击面：攻击者可预先获取一个 session ID，诱导受害者用该 session ID 登录，
   登录后 session ID 不变，攻击者用同一个 session ID 获得受害者权限。
4. 防御检查：未发现 session 重新生成机制。
5. 结论：存在 Session Fixation 漏洞。"""
)

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    # 从数据库查询订单
    order = db.query('SELECT * FROM orders WHERE id = ?', (order_id,))
    if order:
        return jsonify({'id': order.id, 'user_id': order.user_id, 'total': order.total, 'items': order.items})
    return jsonify({'error': 'not found'}), 404
""",
    "python",
    "supplement_idor_missing_authz.py",
    True,
    "CWE-862 缺失授权",
    "High",
    "GET /api/orders/<id> 无归属校验",
    "db.query('SELECT * FROM orders WHERE id = ?', (order_id,))",
    "查询参数化但缺少授权校验，任意用户可查看他人订单",
    "查询订单时加 WHERE id = ? AND user_id = ? 条件，或先校验 order.user_id == current_user.id",
    """分析过程：
1. 控制点检查：查看订单 API 应验证当前用户是否有权访问该订单（归属校验）。
2. 控制是否缺失：代码直接用 order_id 查询订单并返回全部信息，
   没有对比 session 中的 user_id 与订单的 user_id。
3. 攻击面：任意已登录用户可通过修改 URL 中的 order_id 查看其他用户的订单，
   虽然用了参数化查询（没有 SQL 注入），但存在水平越权（IDOR）。
4. 防御检查：未发现 token 校验、归属校验、角色检查等任何授权控制。
5. 结论：存在缺失授权漏洞（IDOR）。注意：参数化查询只防 SQL 注入，不防越权。"""
)

# ===========================================================================
# 4. JWT none algorithm / NoSQL injection / open redirect（特殊绕过类）
# ===========================================================================

add(
    """
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/protected')
def protected():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, key='', algorithms=['HS256', 'none'])
        return jsonify({'user': payload.get('username')})
    except jwt.PyJWTError as e:
        return jsonify({'error': str(e)}), 401
""",
    "python",
    "supplement_jwt_none_alg.py",
    True,
    "CWE-347 JWT none 算法绕过",
    "Critical",
    "jwt.decode(token, key='', algorithms=['HS256', 'none'])",
    "jwt.decode 接受 none 算法",
    "algorithms 列表包含 'none'，攻击者可构造 alg=none 的 JWT 绕过签名验证",
    "从 algorithms 列表中移除 'none'，只保留实际使用的签名算法（如 ['HS256']）",
    """分析过程：
1. 输入来源：Authorization header 中的 JWT token。
2. sink 评估：jwt.decode 用于验证和解码 token。
3. 关键问题：algorithms 参数包含 'none'，这意味着 jwt.decode 接受 alg=none 的 token。
   当 JWT 的 header 中 alg 为 none 时，签名部分为空，jwt.decode 不会验证签名，
   攻击者可以伪造任意 payload。
4. 防御检查：虽然用了 try-except，但 'none' 算法下不会抛异常，异常处理形同虚设。
   key='' 也是空密钥，与 none 算法配合使得验证完全失效。
5. 结论：存在 JWT none 算法绕过漏洞。verify=False 或 algorithms 含 'none' 都是严重问题。"""
)

add(
    """
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient()
db = client['appdb']

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.users.find_one({'username': username, 'password': password})
    if user:
        return {'status': 'logged in'}
    return {'error': 'invalid'}, 401
""",
    "python",
    "supplement_nosql_injection.py",
    True,
    "CWE-943 NoSQL 注入",
    "Critical",
    "request.form.get('username') / 'password'",
    "db.users.find_one({'username': username, 'password': password})",
    "用户输入直接作为 MongoDB 查询条件，攻击者可传 {'$ne': ''} 匹配所有记录绕过认证",
    "对输入做类型检查（确保是字符串而非 dict），或用查询构造器限定操作符",
    """分析过程：
1. 输入来源：request.form.get 获取用户名和密码。
2. sink 评估：db.users.find_one 直接用用户输入作为查询条件。
3. 关键问题：MongoDB 查询支持操作符语法（如 {'$ne': ''} 表示"不等于空"）。
   如果攻击者发送 username={'$ne': ''} 和 password={'$ne': ''}，
   查询条件变成 {'username': {'$ne': ''}, 'password': {'$ne': ''}}，
   会匹配所有 username 和 password 非空的记录，从而绕过认证。
4. 防御检查：代码未对输入做类型检查（未确保是字符串），未使用参数化查询。
5. 结论：存在 NoSQL 注入漏洞。注意：这不是 SQL 注入，但原理类似——用户输入成为查询条件。"""
)

add(
    """
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def do_redirect():
    next_url = request.args.get('next', '/')
    return redirect(next_url)
""",
    "python",
    "supplement_open_redirect.py",
    True,
    "CWE-601 开放重定向",
    "Medium",
    "request.args.get('next')",
    "redirect(next_url)",
    "用户输入 next 参数直接用于重定向，攻击者可构造钓鱼 URL 如 /redirect?next=https://evil.com",
    "校验 next_url 是否以 / 开头且不以 // 开头（防止协议相对 URL），或用白名单",
    """分析过程：
1. 输入来源：request.args.get('next') 获取重定向目标。
2. sink 评估：redirect(next_url) 直接使用用户输入做重定向。
3. 关键问题：未对 next_url 做任何校验。攻击者可构造
   /redirect?next=https://evil.com 链接，用户点击后跳转到恶意网站。
   常用于钓鱼攻击——用户看到的是可信域名的 URL，但最终跳转到钓鱼页面。
4. 防御检查：未发现 URL 白名单、协议检查、相对路径校验等任何防护。
5. 结论：存在开放重定向漏洞。"""
)

# ===========================================================================
# 5. 硬编码凭证（教模型识别真实凭证 vs 非凭证字符串）
# ===========================================================================

add(
    """
import hashlib
import os

DB_HOST = 'localhost'
DB_NAME = 'app_db'
DB_PORT = 5432

API_KEY = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz'
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
""",
    "python",
    "supplement_hardcoded_secrets.py",
    True,
    "CWE-798 硬编码凭证",
    "Critical",
    "API_KEY = 'sk-proj-...' / AWS_SECRET_ACCESS_KEY = '...'",
    "源码中的凭证字面量",
    "API_KEY 和 AWS 密钥直接硬编码在源码中，任何能看到源码的人都能获取凭证",
    "从 os.environ 或配置文件读取，不要在源码中写死凭证",
    """分析过程：
1. 凭证位置：扫描源码中的变量赋值，寻找 key/secret/password/token 命名的变量。
2. 识别结果：API_KEY 赋值为字符串字面量 'sk-proj-...'，符合 API Key 特征。
   AWS_ACCESS_KEY_ID 和 AWS_SECRET_ACCESS_KEY 也是硬编码的 AWS 凭证。
3. 与非凭证区分：DB_HOST='localhost'、DB_NAME='app_db'、DB_PORT=5432 这些不是凭证，
   是数据库连接配置（主机名、库名、端口号），不构成安全风险。
4. 是否从环境读取：API_KEY 和 AWS 密钥没有从 os.environ 读取，而是直接写死在代码中。
5. 结论：存在硬编码凭证漏洞。API_KEY 和 AWS 密钥本身就是漏洞，无论是否有其他安全问题。"""
)

# ===========================================================================
# 6. 整数溢出
# ===========================================================================

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    quantity = int(data.get('quantity', 0))
    unit_price = int(data.get('unit_price', 0))
    total = quantity * unit_price
    if total < 0:
        return {'error': 'invalid total'}, 400
    return jsonify({'total': total})
""",
    "python",
    "supplement_integer_overflow.py",
    True,
    "CWE-190 整数溢出",
    "Medium",
    "int(data.get('quantity')) 和 int(data.get('unit_price'))",
    "quantity * unit_price 算术运算",
    "两个用户可控整数相乘，结果可能溢出 Python 整数边界（在 C 扩展或固定宽度整数场景下）",
    "使用 Decimal 或对运算结果做范围检查，确保不超出预期范围",
    """分析过程：
1. 运算识别：quantity 和 unit_price 从用户输入转为整数后直接相乘。
2. 范围检查：代码只检查 total < 0（检测负数结果），但没有检查 total 是否超出业务合理范围。
   在 Python 中整数不会溢出，但如果此值传入 C 扩展、数据库固定宽度整数字段、
   或序列化为 32 位整数，就可能发生溢出。
3. 溢出可能：quantity=2^31, unit_price=2 时，total=2^32，在 32 位系统中会溢出回绕。
4. 后果：溢出可能导致金额计算错误、绕过支付校验、或缓冲区大小计算错误。
5. 结论：存在整数溢出风险，特别是在与固定宽度整数系统交互时。"""
)


# ===========================================================================
# 构建逻辑
# ===========================================================================

def build_json_verdict(sample):
    """构造 JSON 结论块。"""
    has_vuln = sample["has_vulnerability"]
    taint_path = sample.get("taint_path", "")
    verdict = {
        "has_vulnerability": has_vuln,
        "vulnerability_type": sample["vulnerability_type"],
        "risk_level": sample["risk_level"],
        "source": sample["source"],
        "sink": sample["sink"],
        "explanation": taint_path if has_vuln
                       else (taint_path or "代码中未发现可利用的安全漏洞。"),
        "fix_suggestion": sample["fix_idea"],
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_messages(sample):
    """转为 ChatML。"""
    user_content = build_user_prompt(
        code=sample["code"], language=sample["language"],
        filename=sample["filename"],
    )
    json_block = build_json_verdict(sample)
    assistant_content = f"{sample['cot_analysis']}\n\n{json_block}"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    print(f"共 {len(SAMPLES)} 条补充样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证 CoT 多样性
    cot_texts = [s["cot_analysis"] for s in SAMPLES]
    print(f"CoT 唯一文本: {len(set(cot_texts))}/{len(cot_texts)}")


if __name__ == "__main__":
    main()
