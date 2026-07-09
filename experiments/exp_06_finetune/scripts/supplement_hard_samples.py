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
# 2.1 Noise：危险 API 但无用户输入到达 sink（硬编码 → 安全）
# ===========================================================================

add(
    """
import subprocess

def list_files():
    result = subprocess.run('ls -la /tmp', shell=True, capture_output=True, text=True)
    return result.stdout
""",
    "python", "supplement_noise_shell_true_hardcoded.py",
    False, "none", "None",
    "subprocess.run('ls -la /tmp', shell=True)",
    "subprocess.run(shell=True) 但命令是硬编码字符串",
    "shell=True 但命令 'ls -la /tmp' 是硬编码字面量，无任何用户输入参与拼接，攻击者无法影响命令内容",
    "no fix needed",
    """分析过程：
1. 输入可控性检查：subprocess.run 的第一个参数是字符串字面量 'ls -la /tmp'，
   没有任何变量、函数返回值或用户输入参与。
2. sink 评估：虽然 shell=True 会让命令经过 shell 解释器，但命令内容固定不变。
3. 数据流追踪：函数 list_files() 不接受任何参数，不读取 request/argv/环境变量，
   不存在外部输入到达 sink 的路径。
4. shell=True 的风险在于"用户输入拼接进命令字符串"，此处不存在该情况。
5. 结论：代码安全。shell=True 本身不是漏洞，漏洞在于用户可控输入到达 shell 命令。"""
)

add(
    """
import os

def clear_temp():
    os.system('rm -rf /tmp/cache/*')
    return 'cleared'
""",
    "python", "supplement_noise_os_system_hardcoded.py",
    False, "none", "None",
    "os.system('rm -rf /tmp/cache/*')",
    "os.system 但命令硬编码",
    "os.system 调用的命令是硬编码字符串，无用户输入参与，无法注入",
    "no fix needed",
    """分析过程：
1. 输入可控性：os.system 的参数是字面量 'rm -rf /tmp/cache/*'，无变量拼接。
2. 函数 clear_temp() 无入参，不读取任何外部输入源。
3. os.system 是危险函数，但危险的前提是用户输入能进入命令字符串。此处命令完全固定。
4. 即使 shell 会解释 * 通配符，通配的也是 /tmp/cache/ 下的文件，不是用户可控的内容。
5. 结论：代码安全。os.system + 硬编码命令不构成命令注入。"""
)

add(
    """
def calculate():
    expression = '2 + 3 * 4 - 10 / 2'
    result = eval(expression)
    return result
""",
    "python", "supplement_noise_eval_hardcoded.py",
    False, "none", "None",
    "eval(expression)",
    "eval 但表达式硬编码",
    "eval 调用的表达式是硬编码字符串 '2 + 3 * 4 - 10 / 2'，无用户输入",
    "no fix needed",
    """分析过程：
1. 输入可控性：eval 的参数 expression 是字符串字面量 '2 + 3 * 4 - 10 / 2'，
   不含任何变量或用户输入。
2. 函数 calculate() 无入参，不读取 request/argv 等外部输入。
3. eval 是危险函数，但此处执行的是固定数学表达式，不涉及命名空间访问或用户输入。
4. 攻击者无法影响 eval 的内容，无法注入 __import__('os').system(...) 等 payload。
5. 结论：代码安全。eval + 硬编码表达式不构成代码注入。"""
)

add(
    """
from flask import Flask, render_template_string

app = Flask(__name__)

TEMPLATE = '<h1>Welcome</h1><p>Static content here.</p>'

@app.route('/')
def index():
    return render_template_string(TEMPLATE)
""",
    "python", "supplement_noise_ssti_fixed_template.py",
    False, "none", "None",
    "render_template_string(TEMPLATE)",
    "render_template_string 但模板是固定常量",
    "模板字符串 TEMPLATE 是模块级常量，不含用户输入，无注入点",
    "no fix needed",
    """分析过程：
1. 输入可控性：TEMPLATE 是模块级常量 '<h1>Welcome</h1>...'，不读取任何用户输入。
2. 路由 index() 不从 request 获取任何参数，直接渲染固定模板。
3. render_template_string 会执行 Jinja2 模板，但模板内容固定，攻击者无法注入 {{ }} 或 {% %}。
4. SSTI 漏洞的关键是"用户输入成为模板的一部分"，此处不存在该情况。
5. 结论：代码安全。render_template_string + 固定模板不构成 SSTI。"""
)

add(
    """
import sqlite3

def init_db():
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)"
    cursor.execute(query)
    conn.commit()
    conn.close()
""",
    "python", "supplement_noise_sql_hardcoded.py",
    False, "none", "None",
    "cursor.execute(query)",
    "cursor.execute 但 SQL 语句硬编码",
    "SQL 语句是硬编码的 DDL，无用户输入拼接，无注入风险",
    "no fix needed",
    """分析过程：
1. 输入可控性：query 是字面量 "CREATE TABLE IF NOT EXISTS users ..."，无变量拼接。
2. 函数 init_db() 无入参，不读取外部输入。
3. cursor.execute 直接执行固定 DDL 语句，不涉及用户数据。
4. SQL 注入的前提是用户输入进入 SQL 语句的语法层，此处不存在。
5. 结论：代码安全。硬编码 SQL 不构成 SQL 注入。"""
)

add(
    """
import pickle

DEFAULT_CONFIG = b'\\x80\\x04\\x95\\x15\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x8c\\x05dummy\\x94.'

def load_default_config():
    return pickle.loads(DEFAULT_CONFIG)
""",
    "python", "supplement_noise_pickle_trusted.py",
    False, "none", "None",
    "pickle.loads(DEFAULT_CONFIG)",
    "pickle.loads 但数据是硬编码常量",
    "pickle 反序列化的数据是模块级常量 bytes，非用户输入，无法构造恶意 payload",
    "no fix needed",
    """分析过程：
1. 输入可控性：DEFAULT_CONFIG 是硬编码 bytes 字面量，不从文件/网络/用户输入读取。
2. 函数 load_default_config() 无入参，反序列化的是固定数据。
3. pickle.loads 是危险函数，但危险在于反序列化"不可信的数据"——攻击者可构造
  恶意 pickle 流执行任意代码。此处数据是开发者硬编码的，可信。
4. 攻击者无法影响 DEFAULT_CONFIG 的内容。
5. 结论：代码安全。pickle 反序列化可信的硬编码数据不构成反序列化漏洞。"""
)

# ===========================================================================
# 2.2 Noise：危险 API + 有效防御（用户输入有到达，但被防护）
# ===========================================================================

add(
    """
import subprocess
import shlex

def ping_host(hostname):
    if not hostname.replace('.', '').replace('-', '').isalnum():
        raise ValueError("Invalid hostname")
    safe_hostname = shlex.quote(hostname)
    result = subprocess.run(f'ping -c 1 {safe_hostname}', shell=True, capture_output=True, text=True)
    return result.stdout
""",
    "python", "supplement_noise_shell_true_shlex_quote.py",
    False, "none", "None",
    "hostname 参数（函数入参）",
    "subprocess.run(shell=True) 但参数经 shlex.quote + isalnum 校验",
    "用户输入 hostname 先经 isalnum 白名单校验，再用 shlex.quote 转义，双重防护",
    "no fix needed",
    """分析过程：
1. 输入可控性：hostname 是函数参数，调用方可能传入用户输入。
2. sink 评估：subprocess.run(shell=True) 会经过 shell 解释器。
3. 防御确认（第一层）：hostname.replace('.','').replace('-','').isalnum() 白名单校验，
   只允许字母、数字、点号、连字符，阻止 ; | & $ ` 等 shell 元字符。
4. 防御确认（第二层）：shlex.quote 对 hostname 做 shell 转义，即使含特殊字符也会被引号包裹。
5. 双重防护下，攻击者无法注入 shell 元字符。结论：代码安全。"""
)

add(
    """
import subprocess

ALLOWED_CMDS = {'ls', 'cat', 'grep', 'wc'}

def run_command(cmd_name, args):
    if cmd_name not in ALLOWED_CMDS:
        raise ValueError("Command not allowed")
    if not all(isinstance(a, str) and a.isalnum() for a in args):
        raise ValueError("Invalid args")
    result = subprocess.run([cmd_name] + args, shell=False, capture_output=True, text=True)
    return result.stdout
""",
    "python", "supplement_noise_subprocess_whitelist.py",
    False, "none", "None",
    "cmd_name / args 参数（函数入参）",
    "subprocess.run([cmd_name] + args, shell=False)",
    "命令名白名单校验 + 参数 isalnum 校验 + 列表形式 shell=False，三重防护",
    "no fix needed",
    """分析过程：
1. 输入可控性：cmd_name 和 args 是函数参数，可能来自用户输入。
2. sink 评估：subprocess.run 用列表形式传参，shell=False，参数直接传给程序不经 shell。
3. 防御确认（第一层）：cmd_name 必须在 ALLOWED_CMDS 白名单 {'ls','cat','grep','wc'} 中。
4. 防御确认（第二层）：每个 arg 必须是字符串且 isalnum()，阻止 shell 元字符和路径穿越。
5. 列表形式 + shell=False + 白名单 + isalnum，攻击者无法注入。结论：代码安全。"""
)

add(
    """
import os

ALLOWED_DIRS = {'/var/uploads', '/tmp/files'}

def read_file(filepath):
    abs_path = os.path.abspath(filepath)
    if not any(abs_path.startswith(d) for d in ALLOWED_DIRS):
        raise ValueError("Access denied")
    with open(abs_path, 'r') as f:
        return f.read()
""",
    "python", "supplement_noise_path_whitelist.py",
    False, "none", "None",
    "filepath 参数（函数入参）",
    "open(abs_path)",
    "abspath 规范化 + 白名单目录 startswith 校验，阻止路径穿越",
    "no fix needed",
    """分析过程：
1. 输入可控性：filepath 是函数参数，可能来自用户输入。
2. sink 评估：open(abs_path) 打开文件。
3. 防御确认：os.path.abspath 规范化路径（解析 .. 和符号链接），
   然后检查是否以 ALLOWED_DIRS 中的目录开头。
4. 攻击者传 '../../etc/passwd' 时，abspath 会解析为 /etc/passwd，
   不以 /var/uploads 或 /tmp/files 开头，被拒绝。
5. abspath + 白名单 startswith 是有效的路径穿越防护。结论：代码安全。"""
)

add(
    """
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = 'super-secret-key-from-env'

@app.route('/api/protected')
def protected():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'user': payload.get('username')})
    except jwt.PyJWTError:
        return jsonify({'error': 'invalid token'}), 401
""",
    "python", "supplement_noise_jwt_proper_verify.py",
    False, "none", "None",
    "Authorization header 中的 JWT token",
    "jwt.decode(token, SECRET_KEY, algorithms=['HS256'])",
    "algorithms 限定 ['HS256']（不含 none），使用密钥验证签名，try-except 捕获无效 token",
    "no fix needed",
    """分析过程：
1. 输入可控性：token 来自 Authorization header，用户完全可控。
2. sink 评估：jwt.decode 验证并解码 token。
3. 防御确认（第一层）：algorithms=['HS256'] 明确限定只接受 HS256 算法，
   不含 'none'，阻止 alg=none 绕过攻击。
4. 防御确认（第二层）：SECRET_KEY 是非空密钥，HS256 会验证签名，
   攻击者无法伪造有效签名的 token。
5. 防御确认（第三层）：try-except 捕获所有 PyJWTError（包括签名错误、过期等），
   无效 token 返回 401。
6. 结论：代码安全。JWT 验证正确，无 none 算法绕过风险。"""
)

add(
    """
from flask import Flask, request, redirect

ALLOWED_REDIRECTS = {'/dashboard', '/profile', '/home', '/login'}

@app.route('/redirect')
def do_redirect():
    next_url = request.args.get('next', '/home')
    if next_url in ALLOWED_REDIRECTS:
        return redirect(next_url)
    return redirect('/home')
""",
    "python", "supplement_noise_redirect_whitelist.py",
    False, "none", "None",
    "request.args.get('next')",
    "redirect(next_url)",
    "next_url 必须在白名单 ALLOWED_REDIRECTS 中才允许重定向，否则回退到 /home",
    "no fix needed",
    """分析过程：
1. 输入可控性：next_url 来自 request.args.get('next')，用户可控。
2. sink 评估：redirect(next_url) 做重定向。
3. 防御确认：next_url 必须严格匹配 ALLOWED_REDIRECTS 白名单 {'/dashboard','/profile','/home','/login'}。
4. 攻击者传 next=https://evil.com 时，不在白名单中，回退到 redirect('/home')。
5. 白名单是精确匹配（不是 startswith），阻止了协议相对 URL 和路径穿越。
6. 结论：代码安全。URL 白名单有效防护开放重定向。"""
)

add(
    """
import hashlib
import secrets

def hash_password(password):
    salt = secrets.token_bytes(16)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return salt.hex() + ':' + hashed.hex()

def verify_password(password, stored):
    salt_hex, hash_hex = stored.split(':')
    salt = bytes.fromhex(salt_hex)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return secrets.compare_digest(hashed.hex(), hash_hex)
""",
    "python", "supplement_noise_proper_password_hash.py",
    False, "none", "None",
    "password 参数（函数入参）",
    "hashlib.pbkdf2_hmac('sha256', ...)",
    "使用 PBKDF2-SHA256 + 随机 salt + 10万次迭代 + secrets.compare_digest 恒定时间比较",
    "no fix needed",
    """分析过程：
1. 输入可控性：password 是函数参数（用户密码），但这是预期的输入。
2. 密码存储评估：使用 hashlib.pbkdf2_hmac('sha256', ...) 而非 MD5/SHA1。
3. 防御确认（第一层）：secrets.token_bytes(16) 生成加密安全的随机 salt。
4. 防御确认（第二层）：100000 次迭代增加暴力破解成本。
5. 防御确认（第三层）：secrets.compare_digest 做恒定时间比较，防止计时攻击。
6. 结论：代码安全。PBKDF2 + salt + 高迭代 + 恒定时间比较是标准的密码存储方案。"""
)

add(
    """
import yaml

def load_config(yaml_str):
    return yaml.safe_load(yaml_str)
""",
    "python", "supplement_noise_yaml_safe_load.py",
    False, "none", "None",
    "yaml_str 参数（函数入参）",
    "yaml.safe_load(yaml_str)",
    "使用 yaml.safe_load 而非 yaml.load，禁止构造任意 Python 对象",
    "no fix needed",
    """分析过程：
1. 输入可控性：yaml_str 是函数参数，可能来自用户输入或配置文件。
2. sink 评估：yaml.safe_load 解析 YAML 字符串。
3. 防御确认：yaml.safe_load 只解析基本 YAML 类型（dict/list/str/int/float/bool/None），
   不会执行 !!python/object 等标签，无法构造任意 Python 对象。
4. 对比：yaml.load(yaml_str) 不带 Loader 参数是危险的（可构造任意对象），
   但 safe_load 限制了可解析的类型。
5. 结论：代码安全。yaml.safe_load 是安全的 YAML 解析方式。"""
)

add(
    """
import xml.etree.ElementTree as ET
import defusedxml.ElementTree as DET

def parse_xml(xml_str):
    return DET.fromstring(xml_str)
""",
    "python", "supplement_noise_xml_defused.py",
    False, "none", "None",
    "xml_str 参数（函数入参）",
    "DET.fromstring(xml_str)",
    "使用 defusedxml 而非标准 xml.etree，阻止 XXE 和实体爆炸攻击",
    "no fix needed",
    """分析过程：
1. 输入可控性：xml_str 是函数参数，可能来自用户输入。
2. sink 评估：DET.fromstring 解析 XML 字符串。
3. 防御确认：使用 defusedxml.ElementTree 而非标准 xml.etree.ElementTree。
   defusedxml 禁用外部实体解析（阻止 XXE）和实体扩展（阻止实体爆炸）。
4. 标准 xml.etree.ElementTree.fromstring 易受 XXE 攻击（可读取本地文件/SSRF），
   defusedxml 修复了这些漏洞。
5. 结论：代码安全。defusedxml 是 XML 解析的安全替代方案。"""
)

add(
    """
import re

def search_pattern(text, pattern):
    safe_pattern = re.escape(pattern)
    return re.findall(safe_pattern, text)
""",
    "python", "supplement_noise_regex_escape.py",
    False, "none", "None",
    "pattern 参数（函数入参）",
    "re.findall(safe_pattern, text)",
    "用户提供的 pattern 经 re.escape 转义，阻止 ReDoS 和意外匹配",
    "no fix needed",
    """分析过程：
1. 输入可控性：pattern 是函数参数，可能来自用户输入。
2. sink 评估：re.findall 用 pattern 做正则匹配。
3. 防御确认：re.escape(pattern) 将 pattern 中的所有特殊字符（.*+?[](){}^$|\\）转义，
   使其作为字面量匹配，而非正则元字符。
4. 这阻止了两种攻击：①攻击者构造恶意正则导致 ReDoS（如 (a+)+）；
   ②攻击者用正则元字符做意外匹配。
5. 结论：代码安全。re.escape 是处理用户提供的正则模式的安全方式。"""
)

add(
    """
import base64

def decode_token(b64_token):
    try:
        decoded = base64.b64decode(b64_token, validate=True)
        return decoded.decode('utf-8')
    except Exception:
        return None
""",
    "python", "supplement_noise_base64_safe.py",
    False, "none", "None",
    "b64_token 参数（函数入参）",
    "base64.b64decode(b64_token, validate=True)",
    "base64 解码是安全操作（不执行代码），validate=True 严格校验输入格式",
    "no fix needed",
    """分析过程：
1. 输入可控性：b64_token 是函数参数，用户可控。
2. sink 评估：base64.b64decode 只是解码 base64 编码，不执行任何代码。
3. 防御确认：validate=True 严格校验输入是否为合法 base64，非法字符会抛异常。
4. base64 解码本身不是危险操作——它只是把编码数据还原为字节串。
   危险在于解码后的数据如何被使用（如 eval(decoded)），但此处只是 decode 为 utf-8 字符串。
5. try-except 捕获所有异常，非法输入返回 None。
6. 结论：代码安全。base64 解码 + validate 是安全的数据处理操作。"""
)

add(
    """
import secrets

def generate_token():
    return secrets.token_hex(32)

def generate_password():
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(secrets.choice(alphabet) for _ in range(16))
""",
    "python", "supplement_noise_proper_random.py",
    False, "none", "None",
    "None（无用户输入）",
    "secrets.token_hex(32) / secrets.choice(alphabet)",
    "使用 secrets 模块（密码学安全随机数）而非 random 模块",
    "no fix needed",
    """分析过程：
1. 输入可控性：函数无入参，不涉及用户输入。
2. 随机数评估：使用 secrets 模块而非 random 模块。
3. 防御确认：secrets.token_hex 使用操作系统提供的密码学安全随机数生成器
   （/dev/urandom 或 CryptGenRandom）。
4. 对比：random.randint/random.choice 使用伪随机数生成器（Mersenne Twister），
   可预测，不适用于安全场景（如 token、密码、session ID）。
5. 结论：代码安全。secrets 模块是生成安全随机数的正确方式。"""
)

add(
    """
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
""",
    "python", "supplement_noise_bcrypt_proper.py",
    False, "none", "None",
    "password 参数（函数入参，预期输入）",
    "bcrypt.hashpw(password.encode(), salt)",
    "使用 bcrypt + rounds=12 做密码哈希，checkpw 做恒定时间验证",
    "no fix needed",
    """分析过程：
1. 输入可控性：password 是函数参数（用户密码），这是预期输入。
2. 密码存储评估：使用 bcrypt 而非 MD5/SHA1/明文存储。
3. 防御确认（第一层）：bcrypt.gensalt(rounds=12) 生成 salt 并指定 cost factor=12
   （2^12=4096 次迭代），增加暴力破解成本。
4. 防御确认（第二层）：bcrypt 自带 salt，无需单独管理。
5. 防御确认（第三层）：bcrypt.checkpw 做恒定时间比较，防止计时攻击。
6. 结论：代码安全。bcrypt 是推荐的密码哈希方案。"""
)

add(
    """
import hmac

def verify_signature(payload, signature, secret):
    expected = hmac.new(secret.encode(), payload.encode(), 'sha256').hexdigest()
    return hmac.compare_digest(expected, signature)
""",
    "python", "supplement_noise_hmac_compare.py",
    False, "none", "None",
    "payload / signature 参数（函数入参）",
    "hmac.compare_digest(expected, signature)",
    "使用 hmac.compare_digest 做恒定时间比较，防止计时攻击",
    "no fix needed",
    """分析过程：
1. 输入可控性：payload 和 signature 是函数参数，可能来自用户请求。
2. sink 评估：hmac.compare_digest 比较两个字符串是否相等。
3. 防御确认：hmac.compare_digest 做恒定时间比较——无论字符串在哪一位不同，
   比较时间都相同，防止攻击者通过响应时间推断签名内容。
4. 对比：直接用 == 比较会在第一个不匹配字符处短路返回，泄露签名前缀信息。
5. HMAC 本身使用 secret 做 SHA-256 签名，攻击者无法伪造有效签名。
6. 结论：代码安全。hmac + compare_digest 是签名验证的安全方式。"""
)

# ===========================================================================
# 2.3 Noise：看起来缺失控制但实际有（有控制 → 安全）
# ===========================================================================

add(
    """
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = 'from-env-secret'

@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return 'Invalid CSRF token', 403
    if 'user_id' not in session:
        return redirect('/login')
    amount = request.form.get('amount')
    return {'status': 'transferred'}
""",
    "python", "supplement_noise_csrf_token_present.py",
    False, "none", "None",
    "POST /transfer 表单数据",
    "资金转账操作",
    "转账操作前验证 CSRF token，token 不匹配返回 403",
    "no fix needed",
    """分析过程：
1. 控制点检查：资金转账是 state-changing POST 请求，需要 CSRF 防护。
2. 控制是否缺失：代码在执行转账前先检查 csrf_token：
   request.form.get('csrf_token') 与 session.get('csrf_token') 比较。
3. 攻击面分析：攻击者构造的跨站表单无法获取受害者的 session 中的 csrf_token，
   因此提交时 token 不匹配，返回 403。
4. 防御有效性：token 比较在转账逻辑之前，未通过则不执行转账。
   虽然用了 != 比较（理论上有时序风险），但对 CSRF 防护已足够。
5. 结论：代码安全。CSRF token 验证已正确实施。"""
)

add(
    """
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'from-env-secret'

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.authenticate(username, password)
    if user:
        session.clear()
        session['user_id'] = user.id
        session['role'] = user.role
        return {'status': 'logged in'}
    return {'error': 'invalid'}, 401
""",
    "python", "supplement_noise_session_regenerate_present.py",
    False, "none", "None",
    "POST /login 表单数据",
    "session['user_id'] = user.id",
    "登录成功后先调用 session.clear() 清除旧 session，防止 session fixation",
    "no fix needed",
    """分析过程：
1. 控制点检查：登录成功后应重新生成 session ID（防 session fixation）。
2. 控制是否缺失：代码在设置 session['user_id'] 前先调用 session.clear()，
   清除旧 session 中的所有数据。
3. Flask 的 session 机制下，session.clear() 会使旧 session ID 失效，
   下次响应会分配新的 session ID。
4. 攻击面分析：即使攻击者预先获取了 session ID 并诱导受害者使用，
   登录后 session.clear() 会使该 ID 失效，攻击者无法复用。
5. 结论：代码安全。session.clear() 在登录后重新生成 session，防止 session fixation。"""
)

add(
    """
from flask import Flask, request, jsonify, session

app = Flask(__name__)

@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    if 'user_id' not in session:
        return jsonify({'error': 'not logged in'}), 401
    order = db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?',
                     (order_id, session['user_id']))
    if order:
        return jsonify({'id': order.id, 'total': order.total})
    return jsonify({'error': 'not found'}), 404
""",
    "python", "supplement_noise_authz_check_present.py",
    False, "none", "None",
    "GET /api/orders/<id> 路由参数",
    "db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?')",
    "SQL 查询同时校验 order_id 和 user_id 归属，参数化查询防注入 + 授权校验防越权",
    "no fix needed",
    """分析过程：
1. 控制点检查：查看订单 API 应验证当前用户是否有权访问该订单。
2. 控制是否缺失：SQL 查询条件是 WHERE id = ? AND user_id = ?，
   同时匹配订单 ID 和当前用户的 user_id（从 session 获取）。
3. 授权逻辑：即使攻击者修改 order_id，查询也只返回属于当前用户的订单。
   其他用户的订单因 user_id 不匹配而返回 not found。
4. 参数化查询：使用 ? 占位符，同时防 SQL 注入。
5. 登录检查：session 中无 user_id 时返回 401。
6. 结论：代码安全。授权校验 + 参数化查询都已正确实施。"""
)

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

MAX_QUANTITY = 1000000
MAX_PRICE = 100000

@app.route('/api/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    quantity = int(data.get('quantity', 0))
    unit_price = int(data.get('unit_price', 0))
    if quantity < 0 or quantity > MAX_QUANTITY:
        return {'error': 'invalid quantity'}, 400
    if unit_price < 0 or unit_price > MAX_PRICE:
        return {'error': 'invalid price'}, 400
    total = quantity * unit_price
    return jsonify({'total': total})
""",
    "python", "supplement_noise_integer_range_check.py",
    False, "none", "None",
    "int(data.get('quantity')) / int(data.get('unit_price'))",
    "quantity * unit_price 算术运算",
    "对用户输入的整数做范围校验（0 ~ MAX），阻止越界值导致的溢出",
    "no fix needed",
    """分析过程：
1. 输入可控性：quantity 和 unit_price 从用户 JSON 输入转为整数。
2. 运算评估：quantity * unit_price 可能产生大数。
3. 防御确认：代码对两个值都做了范围校验：
   quantity 限制在 [0, 1000000]，unit_price 限制在 [0, 100000]。
4. 溢出分析：最大乘积 = 1000000 × 100000 = 10^11，在 Python 整数范围内不会溢出
   （Python 整数无限精度）。即使传入 C 扩展，范围校验也阻止了超界值。
5. 负数也被校验（quantity < 0 返回错误），阻止了负数绕过支付逻辑。
6. 结论：代码安全。范围校验有效防止整数溢出和负数攻击。"""
)

add(
    """
import threading

class BankAccount:
    def __init__(self, balance=0):
        self.balance = balance
        self.lock = threading.Lock()

    def transfer(self, amount):
        with self.lock:
            if self.balance >= amount:
                self.balance -= amount
                return True
            return False
""",
    "python", "supplement_noise_race_lock_present.py",
    False, "none", "None",
    "amount 参数（函数入参）",
    "self.balance -= amount 余额修改",
    "使用 threading.Lock 保护共享状态 balance，阻止竞态条件",
    "no fix needed",
    """分析过程：
1. 共享状态：self.balance 是多线程共享的账户余额。
2. 同步机制：使用 threading.Lock，在 transfer 方法中用 with self.lock 获取锁。
3. 竞态分析：若无锁，两个线程同时读到 balance=100 并各转 100，会导致余额变为 -100
   （透支）。with self.lock 确保同一时刻只有一个线程执行 读取-检查-修改 序列。
4. 锁的有效性：with 语句确保锁在退出代码块时释放（即使抛异常），
   不会死锁。检查 balance >= amount 和修改 balance 都在锁内，是原子操作。
5. 结论：代码安全。Lock 正确保护了共享状态，无竞态条件。"""
)

add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return {'error': 'no file'}, 400
    if len(file.read()) > 1024 * 1024:
        return {'error': 'file too large'}, 400
    file.seek(0)
    allowed = {'jpg', 'png', 'gif', 'pdf'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed:
        return {'error': 'extension not allowed'}, 400
    file.save(f'/var/uploads/{file.filename}')
    return {'status': 'uploaded'}
""",
    "python", "supplement_noise_upload_validation.py",
    False, "none", "None",
    "request.files.get('file') 上传文件",
    "file.save(...)",
    "文件大小校验 + 扩展名白名单校验",
    "no fix needed",
    """分析过程：
1. 输入可控性：上传文件的内容和文件名都由用户控制。
2. sink 评估：file.save 保存文件到服务器。
3. 防御确认（第一层）：len(file.read()) > 1MB 时拒绝，限制文件大小。
4. 防御确认（第二层）：扩展名白名单 {'jpg','png','gif','pdf'}，
   阻止上传 .py/.php/.jsp 等可执行文件。
5. file.seek(0) 重置读取位置，确保保存完整文件。
6. 注意：此处用 file.filename 直接拼路径有一定风险（路径穿越），
   但主要目的是展示大小+扩展名校验。实际生产应额外做路径规范化。
7. 结论：文件大小和扩展名校验已实施，降低了上传风险。"""
)

add(
    """
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    safe_keyword = escape(keyword)
    template = '<p>Search results for: {{ keyword }}</p>'
    return render_template_string(template, keyword=safe_keyword)
""",
    "python", "supplement_noise_xss_escape.py",
    False, "none", "None",
    "request.args.get('q')",
    "render_template_string(template, keyword=safe_keyword)",
    "用户输入经 markupsafe.escape 转义后再传入模板，阻止 XSS",
    "no fix needed",
    """分析过程：
1. 输入可控性：keyword 来自 request.args.get('q')，用户可控。
2. sink 评估：render_template_string 渲染模板。
3. 防御确认（第一层）：escape(keyword) 将 < > & " ' 转义为 HTML 实体，
   阻止 <script> 等标签执行。
4. 防御确认（第二层）：模板中用 {{ keyword }} 而非直接拼接到模板字符串，
   Jinja2 的 {{ }} 默认对内容做自动转义。
5. 双重转义（escape + Jinja2 自动转义）确保即使输入含 HTML/JS 也只显示为文本。
6. 结论：代码安全。escape + 模板变量传参有效防护 XSS。"""
)

add(
    """
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
                   (f'%{keyword}%', f'%{keyword}%'))
    results = cursor.fetchall()
    conn.close()
    return {'results': results}
""",
    "python", "supplement_noise_sql_parameterized.py",
    False, "none", "None",
    "request.args.get('q')",
    "cursor.execute(..., (f'%{keyword}%', ...))",
    "使用 ? 占位符参数化查询，用户输入只作为数据而非 SQL 语法",
    "no fix needed",
    """分析过程：
1. 输入可控性：keyword 来自 request.args.get('q')，用户完全可控。
2. sink 评估：cursor.execute 执行 SQL。
3. 防御确认：SQL 语句用 ? 占位符，参数通过元组 (f'%{keyword}%', ...) 传入。
   数据库驱动会自动转义参数值，确保 keyword 只作为数据而非 SQL 语法。
4. 攻击者输入 ' OR 1=1 -- 时，整个字符串会被当作 LIKE 的搜索模式处理
   （查找包含 "' OR 1=1 --" 的产品名），而非改变 SQL 语义。
5. f'%{keyword}%' 是字符串格式化生成搜索模式，不是 SQL 拼接——
   关键在于这个字符串作为参数传给 ?，而非拼进 SQL 语句。
6. 结论：代码安全。参数化查询是防 SQL 注入的标准方案。"""
)

add(
    """
from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine('sqlite:///app.db')

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    with engine.connect() as conn:
        query = text("SELECT * FROM products WHERE name LIKE :pattern")
        result = conn.execute(query, {'pattern': f'%{keyword}%'})
        return {'results': [dict(r) for r in result]}
""",
    "python", "supplement_noise_sqlalchemy_orm.py",
    False, "none", "None",
    "request.args.get('q')",
    "conn.execute(query, {'pattern': ...})",
    "使用 SQLAlchemy text + 命名参数 :pattern，参数化查询防注入",
    "no fix needed",
    """分析过程：
1. 输入可控性：keyword 来自 request.args.get('q')，用户可控。
2. sink 评估：conn.execute 执行 SQL。
3. 防御确认：使用 SQLAlchemy 的 text() 构造 SQL，用命名参数 :pattern，
   参数通过字典 {'pattern': f'%{keyword}%'} 传入。
4. SQLAlchemy 的参数绑定机制会自动转义参数值，防止 SQL 注入。
5. 对比：如果用字符串拼接 f"SELECT * FROM products WHERE name LIKE '%{keyword}%'" 
   传给 text() 则有注入风险。正确做法是用参数绑定。
6. 结论：代码安全。SQLAlchemy text + 命名参数是参数化查询的正确用法。"""
)

add(
    """
import subprocess

def run_task(task_name):
    if task_name == 'backup':
        cmd = ['tar', '-czf', '/tmp/backup.tar.gz', '/var/data']
    elif task_name == 'cleanup':
        cmd = ['find', '/tmp', '-type', 'f', '-mtime', '+7', '-delete']
    else:
        raise ValueError("Unknown task")
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    return result.stdout
""",
    "python", "supplement_noise_subprocess_dispatch.py",
    False, "none", "None",
    "task_name 参数（函数入参）",
    "subprocess.run(cmd, shell=False)",
    "命令由 task_name 映射到固定列表，shell=False，无用户输入拼接",
    "no fix needed",
    """分析过程：
1. 输入可控性：task_name 是函数参数，可能来自用户输入。
2. sink 评估：subprocess.run(cmd, shell=False) 执行命令。
3. 防御确认（第一层）：cmd 不是由 task_name 拼接的，而是通过 if/elif 映射到
   固定的命令列表（['tar', ...] 或 ['find', ...]）。task_name 只做选择，不影响命令内容。
4. 防御确认（第二层）：shell=False，参数以列表形式传递，不经 shell 解释器。
5. 未知 task_name 抛 ValueError，不会执行任意命令。
6. 结论：代码安全。命令白名单映射 + 列表形式 + shell=False，无注入风险。"""
)

add(
    """
import json

def parse_config(json_str):
    try:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            return None
        return data
    except json.JSONDecodeError:
        return None
""",
    "python", "supplement_noise_json_safe.py",
    False, "none", "None",
    "json_str 参数（函数入参）",
    "json.loads(json_str)",
    "json.loads 只解析 JSON 数据结构，不执行代码，且校验返回类型为 dict",
    "no fix needed",
    """分析过程：
1. 输入可控性：json_str 是函数参数，可能来自用户输入。
2. sink 评估：json.loads 解析 JSON 字符串。
3. 安全性分析：json.loads 只解析 JSON 基本类型（dict/list/str/int/float/bool/None），
   不会执行任意代码（对比 eval 可以执行 Python 表达式）。
4. 防御确认：isinstance(data, dict) 校验解析结果必须是字典，
   防止其他 JSON 类型（如数组、字符串）被误用。
5. try-except 捕获 JSON 解析错误，非法输入返回 None。
6. 结论：代码安全。json.loads 是安全的解析方式，不构成代码注入。"""
)

add(
    """
from flask import Flask, request, jsonify
import html

app = Flask(__name__)

@app.route('/profile')
def profile():
    username = request.args.get('name', 'Guest')
    safe_name = html.escape(username, quote=True)
    return jsonify({'message': f'Hello, {safe_name}!'})
""",
    "python", "supplement_noise_xss_html_escape.py",
    False, "none", "None",
    "request.args.get('name')",
    "jsonify({'message': f'Hello, {safe_name}!'})",
    "用户输入经 html.escape(quote=True) 转义后再使用，阻止 XSS",
    "no fix needed",
    """分析过程：
1. 输入可控性：username 来自 request.args.get('name')，用户可控。
2. sink 评估：用户输入进入 jsonify 响应。
3. 防御确认：html.escape(username, quote=True) 将 < > & " ' 转义为 HTML 实体，
   quote=True 确保引号也被转义（防止属性注入）。
4. jsonify 返回 JSON 响应（Content-Type: application/json），
   浏览器不会将其作为 HTML 解析，进一步降低 XSS 风险。
5. 即使输入含 <script>alert(1)</script>，转义后变为 &lt;script&gt;...，
   在 JSON 值中只是普通字符串。
6. 结论：代码安全。html.escape + JSON 响应是安全的处理方式。"""
)

add(
    """
import os
from urllib.parse import urlparse

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Only http/https allowed")
    if parsed.hostname in ('localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0'):
        raise ValueError("Internal host blocked")
    import urllib.request
    req = urllib.request.Request(url)
    return urllib.request.urlopen(req, timeout=5).read()
""",
    "python", "supplement_noise_ssrf_url_validate.py",
    False, "none", "None",
    "url 参数（函数入参）",
    "urllib.request.urlopen(req)",
    "URL 经 urlparse 校验 scheme + 屏蔽内网主机，阻止 SSRF",
    "no fix needed",
    """分析过程：
1. 输入可控性：url 是函数参数，用户可控。
2. sink 评估：urllib.request.urlopen 发起 HTTP 请求。
3. 防御确认（第一层）：urlparse 解析 URL，检查 scheme 必须是 http/https，
   阻止 file:///、ftp:// 等协议。
4. 防御确认（第二层）：屏蔽内网主机（localhost、127.0.0.1、169.254.169.254、0.0.0.0），
   阻止 SSRF 访问云元数据服务和本地服务。
5. 超时设置 timeout=5 防止长时间挂起。
6. 注意：此校验不完美（如 DNS rebinding），但已覆盖常见 SSRF 向量。
7. 结论：代码安全。scheme + 主机黑名单是基本的 SSRF 防护。"""
)

add(
    """
from flask import Flask, request, jsonify
import bcrypt

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = db.get_user(username)
    if user and bcrypt.checkpw(password.encode(), user.password_hash):
        session.clear()
        session['user_id'] = user.id
        session['role'] = user.role
        return {'status': 'logged in'}
    return {'error': 'invalid credentials'}, 401
""",
    "python", "supplement_noise_login_proper.py",
    False, "none", "None",
    "POST /login 表单数据",
    "bcrypt.checkpw(password.encode(), user.password_hash)",
    "bcrypt 验证密码 + session.clear() 防 session fixation + 统一错误消息",
    "no fix needed",
    """分析过程：
1. 输入可控性：username 和 password 来自用户表单输入。
2. 密码验证：使用 bcrypt.checkpw 而非字符串比较，恒定时间验证防计时攻击。
3. session 安全：登录成功后先 session.clear() 清除旧 session，防 session fixation。
4. 错误处理：无论用户名不存在还是密码错误，都返回相同的 'invalid credentials'，
   不泄露用户名是否存在（防用户名枚举）。
5. 密码不存储在明文/MD5/SHA1 中，使用 bcrypt 哈希存储。
6. 结论：代码安全。登录流程遵循安全最佳实践。"""
)

add(
    """
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({'id': user[0], 'name': user[1], 'email': user[2]})
    return jsonify({'error': 'not found'}), 404
""",
    "python", "supplement_noise_sql_int_param.py",
    False, "none", "None",
    "GET /api/user/<int:user_id> 路由参数",
    "cursor.execute(..., (user_id,))",
    "Flask 路由 <int:user_id> 强制整数类型 + 参数化查询，双重防护",
    "no fix needed",
    """分析过程：
1. 输入可控性：user_id 来自 URL 路径参数，用户可控。
2. 防御确认（第一层）：Flask 路由用 <int:user_id>，只匹配整数。
   非整数输入（如 /api/user/1 OR 1=1）会返回 404，不到达视图函数。
3. 防御确认（第二层）：cursor.execute 用 ? 占位符 + (user_id,) 参数元组，
   即使 user_id 含特殊字符也只作为数据值。
4. 查询只返回 id/name/email，不返回 password 等敏感字段（最小信息暴露）。
5. 结论：代码安全。路由类型强制 + 参数化查询有效防护 SQL 注入。"""
)

add(
    """
import os

def get_config(key):
    value = os.environ.get(key)
    if value is None:
        raise KeyError(f"Config {key} not set")
    return value

DB_PASSWORD = get_config('DB_PASSWORD')
API_SECRET = get_config('API_SECRET')
""",
    "python", "supplement_noise_env_var_secrets.py",
    False, "none", "None",
    "None（无用户输入）",
    "os.environ.get(key)",
    "凭证从环境变量读取，未硬编码在源码中",
    "no fix needed",
    """分析过程：
1. 凭证位置检查：扫描源码中的变量赋值，寻找 key/secret/password 命名的变量。
2. 识别结果：DB_PASSWORD 和 API_SECRET 通过 get_config 函数从 os.environ 读取，
   不是硬编码的字面量。
3. get_config 在环境变量不存在时抛 KeyError，确保必须配置。
4. 对比硬编码：API_KEY = 'sk-xxx' 是漏洞（源码可见即泄露）；
   os.environ.get('API_SECRET') 是安全做法（凭证不入库，部署时注入）。
5. 结论：代码安全。凭证从环境变量读取是正确的实践。"""
)

add(
    """
from flask import Flask, request, jsonify
import re

@app.route('/api/user')
def get_user():
    username = request.args.get('name', '')
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return jsonify({'error': 'invalid username'}), 400
    user = db.query('SELECT * FROM users WHERE username = ?', (username,))
    return jsonify({'user': user})
""",
    "python", "supplement_noise_input_regex_validate.py",
    False, "none", "None",
    "request.args.get('name')",
    "db.query(..., (username,))",
    "用户输入经正则白名单校验（仅字母数字下划线，3-20字符）+ 参数化查询",
    "no fix needed",
    """分析过程：
1. 输入可控性：username 来自 request.args.get('name')，用户可控。
2. 防御确认（第一层）：re.match(r'^[a-zA-Z0-9_]{3,20}$', username) 白名单校验，
   只允许字母、数字、下划线，长度 3-20 字符。
   ^ 和 $ 确保整个字符串匹配，阻止部分匹配绕过。
3. 防御确认（第二层）：db.query 用 ? 占位符参数化查询。
4. 校验在查询之前，未通过则返回 400，不执行查询。
5. 即使参数化查询已防注入，输入校验仍提供纵深防御（限制输入格式，降低其他攻击面）。
6. 结论：代码安全。输入校验 + 参数化查询是纵深防御的正确实践。"""
)

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
