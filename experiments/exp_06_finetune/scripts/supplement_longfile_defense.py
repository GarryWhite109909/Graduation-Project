"""
补充训练样本 —— 长文件注意力丢失 + 伪防御错觉 + 跨文件 sink 追踪。

针对微调后 Qwen2.5-Coder-3B 的三类 FN 失败案例：
  1. 长文件隐藏漏洞（模型注意力在前段安全代码上分散，遗漏后段漏洞）
  2. 伪防御错觉（模型看到有防御措施就判 safe，忽略防御可被绕过）
  3. 跨文件 sink 追踪（模型只分析主文件，不追踪 helper 中的 sink）

样本设计：
  - 类别1: 6 条长文件样本（3 vuln + 3 safe），150-250 行真实业务代码
  - 类别2: 6 条伪防御样本（3 vuln + 3 safe），可被绕过的弱防御 vs 真正有效的防御
  - 类别3: 4 条跨文件样本（2 vuln + 2 safe），input + sink 配对

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/supplement_longfile_defense.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_longfile_defense.jsonl"

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, explanation, fix_suggestion, cot_analysis):
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
        "explanation": explanation,
        "fix_suggestion": fix_suggestion,
        "cot_analysis": cot_analysis,
    })


# ===========================================================================
# 类别1: 长文件样本（6条，3 vuln + 3 safe）
# ===========================================================================

# --- 样本1: 长文件 + 隐藏 SQL 注入（电商系统报表导出）---
add(
    """
import os
import logging
import sqlite3
import hashlib
import secrets
from datetime import datetime
from flask import Flask, request, jsonify, g

app = Flask(__name__)
app.config['DATABASE'] = 'ecommerce.db'
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return salt.hex() + ':' + hashed.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, hash_hex = stored.split(':')
    salt = bytes.fromhex(salt_hex)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return secrets.compare_digest(hashed.hex(), hash_hex)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    if not username or not password or not email:
        return jsonify({'error': 'missing fields'}), 400
    if len(username) < 3 or len(password) < 8:
        return jsonify({'error': 'invalid input'}), 400
    db = get_db()
    existing = db.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    if existing:
        return jsonify({'error': 'user already exists'}), 409
    pwd_hash = hash_password(password)
    db.execute(
        'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
        (username, email, pwd_hash, datetime.utcnow().isoformat())
    )
    db.commit()
    logger.info(f'User registered: {username}')
    return jsonify({'status': 'registered', 'username': username}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'missing credentials'}), 400
    db = get_db()
    user = db.execute(
        'SELECT id, username, password_hash FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    if not user or not verify_password(password, user['password_hash']):
        return jsonify({'error': 'invalid credentials'}), 401
    token = secrets.token_hex(32)
    db.execute(
        'UPDATE users SET auth_token = ? WHERE id = ?',
        (token, user['id'])
    )
    db.commit()
    return jsonify({'token': token, 'username': user['username']})


@app.route('/api/products')
def list_products():
    category = request.args.get('category', '')
    page = request.args.get('page', '1')
    try:
        page_num = int(page)
        if page_num < 1:
            page_num = 1
    except ValueError:
        page_num = 1
    offset = (page_num - 1) * 20
    db = get_db()
    if category:
        products = db.execute(
            'SELECT id, name, price, category FROM products WHERE category = ? ORDER BY id LIMIT 20 OFFSET ?',
            (category, offset)
        ).fetchall()
    else:
        products = db.execute(
            'SELECT id, name, price, category FROM products ORDER BY id LIMIT 20 OFFSET ?',
            (offset,)
        ).fetchall()
    return jsonify([dict(p) for p in products])


@app.route('/api/products/search')
def search_products():
    keyword = request.args.get('q', '')
    if not keyword:
        return jsonify([])
    db = get_db()
    products = db.execute(
        'SELECT id, name, price FROM products WHERE name LIKE ? OR description LIKE ?',
        (f'%{keyword}%', f'%{keyword}%')
    ).fetchall()
    return jsonify([dict(p) for p in products])


@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not user_token:
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'invalid token'}), 401
    product = db.execute(
        'SELECT id, price, stock FROM products WHERE id = ?',
        (product_id,)
    ).fetchone()
    if not product or product['stock'] < quantity:
        return jsonify({'error': 'product unavailable'}), 400
    db.execute(
        'INSERT INTO cart_items (user_id, product_id, quantity, added_at) VALUES (?, ?, ?, ?)',
        (user['id'], product_id, quantity, datetime.utcnow().isoformat())
    )
    db.commit()
    return jsonify({'status': 'added'})


@app.route('/api/orders', methods=['POST'])
def create_order():
    data = request.get_json(force=True, silent=True) or {}
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    cart_items = db.execute(
        'SELECT c.product_id, c.quantity, p.price FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
        (user['id'],)
    ).fetchall()
    if not cart_items:
        return jsonify({'error': 'cart is empty'}), 400
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    db.execute(
        'INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)',
        (user['id'], total, 'pending', datetime.utcnow().isoformat())
    )
    order_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    for item in cart_items:
        db.execute(
            'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
            (order_id, item['product_id'], item['quantity'], item['price'])
        )
    db.execute('DELETE FROM cart_items WHERE user_id = ?', (user['id'],))
    db.commit()
    return jsonify({'order_id': order_id, 'total': total})


@app.route('/api/orders/history')
def order_history():
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    orders = db.execute(
        'SELECT id, total, status, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC',
        (user['id'],)
    ).fetchall()
    return jsonify([dict(o) for o in orders])


@app.route('/api/report/export')
def export_report():
    table = request.args.get('table', 'orders')
    limit = request.args.get('limit', '100')
    db = get_db()
    query = "SELECT * FROM " + table + " ORDER BY id DESC LIMIT " + limit
    rows = db.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])
""",
    "python",
    "longfile_ecommerce_export.py",
    True,
    "CWE-89 SQL注入",
    "Critical",
    "request.args.get('table') / request.args.get('limit')",
    "db.execute(query)（拼接 SQL）",
    "export_report 函数将用户传入的 table 和 limit 参数直接拼接到 SQL 字符串中，未使用参数化查询，攻击者可通过 table 参数注入任意 SQL",
    "使用白名单校验 table 参数（仅允许 orders/products/users），limit 用 int() 转换后参数化传入：db.execute('SELECT * FROM ' + safe_table + ' ORDER BY id DESC LIMIT ?', (limit,))",
    """分析过程（全文扫描）：
1. 逐函数扫描所有路由，追踪用户输入到数据库操作的数据流。
2. /api/register：INSERT 使用 ? 占位符 + 参数元组，参数化查询，安全。
3. /api/login：SELECT 使用 ? 占位符，密码用 pbkdf2_hmac + compare_digest 验证，安全。
4. /api/products：page 经 int() 转换，category 用 ? 占位符，安全。
5. /api/products/search：keyword 用 ? 占位符 + LIKE 参数，安全。
6. /api/cart/add 和 /api/orders：均使用 ? 占位符参数化查询，安全。
7. /api/orders/history：user_id 用 ? 占位符，安全。
8. 定位到文件末尾的 /api/report/export 函数：
   - request.args.get('table') 和 request.args.get('limit') 直接拼接到 SQL 字符串
   - query = "SELECT * FROM " + table + " ORDER BY id DESC LIMIT " + limit
   - table 未经白名单校验，limit 未经 int() 转换，直接字符串拼接进 SQL
   - 攻击者可传 table=orders; DROP TABLE users-- 实现注入
9. 结论：虽然前段所有数据库操作都使用了参数化查询，但最后的报表导出函数存在 SQL 注入漏洞。其他路由的安全性不能掩盖这个漏洞。"""
)

# --- 样本2: 长文件 + 隐藏命令注入（运维工具备份函数）---
add(
    """
import os
import sys
import shutil
import logging
import subprocess
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('/var/log/ops_tool.log'), logging.StreamHandler()]
)
logger = logging.getLogger('ops_tool')

WORK_DIR = Path('/var/lib/ops_tool')
LOG_DIR = Path('/var/log/app')
ARCHIVE_DIR = Path('/var/backups/ops')
CONFIG_FILE = Path('/etc/ops_tool/config.yaml')

WORK_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def rotate_logs(max_files=10, max_size_mb=100):
    if not LOG_DIR.exists():
        logger.warning(f'Log dir not found: {LOG_DIR}')
        return
    log_files = sorted(LOG_DIR.glob('*.log'), key=lambda f: f.stat().st_mtime, reverse=True)
    for old_log in log_files[max_files:]:
        old_log.unlink()
        logger.info(f'Removed old log: {old_log.name}')
    for log_file in log_files[:max_files]:
        size_mb = log_file.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            rotated = log_file.with_suffix(f'.{timestamp}.log')
            log_file.rename(rotated)
            logger.info(f'Rotated {log_file.name} -> {rotated.name} ({size_mb:.1f}MB)')


def check_disk_usage(path='/'):
    result = subprocess.run(
        ['df', '-h', path],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        lines = result.stdout.strip().split('\\n')
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                usage = parts[4].rstrip('%')
                logger.info(f'Disk usage for {path}: {usage}%')
                return int(usage)
    return -1


def check_service_status(service_name):
    result = subprocess.run(
        ['systemctl', 'is-active', service_name],
        capture_output=True, text=True, timeout=5
    )
    status = result.stdout.strip()
    logger.info(f'Service {service_name}: {status}')
    return status == 'active'


def analyze_log_errors(log_file, error_keywords=None):
    if error_keywords is None:
        error_keywords = ['ERROR', 'CRITICAL', 'Traceback', 'Exception']
    if not log_file.exists():
        return []
    errors = []
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            for keyword in error_keywords:
                if keyword in line:
                    errors.append({
                        'line': line_num,
                        'keyword': keyword,
                        'content': line.strip()[:200]
                    })
                    break
    return errors


def cleanup_temp_files(directory='/tmp', days_old=7):
    target = Path(directory)
    if not target.exists():
        return 0
    cutoff = datetime.now() - timedelta(days=days_old)
    count = 0
    for item in target.iterdir():
        try:
            mtime = datetime.fromtimestamp(item.stat().st_mtime)
            if mtime < cutoff:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
                count += 1
        except (PermissionError, FileNotFoundError):
            continue
    logger.info(f'Cleaned up {count} temp files older than {days_old} days')
    return count


def sync_config(source_path, dest_path):
    src = Path(source_path)
    dst = Path(dest_path)
    if not src.exists():
        logger.error(f'Source config not found: {src}')
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    with open(src, 'rb') as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    logger.info(f'Config synced: {src} -> {dst} (sha256={checksum[:16]})')
    return True


def backup_directory(source_dir, archive_name):
    source = Path(source_dir)
    if not source.exists():
        logger.error(f'Source directory not found: {source_dir}')
        return False
    archive_path = ARCHIVE_DIR / archive_name
    if not archive_name.endswith('.tar.gz'):
        archive_name += '.tar.gz'
    cmd = f"tar -czf {archive_path} -C {source.parent} {source.name}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
    if result.returncode == 0:
        size_mb = archive_path.stat().st_size / (1024 * 1024)
        logger.info(f'Backup created: {archive_path} ({size_mb:.1f}MB)')
        return True
    else:
        logger.error(f'Backup failed: {result.stderr}')
        return False


def run_maintenance():
    logger.info('Starting maintenance routine...')
    rotate_logs()
    usage = check_disk_usage('/')
    if usage > 90:
        cleanup_temp_files()
    for svc in ['nginx', 'postgresql', 'redis']:
        check_service_status(svc)
    errors = analyze_log_errors(LOG_DIR / 'app.log')
    if errors:
        logger.warning(f'Found {len(errors)} errors in app.log')
    sync_config(CONFIG_FILE, WORK_DIR / 'config.yaml')
    backup_directory('/var/www/data', f'backup_{datetime.now().strftime("%Y%m%d")}')
    logger.info('Maintenance complete.')


if __name__ == '__main__':
    run_maintenance()
""",
    "python",
    "longfile_ops_backup.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "backup_directory 的 archive_name 参数",
    "subprocess.run(cmd, shell=True)（f-string 拼接命令）",
    "backup_directory 函数将 archive_name 参数通过 f-string 拼接到 shell 命令字符串中，并使用 shell=True 执行，攻击者可通过 archive_name 注入 shell 元字符",
    "使用 subprocess.run(['tar', '-czf', str(archive_path), '-C', str(source.parent), source.name], shell=False) 列表形式，不使用 shell=True",
    """分析过程（全文扫描）：
1. 逐函数扫描所有工具函数，关注用户输入和外部参数到危险操作的数据流。
2. rotate_logs：文件操作，使用 Path.glob 和 unlink/rename，无外部输入参与，安全。
3. check_disk_usage：subprocess.run(['df', '-h', path]) 使用列表形式，shell 默认 False，安全。
4. check_service_status：subprocess.run(['systemctl', 'is-active', service_name]) 列表形式，安全。
5. analyze_log_errors：文件读取操作，error_keywords 是内部定义的列表，安全。
6. cleanup_temp_files：文件操作，参数有默认值，days_old 在调用时为硬编码，安全。
7. sync_config：shutil.copy2 文件复制，source_path 和 dest_path 在调用时为硬编码路径，安全。
8. 定位到 backup_directory 函数（文件中后部）：
   - archive_name 是函数参数，调用时来自 f'backup_{datetime.now()...}'（硬编码，看似安全）
   - 但函数本身的设计有缺陷：archive_name 直接拼接到 f-string 命令字符串中
   - cmd = f"tar -czf {archive_path} -C {source.parent} {source.name}"
   - subprocess.run(cmd, shell=True) 使用 shell=True，命令经过 shell 解释器
   - 如果 archive_name 包含 shell 元字符（如 ; rm -rf /），会被 shell 执行
   - source.name 也参与拼接，如果目录名含特殊字符同样可被注入
9. 结论：虽然前段所有 subprocess 调用都使用了列表形式（shell=False），但 backup_directory 函数使用 shell=True + f-string 拼接，存在命令注入漏洞。"""
)

# --- 样本3: 长文件 + 隐藏 SSTI（Web 应用自定义路由）---
add(
    """
import os
import logging
from datetime import datetime
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, flash, g
)
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['TEMPLATES_AUTO_RELOAD'] = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

template_env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml']),
)

USERS = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'pass456', 'role': 'user'},
}

PRODUCTS = [
    {'id': 1, 'name': 'Laptop', 'price': 999.99, 'category': 'electronics'},
    {'id': 2, 'name': 'Mouse', 'price': 29.99, 'category': 'electronics'},
    {'id': 3, 'name': 'Keyboard', 'price': 79.99, 'category': 'electronics'},
    {'id': 4, 'name': 'Notebook', 'price': 4.99, 'category': 'stationery'},
    {'id': 5, 'name': 'Pen Set', 'price': 14.99, 'category': 'stationery'},
]

COMMENTS = [
    {'id': 1, 'product_id': 1, 'author': 'admin', 'content': 'Great product!'},
    {'id': 2, 'product_id': 1, 'author': 'user1', 'content': 'Works as expected.'},
]


@app.before_request
def load_user():
    g.user = None
    username = session.get('username')
    if username and username in USERS:
        g.user = {'username': username, 'role': USERS[username]['role']}


def format_timestamp(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


@app.route('/')
def index():
    template = template_env.get_template('index.html')
    return template.render(user=g.user)


@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = USERS.get(username)
        if user and user['password'] == password:
            session.clear()
            session['username'] = username
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('dashboard.html')
    return template.render(user=g.user, page_title='Dashboard')


@app.route('/profile')
def profile():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('profile.html')
    return template.render(user=g.user)


@app.route('/api/products')
def list_products_api():
    category = request.args.get('category', '')
    if category:
        filtered = [p for p in PRODUCTS if p['category'] == category]
    else:
        filtered = PRODUCTS
    return jsonify(filtered)


@app.route('/api/products/<int:product_id>')
def get_product_api(product_id):
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return jsonify({'error': 'not found'}), 404
    product_comments = [c for c in COMMENTS if c['product_id'] == product_id]
    return jsonify({'product': product, 'comments': product_comments})


@app.route('/products')
def products_page():
    category = request.args.get('category', '')
    template = template_env.get_template('products.html')
    if category:
        displayed = [p for p in PRODUCTS if p['category'] == category]
    else:
        displayed = PRODUCTS
    return template.render(products=displayed, category=category, user=g.user)


@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    template = template_env.get_template('search.html')
    return template.render(keyword=keyword, user=g.user)


@app.route('/notifications')
def notifications():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('notifications.html')
    return template.render(user=g.user)


@app.route('/settings')
def settings():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('settings.html')
    return template.render(user=g.user)


@app.route('/profile/update', methods=['POST'])
def update_profile():
    if not g.user:
        return redirect(url_for('login'))
    new_password = request.form.get('password', '')
    if new_password and len(new_password) >= 8:
        USERS[g.user['username']]['password'] = new_password
        flash('Password updated', 'success')
    else:
        flash('Password too short', 'error')
    return redirect(url_for('profile'))


@app.route('/admin')
def admin_panel():
    if not g.user or g.user['role'] != 'admin':
        return jsonify({'error': 'forbidden'}), 403
    template = template_env.get_template('admin.html')
    return template.render(user=g.user, users=list(USERS.keys()), products=PRODUCTS)


@app.route('/custom-page')
def custom_page():
    if not g.user:
        return redirect(url_for('login'))
    title = request.args.get('title', 'Custom Page')
    content = request.args.get('content', 'Welcome to custom page')
    template_str = f'<h1>{{title}}</h1><div>{{content}}</div><p>Author: {g.user["username"]}</p>'
    env = Environment()
    template = env.from_string(template_str)
    return template.render(title=title, content=content)
""",
    "python",
    "longfile_webapp_ssti.py",
    True,
    "CWE-94 代码注入",
    "Critical",
    "request.args.get('content') / g.user['username']",
    "env.from_string(template_str)",
    "custom_page 路由将用户输入 content 和 session 中的 username 通过 f-string 拼接到模板字符串，再用 jinja2.Environment().from_string() 编译渲染，攻击者可注入 {{ }} 或 {% %} 标签执行任意代码",
    "不要将用户输入拼接到模板字符串中；改用固定模板文件 + context 传参：template_env.get_template('custom.html').render(title=title, content=content, user=g.user)",
    """分析过程（全文扫描）：
1. 逐路由扫描所有处理函数，关注用户输入到模板渲染的数据流。
2. / 和 /health：使用预定义模板或返回 JSON，无用户输入参与模板构造，安全。
3. /login：POST 处理用 session 和 redirect，GET 用 render_template，安全。
4. /dashboard、/profile、/search、/notifications、/settings：
   均使用 template_env.get_template() 加载预定义模板文件，通过 context 传参，
   且 template_env 配置了 autoescape=select_autoescape(['html','xml'])，安全。
5. 定位到 /custom-page 路由（文件末尾）：
   - request.args.get('content') 获取用户输入
   - template_str = f'<h1>{{title}}</h1><div>{{content}}</div><p>Author: {g.user["username"]}</p>'
   - f-string 中 {g.user["username"]} 直接将用户名嵌入模板字符串（成为模板源码的一部分）
   - env = Environment() 创建了未配置 autoescape 的裸 Environment
   - env.from_string(template_str) 将含用户输入的字符串编译为 Jinja2 模板
   - 虽然 content 在模板中用 {{content}} 引用（作为变量），但 username 是通过 f-string 拼入模板源码的
   - 更关键的是，如果 content 参数本身包含 {{ }} 或 {% %} 标签，from_string 会将其编译执行
6. 结论：虽然前面所有路由都安全使用了预定义模板 + context 传参，但 /custom-page 路由使用 from_string 编译含用户输入的模板字符串，存在 SSTI 漏洞。"""
)

# --- 样本4: 长文件 + 安全的报表导出（参数化查询）---
add(
    """
import os
import logging
import sqlite3
import hashlib
import secrets
from datetime import datetime
from flask import Flask, request, jsonify, g

app = Flask(__name__)
app.config['DATABASE'] = 'ecommerce.db'
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return salt.hex() + ':' + hashed.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, hash_hex = stored.split(':')
    salt = bytes.fromhex(salt_hex)
    iterations = 100000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return secrets.compare_digest(hashed.hex(), hash_hex)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    if not username or not password or not email:
        return jsonify({'error': 'missing fields'}), 400
    if len(username) < 3 or len(password) < 8:
        return jsonify({'error': 'invalid input'}), 400
    db = get_db()
    existing = db.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    if existing:
        return jsonify({'error': 'user already exists'}), 409
    pwd_hash = hash_password(password)
    db.execute(
        'INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
        (username, email, pwd_hash, datetime.utcnow().isoformat())
    )
    db.commit()
    logger.info(f'User registered: {username}')
    return jsonify({'status': 'registered', 'username': username}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'missing credentials'}), 400
    db = get_db()
    user = db.execute(
        'SELECT id, username, password_hash FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    if not user or not verify_password(password, user['password_hash']):
        return jsonify({'error': 'invalid credentials'}), 401
    token = secrets.token_hex(32)
    db.execute(
        'UPDATE users SET auth_token = ? WHERE id = ?',
        (token, user['id'])
    )
    db.commit()
    return jsonify({'token': token, 'username': user['username']})


@app.route('/api/products')
def list_products():
    category = request.args.get('category', '')
    page = request.args.get('page', '1')
    try:
        page_num = int(page)
        if page_num < 1:
            page_num = 1
    except ValueError:
        page_num = 1
    offset = (page_num - 1) * 20
    db = get_db()
    if category:
        products = db.execute(
            'SELECT id, name, price, category FROM products WHERE category = ? ORDER BY id LIMIT 20 OFFSET ?',
            (category, offset)
        ).fetchall()
    else:
        products = db.execute(
            'SELECT id, name, price, category FROM products ORDER BY id LIMIT 20 OFFSET ?',
            (offset,)
        ).fetchall()
    return jsonify([dict(p) for p in products])


@app.route('/api/products/search')
def search_products():
    keyword = request.args.get('q', '')
    if not keyword:
        return jsonify([])
    db = get_db()
    products = db.execute(
        'SELECT id, name, price FROM products WHERE name LIKE ? OR description LIKE ?',
        (f'%{keyword}%', f'%{keyword}%')
    ).fetchall()
    return jsonify([dict(p) for p in products])


@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not user_token:
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'invalid token'}), 401
    product = db.execute(
        'SELECT id, price, stock FROM products WHERE id = ?',
        (product_id,)
    ).fetchone()
    if not product or product['stock'] < quantity:
        return jsonify({'error': 'product unavailable'}), 400
    db.execute(
        'INSERT INTO cart_items (user_id, product_id, quantity, added_at) VALUES (?, ?, ?, ?)',
        (user['id'], product_id, quantity, datetime.utcnow().isoformat())
    )
    db.commit()
    return jsonify({'status': 'added'})


@app.route('/api/orders', methods=['POST'])
def create_order():
    data = request.get_json(force=True, silent=True) or {}
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    cart_items = db.execute(
        'SELECT c.product_id, c.quantity, p.price FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
        (user['id'],)
    ).fetchall()
    if not cart_items:
        return jsonify({'error': 'cart is empty'}), 400
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    db.execute(
        'INSERT INTO orders (user_id, total, status, created_at) VALUES (?, ?, ?, ?)',
        (user['id'], total, 'pending', datetime.utcnow().isoformat())
    )
    order_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    for item in cart_items:
        db.execute(
            'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
            (order_id, item['product_id'], item['quantity'], item['price'])
        )
    db.execute('DELETE FROM cart_items WHERE user_id = ?', (user['id'],))
    db.commit()
    return jsonify({'order_id': order_id, 'total': total})


@app.route('/api/orders/history')
def order_history():
    user_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    db = get_db()
    user = db.execute(
        'SELECT id FROM users WHERE auth_token = ?',
        (user_token,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'unauthorized'}), 401
    orders = db.execute(
        'SELECT id, total, status, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC',
        (user['id'],)
    ).fetchall()
    return jsonify([dict(o) for o in orders])


ALLOWED_REPORT_TABLES = {'orders', 'products', 'users', 'cart_items'}


@app.route('/api/report/export')
def export_report():
    table = request.args.get('table', 'orders')
    limit_str = request.args.get('limit', '100')
    if table not in ALLOWED_REPORT_TABLES:
        return jsonify({'error': 'invalid table name'}), 400
    try:
        limit = int(limit_str)
        if limit < 1 or limit > 1000:
            limit = 100
    except ValueError:
        limit = 100
    db = get_db()
    query = f'SELECT * FROM {table} ORDER BY id DESC LIMIT ?'
    rows = db.execute(query, (limit,)).fetchall()
    return jsonify([dict(r) for r in rows])
""",
    "python",
    "longfile_safe_export.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "全文所有数据库操作均使用参数化查询（? 占位符 + 参数元组），export_report 函数额外用白名单 ALLOWED_REPORT_TABLES 校验 table 参数、int() 转换 limit 参数，table 经白名单后用于 f-string 仅做表名插值（不可注入），limit 用 ? 占位符参数化传入",
    "no fix needed",
    """分析过程（全文扫描）：
1. 逐函数扫描所有路由，追踪用户输入到数据库操作的数据流。
2. /api/register：INSERT 使用 ? 占位符 + 参数元组，参数化查询，安全。
3. /api/login：SELECT 使用 ? 占位符，密码用 pbkdf2_hmac + compare_digest 验证，安全。
4. /api/products：page 经 int() 转换，category 用 ? 占位符，安全。
5. /api/products/search：keyword 用 ? 占位符 + LIKE 参数，安全。
6. /api/cart/add 和 /api/orders：均使用 ? 占位符参数化查询，安全。
7. /api/orders/history：user_id 用 ? 占位符，安全。
8. /api/report/export 函数：
   - table 参数经过 ALLOWED_REPORT_TABLES 白名单校验（仅允许 orders/products/users/cart_items）
   - 未通过白名单则返回 400，不执行查询
   - limit_str 经 int() 转换并范围限制 [1, 1000]
   - 查询使用 f'SELECT * FROM {table} ORDER BY id DESC LIMIT ?'
   - table 虽然通过 f-string 插入 SQL，但已通过严格白名单校验（只允许 4 个硬编码表名），不存在注入
   - limit 通过 ? 占位符参数化传入，不是字符串拼接
9. 结论：全文所有数据库操作均使用参数化查询或白名单校验，未发现 SQL 注入漏洞。"""
)

# --- 样本5: 长文件 + 安全的备份函数（subprocess 列表形式）---
add(
    """
import os
import sys
import shutil
import logging
import subprocess
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('/var/log/ops_tool.log'), logging.StreamHandler()]
)
logger = logging.getLogger('ops_tool')

WORK_DIR = Path('/var/lib/ops_tool')
LOG_DIR = Path('/var/log/app')
ARCHIVE_DIR = Path('/var/backups/ops')
CONFIG_FILE = Path('/etc/ops_tool/config.yaml')

WORK_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


def rotate_logs(max_files=10, max_size_mb=100):
    if not LOG_DIR.exists():
        logger.warning(f'Log dir not found: {LOG_DIR}')
        return
    log_files = sorted(LOG_DIR.glob('*.log'), key=lambda f: f.stat().st_mtime, reverse=True)
    for old_log in log_files[max_files:]:
        old_log.unlink()
        logger.info(f'Removed old log: {old_log.name}')
    for log_file in log_files[:max_files]:
        size_mb = log_file.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            rotated = log_file.with_suffix(f'.{timestamp}.log')
            log_file.rename(rotated)
            logger.info(f'Rotated {log_file.name} -> {rotated.name} ({size_mb:.1f}MB)')


def check_disk_usage(path='/'):
    result = subprocess.run(
        ['df', '-h', path],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        lines = result.stdout.strip().split('\\n')
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                usage = parts[4].rstrip('%')
                logger.info(f'Disk usage for {path}: {usage}%')
                return int(usage)
    return -1


def check_service_status(service_name):
    result = subprocess.run(
        ['systemctl', 'is-active', service_name],
        capture_output=True, text=True, timeout=5
    )
    status = result.stdout.strip()
    logger.info(f'Service {service_name}: {status}')
    return status == 'active'


def analyze_log_errors(log_file, error_keywords=None):
    if error_keywords is None:
        error_keywords = ['ERROR', 'CRITICAL', 'Traceback', 'Exception']
    if not log_file.exists():
        return []
    errors = []
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            for keyword in error_keywords:
                if keyword in line:
                    errors.append({
                        'line': line_num,
                        'keyword': keyword,
                        'content': line.strip()[:200]
                    })
                    break
    return errors


def cleanup_temp_files(directory='/tmp', days_old=7):
    target = Path(directory)
    if not target.exists():
        return 0
    cutoff = datetime.now() - timedelta(days=days_old)
    count = 0
    for item in target.iterdir():
        try:
            mtime = datetime.fromtimestamp(item.stat().st_mtime)
            if mtime < cutoff:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
                count += 1
        except (PermissionError, FileNotFoundError):
            continue
    logger.info(f'Cleaned up {count} temp files older than {days_old} days')
    return count


def sync_config(source_path, dest_path):
    src = Path(source_path)
    dst = Path(dest_path)
    if not src.exists():
        logger.error(f'Source config not found: {src}')
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    with open(src, 'rb') as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    logger.info(f'Config synced: {src} -> {dst} (sha256={checksum[:16]})')
    return True


def backup_directory(source_dir, archive_name):
    source = Path(source_dir)
    if not source.exists():
        logger.error(f'Source directory not found: {source_dir}')
        return False
    if not archive_name.replace('_', '').replace('-', '').isalnum():
        logger.error(f'Invalid archive name: {archive_name}')
        return False
    archive_path = ARCHIVE_DIR / f'{archive_name}.tar.gz'
    result = subprocess.run(
        ['tar', '-czf', str(archive_path), '-C', str(source.parent), source.name],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode == 0:
        size_mb = archive_path.stat().st_size / (1024 * 1024)
        logger.info(f'Backup created: {archive_path} ({size_mb:.1f}MB)')
        return True
    else:
        logger.error(f'Backup failed: {result.stderr}')
        return False


def run_maintenance():
    logger.info('Starting maintenance routine...')
    rotate_logs()
    usage = check_disk_usage('/')
    if usage > 90:
        cleanup_temp_files()
    for svc in ['nginx', 'postgresql', 'redis']:
        check_service_status(svc)
    errors = analyze_log_errors(LOG_DIR / 'app.log')
    if errors:
        logger.warning(f'Found {len(errors)} errors in app.log')
    sync_config(CONFIG_FILE, WORK_DIR / 'config.yaml')
    backup_directory('/var/www/data', f'backup_{datetime.now().strftime("%Y%m%d")}')
    logger.info('Maintenance complete.')


if __name__ == '__main__':
    run_maintenance()
""",
    "python",
    "longfile_safe_backup.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "全文所有 subprocess 调用均使用列表形式（shell 默认 False），backup_directory 额外对 archive_name 做 isalnum 白名单校验，命令参数以列表形式传递不经 shell 解释器，无命令注入风险",
    "no fix needed",
    """分析过程（全文扫描）：
1. 逐函数扫描所有工具函数，关注外部参数到 subprocess 的数据流。
2. rotate_logs：文件操作，使用 Path.glob 和 unlink/rename，安全。
3. check_disk_usage：subprocess.run(['df', '-h', path]) 列表形式，shell 默认 False，安全。
4. check_service_status：subprocess.run(['systemctl', 'is-active', service_name]) 列表形式，安全。
5. analyze_log_errors：文件读取操作，error_keywords 内部定义，安全。
6. cleanup_temp_files：文件操作，参数有默认值，安全。
7. sync_config：shutil.copy2 文件复制，调用时为硬编码路径，安全。
8. backup_directory 函数：
   - archive_name 经过 isalnum 白名单校验（replace('_','').replace('-','').isalnum()），只允许字母数字下划线连字符
   - subprocess.run(['tar', '-czf', str(archive_path), '-C', str(source.parent), source.name]) 使用列表形式
   - shell 参数默认 False，命令和参数以列表形式传递，不经 shell 解释器
   - archive_path 由 ARCHIVE_DIR 和 archive_name 拼接，archive_name 已校验
9. 结论：全文所有 subprocess 调用均使用列表形式 + shell=False，backup_directory 额外做了 archive_name 白名单校验，未发现命令注入漏洞。"""
)

# --- 样本6: 长文件 + 安全的模板渲染（sandbox Environment）---
add(
    """
import os
import logging
from datetime import datetime
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, flash, g
)
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['TEMPLATES_AUTO_RELOAD'] = True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

template_env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml']),
)

sandbox_env = SandboxedEnvironment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml']),
)

USERS = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user1': {'password': 'pass456', 'role': 'user'},
}

PRODUCTS = [
    {'id': 1, 'name': 'Laptop', 'price': 999.99, 'category': 'electronics'},
    {'id': 2, 'name': 'Mouse', 'price': 29.99, 'category': 'electronics'},
    {'id': 3, 'name': 'Keyboard', 'price': 79.99, 'category': 'electronics'},
    {'id': 4, 'name': 'Notebook', 'price': 4.99, 'category': 'stationery'},
    {'id': 5, 'name': 'Pen Set', 'price': 14.99, 'category': 'stationery'},
]

COMMENTS = [
    {'id': 1, 'product_id': 1, 'author': 'admin', 'content': 'Great product!'},
    {'id': 2, 'product_id': 1, 'author': 'user1', 'content': 'Works as expected.'},
]


@app.before_request
def load_user():
    g.user = None
    username = session.get('username')
    if username and username in USERS:
        g.user = {'username': username, 'role': USERS[username]['role']}


def format_timestamp(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


@app.route('/')
def index():
    template = template_env.get_template('index.html')
    return template.render(user=g.user)


@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = USERS.get(username)
        if user and user['password'] == password:
            session.clear()
            session['username'] = username
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('dashboard.html')
    return template.render(user=g.user, page_title='Dashboard')


@app.route('/profile')
def profile():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('profile.html')
    return template.render(user=g.user)


@app.route('/api/products')
def list_products_api():
    category = request.args.get('category', '')
    if category:
        filtered = [p for p in PRODUCTS if p['category'] == category]
    else:
        filtered = PRODUCTS
    return jsonify(filtered)


@app.route('/api/products/<int:product_id>')
def get_product_api(product_id):
    product = next((p for p in PRODUCTS if p['id'] == product_id), None)
    if not product:
        return jsonify({'error': 'not found'}), 404
    product_comments = [c for c in COMMENTS if c['product_id'] == product_id]
    return jsonify({'product': product, 'comments': product_comments})


@app.route('/products')
def products_page():
    category = request.args.get('category', '')
    template = template_env.get_template('products.html')
    if category:
        displayed = [p for p in PRODUCTS if p['category'] == category]
    else:
        displayed = PRODUCTS
    return template.render(products=displayed, category=category, user=g.user)


@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    template = template_env.get_template('search.html')
    return template.render(keyword=keyword, user=g.user)


@app.route('/notifications')
def notifications():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('notifications.html')
    return template.render(user=g.user)


@app.route('/settings')
def settings():
    if not g.user:
        return redirect(url_for('login'))
    template = template_env.get_template('settings.html')
    return template.render(user=g.user)


@app.route('/profile/update', methods=['POST'])
def update_profile():
    if not g.user:
        return redirect(url_for('login'))
    new_password = request.form.get('password', '')
    if new_password and len(new_password) >= 8:
        USERS[g.user['username']]['password'] = new_password
        flash('Password updated', 'success')
    else:
        flash('Password too short', 'error')
    return redirect(url_for('profile'))


@app.route('/admin')
def admin_panel():
    if not g.user or g.user['role'] != 'admin':
        return jsonify({'error': 'forbidden'}), 403
    template = template_env.get_template('admin.html')
    return template.render(user=g.user, users=list(USERS.keys()), products=PRODUCTS)


@app.route('/custom-page')
def custom_page():
    if not g.user:
        return redirect(url_for('login'))
    title = request.args.get('title', 'Custom Page')
    content = request.args.get('content', 'Welcome to custom page')
    template = sandbox_env.get_template('custom_page.html')
    return template.render(title=title, content=content, user=g.user)
""",
    "python",
    "longfile_safe_template.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "全文所有模板渲染均使用预定义模板文件 + context 传参，custom_page 路由使用 SandboxedEnvironment 加载固定模板文件，用户输入仅作为 context 数据传入而非模板源码，autoescape 开启自动转义",
    "no fix needed",
    """分析过程（全文扫描）：
1. 逐路由扫描所有处理函数，关注用户输入到模板渲染的数据流。
2. / 和 /health：使用预定义模板或返回 JSON，安全。
3. /login：POST 处理用 session 和 redirect，GET 用 render_template，安全。
4. /dashboard、/profile、/search、/notifications、/settings：
   均使用 template_env.get_template() 加载预定义模板文件，通过 context 传参，
   template_env 配置了 autoescape=select_autoescape(['html','xml'])，安全。
5. /custom-page 路由：
   - title 和 content 从 request.args 获取用户输入
   - 使用 sandbox_env.get_template('custom_page.html') 加载预定义模板文件
   - sandbox_env 是 SandboxedEnvironment，禁止访问危险属性和方法（如 __import__、os.popen）
   - 用户输入通过 template.render(title=title, content=content, user=g.user) 作为 context 传入
   - 用户输入不会成为模板源码的一部分，只作为数据变量
   - autoescape=select_autoescape(['html','xml']) 自动对输出进行 HTML 转义
6. 结论：全文所有模板渲染均使用预定义模板文件 + context 传参 + autoescape，custom_page 额外使用 SandboxedEnvironment，未发现 SSTI 漏洞。"""
)


# ===========================================================================
# 类别2: 伪防御样本（6条，3 vuln + 3 safe）
# ===========================================================================

# --- 样本7: 伪防御 - path regex sub 可被绕过 ---
add(
    """
import re
import os
from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"


@app.route("/view")
def view():
    filename = request.args.get("file", "")
    # 防御：移除路径穿越序列
    path = re.sub(r"\\.\\./", "", filename)
    full_path = os.path.join(BASE_DIR, path)
    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404
""",
    "python",
    "pseudodefense_path_regex.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "request.args.get('file')",
    "open(full_path, 'r')",
    "re.sub(r'\\\\.\\\\./', '', filename) 只替换字面的 ../ 序列，可被 ....// 绕过（替换后剩余 ../），也可被 URL 编码 %2e%2e%2f 或绝对路径 /etc/passwd 绕过",
    "使用 os.path.realpath 规范化路径后检查是否在 BASE_DIR 内：real = os.path.realpath(full_path); if not real.startswith(os.path.realpath(BASE_DIR) + os.sep): abort(403)",
    """分析过程：
1. 污染源：request.args.get('file') 获取用户输入 filename。
2. 危险 sink：open(full_path, 'r') 读取文件。
3. 数据流：filename → re.sub(r'\\.\\./', '', filename) → os.path.join → open(full_path)。
4. 防御评估：代码使用 re.sub(r"\\.\\./", "", filename) 试图移除路径穿越序列。
   看起来有防御，但该防御可被多种方式绕过：
   (a) 双写绕过：输入 "....//" → re.sub 替换掉中间的 "../" 后剩余 "../" → 路径穿越成功
   (b) URL 编码：输入 "%2e%2e%2f" → 不匹配正则 \\.\\./ → 直接通过
   (c) 绝对路径：输入 "/etc/passwd" → 不包含 ../ → os.path.join 丢弃 BASE_DIR
   (d) 反斜杠变体：在 Windows 上 "..\\" 也不匹配正则
5. 结论：正则黑名单 re.sub 不是有效的路径穿越防御，可被双写和编码绕过。存在路径穿越漏洞。"""
)

# --- 样本8: 伪防御 - 分号检查可被绕过 ---
add(
    """
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    cmd = f"ping -c 1 {host}"
    # 防御：检查分号防止命令注入
    if ";" in cmd:
        return "Invalid host", 400
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout
""",
    "python",
    "pseudodefense_cmd_semicolon.py",
    True,
    "CWE-78 命令注入",
    "Critical",
    "request.args.get('host')",
    "subprocess.run(cmd, shell=True)",
    "if ';' in cmd 只检查分号，但 shell 命令分隔符还包括 |（管道）、&&（与）、||（或）、换行符等，攻击者可用 host=8.8.8.8 | cat /etc/passwd 绕过",
    "不要用 shell=True + 字符串拼接；改用 subprocess.run(['ping', '-c', '1', host], shell=False) 列表形式，或对 host 做严格白名单校验",
    """分析过程：
1. 污染源：request.args.get('host') 获取用户输入。
2. 危险 sink：subprocess.run(cmd, shell=True) 使用 shell=True 执行命令。
3. 数据流：host → f"ping -c 1 {host}" → if ";" in cmd 检查 → subprocess.run(shell=True)。
4. 防御评估：代码用 if ";" in cmd 检查分号。
   看起来有防御，但该防御可被多种 shell 元字符绕过：
   (a) 管道符 |：host=8.8.8.8 | cat /etc/passwd → 不含分号，通过检查
   (b) 逻辑与 &&：host=8.8.8.8 && whoami → 不含分号，通过检查
   (c) 逻辑或 ||：host=8.8.8.8 || id → 不含分号，通过检查
   (d) 反引号 `：host=8.8.8.8`whoami` → 不含分号，通过检查
   (e) 换行符 %0a：host=8.8.8.8\\nwhoami → 不含分号，通过检查
5. 结论：仅检查分号不能防御命令注入，shell 的命令分隔符有多种。根本问题是 shell=True + 用户输入拼接。"""
)

# --- 样本9: 伪防御 - script 标签 replace 可被绕过 ---
add(
    """
from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # 防御：移除 <script> 标签防止 XSS
    safe_name = name.replace("<script>", "")
    html_content = f"<h1>Hello, {safe_name}!</h1>"
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response
""",
    "python",
    "pseudodefense_xss_replace.py",
    True,
    "CWE-79 XSS",
    "High",
    "request.args.get('name')",
    "f'<h1>Hello, {safe_name}!</h1>'（HTML 拼接）",
    "name.replace('<script>', '') 只移除小写的 <script>，可被 <SCRIPT>、<ScRiPt>（大小写绕过）、<img onerror=alert(1)>（不同标签）、<svg onload=alert(1)> 等方式绕过",
    "使用 html.escape(name, quote=True) 转义所有 HTML 特殊字符（< > & \\\" '），或使用模板引擎的自动转义功能",
    """分析过程：
1. 污染源：request.args.get('name') 获取用户输入。
2. 危险 sink：f'<h1>Hello, {safe_name}!</h1>' 将用户输入拼接到 HTML 字符串，Content-Type 为 text/html。
3. 数据流：name → replace("<script>", "") → f-string 拼接到 HTML → 返回给浏览器。
4. 防御评估：代码用 name.replace("<script>", "") 试图移除 script 标签。
   看起来有防御，但该防御可被多种方式绕过：
   (a) 大小写绕过：输入 "<SCRIPT>alert(1)</SCRIPT>" → replace 只匹配小写 <script>，不移除
   (b) 混合大小写：输入 "<ScRiPt>alert(1)</ScRiPt>" → 同样不匹配
   (c) 不同标签：输入 "<img src=x onerror=alert(1)>" → 不含 <script>，直接通过
   (d) SVG 标签：输入 "<svg onload=alert(1)>" → 不含 <script>，直接通过
   (e) 嵌套绕过：输入 "<scr<script>ipt>alert(1)</script>" → replace 移除中间 <script> 后剩余 "<script>alert(1)</script>"
5. 结论：replace("<script>", "") 是黑名单过滤，只处理一种标签一种大小写，可被多种方式绕过。存在 XSS 漏洞。"""
)

# --- 样本10: 安全 - realpath + 白名单 ---
add(
    """
import os
from flask import Flask, request, abort

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"
ALLOWED_FILES = {"report.pdf", "data.csv", "config.json", "readme.txt"}


@app.route("/view")
def view():
    filename = request.args.get("file", "")
    full_path = os.path.join(BASE_DIR, filename)
    real_path = os.path.realpath(full_path)
    real_base = os.path.realpath(BASE_DIR)
    if not real_path.startswith(real_base + os.sep):
        abort(403)
    if os.path.basename(real_path) not in ALLOWED_FILES:
        abort(403)
    try:
        with open(real_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404
""",
    "python",
    "pseudodefense_safe_path.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "os.path.realpath 规范化路径解析所有 ../ 和符号链接，startswith(real_base + os.sep) 确保目标在 BASE_DIR 内，ALLOWED_FILES 白名单限制可访问文件名，三重防御有效阻止路径穿越",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('file') 获取用户输入 filename。
2. 潜在 sink：open(real_path, 'r') 读取文件。
3. 数据流：filename → os.path.join → os.path.realpath → startswith 校验 + 白名单校验 → open(real_path)。
4. 防御评估（有效）：
   (a) os.path.realpath(full_path) 会解析所有 ../ 序列、符号链接和 .，返回真实的绝对路径。
       攻击者传 file=../../etc/passwd 时，realpath 解析为 /etc/passwd。
   (b) real_path.startswith(real_base + os.sep) 检查解析后的真实路径是否在 BASE_DIR 内。
       /etc/passwd 不以 /var/www/uploads/ 开头，被拒绝。
       os.sep 后缀防止 /var/www/uploads_evil 前缀误匹配。
   (c) os.path.basename(real_path) not in ALLOWED_FILES 白名单校验，只允许 4 个硬编码文件名。
       即使路径在 BASE_DIR 内，文件名不在白名单也被拒绝。
5. 结论：realpath + startswith 目录边界校验 + 文件名白名单，三重防御有效阻止路径穿越。代码安全。"""
)

# --- 样本11: 安全 - shlex.split + shell=False ---
add(
    """
import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    cmd_str = f"ping -c 1 {host}"
    cmd_parts = shlex.split(cmd_str)
    result = subprocess.run(
        cmd_parts,
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    if result.returncode == 0:
        return result.stdout
    return f"Error: {result.stderr}", 500
""",
    "python",
    "pseudodefense_safe_cmd.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "shlex.split 将命令字符串拆分为参数列表，subprocess.run 用 shell=False 列表形式执行，参数直接传递给程序不经 shell 解释器，即使用户输入含 ; | & 等元字符也只被当作字面参数",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('host') 获取用户输入。
2. 潜在 sink：subprocess.run(cmd_parts, ...) 执行命令。
3. 数据流：host → f"ping -c 1 {host}" → shlex.split → subprocess.run(shell=False)。
4. 防御评估（有效）：
   (a) shlex.split(cmd_str) 将命令字符串按 shell 规则拆分为参数列表。
       例如 "ping -c 1 8.8.8.8" → ['ping', '-c', '1', '8.8.8.8']
   (b) subprocess.run(cmd_parts, shell=False) 使用列表形式传参，shell 默认 False。
       参数被直接传递给 execvp 系统调用，不经过 shell 解释器。
   (c) 即使用户输入 host=8.8.8.8;rm -rf /，shlex.split 会拆分为
       ['ping', '-c', '1', '8.8.8.8;rm', '-rf', '/']，
       其中 '8.8.8.8;rm' 作为 ping 的一个参数（ping 会因无效主机名失败），
       但 ; 不会被解释为命令分隔符，rm 不会被执行。
   (d) timeout=5 防止命令长时间挂起。
5. 结论：shell=False + 列表形式是命令注入的标准防御方案。即使用户输入含 shell 元字符，也只被当作字面参数传递给程序，不会被 shell 解释执行。代码安全。"""
)

# --- 样本12: 安全 - html.escape ---
add(
    """
import html
from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    safe_name = html.escape(name, quote=True)
    html_content = f"<h1>Hello, {safe_name}!</h1>"
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response
""",
    "python",
    "pseudodefense_safe_xss.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "html.escape(name, quote=True) 将 < > & \\\" ' 全部转义为 HTML 实体（&lt; &gt; &amp; &quot; &#x27;），quote=True 确保引号也被转义，阻止所有形式的 HTML 标签注入和属性注入",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('name') 获取用户输入。
2. 潜在 sink：f'<h1>Hello, {safe_name}!</h1>' 拼接到 HTML，Content-Type 为 text/html。
3. 数据流：name → html.escape(name, quote=True) → f-string 拼接到 HTML → 返回浏览器。
4. 防御评估（有效）：
   (a) html.escape(name, quote=True) 转义所有 HTML 特殊字符：
       < → &lt;  > → &gt;  & → &amp;  " → &quot;  ' → &#x27;
   (b) quote=True 确保引号也被转义，防止属性注入（如 name=" onmouseover="alert(1)）。
   (c) 测试绕过场景：
       - <script>alert(1)</script> → &lt;script&gt;alert(1)&lt;/script&gt;（浏览器显示为文本）
       - <SCRIPT> → &lt;SCRIPT&gt;（大小写无关，< 和 > 被转义）
       - <img onerror=alert(1)> → &lt;img onerror=alert(1)&gt;（同样被转义）
       - <svg onload=alert(1)> → &lt;svg onload=alert(1)&gt;（同样被转义）
   (d) 转义后的字符串在浏览器中只显示为纯文本，不会被解析为 HTML 标签或 JavaScript。
5. 结论：html.escape + quote=True 是 XSS 的标准防御方案，转义所有特殊字符使浏览器无法将其解析为 HTML/JS。代码安全。"""
)


# ===========================================================================
# 类别3: 跨文件样本（4条，2 vuln + 2 safe）
# ===========================================================================

# --- 对1（漏洞）: input 文件无过滤 + sink 文件调用 ---

CROSSFILE_02_INPUT_CODE = """
import os


def safe_read_file(base_dir, filename):
    \"\"\"读取 base_dir 下的文件内容。\"\"\"
    filepath = os.path.join(base_dir, filename)
    with open(filepath, "r") as f:
        return f.read()


def list_files(base_dir):
    \"\"\"列出目录下的文件。\"\"\"
    return os.listdir(base_dir)


def get_file_info(base_dir, filename):
    \"\"\"获取文件信息。\"\"\"
    filepath = os.path.join(base_dir, filename)
    if os.path.exists(filepath):
        stat = os.stat(filepath)
        return {
            "size": stat.st_size,
            "modified": stat.st_mtime,
        }
    return None
"""

CROSSFILE_02_SINK_CODE = """
from flask import Flask, request, jsonify
from crossfile_02_input import safe_read_file

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"


@app.route("/view_file")
def view_file():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "filename required"}), 400
    try:
        content = safe_read_file(BASE_DIR, filename)
        return jsonify({"content": content, "file": filename})
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/file_info")
def file_info():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "filename required"}), 400
    from crossfile_02_input import get_file_info
    info = get_file_info(BASE_DIR, filename)
    if info:
        return jsonify(info)
    return jsonify({"error": "file not found"}), 404
"""

# 样本13: 跨文件 - input 文件独立分析（漏洞）
add(
    CROSSFILE_02_INPUT_CODE,
    "python",
    "crossfile_02_input.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "filename 参数（函数入参，可能来自用户输入）",
    "open(filepath, 'r')",
    "safe_read_file 函数用 os.path.join(base_dir, filename) 拼接路径后直接 open，未做路径校验，当 filename 含 ../ 或为绝对路径时可穿越目录读取任意文件",
    "在 open 之前用 os.path.realpath + startswith 校验路径在 base_dir 内，或用白名单限制可访问文件名",
    """分析过程（跨文件 helper 分析）：
1. 这是一个 helper 模块，定义了 safe_read_file、list_files、get_file_info 三个文件操作函数。
2. 函数 safe_read_file(base_dir, filename) 的 filename 参数可能来自调用方的用户输入。
3. 数据流：filename → os.path.join(base_dir, filename) → open(filepath, 'r')。
4. 防御检查：os.path.join 只做路径拼接，不做安全校验。
   - filename="../../etc/passwd" 时，os.path.join("/var/www/uploads", "../../etc/passwd")
     返回 "/var/www/uploads/../../etc/passwd"，open 会解析为 "/etc/passwd"
   - filename="/etc/passwd"（绝对路径）时，os.path.join 丢弃 base_dir，直接返回 "/etc/passwd"
   - 代码未使用 os.path.realpath 或 abspath + startswith 做目录边界校验
5. get_file_info 函数同样存在路径穿越问题（os.path.join 后直接 os.stat）。
6. 结论：虽然函数名包含 "safe"，但实际未做任何路径安全校验，存在路径穿越漏洞。函数名不等于安全性。"""
)

# 样本14: 跨文件 - sink 文件（input 文件内容拼接到前面）
combined_code_02 = f"# 配套输入层文件 crossfile_02_input.py\n{CROSSFILE_02_INPUT_CODE.strip()}\n\n# 当前 sink 文件\n{CROSSFILE_02_SINK_CODE.strip()}"
add(
    combined_code_02,
    "python",
    "crossfile_02_sink.py",
    True,
    "CWE-22 路径穿越",
    "High",
    "request.args.get('file')",
    "safe_read_file 中的 open(filepath, 'r')",
    "sink 文件的 view_file 路由将用户输入 filename 传给 input 文件的 safe_read_file 函数，该函数内部 os.path.join 后直接 open 无路径校验，攻击者可通过 file=../../etc/passwd 读取任意文件",
    "在 safe_read_file 函数中添加 os.path.realpath + startswith 路径校验，或用白名单限制可访问文件名",
    """分析过程（跨文件 sink 追踪）：
1. 当前是 sink 文件 crossfile_02_sink.py，配套输入层文件 crossfile_02_input.py 已拼接在前面。
2. 分析 sink 文件中的用户输入数据流：
   - view_file 路由：request.args.get('file') → safe_read_file(BASE_DIR, filename)
   - file_info 路由：request.args.get('file') → get_file_info(BASE_DIR, filename)
3. 跨文件追踪 safe_read_file 函数（在 input 文件中定义）：
   - safe_read_file(base_dir, filename) 内部：
     filepath = os.path.join(base_dir, filename)
     with open(filepath, "r") as f: return f.read()
   - os.path.join 只做路径拼接，不做安全校验
   - filename 含 "../" 时可穿越目录，如 file=../../etc/passwd 读取系统文件
   - filename 为绝对路径时 os.path.join 丢弃 base_dir
4. 同样追踪 get_file_info 函数：os.path.join 后直接 os.stat，同样存在路径穿越。
5. 防御检查：sink 文件和 input 文件均未做路径校验（无 realpath、无 abspath + startswith、无白名单）。
6. 结论：用户输入 file 参数通过 sink 文件传入 input 文件的 safe_read_file，最终到达 open sink，中间无有效防御。存在跨文件路径穿越漏洞。"""
)

# --- 对2（安全）: input 文件有 realpath + 白名单 + sink 文件调用 ---

CROSSFILE_03_INPUT_CODE = """
import os

ALLOWED_FILES = {"report.pdf", "data.csv", "config.json", "readme.txt"}


def safe_read_file(base_dir, filename):
    \"\"\"安全地读取 base_dir 下的文件内容。\"\"\"
    filepath = os.path.join(base_dir, filename)
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    if not real_path.startswith(real_base + os.sep):
        raise ValueError("Path traversal detected")
    if os.path.basename(real_path) not in ALLOWED_FILES:
        raise ValueError("File not in whitelist")
    with open(real_path, "r") as f:
        return f.read()


def list_files(base_dir):
    \"\"\"列出目录下的文件。\"\"\"
    real_base = os.path.realpath(base_dir)
    if not real_base.startswith(os.path.realpath(base_dir) + os.sep) and real_base != os.path.realpath(base_dir):
        raise ValueError("Invalid base directory")
    return os.listdir(real_base)


def get_file_info(base_dir, filename):
    \"\"\"安全地获取文件信息。\"\"\"
    filepath = os.path.join(base_dir, filename)
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    if not real_path.startswith(real_base + os.sep):
        raise ValueError("Path traversal detected")
    if os.path.basename(real_path) not in ALLOWED_FILES:
        raise ValueError("File not in whitelist")
    if os.path.exists(real_path):
        stat = os.stat(real_path)
        return {"size": stat.st_size, "modified": stat.st_mtime}
    return None
"""

CROSSFILE_03_SINK_CODE = """
from flask import Flask, request, jsonify
from crossfile_03_input import safe_read_file, get_file_info

app = Flask(__name__)
BASE_DIR = "/var/www/uploads"


@app.route("/view_file")
def view_file():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "filename required"}), 400
    try:
        content = safe_read_file(BASE_DIR, filename)
        return jsonify({"content": content, "file": filename})
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/file_info")
def file_info():
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "filename required"}), 400
    try:
        info = get_file_info(BASE_DIR, filename)
        if info:
            return jsonify(info)
        return jsonify({"error": "file not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
"""

# 样本15: 跨文件 - input 文件独立分析（安全）
add(
    CROSSFILE_03_INPUT_CODE,
    "python",
    "crossfile_03_input.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "safe_read_file 函数使用 os.path.realpath 解析路径后用 startswith 校验目录边界，并用 ALLOWED_FILES 白名单限制可访问文件名，get_file_info 同样做了双重校验，有效防御路径穿越",
    "no fix needed",
    """分析过程（跨文件 helper 分析）：
1. 这是一个 helper 模块，定义了 safe_read_file、list_files、get_file_info 三个文件操作函数。
2. 函数 safe_read_file(base_dir, filename) 的 filename 参数可能来自调用方的用户输入。
3. 数据流：filename → os.path.join → os.path.realpath → startswith 校验 + 白名单校验 → open(real_path)。
4. 防御评估（有效）：
   (a) os.path.realpath(filepath) 解析所有 ../ 序列和符号链接，返回真实绝对路径。
   (b) real_path.startswith(real_base + os.sep) 确保目标在 base_dir 内。
       攻击者传 filename="../../etc/passwd" 时，realpath 解析为 "/etc/passwd"，
       不以 "/var/www/uploads/" 开头，抛出 ValueError。
   (c) os.path.basename(real_path) not in ALLOWED_FILES 白名单校验，
       只允许 report.pdf/data.csv/config.json/readme.txt 四个文件。
   (d) get_file_info 函数也做了同样的 realpath + startswith + 白名单校验。
5. 结论：所有文件操作函数都有 realpath 目录边界校验 + 文件名白名单，有效防御路径穿越。代码安全。"""
)

# 样本16: 跨文件 - sink 文件（input 文件内容拼接到前面）
combined_code_03 = f"# 配套输入层文件 crossfile_03_input.py\n{CROSSFILE_03_INPUT_CODE.strip()}\n\n# 当前 sink 文件\n{CROSSFILE_03_SINK_CODE.strip()}"
add(
    combined_code_03,
    "python",
    "crossfile_03_sink.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "sink 文件的 view_file 路由将用户输入传给 input 文件的 safe_read_file，该函数使用 os.path.realpath + startswith 目录边界校验 + ALLOWED_FILES 白名单，跨文件追踪确认防御有效",
    "no fix needed",
    """分析过程（跨文件 sink 追踪）：
1. 当前是 sink 文件 crossfile_03_sink.py，配套输入层文件 crossfile_03_input.py 已拼接在前面。
2. 分析 sink 文件中的用户输入数据流：
   - view_file 路由：request.args.get('file') → safe_read_file(BASE_DIR, filename)
   - file_info 路由：request.args.get('file') → get_file_info(BASE_DIR, filename)
3. 跨文件追踪 safe_read_file 函数（在 input 文件中定义）：
   - filepath = os.path.join(base_dir, filename)
   - real_path = os.path.realpath(filepath) → 解析所有 ../ 和符号链接
   - real_base = os.path.realpath(base_dir)
   - if not real_path.startswith(real_base + os.sep): raise ValueError → 目录边界校验
   - if os.path.basename(real_path) not in ALLOWED_FILES: raise ValueError → 文件名白名单
   - 只有通过双重校验后才 open(real_path, 'r')
4. 同样追踪 get_file_info 函数：也做了 realpath + startswith + 白名单校验。
5. sink 文件的异常处理：try-except 捕获 ValueError 返回 403，捕获 FileNotFoundError 返回 404。
6. 结论：用户输入 file 参数通过 sink 文件传入 input 文件的 safe_read_file，中间有 realpath 目录边界校验 + 文件名白名单双重防御。跨文件追踪确认防御有效，代码安全。"""
)


# ===========================================================================
# 构建与写入逻辑
# ===========================================================================

def build_json_verdict(sample):
    """构造 JSON 结论块。"""
    verdict = {
        "has_vulnerability": sample["has_vulnerability"],
        "vulnerability_type": sample["vulnerability_type"],
        "risk_level": sample["risk_level"],
        "source": sample["source"],
        "sink": sample["sink"],
        "explanation": sample["explanation"],
        "fix_suggestion": sample["fix_suggestion"],
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
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    print(f"共 {len(SAMPLES)} 条补充样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    # 按类别统计
    longfile = [s for s in SAMPLES if s["filename"].startswith("longfile_")]
    pseudodef = [s for s in SAMPLES if s["filename"].startswith("pseudodefense_")]
    crossfile = [s for s in SAMPLES if s["filename"].startswith("crossfile_")]
    print(f"  长文件: {len(longfile)}  伪防御: {len(pseudodef)}  跨文件: {len(crossfile)}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证 CoT 多样性
    cot_texts = [s["cot_analysis"] for s in SAMPLES]
    print(f"CoT 唯一文本: {len(set(cot_texts))}/{len(cot_texts)}")

    # 验证长文件代码行数
    print("\n长文件样本代码行数:")
    for s in longfile:
        line_count = len(s["code"].split("\n"))
        print(f"  {s['filename']}: {line_count} 行")


if __name__ == "__main__":
    main()
