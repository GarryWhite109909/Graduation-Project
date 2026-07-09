"""
补充训练样本 —— Qwen2.5-Coder-7B-Instruct 特有失败案例修复。

针对 7B 基座在 exp_04 测试集上的 7B 特有失败案例（3B 没有这些问题）：
  FP 案例（7B 误报安全代码为漏洞）：
    1. hard_crossfile_01_input.py / hard_crossfile_03_input.py
       —— 跨文件 input 文件只有用户输入源（source），没有危险 sink，7B 误报为漏洞
    2. safe_08_shlex.py —— shlex.quote() 转义后传给 subprocess，7B 误报为命令注入
    3. safe_10_session_regenerate.py —— 登录后 session.clear() 防固定，7B 误报为漏洞
  FN 案例（7B 漏报漏洞）：
    4. typical_15_missing_authz.py —— 缺失授权检查
    5. typical_30_mass_assignment.py —— 批量赋值漏洞
    6. hard_cve_02_python_log_injection.py —— Python 日志注入

样本设计（14 条：8 safe + 6 vuln）：
  - 类别1: 4 条 crossfile input 安全样本（全 safe）—— 处理用户输入但无危险 sink
  - 类别2: 4 条 shlex/session 安全样本（全 safe）—— shlex 转义 / session 防固定
  - 类别3: 6 条漏报漏洞补充样本（全 vuln）—— 缺失授权 / 批量赋值 / 日志注入

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/supplement_7b_weakness.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_7b_weakness.jsonl"

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
# 类别1: crossfile input 安全样本（4条，全 safe）
# 模拟跨文件场景中的 input 文件 —— 只定义用户输入入口和数据处理逻辑，
# 但不包含任何危险 sink（open/execute/eval/subprocess）。
# ===========================================================================

# --- 样本1: Flask 路由接收用户输入，验证后存入 session，无危险函数 ---
add(
    """
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "change-me-in-production"


@app.route("/set_prefs", methods=["POST"])
def set_preferences():
    theme = request.form.get("theme", "light")
    lang = request.form.get("lang", "en")
    if theme not in ("light", "dark", "auto"):
        return "Invalid theme", 400
    if len(lang) > 10 or not lang.isalpha():
        return "Invalid language", 400
    session["theme"] = theme
    session["lang"] = lang
    return "Preferences saved"
""",
    "python",
    "7bweak_crossfile_input_prefs.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "代码接收用户输入 theme 和 lang，经白名单校验（theme 限定 light/dark/auto）和 isalpha+长度校验（lang）后仅存入 Flask session，全文无 open/execute/eval/subprocess/system 等危险 sink，session 写入不属于危险操作",
    "no fix needed",
    """分析过程：
1. 污染源：request.form.get('theme') 和 request.form.get('lang') 获取用户输入。
2. 危险 sink 扫描：全文检查是否存在 open/execute/eval/subprocess/os.system/pickle.loads 等危险函数 —— 均未出现。
3. 数据流追踪：theme → 白名单校验（in light/dark/auto）→ session['theme']；lang → isalpha()+len<=10 校验 → session['lang']。
4. 防御评估：输入经白名单和类型校验后仅写入 session 字典，session 是 Flask 服务端会话存储，不是危险 sink。未调用任何文件操作、命令执行、代码执行或数据库拼接函数。
5. 结论：虽然处理了用户输入，但文件中没有危险 sink，输入仅存入 session，安全。"""
)

# --- 样本2: API 端点接收 JSON 输入，schema 验证后返回响应，无危险操作 ---
add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/api/feedback", methods=["POST"])
def submit_feedback():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid body"}), 400
    name = data.get("name", "")
    message = data.get("message", "")
    rating = data.get("rating", 0)
    if not isinstance(name, str) or len(name) > 100:
        return jsonify({"error": "invalid name"}), 400
    if not isinstance(message, str) or len(message) > 1000:
        return jsonify({"error": "invalid message"}), 400
    if not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({"error": "invalid rating"}), 400
    return jsonify({"status": "received", "rating": rating})
""",
    "python",
    "7bweak_crossfile_input_api.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "API 端点接收 JSON 输入后对每个字段做 isinstance 类型检查和长度/范围校验（name str<=100、message str<=1000、rating int 1-5），校验通过后直接返回 JSON 响应，全文无 open/execute/eval/subprocess 等危险 sink，输入不流向任何危险操作",
    "no fix needed",
    """分析过程：
1. 污染源：request.get_json() 获取用户 POST 的 JSON 数据。
2. 危险 sink 扫描：检查是否存在 open/execute/eval/subprocess/os.system 等危险函数 —— 均未出现。
3. 数据流追踪：data → isinstance(dict) 类型检查 → 逐字段提取 name/message/rating → isinstance+长度/范围校验 → jsonify 返回。
4. 防御评估：每个字段都经过严格类型检查（isinstance）和值域校验（长度限制、范围限制），校验失败返回 400。校验通过后仅通过 jsonify 返回 JSON 响应，不涉及文件操作、命令执行、代码执行或数据库操作。
5. 结论：虽然处理了用户 JSON 输入，但文件中没有危险 sink，输入经验证后仅用于构造响应，安全。"""
)

# --- 样本3: 表单处理函数，正则验证邮箱后参数化查询存入数据库 ---
add(
    """
import re
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")


@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email", "")
    if not EMAIL_RE.match(email):
        return jsonify({"error": "invalid email"}), 400
    conn = sqlite3.connect("newsletter.db")
    conn.execute(
        "INSERT INTO subscribers (email, created_at) VALUES (?, datetime('now'))",
        (email,)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "subscribed"})
""",
    "python",
    "7bweak_crossfile_input_subscribe.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "用户输入 email 经正则 EMAIL_RE 校验格式后，通过参数化查询（? 占位符 + 参数元组 (email,)）插入数据库，无字符串拼接 SQL；全文无 open/execute/eval/subprocess 等危险 sink，唯一的数据库操作使用了参数化查询",
    "no fix needed",
    """分析过程：
1. 污染源：request.form.get('email') 获取用户输入。
2. 危险 sink 扫描：检查 open/execute/eval/subprocess —— 无。唯一的 sink 是 conn.execute（数据库操作）。
3. 数据流追踪：email → EMAIL_RE.match 正则校验 → conn.execute('... VALUES (?, ...)', (email,))。
4. 防御评估：conn.execute 使用 ? 占位符 + 参数元组 (email,)，这是参数化查询的标准写法，数据库驱动自动处理转义，不存在 SQL 注入。正则校验确保 email 格式合法。全文无文件操作、命令执行或代码执行。
5. 结论：虽然处理了用户输入并存入数据库，但使用了参数化查询（? 占位符），且无其他危险 sink，安全。"""
)

# --- 样本4: 配置读取函数，从预设字典查找配置，无危险操作 ---
add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)
CONFIG_STORE = {
    "timeout": 30,
    "max_retries": 3,
    "log_level": "INFO",
    "cache_size": 256,
}


@app.route("/api/config")
def get_config():
    key = request.args.get("key", "")
    if not key or not key.replace("_", "").isalnum():
        return jsonify({"error": "invalid key"}), 400
    value = CONFIG_STORE.get(key)
    if value is None:
        return jsonify({"error": "config not found"}), 404
    return jsonify({"key": key, "value": value})
""",
    "python",
    "7bweak_crossfile_input_config.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "用户输入 key 经 isalnum 白名单校验后从硬编码字典 CONFIG_STORE 查找配置值，不涉及文件读取、命令执行、代码执行或数据库操作；全文无 open/execute/eval/subprocess 等危险 sink，输入仅用于字典查找",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('key') 获取用户输入。
2. 危险 sink 扫描：检查 open/execute/eval/subprocess/os.system —— 均未出现。
3. 数据流追踪：key → isalnum 白名单校验 → CONFIG_STORE.get(key) 字典查找 → jsonify 返回。
4. 防御评估：key 经 replace('_','').isalnum() 校验确保只含字母数字下划线，然后从硬编码的 CONFIG_STORE 字典中查找值。字典查找不是危险操作，CONFIG_STORE 是预设常量，不受用户输入影响。全文无文件操作、命令执行、代码执行或数据库操作。
5. 结论：虽然处理了用户输入，但文件中没有危险 sink，输入仅用于字典查找，安全。"""
)


# ===========================================================================
# 类别2: shlex/session 安全样本（4条，全 safe）
# ===========================================================================

# --- 样本5: subprocess 列表形式 + shlex.quote 双重防护 ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/echo")
def echo():
    text = request.args.get("text", "")
    safe_text = shlex.quote(text)
    result = subprocess.run(
        ["echo", safe_text],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
""",
    "python",
    "7bweak_shlex_list_echo.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "双重防护：(1) shlex.quote(text) 转义所有 shell 特殊字符（; | & $ ` 等），将用户输入包裹为单引号字符串；(2) subprocess.run(['echo', safe_text], shell=False) 使用列表形式传参，不经过 shell 解释器，即使用户输入含元字符也只被当作字面参数传递",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('text') 获取用户输入。
2. 潜在 sink：subprocess.run(['echo', safe_text]) 执行命令。
3. 数据流追踪：text → shlex.quote(text) 转义 → subprocess.run(['echo', safe_text], shell=False)。
4. 防御评估（双重防护有效）：
   (a) shlex.quote(text) 将用户输入中的所有 shell 特殊字符（; | & $ ` \\ " ' 等）转义，用单引号包裹整个字符串。
       例如输入 "hello; rm -rf /" → shlex.quote 返回 "'hello; rm -rf /'"，其中分号被包裹在单引号内不再作为命令分隔符。
   (b) subprocess.run(['echo', safe_text], shell=False) 使用列表形式传参，shell 参数为 False（默认值，显式写出）。
       参数直接传递给 execvp 系统调用，不经过 shell 解释器。即 safe_text 中万一有遗漏的元字符也不会被解释。
   (c) timeout=5 防止命令挂起。
   (d) 列表形式 + shell=False 是命令注入的标准防御方案，shlex.quote 提供额外层防护。
5. 结论：shlex.quote 转义 + 列表形式 shell=False 双重防护，有效阻止命令注入。代码安全。"""
)

# --- 样本6: shlex.split 拆分命令 + shell=False ---
add(
    """
import shlex
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/dns_lookup")
def dns_lookup():
    domain = request.args.get("domain", "")
    if not domain or not domain.replace(".", "").replace("-", "").isalnum():
        return "Invalid domain", 400
    safe_domain = shlex.quote(domain)
    cmd_parts = shlex.split(f"nslookup {safe_domain}")
    result = subprocess.run(
        cmd_parts,
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout
""",
    "python",
    "7bweak_shlex_split_nslookup.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "三层防护：(1) isalnum 白名单校验 domain 只含字母数字点连字符；(2) shlex.quote 转义 shell 特殊字符；(3) shlex.split 拆分为列表后 subprocess.run(shell=False) 不经 shell 解释器执行",
    "no fix needed",
    """分析过程：
1. 污染源：request.args.get('domain') 获取用户输入。
2. 潜在 sink：subprocess.run(cmd_parts) 执行命令。
3. 数据流追踪：domain → isalnum 白名单校验 → shlex.quote 转义 → shlex.split 拆分 → subprocess.run(shell=False)。
4. 防御评估（三层防护有效）：
   (a) domain.replace('.','').replace('-','').isalnum() 白名单校验，只允许字母数字加点和连字符，
       拒绝包含 ; | & $ 等特殊字符的输入。
   (b) shlex.quote(domain) 对通过校验的 domain 再次转义，用单引号包裹。
   (c) shlex.split(f"nslookup {safe_domain}") 将命令字符串按 shell 词法规则拆分为列表 ['nslookup', "'domain'"]。
   (d) subprocess.run(cmd_parts, shell=False) 使用列表形式，shell 参数为 False，
       参数直接传递给 execvp，不经过 shell 解释器。
   (e) timeout=10 防止命令挂起。
5. 结论：isalnum 白名单 + shlex.quote 转义 + shell=False 列表形式三层防护，有效阻止命令注入。代码安全。"""
)

# --- 样本7: Flask 登录后 session.clear() 防会话固定 ---
add(
    """
import os
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == "admin" and password == "secret":
        session.clear()
        session["user_id"] = "admin"
        session["login_time"] = "2026-01-01"
        session.modified = True
        return redirect(url_for("dashboard"))
    return "Invalid credentials", 401


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return f"Welcome {session['user_id']}"
""",
    "python",
    "7bweak_session_clear_flask.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "登录成功后调用 session.clear() 清除旧 session 数据（防止会话固定攻击），然后设置新的 user_id 和 login_time，session.modified=True 确保会话 ID 被刷新。这是 Flask 防会话固定的标准安全实践，session.clear 不是危险操作",
    "no fix needed",
    """分析过程：
1. 污染源：request.form.get('username') / request.form.get('password') 获取用户输入。
2. 危险 sink 扫描：检查 open/execute/eval/subprocess/os.system —— 均未出现。
3. 数据流追踪：username/password → 与硬编码凭据比较 → session.clear() + session['user_id'] 设置。
4. 防御评估（session.clear 是安全最佳实践）：
   (a) session.clear() 在登录成功后清除旧的 session 数据，这是防止会话固定攻击（CWE-384）的标准做法。
       会话固定攻击中，攻击者预设一个 session ID 让受害者使用，如果登录后不刷新 session，
       攻击者可以用同一个 session ID 访问受害者账户。
   (b) session.clear() 后设置新的 session['user_id'] 和 session['login_time']，
       Flask 会在响应中设置新的 session cookie。
   (c) session.modified = True 确保会话被标记为已修改，触发 session ID 刷新。
   (d) dashboard 路由检查 'user_id' not in session 实现认证守卫。
   (e) secret_key 从 os.environ 读取（有默认值用于开发），是 session 签名密钥。
5. 结论：session.clear() 是防会话固定的安全最佳实践，不是漏洞。代码安全。"""
)

# --- 样本8: Django 登录后 request.session.cycle_key() 防会话固定 ---
add(
    """
from django.http import HttpResponse
from django.views.decorators.http import require_POST


@require_POST
def login_view(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    if username == "admin" and password == "secret":
        request.session.cycle_key()
        request.session["user_id"] = 1
        request.session["is_authenticated"] = True
        return HttpResponse("Login success")
    return HttpResponse("Invalid credentials", status=401)
""",
    "python",
    "7bweak_session_cycle_django.py",
    False,
    "none",
    "None",
    "N/A",
    "N/A",
    "Django 登录成功后调用 request.session.cycle_key() 轮换 session key（生成新 session ID 同时保留数据），这是 Django 防会话固定攻击（CWE-384）的官方推荐做法，随后设置 user_id 和 is_authenticated",
    "no fix needed",
    """分析过程：
1. 污染源：request.POST.get('username') / request.POST.get('password') 获取用户输入。
2. 危险 sink 扫描：检查 open/execute/eval/subprocess/os.system —— 均未出现。
3. 数据流追踪：username/password → 与硬编码凭据比较 → request.session.cycle_key() + session 设置。
4. 防御评估（cycle_key 是安全最佳实践）：
   (a) request.session.cycle_key() 是 Django 提供的防会话固定攻击方法，
       它会生成一个新的 session ID，同时保留当前 session 中的数据。
       这确保攻击者预设的 session ID 在用户登录后失效。
   (b) cycle_key() 后设置 request.session['user_id'] 和 request.session['is_authenticated']，
       新的 session ID 与用户认证状态绑定。
   (c) @require_POST 限制只接受 POST 请求，防止通过 GET 参数泄露凭据。
   (d) Django 官方文档明确推荐在登录后调用 cycle_key() 防止会话固定。
5. 结论：request.session.cycle_key() 是 Django 防会话固定的官方安全实践，不是漏洞。代码安全。"""
)


# ===========================================================================
# 类别3: 漏报漏洞补充样本（6条，全 vuln）
# ===========================================================================

# --- 样本9: 缺失授权 - Flask /admin/users 路由无权限检查 ---
add(
    """
from flask import Flask, session, jsonify

app = Flask(__name__)
app.secret_key = "dev_key"


@app.route("/admin/users")
def list_all_users():
    users = [
        {"id": 1, "username": "admin", "email": "admin@example.com"},
        {"id": 2, "username": "user1", "email": "user1@example.com"},
    ]
    return jsonify(users)
""",
    "python",
    "7bweak_missing_authz_flask.py",
    True,
    "CWE-862 缺失授权",
    "High",
    "任意未认证用户的 HTTP 请求",
    "list_all_users() 返回所有用户数据",
    "/admin/users 路由没有任何认证或授权检查（无 @login_required 装饰器、无 session 角色检查、无 if g.user 判断），任何匿名用户访问 /admin/users 即可获取所有用户的用户名和邮箱等敏感信息",
    "添加认证和授权检查：(1) 使用 @login_required 装饰器确保用户已登录；(2) 检查 session 中的用户角色是否为 admin，如 if session.get('role') != 'admin': abort(403)",
    """分析过程：
1. 污染源：任意未认证用户的 HTTP 请求（无 source 过滤）。
2. 危险 sink：list_all_users() 函数返回所有用户的敏感信息（username、email）。
3. 数据流追踪：HTTP 请求 → /admin/users 路由 → 直接返回用户列表 JSON。
4. 防御检查（缺失）：
   (a) 路由没有 @login_required 装饰器，不检查用户是否已登录（认证缺失）。
   (b) 路由没有检查 session 中的用户角色（授权缺失）。
   (c) 虽然配置了 app.secret_key 和 session，但 list_all_users 函数内部完全没有引用 session 做权限判断。
   (d) 任何匿名用户直接 GET /admin/users 即可获取所有用户数据。
5. 攻击路径：攻击者直接访问 http://target/admin/users → 无需登录 → 获取所有用户 username 和 email → 可用于钓鱼、撞库等后续攻击。
6. 结论：存在 CWE-862 缺失授权漏洞，敏感的管理员接口缺少认证和授权检查。"""
)

# --- 样本10: 缺失授权 - Django 视图查询所有用户无 permission_required ---
add(
    """
from django.http import JsonResponse
from django.contrib.auth.models import User


def user_list(request):
    users = list(User.objects.values("id", "username", "email"))
    return JsonResponse({"users": users})
""",
    "python",
    "7bweak_missing_authz_django.py",
    True,
    "CWE-862 缺失授权",
    "High",
    "任意未认证用户的 HTTP 请求",
    "User.objects.values('id','username','email') 返回所有用户数据",
    "Django user_list 视图没有 @login_required 或 @permission_required 装饰器，也没有 request.user.is_superuser 检查，任何匿名用户访问即可获取所有用户的 id、username 和 email",
    "添加权限检查：(1) 使用 @permission_required('auth.view_user', raise_exception=True) 装饰器；(2) 或在函数内检查 if not request.user.is_authenticated or not request.user.is_staff: return HttpResponseForbidden()",
    """分析过程：
1. 污染源：任意未认证用户的 HTTP 请求。
2. 危险 sink：User.objects.values('id', 'username', 'email') 查询并返回所有用户数据。
3. 数据流追踪：HTTP 请求 → user_list(request) → User.objects.values() → JsonResponse 返回。
4. 防御检查（缺失）：
   (a) 视图函数没有 @login_required 装饰器，不检查 request.user.is_authenticated。
   (b) 视图函数没有 @permission_required 装饰器，不检查用户是否有 auth.view_user 权限。
   (c) 函数内部没有 if request.user.is_superuser 或 is_staff 的角色判断。
   (d) User.objects.values() 查询所有用户，不经过任何权限过滤（如 filter(is_active=True) 或基于 request.user 的范围限制）。
5. 攻击路径：攻击者直接 GET /user_list/ → 无需登录 → 获取所有用户 id/username/email → 批量泄露用户信息。
6. 结论：存在 CWE-862 缺失授权漏洞，用户列表接口缺少认证和授权检查。"""
)

# --- 样本11: 批量赋值 - Flask request.form.to_dict() 传给 Model(**data) ---
add(
    """
from flask import Flask, request, jsonify

app = Flask(__name__)


class UserProfile:
    def __init__(self):
        self.username = ""
        self.email = ""
        self.is_admin = False
        self.is_active = True

    def save(self):
        pass


@app.route("/profile/update", methods=["POST"])
def update_profile():
    data = request.form.to_dict()
    profile = UserProfile(**data)
    profile.save()
    return jsonify({"username": profile.username, "email": profile.email})
""",
    "python",
    "7bweak_mass_assignment_flask.py",
    True,
    "CWE-915 批量赋值",
    "High",
    "request.form.to_dict()",
    "UserProfile(**data) 批量赋值",
    "update_profile 将 request.form.to_dict() 的全部键值对通过 **data 传给 UserProfile 构造器，攻击者可在表单中添加 is_admin=True 字段，直接获取管理员权限",
    "使用白名单只允许赋值非敏感字段：(1) 显式提取 allowed = {'username', 'email'}；(2) filtered = {k: v for k, v in data.items() if k in allowed}；(3) profile = UserProfile(**filtered)",
    """分析过程：
1. 污染源：request.form.to_dict() 获取用户提交的表单数据，转为字典。
2. 危险 sink：UserProfile(**data) 将整个字典作为关键字参数传给构造器，批量赋值所有属性。
3. 数据流追踪：request.form → to_dict() → **data → UserProfile.__init__ → 设置 username/email/is_admin/is_active 等所有属性。
4. 防御检查（缺失）：
   (a) request.form.to_dict() 获取所有表单字段，没有白名单过滤。
   (b) UserProfile(**data) 直接将所有键值对作为构造器参数，包括 is_admin 和 is_active 等敏感字段。
   (c) UserProfile.__init__ 接受任意关键字参数（因为没有 **kwargs 限制，但属性 is_admin 默认 False 可被覆盖）。
   (d) 攻击者在 POST 表单中添加 is_admin=True → data = {'username': 'x', 'is_admin': 'True'} → profile.is_admin 被设为 'True'。
5. 攻击路径：攻击者 POST /profile/update，表单包含 username=hacker&is_admin=True → profile.is_admin 变为 True → save() 后获取管理员权限。
6. 结论：存在 CWE-915 批量赋值漏洞，用户可控的表单数据直接批量赋值给模型对象，未过滤敏感字段。"""
)

# --- 样本12: 批量赋值 - Django ModelForm 未排除 is_staff/is_superuser ---
add(
    """
from django import forms
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_POST


class UserEditForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["username", "email", "is_staff", "is_superuser", "is_active"]


@require_POST
def update_user(request, user_id):
    user = User.objects.get(pk=user_id)
    form = UserEditForm(request.POST, instance=user)
    if form.is_valid():
        form.save()
        return JsonResponse({"status": "updated"})
    return JsonResponse({"errors": form.errors}, status=400)
""",
    "python",
    "7bweak_mass_assignment_django.py",
    True,
    "CWE-915 批量赋值",
    "High",
    "request.POST（表单数据）",
    "UserEditForm.save() 批量更新 User 模型字段",
    "UserEditForm 的 fields 列表包含了 is_staff 和 is_superuser 等敏感权限字段，攻击者可在 POST 数据中提交 is_superuser=on 直接将自己提升为超级管理员",
    "从 fields 中移除敏感权限字段，或改用 exclude 显式排除：class Meta: model = User; fields = ['username', 'email']（只允许普通字段）。权限提升应通过独立的管理员接口处理",
    """分析过程：
1. 污染源：request.POST 表单数据传给 UserEditForm。
2. 危险 sink：form.save() 将表单数据保存到 User 模型实例。
3. 数据流追踪：request.POST → UserEditForm(request.POST, instance=user) → form.is_valid() → form.save()。
4. 防御检查（缺失）：
   (a) UserEditForm.Meta.fields 包含 ['username', 'email', 'is_staff', 'is_superuser', 'is_active']，
       其中 is_staff 和 is_superuser 是敏感权限字段，不应通过用户表单直接修改。
   (b) 没有使用 exclude = ['is_staff', 'is_superuser', 'is_superuser'] 排除敏感字段。
   (c) form.save() 会更新 instance=user 的所有 fields 中列出的字段，包括权限字段。
   (d) 虽然有 @require_POST 和 form.is_valid() 校验，但这些只校验数据格式，不校验用户是否有权修改权限字段。
5. 攻击路径：攻击者 POST /update_user/1，表单包含 username=hacker&is_superuser=on → form.save() 将 user.is_superuser 设为 True → 攻击者获取超级管理员权限。
6. 结论：存在 CWE-915 批量赋值漏洞，ModelForm 的 fields 包含敏感权限字段，允许用户通过表单修改自己的权限。"""
)

# --- 样本13: 日志注入 - logging.info f-string 换行符注入 ---
add(
    """
import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("auth")


@app.route("/api/login")
def api_login():
    username = request.args.get("username", "")
    logger.info(f"User login: {username}")
    return {"status": "processed"}
""",
    "python",
    "7bweak_log_injection_logging.py",
    True,
    "CWE-117 日志注入",
    "Medium",
    "request.args.get('username')",
    "logger.info(f'User login: {username}')",
    "username 通过 f-string 直接拼入日志消息，攻击者传入含换行符的 username（如 admin\\n[INFO] Login success: admin）可注入伪造的日志行，误导审计、掩盖攻击痕迹或注入虚假审计记录",
    "对写入日志的用户输入做换行符过滤或转义：(1) username = username.replace('\\n', '\\\\n').replace('\\r', '\\\\r')；(2) 或使用结构化日志 logging.info('User login', extra={'username': username})；(3) 或使用 logging 模块的 % 参数化格式 logger.info('User login: %s', username)",
    """分析过程：
1. 污染源：request.args.get('username') 获取用户输入。
2. 危险 sink：logger.info(f'User login: {username}') 将用户输入写入日志。
3. 数据流追踪：username → f-string 拼接到日志消息 → logger.info 写入日志文件。
4. 防御检查（缺失）：
   (a) username 未经任何换行符过滤或转义直接拼入 f-string。
   (b) f-string 会原样保留 username 中的换行符 \\n、回车符 \\r 等控制字符。
   (c) logging 模块默认不会过滤换行符，日志消息中的 \\n 会导致日志文件中出现新行。
5. 攻击路径：
   (a) 攻击者传入 username=admin\\n[INFO] 2026-01-01 Login success: admin
   (b) 日志文件中出现两行：
       User login: admin
       [INFO] 2026-01-01 Login success: admin
   (c) 第二行是伪造的，审计人员可能误认为 admin 已成功登录。
   (d) 攻击者可用此掩盖恶意行为（注入虚假的正常日志行）或伪造审计证据。
6. 结论：存在 CWE-117 日志注入漏洞，用户输入未经换行符过滤直接写入日志。"""
)

# --- 样本14: 日志注入 - print f-string ANSI 转义码注入 ---
add(
    """
from flask import Flask, request

app = Flask(__name__)


@app.route("/api/search")
def search():
    query = request.args.get("q", "")
    print(f"[INFO] Search query: {query}")
    return {"results": []}
""",
    "python",
    "7bweak_log_injection_print.py",
    True,
    "CWE-117 日志注入",
    "Medium",
    "request.args.get('q')",
    "print(f'[INFO] Search query: {query}')",
    "query 通过 f-string 直接拼入 print 输出，攻击者传入含 ANSI 转义码的 query（如 \\x1b[2J\\x1b[H 清屏序列或 \\x1b[31m 伪造红色 ERROR 行）可篡改终端显示内容，伪造错误信息或清除审计日志显示",
    "对写入终端/日志的用户输入做控制字符过滤：(1) query = ''.join(c for c in query if c.isprintable() or c == ' ')；(2) 或使用正则 re.sub(r'\\x1b\\[[0-9;]*[a-zA-Z]', '', query) 移除 ANSI 转义序列；(3) 避免用 print 做日志输出，改用 logging 模块的结构化日志",
    """分析过程：
1. 污染源：request.args.get('q') 获取用户输入。
2. 危险 sink：print(f'[INFO] Search query: {query}') 将用户输入输出到终端。
3. 数据流追踪：query → f-string 拼接到输出字符串 → print 输出到 stdout（可能被重定向到日志文件）。
4. 防御检查（缺失）：
   (a) query 未经任何控制字符过滤直接拼入 f-string。
   (b) print 默认输出到 stdout，在终端环境中会解释 ANSI 转义码。
   (c) 如果 stdout 被重定向到日志文件，换行符 \\n 同样可注入伪造日志行。
5. 攻击路径：
   (a) ANSI 转义码注入：攻击者传入 q=\\x1b[2J\\x1b[H（清屏+光标归位）→ 终端被清空，之前的日志记录消失。
   (b) 伪造错误：攻击者传入 q=\\n\\x1b[31m[ERROR] Database connection failed\\x1b[0m → 日志中出现红色的伪造 ERROR 行，误导运维人员。
   (c) 换行符注入：攻击者传入 q=test\\n[INFO] Admin logged in → 日志文件中出现伪造的 admin 登录记录。
   (d) 这些攻击可误导审计、掩盖真实攻击痕迹或制造虚假告警。
6. 结论：存在 CWE-117 日志注入漏洞，用户输入未经控制字符过滤直接输出到终端/日志。"""
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


def validate():
    """验证生成的样本。"""
    print("\n" + "=" * 60)
    print("验证样本")
    print("=" * 60)

    errors = []

    # 1. 数量检查
    assert len(SAMPLES) == 14, f"样本数应为 14，实际 {len(SAMPLES)}"
    vuln_count = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe_count = len(SAMPLES) - vuln_count
    assert vuln_count == 6, f"漏洞样本应为 6，实际 {vuln_count}"
    assert safe_count == 8, f"安全样本应为 8，实际 {safe_count}"
    print(f"[OK] 样本数: {len(SAMPLES)} (vuln={vuln_count}, safe={safe_count})")

    # 2. 类别分布
    crossfile = [s for s in SAMPLES if s["filename"].startswith("7bweak_crossfile")]
    shlex_sess = [s for s in SAMPLES if s["filename"].startswith("7bweak_shlex") or s["filename"].startswith("7bweak_session")]
    vuln_samples = [s for s in SAMPLES if s["filename"].startswith("7bweak_missing") or s["filename"].startswith("7bweak_mass") or s["filename"].startswith("7bweak_log")]
    print(f"[OK] 类别分布: crossfile_input={len(crossfile)}, shlex/session={len(shlex_sess)}, vuln={len(vuln_samples)}")

    # 3. JSON 可解析 + schema 合规
    for i, sample in enumerate(SAMPLES):
        record = build_messages(sample)
        msgs = record["messages"]
        assert len(msgs) == 3, f"样本{i}: messages 应有 3 条，实际 {len(msgs)}"
        assert msgs[0]["role"] == "system"
        assert msgs[1]["role"] == "user"
        assert msgs[2]["role"] == "assistant"

        # system prompt 必须是 SYSTEM_PROMPT_LITE（非硬编码）
        assert msgs[0]["content"] == SYSTEM_PROMPT_LITE, f"样本{i}: system prompt 不匹配 SYSTEM_PROMPT_LITE"

        # user prompt 必须含 build_user_prompt 格式
        assert "代码片段" in msgs[1]["content"], f"样本{i}: user prompt 缺少 '代码片段' 头"
        assert sample["filename"] in msgs[1]["content"], f"样本{i}: user prompt 缺少 filename"

        # assistant 必须含 CoT + json 块
        assistant = msgs[2]["content"]
        assert "```json" in assistant, f"样本{i}: assistant 缺少 json 块"
        assert "分析过程" in assistant, f"样本{i}: assistant 缺少 CoT 分析"

        # 提取 JSON 结论块并验证 schema
        import re
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', assistant, re.DOTALL)
        assert json_match, f"样本{i}: 无法提取 JSON 块"
        verdict = json.loads(json_match.group(1))

        required_fields = ["has_vulnerability", "vulnerability_type", "risk_level",
                          "source", "sink", "explanation", "fix_suggestion"]
        for field in required_fields:
            assert field in verdict, f"样本{i}: JSON 缺少字段 {field}"

        # 安全样本 schema 约束
        if not sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] == "none", f"样本{i}: safe 样本 vuln_type 应为 'none'"
            assert verdict["risk_level"] == "None", f"样本{i}: safe 样本 risk_level 应为 'None'"
            assert verdict["source"] == "N/A", f"样本{i}: safe 样本 source 应为 'N/A'"
            assert verdict["sink"] == "N/A", f"样本{i}: safe 样本 sink 应为 'N/A'"
            assert verdict["fix_suggestion"] == "no fix needed", f"样本{i}: safe 样本 fix 应为 'no fix needed'"

        # 漏洞样本必须有具体 vuln_type
        if sample["has_vulnerability"]:
            assert verdict["vulnerability_type"] != "none", f"样本{i}: vuln 样本 vuln_type 不应为 'none'"
            assert verdict["risk_level"] != "None", f"样本{i}: vuln 样本 risk_level 不应为 'None'"

    print(f"[OK] 所有 {len(SAMPLES)} 条样本 JSON 可解析且 schema 合规")

    # 4. 安全样本 explanation 不重复
    safe_explanations = [s["explanation"] for s in SAMPLES if not s["has_vulnerability"]]
    unique_explanations = set(safe_explanations)
    assert len(unique_explanations) == len(safe_explanations), \
        f"安全样本 explanation 有重复: {len(unique_explanations)}/{len(safe_explanations)}"
    print(f"[OK] 安全样本 explanation 唯一: {len(unique_explanations)}/{len(safe_explanations)}")

    # 5. CoT 不重复
    cot_texts = [s["cot_analysis"] for s in SAMPLES]
    unique_cots = set(cot_texts)
    assert len(unique_cots) == len(cot_texts), \
        f"CoT 有重复: {len(unique_cots)}/{len(cot_texts)}"
    print(f"[OK] CoT 唯一: {len(unique_cots)}/{len(cot_texts)}")

    # 6. 代码行数检查（5-20 行合理范围，crossfile input 可能更短）
    print("\n代码行数:")
    for s in SAMPLES:
        line_count = len(s["code"].split("\n"))
        print(f"  {s['filename']}: {line_count} 行 ({'vuln' if s['has_vulnerability'] else 'safe'})")

    # 7. 漏洞类型分布
    print("\n漏洞类型分布:")
    from collections import Counter
    vtype_counter = Counter(s["vulnerability_type"] for s in SAMPLES if s["has_vulnerability"])
    for t, c in vtype_counter.most_common():
        print(f"  {c}  {t}")

    if errors:
        print(f"\n[FAIL] 发现 {len(errors)} 个错误:")
        for e in errors:
            print(f"  - {e}")
        return False
    print(f"\n[OK] 所有验证通过")
    return True


def main():
    print(f"共 {len(SAMPLES)} 条补充样本")
    vuln = sum(1 for s in SAMPLES if s["has_vulnerability"])
    safe = len(SAMPLES) - vuln
    print(f"  漏洞样本: {vuln}  安全样本: {safe}")

    # 按类别统计
    crossfile = [s for s in SAMPLES if s["filename"].startswith("7bweak_crossfile")]
    shlex_sess = [s for s in SAMPLES if s["filename"].startswith("7bweak_shlex") or s["filename"].startswith("7bweak_session")]
    vuln_samples = [s for s in SAMPLES if s["filename"].startswith("7bweak_missing") or s["filename"].startswith("7bweak_mass") or s["filename"].startswith("7bweak_log")]
    print(f"  crossfile input: {len(crossfile)}  shlex/session: {len(shlex_sess)}  vuln: {len(vuln_samples)}")

    # 验证
    validate()

    # 写入
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in SAMPLES:
            record = build_messages(sample)
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证写入的文件可被逐行解析
    print("\n验证写入文件...")
    count = 0
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)  # 会抛异常如果 JSON 不合法
            assert "messages" in rec
            assert len(rec["messages"]) == 3
            count += 1
    assert count == 14, f"写入行数应为 14，实际 {count}"
    print(f"[OK] 文件包含 {count} 条有效 JSONL 记录")


if __name__ == "__main__":
    main()
