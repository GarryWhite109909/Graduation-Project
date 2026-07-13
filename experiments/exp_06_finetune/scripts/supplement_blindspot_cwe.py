"""
盲区 CWE 补充样本生成 —— 补齐改进文档点名的分类法盲区。

背景：
  改进文档（docs/改进.md）指出 7B baseline 漏报 3 类漏洞的根因是
  SYSTEM_PROMPT 的 ANALYSIS_SCOPE 没列这些类别。已扩展 ANALYSIS_SCOPE
  （prompts.py），但训练数据里这些类别的样本太少：

    CWE-117 日志注入：2 条（supplement_7b_weakness.jsonl）
    CWE-330/338 弱随机数：1 条（supplement_crypto_noise.jsonl）
    CWE-327 弱密码学：3 条（supplement_crypto_noise.jsonl）

  本脚本补充 10 条高质量样本（4 + 4 + 2），凑到每类 5-7 条，CoT 由
  GLM5.2 直接撰写（非模板填空），演示"这个 API/算法为什么不安全"的
  推理路径。

输出：
  data/supplement_blindspot_cwe.jsonl（10 条 ChatML 样本）

设计原则：
  - 每条代码场景不同（不同框架、不同 sink）
  - CoT 必须包含：污染源、sink、弱点分析、具体攻击 payload、与安全写法对比
  - system message 内容会被 combine_and_augment.py 覆盖为 SYSTEM_PROMPT_LITE
  - 不写安全对照样本（supplement_crypto_noise.jsonl 已有 18 条安全样本）

用法：
  PYTHONPATH=. /home/zane/miniconda3/envs/graproj/bin/python \
      experiments/exp_06_finetune/scripts/supplement_blindspot_cwe.py
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/supplement_blindspot_cwe.jsonl"


# ---------------------------------------------------------------------------
# 样本定义：每条含代码 + CoT 分析 + JSON 结论
# CoT 由 GLM5.2 直接撰写，演示"这个 API/算法为什么不安全"的推理路径
# ---------------------------------------------------------------------------
SAMPLES = [
    # =====================================================================
    # CWE-117 日志注入（4 条漏洞）
    # =====================================================================
    {
        "filename": "blind_log_warning_crlf.py",
        "code": '''import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("audit")
handler = logging.FileHandler("audit.log")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(handler)


@app.route("/api/transfer")
def transfer():
    account = request.args.get("account", "")
    amount = request.args.get("amount", "0")
    logger.warning(f"Transfer to account {account} amount {amount}")
    return {"status": "queued"}''',
        "cot": """分析过程：
1. 污染源：request.args.get('account') 和 request.args.get('amount') 直接获取用户输入。
2. 危险 sink：logger.warning(f"Transfer to account {account} amount {amount}") 将用户输入写入 audit.log。
3. 数据流追踪：account/amount → f-string 拼接到日志消息 → logging.FileHandler 写入文件。
4. 防御检查（缺失）：
   (a) account 和 amount 未经任何换行符（\\n、\\r）过滤直接拼入 f-string。
   (b) logging.Formatter 的 %(message)s 字段会原样输出消息内容，不转义控制字符。
   (c) FileHandler 写入文件时按字节写入，换行符会真实地分割日志行。
5. 攻击路径（CRLF 注入伪造审计记录）：
   (a) 攻击者传入 account=victim%0a2026-07-10 [WARNING] Admin reset 2FA for user attacker
       （%0a 是 URL 编码的 \\n，Flask 自动解码为换行符）
   (b) audit.log 中出现两行：
       2026-07-10 12:00:00 [WARNING] Transfer to account victim
       2026-07-10 [WARNING] Admin reset 2FA for user attacker amount 0
   (c) 第二行是伪造的"管理员重置 2FA"审计记录，攻击者可借此掩盖真实操作或嫁祸他人。
   (d) 在合规审计场景下，伪造的审计记录可导致取证失败或错误追责。
6. 结论：存在 CWE-117 日志注入漏洞，用户输入未过滤 CRLF 控制字符直接写入审计日志。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-117 日志注入",
            "risk_level": "Medium",
            "source": "request.args.get('account')/('amount')",
            "sink": "logger.warning(f'... {account} ... {amount}')",
            "explanation": "用户输入 account/amount 未过滤换行符直接拼入 f-string 写入审计日志，攻击者可通过 CRLF 注入伪造审计记录掩盖恶意操作或嫁祸他人",
            "fix_suggestion": "过滤换行符与控制字符：safe_account = account.replace('\\n', '_').replace('\\r', '_')[:64]，或用 repr() 让字符串中的特殊字符以字面形式记录；审计日志建议同时记录原始字节数据的哈希用于取证比对"
        }
    },
    {
        "filename": "blind_log_error_useragent.py",
        "code": '''import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger("web")


@app.route("/api/order", methods=["POST"])
def create_order():
    user_agent = request.headers.get("User-Agent", "")
    sku = request.form.get("sku", "")
    logger.error(f"Order failed for UA={user_agent} sku={sku}")
    return {"status": "error"}, 500''',
        "cot": """分析过程：
1. 污染源：request.headers.get('User-Agent') 和 request.form.get('sku') 获取用户输入（User-Agent 完全由客户端控制）。
2. 危险 sink：logger.error(f"Order failed for UA={user_agent} sku={sku}") 写入 web logger。
3. 数据流追踪：user_agent/sku → f-string 拼接 → logger.error 输出到日志处理器（可能是 FileHandler 或 StreamHandler）。
4. 防御检查（缺失）：
   (a) User-Agent 和 sku 未经任何控制字符过滤直接拼入日志消息。
   (b) User-Agent 是 HTTP 头字段，攻击者可任意构造（curl -H "User-Agent: ..."）。
   (c) logger.error 默认按 message 原样输出，logging 模块不提供自动换行符过滤。
5. 攻击路径（终端转义码 + 换行符双重注入）：
   (a) 终端清屏攻击：User-Agent=\\x1b[2J\\x1b[H（ANSI 清屏+光标归位）→ 如果日志输出到终端（如运维通过 tail -f 查看），终端会被清空，之前的错误记录消失，运维人员误判为没有错误。
   (b) 伪造 ERROR 优先级日志：User-Agent=test\\n2026-07-10 12:00 [CRITICAL] Database dropped → 日志文件中出现伪造的 CRITICAL 级别记录，触发告警系统误报。
   (c) sku 注入：sku=\\r\\r[ERROR] Payment gateway leaked card numbers → 利用 \\r 回车覆盖当前行，伪造支付网关泄露的假象。
6. 结论：存在 CWE-117 日志注入漏洞，User-Agent 和 SKU 未过滤控制字符直接写入错误日志。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-117 日志注入",
            "risk_level": "Medium",
            "source": "request.headers.get('User-Agent')/request.form.get('sku')",
            "sink": "logger.error(f'... UA={user_agent} sku={sku}')",
            "explanation": "User-Agent 和 SKU 未过滤换行符与 ANSI 转义码直接写入错误日志，可注入伪造 CRITICAL 级别记录触发告警误报，或通过 ANSI 清屏码欺骗运维终端",
            "fix_suggestion": "对所有进入日志的字符串做控制字符剥离：import re; safe = re.sub(r'[\\x00-\\x1f\\x7f]', '?', value)；或使用 structlog 等结构化日志库，将用户输入作为结构化字段而非文本拼接"
        }
    },
    {
        "filename": "blind_log_syslog_format.py",
        "code": '''import syslog
from flask import Flask, request

app = Flask(__name__)


@app.route("/api/auth")
def auth():
    username = request.args.get("username", "")
    syslog.syslog(syslog.LOG_INFO, f"Auth attempt for user {username}")
    return {"status": "ok"}''',
        "cot": """分析过程：
1. 污染源：request.args.get('username') 获取用户输入。
2. 危险 sink：syslog.syslog(syslog.LOG_INFO, f"Auth attempt for user {username}") 写入系统日志（/var/log/syslog 或 /var/log/messages）。
3. 数据流追踪：username → f-string 拼接 → syslog.syslog → syslog 协议（RFC 5424）传输 → 系统日志守护进程写入文件。
4. 防御检查（缺失）：
   (a) username 未经任何过滤直接拼入 syslog 消息。
   (b) syslog 协议本身不转义消息内容中的换行符，syslog 守护进程按行写入日志文件。
   (c) syslog 消息会被多个日志收集器（rsyslog、journald、ELK）转发，换行符会沿转发链传播。
5. 攻击路径（系统级日志伪造）：
   (a) 攻击者传入 username=root\\nJul 10 12:00:00 host sshd[1234]: Accepted password for root from 1.2.3.4 port 22
   (b) /var/log/auth.log 中出现两行：
       Jul 10 12:00:00 host app[1234]: Auth attempt for user root
       Jul 10 12:00:00 host sshd[1234]: Accepted password for root from 1.2.3.4 port 22
   (c) 第二行是伪造的 SSH 登录成功记录，安全审计工具（如 fail2ban、OSSEC）可能据此误判攻击者已通过 SSH 登录。
   (d) 在 SOC 取证场景下，伪造的 sshd 记录与真实 sshd 记录难以区分，可导致调查方向错误。
6. 结论：存在 CWE-117 日志注入漏洞，用户输入未过滤换行符直接写入系统日志。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-117 日志注入",
            "risk_level": "Medium",
            "source": "request.args.get('username')",
            "sink": "syslog.syslog(LOG_INFO, f'... {username}')",
            "explanation": "用户输入未过滤换行符直接拼入 syslog 消息，可注入伪造的 sshd 登录成功记录误导安全审计与取证工具（fail2ban/OSSEC）",
            "fix_suggestion": "对进入 syslog 的字符串做换行符剥离：safe_username = username.replace('\\n', '').replace('\\r', '')[:64]；或改用结构化日志库 logging 模块的 extra 字段传递用户输入而非拼接到 message"
        }
    },
    {
        "filename": "blind_log_structlog_event.py",
        "code": '''import structlog
from flask import Flask, request

app = Flask(__name__)
logger = structlog.get_logger()


@app.route("/api/refund")
def refund():
    order_id = request.args.get("order_id", "")
    reason = request.args.get("reason", "")
    logger.info("refund_requested", order_id=order_id, reason=reason)
    return {"status": "processing"}''',
        "cot": """分析过程：
1. 污染源：request.args.get('order_id') 和 request.args.get('reason') 获取用户输入。
2. 危险 sink：logger.info("refund_requested", order_id=order_id, reason=reason) 通过 structlog 记录事件。
3. 数据流追踪：order_id/reason → 作为 kwargs 传入 structlog → 渲染器（ConsoleRenderer 或 JSONRenderer）输出到日志。
4. 防御检查（部分缺失）：
   (a) structlog 的 JSONRenderer 会把 order_id/reason 作为 JSON 字符串字段的值，JSON 序列化会自动转义换行符为 \\n（这是好的）。
   (b) 但 ConsoleRenderer（默认用于开发环境或 stdout 输出）会将 kwargs 以 key=value 形式拼接到文本日志行，value 中的 \\n 会真实换行。
   (c) 如果生产环境用 ConsoleRenderer 输出到文件（如 systemd journal 或 FileHandler），换行符仍可注入。
   (d) 此外，reason 字段无长度限制，攻击者可传入超长字符串导致日志膨胀（DoS）。
5. 攻击路径（ConsoleRenderer 场景下的换行注入）：
   (a) 如果部署时 logger 配置为 ConsoleRenderer 输出到 journald。
   (b) 攻击者传入 reason=customer_request\\n2026-07-10 [INFO] refund_approved order_id=999999 amount=99999
   (c) journald 中出现两行：第二行是伪造的"退款已批准"记录，财务对账系统可能据此误判大额退款已通过。
   (d) 即使 JSONRenderer 安全，依赖"渲染器配置正确"是脆弱的——一旦运维误配 ConsoleRenderer 到生产，漏洞立即重现。
6. 结论：存在 CWE-117 日志注入风险（取决于渲染器配置），且 reason 字段无长度限制有日志膨胀 DoS 风险。代码依赖渲染器而非输入净化是防御薄弱。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-117 日志注入",
            "risk_level": "Low",
            "source": "request.args.get('order_id')/('reason')",
            "sink": "logger.info('refund_requested', order_id=order_id, reason=reason)",
            "explanation": "structlog 的 ConsoleRenderer 会将 reason 中的换行符真实输出，可注入伪造的退款批准记录误导财务对账；依赖渲染器配置而非输入净化是防御薄弱",
            "fix_suggestion": "对 order_id 做 isalnum 校验，对 reason 做长度限制（如 200 字符）并剥离换行符；强制生产环境使用 JSONRenderer 并设置 max_length 防止日志膨胀 DoS"
        }
    },

    # =====================================================================
    # CWE-330/338 弱随机数（4 条漏洞）
    # =====================================================================
    {
        "filename": "blind_weak_random_session.py",
        "code": '''import random
import string
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "dev"


@app.route("/api/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    session_token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    session["user"] = user
    session["token"] = session_token
    return {"token": session_token}''',
        "cot": """分析过程：
1. 污染源：无外部污染源——但 session_token 本身需要密码学强度随机性（会话令牌的安全属性要求）。
2. 危险 sink："".join(random.choice(...) for _ in range(32)) 生成 32 字符的会话令牌。
3. 弱点分析（PRNG 算法）：
   (a) random 模块使用 Mersenne Twister（MT19937）伪随机数生成器，设计目标是统计模拟而非密码学安全。
   (b) MT 的内部状态为 624 个 32 位字（共 19968 位），通过观察 624 个连续输出可完全恢复内部状态，进而预测所有后续输出。
   (c) 攻击者可通过多次登录获取多个 session_token，若累计观察到 624 个 32 位输出（约 2496 字符的 token = 78 次登录），可反推服务器 MT 状态，预测任意用户的下一个 session_token。
4. 弱点分析（种子可预测性）：
   (a) Python 默认用 os.urandom 初始化 MT 种子，种子本身不可预测。
   (b) 但 MT 的状态空间（2^19937-1）虽大，输出序列是确定性的——一旦状态泄露，所有未来输出可预测。
   (c) 对比 secrets 模块：基于 os.urandom 直接读取 /dev/urandom（Linux 内核 CSPRNG），每次输出独立，无法反推。
5. 攻击路径：
   (a) 攻击者注册账号并登录 78 次，收集 78 个 32 字符的 session_token。
   (b) 每个 token 32 字符 × 6 bit/字符 = 192 bit，但 MT 输出每次 32 bit，32 字符约消耗 48 次 MT 调用。
   (c) 用 untwist 算法恢复 MT 状态后，预测下一个 session_token，冒充任意用户登录。
6. 结论：存在 CWE-330 弱随机数漏洞，会话令牌使用非密码学安全的 random 模块生成。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-330 弱随机数",
            "risk_level": "High",
            "source": "N/A（令牌生成逻辑本身）",
            "sink": "random.choice(string.ascii_letters + string.digits) 生成 session_token",
            "explanation": "会话令牌使用 random 模块（Mersenne Twister）生成，MT 状态可通过观察约 624 个 32 位输出反推，攻击者多次登录后可预测任意用户的下一个 session_token 冒充登录",
            "fix_suggestion": "import secrets; session_token = secrets.token_urlsafe(32)（基于 os.urandom 的 CSPRNG，每次输出独立无法反推）；或用 session.sid 由 Flask-Session 中间件生成"
        }
    },
    {
        "filename": "blind_weak_random_apikey.py",
        "code": '''import random
import string
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/api/keys", methods=["POST"])
def create_api_key():
    user_id = request.form.get("user_id", "")
    api_key = "sk_" + "".join(random.choices(string.ascii_letters + string.digits, k=40))
    conn = sqlite3.connect("app.db")
    conn.execute("INSERT INTO api_keys (user_id, key) VALUES (?, ?)", (user_id, api_key))
    conn.commit()
    conn.close()
    return {"api_key": api_key}''',
        "cot": """分析过程：
1. 污染源：request.form.get('user_id') 是用户输入，但这里 user_id 经过参数化查询存入数据库（无 SQL 注入）。真正的风险在 api_key 生成逻辑。
2. 危险 sink：api_key = "sk_" + "".join(random.choices(string.ascii_letters + string.digits, k=40)) 生成 API 密钥。
3. 弱点分析（PRNG 算法）：
   (a) random.choices 使用 Mersenne Twister，非密码学安全。
   (b) API 密钥是高价值凭证，一旦可预测，攻击者可冒充任意用户调用 API。
   (c) 62 字符集（a-zA-Z0-9）× 40 字符 = 62^40 ≈ 2^238 理论空间，但 MT 状态空间仅 2^19937-1，实际有效输出序列远小于理论空间。
   (d) 更关键：MT 是确定性算法，一旦状态泄露，所有生成的 API 密钥可被预测。
4. 弱点分析（可观测性）：
   (a) API 密钥通过 POST 响应返回给客户端，攻击者注册账号即可获取自己的 API 密钥。
   (b) 多次注册收集 N 个密钥（每个 40 字符约消耗 240 bit MT 输出 ≈ 8 次 MT 调用），78 个密钥即可恢复 MT 状态。
   (c) 状态恢复后，攻击者可预测服务器接下来为其他用户生成的所有 API 密钥。
5. 攻击路径：
   (a) 攻击者注册 78 个账号，获取 78 个 API 密钥。
   (b) 用 untwist 恢复 MT 状态。
   (c) 观察服务器为新用户（如管理员）生成密钥的时序，预测管理员 API 密钥。
   (d) 用管理员 API 密钥调用特权接口。
6. 结论：存在 CWE-330 弱随机数漏洞，API 密钥使用非密码学安全的 random.choices 生成。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-330 弱随机数",
            "risk_level": "High",
            "source": "N/A（密钥生成逻辑本身）",
            "sink": "random.choices(string.ascii_letters + string.digits, k=40) 生成 api_key",
            "explanation": "API 密钥使用 random.choices（Mersenne Twister）生成，攻击者多次注册收集密钥后可恢复 MT 状态，预测为其他用户（含管理员）生成的密钥",
            "fix_suggestion": "import secrets; api_key = 'sk_' + secrets.token_urlsafe(30)（基于 os.urandom，输出不可预测）；API 密钥还应存储哈希值而非明文，泄露时仅哈希泄露"
        }
    },
    {
        "filename": "blind_weak_random_csrf.py",
        "code": '''import random
from flask import Flask, request, session, render_template_string

app = Flask(__name__)
app.secret_key = "dev"


@app.route("/api/transfer", methods=["GET"])
def transfer_form():
    csrf_token = str(random.getrandbits(64))
    session["csrf"] = csrf_token
    return render_template_string('<form><input type="hidden" name="csrf" value="{{ token }}"><input name="amount"></form>', token=csrf_token)''',
        "cot": """分析过程：
1. 污染源：无外部污染源——但 CSRF 令牌本身需要不可预测性（CSRF 防御的安全属性要求）。
2. 危险 sink：csrf_token = str(random.getrandbits(64)) 生成 CSRF 令牌。
3. 弱点分析（PRNG 算法）：
   (a) random.getrandbits(64) 直接调用 Mersenne Twister 生成 64 位整数，非密码学安全。
   (b) MT 的输出是确定性的——给定相同状态，输出完全可复现。
   (c) CSRF 令牌的核心安全假设是"攻击者无法预测令牌值"，而 MT 一旦状态泄露，所有未来令牌可预测。
4. 弱点分析（状态泄露途径）：
   (a) 攻击者访问 /api/transfer 获取自己的 CSRF 令牌，每个令牌消耗 2 次 MT 32 位输出（64 位 = 2 × 32 bit）。
   (b) 收集 312 个 CSRF 令牌（= 624 次 32 位输出）即可用 untwist 恢复 MT 状态。
   (c) 状态恢复后，攻击者可预测服务器为其他用户生成的下一个 CSRF 令牌。
5. 攻击路径（CSRF 绕过）：
   (a) 攻击者收集 312 个自己的 CSRF 令牌。
   (b) 恢复 MT 状态后，预测目标用户（受害者）的下一个 CSRF 令牌。
   (c) 构造恶意页面，嵌入预测的 CSRF 令牌，诱导受害者访问。
   (d) 受害者浏览器携带会话 cookie + 恶意页面提交预测的 CSRF 令牌 → 服务器校验通过，执行转账。
6. 结论：存在 CWE-330 弱随机数漏洞，CSRF 令牌使用 random.getrandbits 生成，可被预测导致 CSRF 防御失效。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-330 弱随机数",
            "risk_level": "High",
            "source": "N/A（令牌生成逻辑本身）",
            "sink": "random.getrandbits(64) 生成 csrf_token",
            "explanation": "CSRF 令牌使用 random.getrandbits（Mersenne Twister）生成，攻击者收集约 312 个令牌可恢复 MT 状态，预测受害者的 CSRF 令牌绕过 CSRF 防御",
            "fix_suggestion": "import secrets; csrf_token = secrets.token_hex(32)（256 位 CSPRNG 输出）；或直接用 Flask-WTF 的 CSRFProtect 中间件，内部使用 secrets"
        }
    },
    {
        "filename": "blind_weak_random_coupon.py",
        "code": '''import random
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/api/coupon", methods=["POST"])
def generate_coupon():
    user_id = request.form.get("user_id", "")
    # 生成 8 位数字优惠码
    coupon = "".join(str(random.randint(0, 9)) for _ in range(8))
    conn = sqlite3.connect("app.db")
    conn.execute("INSERT INTO coupons (user_id, code, discount) VALUES (?, ?, 0.5)", (user_id, coupon))
    conn.commit()
    conn.close()
    return {"coupon": coupon}''',
        "cot": """分析过程：
1. 污染源：request.form.get('user_id') 经参数化查询存入数据库（无 SQL 注入）。风险在 coupon 生成逻辑。
2. 危险 sink：coupon = "".join(str(random.randint(0, 9)) for _ in range(8)) 生成 8 位数字优惠码。
3. 弱点分析（PRNG 算法）：
   (a) random.randint(0, 9) 调用 Mersenne Twister，非密码学安全。
   (b) 优惠码代表 50% 折扣的经济价值，可被预测则造成直接经济损失。
4. 弱点分析（空间与可预测性双重弱点）：
   (a) 空间过小：8 位数字仅 10^8 = 1 亿种可能，攻击者即使暴力枚举也可在数小时内穷举（若服务器无速率限制）。
   (b) 可预测性：MT 状态可恢复，攻击者收集足够输出后可预测下一个优惠码。
   (c) 更严重：每次调用 random.randint(0, 9) 实际消耗 MT 的一次 32 位输出（取低 10 bit 再模 10），8 位优惠码消耗 8 次输出。78 个优惠码 = 624 次输出，足以恢复 MT 状态。
5. 攻击路径：
   (a) 攻击者注册 78 个账号，领取 78 个优惠码（每个 8 字符）。
   (b) 从优惠码反推每次 random.randint 的输出，恢复 MT 状态。
   (c) 预测下一个用户（可能是高价值客户）的优惠码，抢先使用或转卖。
   (d) 即使不预测，1 亿空间也可暴力枚举（若无速率限制）。
6. 结论：存在 CWE-330 弱随机数漏洞（兼 CWE-326 弱熵空间），优惠码使用 random 生成且仅 8 位数字，既可被预测也可被暴力枚举。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-330 弱随机数",
            "risk_level": "Medium",
            "source": "N/A（优惠码生成逻辑本身）",
            "sink": "random.randint(0, 9) 生成 8 位数字优惠码",
            "explanation": "优惠码使用 random.randint 生成且仅 8 位数字（10^8 空间），既可被暴力枚举，也可通过收集约 78 个优惠码恢复 MT 状态后预测",
            "fix_suggestion": "import secrets; coupon = ''.join(secrets.choice('0123456789ABCDEFGHJKLMNPQRSTUVWXYZ') for _ in range(12))（Crockford Base32，去除易混淆字符，扩大空间至 32^12 ≈ 2^60）；并加强制为单次使用 + 用户绑定"
        }
    },

    # =====================================================================
    # CWE-327 弱密码学（2 条漏洞）
    # =====================================================================
    {
        "filename": "blind_weak_crypto_des.py",
        "code": '''from Crypto.Cipher import DES
from flask import Flask, request
import base64

app = Flask(__name__)
KEY = b"8bytekey!"[:8]


@app.route("/api/encrypt")
def encrypt_data():
    plaintext = request.args.get("data", "").encode()
    # DES 块大小为 8 字节，需填充
    pad_len = 8 - (len(plaintext) % 8)
    plaintext += bytes([pad_len] * pad_len)
    cipher = DES.new(KEY, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return {"encrypted": base64.b64encode(ciphertext).decode()}''',
        "cot": """分析过程：
1. 污染源：request.args.get('data') 是用户输入（但此处是加密场景，明文可任意）。
2. 危险 sink：DES.new(KEY, DES.MODE_ECB) 用 DES 算法 + ECB 模式加密数据。
3. 弱点分析（DES 算法）：
   (a) DES 密钥长度仅 56 位有效位（8 字节中每字节最低位是奇偶校验，不参与加密）。
   (b) 56 位 = 2^56 ≈ 7.2 × 10^16，1998 年 EFF Deep Crack 机器 56 小时即可暴力破解。
   (c) 现代消费级 GPU 集群数小时可穷举 56 位空间，DES 已被 NIST 在 2005 年正式废弃。
   (d) KEY = b"8bytekey!"[:8] 实际只有 "8byteke" 8 字节，但有效密钥仅 56 bit。
4. 弱点分析（ECB 模式）：
   (a) ECB（Electronic Codebook）将明文分块独立加密，相同明文块产生相同密文块。
   (b) 攻击者可通过观察密文块的重复模式推断明文结构（如重复字段、模板文本）。
   (c) 经典示例：ECB 模式加密位图图片后，密文仍能看出图片轮廓（penguin.png 示例）。
   (d) ECB 不需要 IV，缺少随机性，相同明文每次加密结果相同，无法语义安全。
5. 弱点分析（密钥硬编码）：
   (a) KEY = b"8bytekey!"[:8] 硬编码在源码中，源码泄露即密钥泄露。
   (b) 这同时是 CWE-798 硬编码凭证，但本样本主要焦点是 DES 弱算法。
6. 攻击路径：
   (a) 攻击者获取密文（通过抓包或日志泄露）。
   (b) 用 DES 破解工具（如 hashcat 模式 14000）在 GPU 上数小时破解密钥。
   (c) 或利用 ECB 模式的模式泄露，通过选择明文攻击推断明文结构。
7. 结论：存在 CWE-327 弱密码学漏洞，DES 算法 + ECB 模式双重不安全。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-327 弱密码学",
            "risk_level": "High",
            "source": "N/A（加密算法选择本身）",
            "sink": "DES.new(KEY, DES.MODE_ECB).encrypt(plaintext)",
            "explanation": "使用 DES 算法（56 位有效密钥，1998 年起已被暴力破解）+ ECB 模式（相同明文块产生相同密文块，可模式泄露），双重弱密码学；密钥还硬编码在源码中",
            "fix_suggestion": "from Crypto.Cipher import AES; 用 AES-256-GCM（密钥从 KMS 读取），GCM 模式提供加密 + 完整性认证；IV 随机生成并随密文存储"
        }
    },
    {
        "filename": "blind_weak_crypto_md5_salt.py",
        "code": '''import hashlib
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/api/register", methods=["POST"])
def register():
    username = request.form.get("user", "")
    password = request.form.get("pwd", "")
    # 加了 salt 但只用 MD5 单次哈希
    salt = "static_salt_2026"
    hashed = hashlib.md5((salt + password).encode()).hexdigest()
    conn = sqlite3.connect("app.db")
    conn.execute("INSERT INTO users (username, pwd_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()
    conn.close()
    return {"status": "registered"}''',
        "cot": """分析过程：
1. 污染源：request.form.get('pwd') 获取用户密码（预期输入，但需安全存储）。
2. 危险 sink：hashlib.md5((salt + password).encode()).hexdigest() 对密码做 MD5 哈希。
3. 弱点分析（MD5 算法）：
   (a) MD5 设计目标是快速计算——这正是密码存储的反面需求。
   (b) 现代消费级 GPU（如 RTX 4090）每秒可计算约 100 亿次 MD5，整个 8 字符密码空间（含大小写+数字+符号 ≈ 2^52）可在数小时内穷举。
   (c) MD5 已存在碰撞攻击（2004 年王小云团队），不适用于任何安全场景。
4. 弱点分析（静态 salt）：
   (a) salt = "static_salt_2026" 硬编码在源码中，所有用户共用同一 salt。
   (b) 静态 salt 的唯一作用是让预计算彩虹表失效（攻击者无法用通用彩虹表反查），但攻击者可用源码中的 salt 自行生成彩虹表。
   (c) 一旦 salt 泄露（源码泄露），所有密码哈希退化为无 salt 场景。
5. 弱点分析（无迭代）：
   (a) 单次 MD5 计算极快，攻击者每秒可尝试 100 亿次密码。
   (b) 对比 bcrypt rounds=12（2^12=4096 次迭代）：bcrypt 每次哈希耗时约 250ms，相同 GPU 每秒仅能尝试 4 次，慢 25 亿倍。
   (c) 对比 argon2id memory_cost=65536：每次哈希消耗 64MB 内存，GPU 显存有限无法大规模并行，进一步阻止破解。
6. 攻击路径：
   (a) 攻击者通过 SQL 注入或备份泄露获取 users 表的 pwd_hash 列。
   (b) 用 hashcat 模式 20（md5($salt.$pass)）配合源码泄露的 salt，在 GPU 上每秒尝试 100 亿次密码。
   (c) 8 字符以下密码可在数小时内破解，弱密码（如 "password123"）秒级破解。
7. 结论：存在 CWE-327 弱密码学漏洞，MD5 + 静态 salt + 无迭代，密码哈希可被快速破解。""",
        "verdict": {
            "has_vulnerability": True,
            "vulnerability_type": "CWE-327 弱密码学",
            "risk_level": "High",
            "source": "request.form.get('pwd')",
            "sink": "hashlib.md5((salt + password).encode()).hexdigest()",
            "explanation": "使用 MD5（快速摘要算法，GPU 每秒 100 亿次）+ 静态 salt（源码泄露即失效）+ 无迭代（单次哈希），密码哈希可被 GPU 快速破解",
            "fix_suggestion": "import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))（每次生成随机 salt，2^12 次迭代，专门为密码存储设计）；或用 argon2-cffi 库的 argon2id"
        }
    },
]


def build_sample(sample: dict) -> dict:
    """构建一条 ChatML 样本。

    system message 会被 combine_and_augment.py 覆盖为 SYSTEM_PROMPT_LITE，
    但为了样本可独立测试，这里也填入 LITE。
    """
    user_prompt = build_user_prompt(
        code=sample["code"], language="python", filename=sample["filename"]
    )
    cot = sample["cot"]
    verdict = sample["verdict"]
    # JSON 块格式与现有样本一致（2 空格缩进）
    json_str = json.dumps(verdict, ensure_ascii=False, indent=2)
    assistant_content = f"{cot}\n\n```json\n{json_str}\n```"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    print(f"生成 {len(SAMPLES)} 条盲区 CWE 补充样本")
    print(f"  CWE-117 日志注入: 4 条")
    print(f"  CWE-330/338 弱随机数: 4 条")
    print(f"  CWE-327 弱密码学: 2 条")
    print(f"输出: {OUTPUT_FILE}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in SAMPLES:
            chatml = build_sample(s)
            f.write(json.dumps(chatml, ensure_ascii=False) + "\n")

    # 校验
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    print(f"\n已写入 {len(lines)} 条样本")

    # 统计 vuln_type
    from collections import Counter
    import re
    c = Counter()
    for line in lines:
        d = json.loads(line)
        for m in d["messages"]:
            if m["role"] == "assistant":
                mm = re.search(r'"vulnerability_type"\s*:\s*"([^"]+)"', m["content"])
                if mm:
                    c[mm.group(1)] += 1
    print("\nvuln_type 分布:")
    for k, v in c.most_common():
        print(f"  {v}  {k}")


if __name__ == "__main__":
    main()
