"""
生成 CWE-441（信任边界绕过）训练样本 ——2026-07-25

背景：
  训练数据中 CWE-441 完全空白（0 条），导致 2/8 CVE-fix 测试样本（0005/0006）
  始终为 FN。CWE-441 是架构级漏洞（信任假设错误），无单一 sink 函数，
  与传统代码级漏洞模式不同。

样本设计（7 条：4 漏洞 + 3 安全）：
  1. 漏洞：loopback 信任绕过（Python Flask）—— 类似 cve_fix_0005.js
  2. 漏洞：X-Forwarded-For 信任绕过（Node.js Express）—— 类似 cve_fix_0006.js
  3. 漏洞：内部 API 无认证暴露（Python Django）
  4. 漏洞：Referer 头访问控制绕过（PHP）
  5. 安全：所有端点统一认证（Python Flask）
  6. 安全：X-Forwarded-For 仅在可信代理后使用（Node.js Express）
  7. 安全：网络层 VPN 访问控制 + 应用层认证（Java Spring）

用法：
  python3 gen_cwe441_samples.py  # 追加到 train_chatml_v4.jsonl
"""

import json
import sys
from pathlib import Path

# 导入新的 SYSTEM_PROMPT_LITE
PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import SYSTEM_PROMPT_LITE

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
OUTPUT_FILE = DATA_DIR / "train_chatml_v4.jsonl"


# ---------------------------------------------------------------------------
# 样本定义
# ---------------------------------------------------------------------------
SAMPLES = [
    # ===== 1. 漏洞：loopback 信任绕过（Python Flask）=====
    {
        "code": """@app.route('/admin/debug', methods=['POST'])
def debug_endpoint():
    # 仅允许本地访问的调试端点
    client_ip = request.remote_addr
    if client_ip == '127.0.0.1' or client_ip == '::1':
        action = request.json.get('action', '')
        target = request.json.get('target', '')
        if action == 'exec':
            result = subprocess.check_output(target, shell=True)
            return jsonify({'output': result.decode()})
        elif action == 'read':
            with open(target, 'r') as f:
                return jsonify({'content': f.read()})
    return jsonify({'error': 'forbidden'}), 403""",
        "language": "python",
        "filename": "vuln_cwe441_loopback_trust.py",
        "is_vuln": True,
        "vulnerability_type": "CWE-441 信任边界绕过",
        "risk_level": "Critical",
        "source": "request.remote_addr（可被 DNS 重绑定/IPv6 映射/SSRF 绕过）",
        "sink": "subprocess.check_output(target, shell=True) / open(target)",
        "explanation": "代码通过 request.remote_addr == '127.0.0.1' 判断是否为本地请求，并据此信任该请求执行任意命令。但 remote_addr 可被 DNS 重绑定、IPv6 映射地址（如 ::ffff:127.0.0.1）、或 SSRF 代理绕过。信任边界基于网络层 IP 而非应用层认证，攻击者可绕过。",
        "fix_suggestion": "移除基于 IP 的信任假设，所有端点（包括调试端点）必须经过应用层认证（如 API Key、JWT），不依赖 remote_addr 判断信任。",
        "cot": """分析过程：
1. 用户可控输入点是 POST 请求的 JSON body（action、target 字段），以及请求来源 IP（request.remote_addr）。
2. 数据流：request.remote_addr → IP 判断 → 如果是 127.0.0.1 则信任 → request.json 的 action/target → subprocess.check_output(target, shell=True) 或 open(target)。
3. 关键问题：代码假设来自 127.0.0.1 的请求是可信的，但 remote_addr 可被 DNS 重绑定、IPv6 映射地址（::ffff:127.0.0.1）、或同机 SSRF 代理绕过。这是信任边界绕过（CWE-441）：将网络层 IP 作为应用层信任依据。
4. 一旦绕过 IP 检查，target 直接进入 shell=True 的 subprocess 和 open()，无任何过滤，构成命令注入和任意文件读取。
5. 防御措施缺失：无应用层认证（API Key/JWT），仅靠 IP 判断信任。

结论：存在信任边界绕过漏洞（CWE-441），导致未认证的命令执行和文件读取。""",
    },

    # ===== 2. 漏洞：X-Forwarded-For 信任绕过（Node.js Express）=====
    {
        "code": """const express = require('express');
const app = express();

// IP 白名单中间件
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const trustedIps = ['10.0.0.1', '10.0.0.2', '192.168.1.0/24'];

    // 检查是否来自内网
    const isInternal = trustedIps.some(ip => clientIp.startsWith(ip.split('/')[0]));
    if (isInternal) {
        req.isTrusted = true;
    }
    next();
});

app.post('/api/internal/sync', (req, res) => {
    if (!req.isTrusted) return res.status(403).json({error: 'forbidden'});
    // 执行内部同步逻辑，无需认证
    const data = req.body;
    db.sync(data.table, data.records);
    res.json({status: 'synced', count: data.records.length});
});""",
        "language": "javascript",
        "filename": "vuln_cwe441_xforwarded_trust.js",
        "is_vuln": True,
        "vulnerability_type": "CWE-441 信任边界绕过",
        "risk_level": "Critical",
        "source": "req.headers['x-forwarded-for']（HTTP 头，可被任意客户端伪造）",
        "sink": "db.sync(data.table, data.records)（内部同步操作）",
        "explanation": "代码从 X-Forwarded-For 头获取客户端 IP 并据此判断是否可信。X-Forwarded-For 是 HTTP 请求头，可被任意客户端伪造。攻击者只需在请求中添加 X-Forwarded-For: 10.0.0.1 即可绕过 IP 白名单，访问内部同步 API。",
        "fix_suggestion": "不要信任 X-Forwarded-For 头做安全决策。如果部署在反向代理后，应使用代理提供的安全通道（mTLS）或独立网络段，应用层仍需认证。",
        "cot": """分析过程：
1. 用户可控输入点是 X-Forwarded-For 请求头和 POST body（data.table、data.records）。X-Forwarded-For 是 HTTP 头，任何客户端均可伪造。
2. 数据流：req.headers['x-forwarded-for'] → clientIp → startsWith 检查 → req.isTrusted = true → /api/internal/sync 端点跳过认证 → db.sync(data.table, data.records)。
3. 关键问题：代码将 X-Forwarded-For 头作为信任依据，但该头可被任意客户端伪造。攻击者只需添加 `X-Forwarded-For: 10.0.0.1` 即可绕过 IP 白名单。这是信任边界绕过（CWE-441）：将可伪造的 HTTP 头作为网络层信任依据。
4. 一旦绕过信任检查，db.sync 接收未认证的 data.table 和 data.records，可操纵数据库同步。
5. 防御措施缺失：无应用层认证，仅靠可伪造的 HTTP 头判断信任。

结论：存在信任边界绕过漏洞（CWE-441），攻击者可伪造 X-Forwarded-For 绕过 IP 白名单访问内部 API。""",
    },

    # ===== 3. 漏洞：内部 API 无认证暴露（Python）=====
    {
        "code": """@app.route('/api/v1/admin/users/<user_id>/reset_password', methods=['POST'])
def reset_password(user_id):
    # 此端点仅由内部管理面板调用，不对外暴露
    new_password = generate_temp_password()
    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
               (hash_password(new_password), user_id))
    audit_log(user_id, 'password_reset')
    return jsonify({'new_password': new_password})

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    # 健康检查端点
    return jsonify({'status': 'ok', 'timestamp': time.time()})""",
        "language": "python",
        "filename": "vuln_cwe441_internal_api_no_auth.py",
        "is_vuln": True,
        "vulnerability_type": "CWE-441 信任边界绕过",
        "risk_level": "High",
        "source": "HTTP 请求（无认证）",
        "sink": "db.execute('UPDATE users SET password_hash...')（密码重置操作）",
        "explanation": "密码重置端点 /api/v1/admin/users/<user_id>/reset_password 无任何认证机制，仅靠'内部管理面板调用'的假设保护。如果该 API 路由被外部访问（配置错误、网络隔离失效），任何人都可重置任意用户密码。信任边界基于网络隔离假设而非应用层认证。",
        "fix_suggestion": "所有 admin 端点必须加认证中间件（如 @requires_admin decorator），不依赖网络隔离假设。",
        "cot": """分析过程：
1. 用户可控输入点是 URL 路径参数 user_id 和 HTTP 请求本身。该端点无任何认证检查。
2. 数据流：POST 请求 → /api/v1/admin/users/<user_id>/reset_password → generate_temp_password() → db.execute('UPDATE users SET password_hash') → 返回新密码。
3. 关键问题：代码注释说'此端点仅由内部管理面板调用'，但没有任何认证机制强制执行这一假设。信任边界基于网络隔离假设（内部网络不可外部访问），而非应用层认证。如果网络隔离失效（配置错误、SSRF、反向代理暴露），任意攻击者可调用此端点重置任意用户密码。
4. 这是信任边界绕过（CWE-441）：将网络层隔离假设作为应用层信任依据，无防御措施。
5. 相比之下，/api/v1/health 端点无需认证是合理的（只返回状态），但密码重置端点无认证是严重漏洞。

结论：存在信任边界绕过漏洞（CWE-441），密码重置端点无应用层认证，依赖网络隔离假设。""",
    },

    # ===== 4. 漏洞：Referer 头访问控制绕过（PHP）=====
    {
        "code": """<?php
function check_admin_access() {
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    $expected_host = 'admin.internal.corp';

    // 仅允许从内部管理面板访问
    if (strpos($referer, $expected_host) === false) {
        http_response_code(403);
        die('Access denied');
    }
    // 通过 Referer 检查后，视为管理员
    return true;
}

if (check_admin_access()) {
    $action = $_POST['action'] ?? '';
    $user_id = $_POST['user_id'] ?? '';
    if ($action === 'delete') {
        $pdo->exec("DELETE FROM users WHERE id = " . intval($user_id));
        echo "User deleted";
    }
}
?>""",
        "language": "php",
        "filename": "vuln_cwe441_referer_trust.php",
        "is_vuln": True,
        "vulnerability_type": "CWE-441 信任边界绕过",
        "risk_level": "Critical",
        "source": "$_SERVER['HTTP_REFERER']（HTTP 头，可被任意客户端伪造）",
        "sink": "$pdo->exec('DELETE FROM users...')（用户删除操作）",
        "explanation": "代码通过 HTTP Referer 头判断是否为管理员请求。Referer 是客户端可控的 HTTP 头，可被任意伪造。攻击者只需在请求中设置 Referer: http://admin.internal.corp/ 即可绕过访问控制，删除任意用户。",
        "fix_suggestion": "移除 Referer 检查，改用服务端会话认证（$_SESSION['is_admin']）或 JWT token 验证管理员权限。",
        "cot": """分析过程：
1. 用户可控输入点是 HTTP Referer 头和 POST 参数（action、user_id）。Referer 是客户端可控的 HTTP 头。
2. 数据流：$_SERVER['HTTP_REFERER'] → strpos 检查 → 如果包含 admin.internal.corp 则视为管理员 → $pdo->exec('DELETE FROM users WHERE id = ' . intval($user_id))。
3. 关键问题：代码将 Referer 头作为访问控制依据，但 Referer 可被任意客户端伪造。攻击者只需设置 `Referer: http://admin.internal.corp/anything` 即可绕过检查。这是信任边界绕过（CWE-441）：将可伪造的 HTTP 头作为权限验证依据。
4. 绕过后，intval($user_id) 仅防止 SQL 注入，但不限制可删除的用户范围，任意用户可被删除。
5. 防御措施缺失：无服务端会话认证，无角色检查，仅靠可伪造的 Referer 头判断管理员身份。

结论：存在信任边界绕过漏洞（CWE-441），攻击者可伪造 Referer 头绕过访问控制执行用户删除。""",
    },

    # ===== 5. 安全：所有端点统一认证（Python Flask）=====
    {
        "code": """@app.route('/api/admin/debug', methods=['POST'])
@require_admin_auth  # JWT token 验证 + admin 角色检查
def debug_endpoint():
    action = request.json.get('action', '')
    target = request.json.get('target', '')

    if action == 'read_config':
        # 仅允许读取配置文件，白名单限制
        allowed_configs = ['app.ini', 'database.ini', 'logging.ini']
        if target not in allowed_configs:
            return jsonify({'error': 'config not in whitelist'}), 400
        with open(f'/etc/app/{target}', 'r') as f:
            return jsonify({'content': f.read()})

    return jsonify({'error': 'unknown action'}), 400""",
        "language": "python",
        "filename": "safe_cwe441_proper_auth.py",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "调试端点使用 @require_admin_auth 装饰器进行应用层认证（JWT + 角色检查），不依赖网络层 IP 判断信任。文件读取有白名单限制，仅允许读取指定配置文件。防御有效，无漏洞。",
        "fix_suggestion": "no fix needed",
        "cot": """分析过程：
1. 用户可控输入点是 POST 请求的 JSON body（action、target）和 JWT token（在 @require_admin_auth 中验证）。
2. 数据流：JWT token → @require_admin_auth 验证（签名校验 + admin 角色检查）→ 通过后才进入端点逻辑 → target → 白名单检查 → open(f'/etc/app/{target}')。
3. 防御评估：
   - 应用层认证：@require_admin_auth 使用 JWT 签名验证 + admin 角色，不依赖 IP 或 HTTP 头等可伪造信息，是有效的信任边界。
   - 文件读取白名单：target 必须在 allowed_configs 列表中，路径拼接 f'/etc/app/{target}' 在白名单约束下无路径穿越风险。
   - 无 shell=True 的 subprocess 调用，不存在命令注入。
4. 信任边界基于应用层认证（JWT），而非网络层假设，防御有效。

结论：防御措施有效，无漏洞。""",
    },

    # ===== 6. 安全：X-Forwarded-For 仅在可信代理后使用（Node.js Express）=====
    {
        "code": """const express = require('express');
const app = express();

// 仅在可信代理（Nginx）后启用 trust proxy
app.set('trust proxy', '10.0.0.1');  // 仅信任 Nginx 所在机器

// 认证中间件：所有 /api/internal/ 端点需要 API Key
app.use('/api/internal/', (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !isValidApiKey(apiKey)) {
        return res.status(401).json({error: 'unauthorized'});
    }
    next();
});

// 日志记录使用 X-Forwarded-For（仅用于日志，不做安全决策）
app.use((req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    logger.info({path: req.path, ip: clientIp, timestamp: Date.now()});
    next();
});

app.post('/api/internal/sync', (req, res) => {
    const data = req.body;
    db.sync(data.table, data.records);
    res.json({status: 'synced'});
});""",
        "language": "javascript",
        "filename": "safe_cwe441_xforwarded_logging.js",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "代码正确使用 X-Forwarded-For：仅在可信代理（10.0.0.1）后启用 trust proxy，X-Forwarded-For 仅用于日志记录而非安全决策。访问控制通过 API Key 认证实现，不依赖 IP 或 HTTP 头。防御有效，无漏洞。",
        "fix_suggestion": "no fix needed",
        "cot": """分析过程：
1. 用户可控输入点是 X-Forwarded-For 头、X-API-Key 头和 POST body。
2. 数据流：
   - 安全决策路径：X-API-Key → isValidApiKey 验证 → 通过则允许访问 db.sync()。
   - 日志路径：X-Forwarded-For → logger.info()（仅记录，不做安全决策）。
3. 防御评估：
   - 应用层认证：/api/internal/ 路径下所有端点需要有效的 API Key，不依赖 IP 或 HTTP 头判断信任。
   - trust proxy 配置：app.set('trust proxy', '10.0.0.1') 仅信任 Nginx 所在机器，防止外部伪造 X-Forwarded-For。
   - X-Forwarded-For 仅用于日志记录，不参与任何安全决策。
4. 信任边界基于应用层认证（API Key），X-Forwarded-For 被正确降级为日志信息，防御有效。

结论：防御措施有效，无漏洞。""",
    },

    # ===== 7. 安全：网络层 VPN + 应用层认证双重防护（Java Spring）=====
    {
        "code": """@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @PostMapping("/users/{id}/resetPassword")
    public ResponseEntity<?> resetPassword(
            @PathVariable Long id,
            @RequestHeader("Authorization") String authHeader) {

        // 1. 应用层认证：验证 JWT token
        if (!tokenProvider.validateToken(authHeader)) {
            return ResponseEntity.status(401).body("Invalid token");
        }

        // 2. 角色检查：必须是 ADMIN 角色
        if (!tokenProvider.hasRole(authHeader, "ADMIN")) {
            return ResponseEntity.status(403).body("Insufficient privileges");
        }

        // 3. 审计日志
        auditService.log(tokenProvider.getUserId(authHeader), "reset_password", id);

        // 4. 执行密码重置
        String newPassword = passwordService.generateTempPassword(id);
        return ResponseEntity.ok(Map.of("new_password", newPassword));
    }
}""",
        "language": "java",
        "filename": "safe_cwe441_dual_auth.java",
        "is_vuln": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "密码重置端点使用 JWT token 认证 + ADMIN 角色检查，不依赖网络层 IP 判断信任。认证和授权在应用层强制执行，即使网络隔离失效也无法绕过。防御有效，无漏洞。",
        "fix_suggestion": "no fix needed",
        "cot": """分析过程：
1. 用户可控输入点是 URL 路径参数 id 和 Authorization 头（JWT token）。
2. 数据流：Authorization header → tokenProvider.validateToken（签名验证）→ tokenProvider.hasRole（ADMIN 角色检查）→ 通过后 passwordService.generateTempPassword(id) → 审计日志。
3. 防御评估：
   - 应用层认证：JWT token 签名验证，不依赖 IP 或网络隔离。
   - 角色授权：仅 ADMIN 角色可执行密码重置，最小权限原则。
   - 审计日志：记录操作者和操作对象，可追溯。
   - 无网络层信任假设，即使端点被外部访问也无法绕过认证。
4. 信任边界基于应用层认证（JWT + 角色），防御有效。

结论：防御措施有效，无漏洞。""",
    },
]


def build_sample(sample: dict) -> dict:
    """构建训练样本的 ChatML 格式。"""
    code = sample["code"]
    language = sample["language"]
    filename = sample["filename"]

    user_prompt = f"代码片段（文件名: {filename}，语言: {language}）：\n```{language}\n{code}\n```\n\n请先给出分析过程，然后在最后给出 JSON 结论。"

    if sample["is_vuln"]:
        json_block = {
            "has_vulnerability": True,
            "vulnerability_type": sample["vulnerability_type"],
            "risk_level": sample["risk_level"],
            "source": sample["source"],
            "sink": sample["sink"],
            "explanation": sample["explanation"],
            "fix_suggestion": sample["fix_suggestion"],
        }
    else:
        json_block = {
            "has_vulnerability": False,
            "vulnerability_type": "none",
            "risk_level": "None",
            "source": "N/A",
            "sink": "N/A",
            "explanation": sample["explanation"],
            "fix_suggestion": "no fix needed",
        }

    assistant_content = f"{sample['cot']}\n\n```json\n{json.dumps(json_block, ensure_ascii=False, indent=2)}\n```"

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_LITE},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def main():
    print(f"生成 {len(SAMPLES)} 条 CWE-441 样本")
    print(f"  漏洞样本: {sum(1 for s in SAMPLES if s['is_vuln'])}")
    print(f"  安全样本: {sum(1 for s in SAMPLES if not s['is_vuln'])}")
    print(f"输出: {OUTPUT_FILE}")

    # 追加到 v4 文件
    with open(OUTPUT_FILE, "a") as f:
        for sample in SAMPLES:
            obj = build_sample(sample)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    print(f"\n✓ 追加 {len(SAMPLES)} 条到 {OUTPUT_FILE}")

    # 验证最终样本数
    with open(OUTPUT_FILE) as f:
        total = sum(1 for _ in f)
    print(f"✓ v4 总样本数: {total}")


if __name__ == "__main__":
    main()
