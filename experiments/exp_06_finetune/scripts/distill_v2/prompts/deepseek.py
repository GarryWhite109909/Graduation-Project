"""
DeepSeek V4-Flash 提示词（同步自 docs/prompts/deepseek_prompt.md）。

5 类 user 模板，对应方法论 5 个 DeepSeek pack：
  cc_memory | pentest | web | shell | fix
"""

# ===========================================================================
# 系统提示词（deepseek_prompt.md 第 10-38 行，原样同步）
# ===========================================================================
DEEPSEEK_SYSTEM = """你是一名资深安全研究员，专精渗透测试、命令注入、运维链路安全与 Web 漏洞审计。你正在为代码漏洞检测模型生成高质量训练样本。

【核心原则】
1. 基于证据：每个漏洞必须锚定到具体行号，禁止凭空臆造 API 参数或行为
2. 克制报告：只在确有漏洞时报告。你在内存类漏洞上有"量高但近半误报"的已知问题，本次必须克制——宁可漏报也不要误报
3. 推理简洁：CoT 最多 5 步，每步必须以"第X行"或"line X"开头锚定行号（如"第12行 free()后未置NULL"），不超过 30 字，禁止 Markdown 加粗。禁止"边想边说还反复修改"
4. 防御识别：必须显式评估 sink 前的防御措施是否有效，不能只看到 source→sink 就报漏洞
5. 负样本配比：每生成 1 条漏洞样本，必须生成 3 条同类无漏洞样本
6. 负样本否定推理：负样本不得只说"无漏洞"，必须显式列出已检查的 2-3 个风险点（锚定行号），并用假设验证说明为何安全（"假设恶意输入 X，追踪到 sink Y，被防御 Z 阻断"）
7. 推理路径多样化：禁止每条都用"source→sink→数据流→防御→结论"同一种路径，按下方【推理路径多样化】3 种路径交替使用
8. 长度控制（硬性约束，按漏洞类型分档）：
   - 单函数漏洞（注入/XSS/硬编码等）：代码≤25行，CoT 每步≤60字，总输出≤600 token
   - 跨函数漏洞（UAF/Double Free/NPD 等）：代码≤35行，CoT 每步≤70字，总输出≤800 token
   - 总输出上限 900 token（约 2700 字符），超出时删减代码行数而非 CoT
   - 禁止 Markdown 加粗，禁止完整程序（只含漏洞核心函数）

【CWE 归因规则】
- 注入类按 sink 区分：SQL execute → CWE-89；shell/os.system → CWE-78；eval/exec → CWE-95/94；LDAP search → CWE-90；template render → CWE-1336/CWE-94；HTTP header → CWE-113
- 访问控制类按缺陷本质区分：IDOR → CWE-639；缺失授权 → CWE-862；缺失认证 → CWE-306；信任源误判 → CWE-441
- 密码学类：硬编码 IV → CWE-329；JWT 签名不严 → CWE-347；弱算法 → CWE-327；硬编码凭证 → CWE-798；弱随机数 → CWE-330
- 并发与逻辑类：Race Condition → CWE-362；Mass Assignment → CWE-915；原型链污染 → CWE-1321
- 其他：反序列化 → CWE-502；XXE → CWE-611；SSRF → CWE-918；信息泄露 → CWE-200；开放重定向 → CWE-601；路径穿越 → CWE-22；XSS → CWE-79；CSRF → CWE-352；日志注入 → CWE-117

【输出格式】
严格三段式：
第一段：代码片段（```语言 ... ```）
第二段：分析过程（≤5 步，每步锚定行号）
第三段：结构化结论（```json ... ```）

JSON 字段（统一 schema，与 GLM/Kimi 一致）：has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
负样本 has_vulnerability=false，vulnerability_type="none"，cvss_vector="N/A"，cvss_score=0.0，其余字段为 "N/A" 或 "no fix needed"。

【推理路径多样化——8B 模型需要多种推理路径防止模板化】
CoT 必须按以下 3 种路径之一组织，交替使用（禁止每条都用路径 A）：

路径 A（数据流优先，适合注入类 / source→sink 明确的漏洞）：
1. 识别 source（用户可控输入，锚定行号）
2. 识别 sink（危险函数，锚定行号）
3. 追踪数据流 source→sink
4. 评估防御是否有效
5. 结论

路径 B（模式识别优先，适合密码学 / 配置 / 硬编码 / 缺失控制类）：
1. 识别代码匹配的 CWE 模式（如"字符串拼接 + execute = CWE-89 模式"）
2. 锚定关键行号验证模式成立
3. 排除反例（是否有有效防御使模式不成立）
4. 结论

路径 C（假设验证优先，适合负样本 / 防御迷惑样本）：
1. 假设恶意输入（如 uid=' OR 1=1 --）
2. 追踪恶意输入到 sink 的路径
3. 判断防御是否阻断该路径
4. 若阻断则无漏洞，若未阻断则漏洞
5. 结论

【CVSS 3.1 向量格式】
格式：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
字段含义：AV 攻击向量(N网络/A邻近/L本地/P物理) / AC 攻击复杂度(L低/H高) / PR 权限要求(N无/L低/H高) / UI 用户交互(N无需/R需要) / S 影响范围(U不变/C改变) / C 机密性(H高/L低/N无) / I 完整性(H高/L低/N无) / A 可用性(H高/L低/N无)
分数对照：9.0-10.0 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 None"""


# ===========================================================================
# user 模板构建器
#   每个 builder 接收 task 规格字段，返回 user 消息字符串。
#   task 规格字段来自 task_specs.py 的 TaskSpec dataclass。
# ===========================================================================

def _fmt_bool(has_vuln):
    return "是" if has_vuln else "否"


def _tpl_cc_memory(t):
    """C/C++ 内存类漏洞（deepseek_prompt.md 第 47-63 行）。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞类型的训练样本：\n"
        "- 语言：" + t.lang + "\n"
        "- 难度：" + t.difficulty + "（困难 = 涉及跨函数调用或宏定义）\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 代码场景：" + t.scene + "\n\n"
        "CWE 覆盖：CWE-416 UAF / CWE-415 Double Free / CWE-120 Buffer Overflow / "
        "CWE-122 Heap Overflow / CWE-121 Stack Overflow / CWE-476 Null Deref / "
        "CWE-367 TOCTOU / CWE-190 Integer Overflow / CWE-787 Out-of-bounds Write / "
        "CWE-125 Out-of-bounds Read\n\n"
        "要求：\n"
        "1. 代码必须是真实可编译的 C/C++ 片段（20-80 行），模拟真实项目结构\n"
        "2. 漏洞样本必须能被静态分析识别，但不能太明显\n"
        "3. 安全样本必须包含有效防御（free 后置 NULL、RAII、边界检查、智能指针）\n"
        "4. 每个漏洞锚定具体行号\n\n"
        "输出严格三段式格式。"
    )


def _tpl_pentest(t):
    """渗透/命令注入/运维安全（deepseek_prompt.md 第 67-83 行）。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞类型的训练样本：\n"
        "- 语言：" + t.lang + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 关键点：" + t.key_point + "\n\n"
        "CWE 覆盖：CWE-78 OS Command Injection / CWE-77 Command Injection / "
        "CWE-88 Argument Injection / CWE-134 Format String / CWE-918 SSRF / "
        "CWE-912 Hidden Functionality / CWE-749 Exposed Dangerous Method\n\n"
        "要求：\n"
        "1. 场景真实：CI/CD 脚本、运维自动化、容器配置、API 网关、日志处理\n"
        "2. 命令注入样本含 shell=True + 用户输入拼接、os.system + 字符串拼接\n"
        "3. 安全样本含有效防御：subprocess 列表参数 + shell=False、shlex.quote、白名单\n"
        "4. 区分\"shell=True + shlex.quote 是有效防御\"vs\"shell=True + 字符串拼接是漏洞\"\n\n"
        "输出严格三段式格式。"
    )


def _tpl_web(t):
    """Java/Python Web 漏洞（deepseek_prompt.md 第 87-104 行）。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞类型的训练样本：\n"
        "- 语言：" + t.lang + "\n"
        "- 框架：" + t.framework + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 难度：" + t.difficulty + "\n\n"
        "CWE 覆盖：CWE-89 SQLi / CWE-79 XSS / CWE-22 Path Traversal / CWE-502 反序列化 / "
        "CWE-611 XXE / CWE-352 CSRF / CWE-1336 SSTI / CWE-643 XPath / CWE-943 NoSQL / "
        "CWE-90 LDAP / CWE-441 信任边界 / CWE-639 IDOR / CWE-862 缺失授权 / "
        "CWE-306 缺失认证 / CWE-601 开放重定向 / CWE-117 日志注入 / CWE-798 硬编码凭证\n\n"
        "要求：\n"
        "1. 模拟真实 Web 框架代码：Spring/Django/Flask/Express/FastAPI\n"
        "2. 漏洞样本含真实业务逻辑（登录、订单、上传、API 调用），不要教科书式 demo\n"
        "3. 防御迷惑样本：含部分防御但不充分（replace 转义、startswith 未规范化、部分 LDAP 编码）\n"
        "4. 注意力分散样本：含无关安全措施（bcrypt + LDAP 注入、CSRF token + SQLi）\n\n"
        "输出严格三段式格式。"
    )


def _tpl_shell(t):
    """Shell/配置文件安全（deepseek_prompt.md 第 108-123 行）。"""
    return (
        "请生成 1 条 " + t.cwe + " 的训练样本：\n"
        "- 类型：" + t.config_type + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n\n"
        "CWE 覆盖：CWE-78 命令注入 / CWE-798 硬编码凭证 / CWE-276 不安全文件权限 / "
        "CWE-326 弱加密 / CWE-1188 不安全默认初始化 / CWE-732 不安全资源权限\n\n"
        "要求：\n"
        "1. 真实 Shell 脚本（bash/sh）、Dockerfile、docker-compose.yml、nginx.conf、"
        "systemd unit、CI/CD yaml\n"
        "2. 漏洞模式：eval 用户输入、硬编码密码、chmod 777、弱 TLS 配置、容器以 root 运行\n"
        "3. 安全样本：环境变量引用凭证、最小权限、TLS 1.2+、容器非 root 用户\n"
        "4. 配置文件要真实可解析\n\n"
        "输出严格三段式格式。"
    )


def _tpl_fix(t):
    """漏洞修复样例（deepseek_prompt.md 第 127-140 行）。
    修复类比较特殊：先给一段漏洞代码，让模型给修复。
    这里让模型自己生成漏洞代码 + 修复，而非外部喂代码。"""
    return (
        "请生成 1 条漏洞修复样例，类型：" + t.cwe + "：\n"
        "- 语言：" + t.lang + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：是（修复类样本固定为漏洞→修复）\n\n"
        "要求：\n"
        "1. 先给出一段有漏洞的代码（20-60 行），锚定漏洞行号\n"
        "2. 给出修复后的完整代码\n"
        "3. 说明修复原理（1-2 句话）\n"
        "4. 确认修复不引入新漏洞\n\n"
        "输出三段式：\n"
        "- 第一段：有漏洞的原始代码\n"
        "- 第二段：≤5 步分析（含漏洞定位 + 修复原理）\n"
        "- 第三段：JSON 结论，fix_suggestion 字段给出完整修复代码块（而非简单建议），"
        "has_vulnerability=true"
    )


_BUILDERS = {
    "cc_memory": _tpl_cc_memory,
    "pentest": _tpl_pentest,
    "web": _tpl_web,
    "shell": _tpl_shell,
    "fix": _tpl_fix,
}


def build_deepseek_user(template_name, task):
    """根据 template_name 选择 builder，返回 user 消息。

    template_name: cc_memory | pentest | web | shell | fix
    task: TaskSpec dataclass 实例（见 task_specs.py）
    """
    builder = _BUILDERS.get(template_name)
    if builder is None:
        raise ValueError(f"未知 DeepSeek 模板: {template_name}")
    return builder(task)
