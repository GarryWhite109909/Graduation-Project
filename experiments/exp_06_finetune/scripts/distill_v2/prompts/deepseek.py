"""DeepSeek 蒸馏提示词。

三阶段三层提示词，各司其职：
  ① 教师 system（DEEPSEEK_DISTILL_SYSTEM）—— 蒸馏时给 DeepSeek，让它"出题 + 写标准答案"
  ② 学生 system（STUDENT_SYSTEM）—— 训练+推理时给 8B，定义"答题角色"，两者必须一致
  ③ user —— 蒸馏时是"出题指令"，训练/推理时是"待测代码"

数据流：
  蒸馏：教师system + 出题user → DeepSeek 返回 [代码 + CoT + JSON]
  训练：学生system + 代码user + 标准答案assistant → 8B 学"在学生角色下，给代码→输出CoT+JSON"
  推理：学生system + 代码user → 8B 自己输出 CoT+JSON

关键：教师system ≠ 学生system（目的不同）；训练system = 推理system（同一学生的考试规则不能变）。
"""

# ===========================================================================
# ① 教师 system（蒸馏专用，~550 token）
# 目的：让 DeepSeek 既"出题"（生成代码）又"写标准答案"（CoT+JSON）。
# 只在调 API 时用，不进训练数据。
# CWE 归因 + CVSS 格式 + 输出格式等"对所有样本固定的全局参考"放 system，
# 不在每个 user 模板里重复（教师 system 不进训练数据，长一点无成本）。
# ===========================================================================
DEEPSEEK_DISTILL_SYSTEM = """你是一名资深安全研究员，为漏洞检测模型生成高质量训练样本。

【生成要求】
1. 生成真实可编译的代码片段（20-80行），模拟真实项目结构
2. 漏洞样本必须能被静态分析识别，但不能太明显
3. 安全样本必须包含有效防御，并用否定推理说明为何安全
4. 每个漏洞锚定具体行号

【输出格式】
三段式：
第一段：代码片段（```语言 ... ```）
第二段：分析过程（用 1. 2. 3. 编号，≤5 步，每步以"第X行"或"line X"锚定行号）
第三段：结构化结论（```json ... ```）

【推理路径多样化】
A 数据流优先（注入类）：source→sink→数据流→防御→结论
B 模式识别（密码学/配置/硬编码）：CWE模式匹配→行号验证→排除反例→结论
C 假设验证（负样本/防御迷惑）：假设恶意输入→追踪→防御是否阻断→结论
交替使用，禁止每条都用路径 A

【长度原则】
以完整覆盖"代码+分析+结论"为准，按复杂度自然伸缩，禁止注水凑长度：
- 低（直接注入/硬编码）：简短代码 + 2-3 步分析
- 中（带防御/单函数UAF）：适中代码 + 3-4 步分析
- 高（跨函数/TOCTOU/整数溢出链）：允许更长代码 + 4-5 步分析
每步必须有信息增量，禁止重复同一结论、禁止"换句话说/也就是说/需要注意的是"式啰嗦。

【JSON 字段】
has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
risk_level 取值：Critical / High / Medium / Low / None（首字母大写）
负样本：has_vulnerability=false, vulnerability_type="none", risk_level="None", cvss_vector="N/A", cvss_score=0.0, 其余字段 "N/A" 或 "no fix needed\"

【CWE 归因参考】
注入类按 sink 区分（SQL→CWE-89, shell→CWE-78, eval→CWE-95, LDAP→CWE-90）；内存类（UAF→CWE-416, Double Free→CWE-415, 栈溢出→CWE-121, NPD→CWE-476, 越界写→CWE-787）；密码学类（硬编码IV→CWE-329, JWT→CWE-347, 凭证→CWE-798）；其他（反序列化→CWE-502, XXE→CWE-611, SSRF→CWE-918, XSS→CWE-79, 路径穿越→CWE-22, IDOR→CWE-639）。

【CVSS 3.1 格式参考】
CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
（9.0-10 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 None）"""


# ② 学生 system（训练 + 推理一致，~180 token）
# 目的：定义 8B 的"答题角色"——分析代码 → 输出 CoT + JSON。
# 训练和推理必须用同一个 system（同一学生的考试规则不变）。
# 不含"生成要求/推理路径/长度控制"——那些是教师的出题指令，学生从标准答案里学。
#
# exp_05 消融实验确定：BASE_PROMPT（482 字符，纯角色+schema+输出格式）在 strict
# 准确率（CWE 归因）上最优（55.8%），任何额外规则维度都会干扰基座原生判断。
# 教师 system（DEEPSEEK_DISTILL_POSITIVE/NEGATIVE）保持不变——那是出题指令，不进训练数据。
try:
    from graduation_project.prompts import BASE_PROMPT as STUDENT_SYSTEM
except ImportError:
    from graduation_project.schema import format_schema_for_prompt
    STUDENT_SYSTEM = (
        "你是一名安全研究员，分析给定代码的安全漏洞。\n\n"
        "在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
        "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
        + format_schema_for_prompt()
        + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
    )


# ===========================================================================
# ③ user 模板构建器（蒸馏用，出题指令）
#   每个 builder 接收 task 规格字段，返回"出题指令"。
#   DeepSeek 收到：教师system（出题角色）+ user（出题指令）→ 返回 代码+CoT+JSON。
#   run_distill.py 提取代码放到 训练user，assistant 只保留 CoT+JSON。
#   user 只放"随样本变化的出题信息"（cwe/lang/scene/难度/场景特定要求），
#   全局参考（CWE归因/CVSS格式/输出格式）已在教师 system，不在此重复。
# ===========================================================================

def _fmt_bool(has_vuln):
    return "是" if has_vuln else "否"


def _tpl_cc_memory(t):
    """C/C++ 内存类漏洞。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞样本并分析其安全性：\n"
        "- 语言：" + t.lang + "\n"
        "- 难度：" + t.difficulty + "（困难=涉及跨函数调用或宏定义）\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 代码场景：" + t.scene + "\n\n"
        "要求：代码真实可编译（20-80行），漏洞锚定行号，安全样本含有效防御（free后置NULL/RAII/边界检查）。"
    )


def _tpl_pentest(t):
    """渗透/命令注入/运维安全。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞样本并分析其安全性：\n"
        "- 语言：" + t.lang + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 关键点：" + t.key_point + "\n\n"
        "要求：场景真实（CI/CD/运维自动化/容器配置/API网关），"
        "命令注入含 shell=True+拼接或 os.system+拼接，安全样本含 subprocess列表参数+shell=False/shlex.quote/白名单。"
    )


def _tpl_web(t):
    """Java/Python Web 漏洞。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞样本并分析其安全性：\n"
        "- 语言：" + t.lang + "\n"
        "- 框架：" + t.framework + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n"
        "- 难度：" + t.difficulty + "\n\n"
        "要求：模拟真实 Web 框架（Spring/Django/Flask/Express/FastAPI），"
        "含真实业务逻辑（登录/订单/上传/API），含防御迷惑样本（replace转义/startswith未规范化）。"
    )


def _tpl_shell(t):
    """Shell/配置文件安全。"""
    return (
        "请生成 1 条 " + t.cwe + " 漏洞样本并分析其安全性：\n"
        "- 类型：" + t.config_type + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n\n"
        "要求：真实 Shell/bash/Dockerfile/nginx.conf/systemd/CI yaml，"
        "漏洞模式（eval输入/硬编码密码/chmod 777/弱TLS/root容器），安全样本含环境变量引用/最小权限/TLS1.2+/非root。"
    )


def _tpl_fix(t):
    """漏洞修复 / 安全写法示范。

    has_vuln=True：先生成漏洞代码再给修复（漏洞→修复样例）。
    has_vuln=False：展示该 CWE 的正确防御写法 + 分析为何安全（安全写法示范）。
    修复 deepseek_fix pack 的 safe 部分原写死 has_vuln=True 导致 900 条全校验失败的问题。
    """
    if t.has_vuln:
        return (
            "请生成 1 条漏洞修复样例（" + t.cwe + "）：\n"
            "- 语言：" + t.lang + "\n"
            "- 场景：" + t.scene + "\n"
            "- 是否有漏洞：是（修复类固定为漏洞→修复）\n\n"
            "要求：\n"
            "1. 先给出有漏洞的代码（20-60行），锚定漏洞行号\n"
            "2. 分析漏洞（≤5步）\n"
            "3. JSON 的 fix_suggestion 字段给出完整修复代码\n"
            "4. has_vulnerability=true"
        )
    return (
        "请生成 1 条 " + t.cwe + " 的安全写法示范：\n"
        "- 语言：" + t.lang + "\n"
        "- 场景：" + t.scene + "\n"
        "- 是否有漏洞：否\n\n"
        "要求：\n"
        "1. 代码从一开始就采用正确防御（20-60行），展示 " + t.cwe + " 的标准防护写法\n"
        "2. 分析为何安全（≤5步，每步锚定行号，说明防御点为何有效）\n"
        "3. JSON 的 fix_suggestion 字段填 'no fix needed'\n"
        "4. has_vulnerability=false"
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
