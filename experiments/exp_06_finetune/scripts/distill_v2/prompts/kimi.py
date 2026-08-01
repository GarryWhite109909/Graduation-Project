"""
Kimi K3 提示词（同步自 docs/prompts/kimi_prompt.md）。

2 类 user 模板，对应方法论 2 个 K3 pack：
  cc_memory   | C/C++ 内存漏洞重构（800 条）
  cross_file  | 跨文件分块审计（1200 条）

关键：K3 原生长链压扁已在 system prompt 里强约束（≤5 步、行号锚定），
     脚本侧 validate_sample.py 再做 ≤5 步兜底校验。
"""

# ===========================================================================
# 系统提示词（kimi_prompt.md 第 10-53 行，原样同步）
# ===========================================================================
KIMI_SYSTEM = """你是一名资深安全研究员，专精内存安全与长代码库审计。你正在为代码漏洞检测模型生成高质量训练样本。

【你的核心优势】
- 长上下文（1M）+ Delta Attention，能跨 .so 追踪调用链
- 在 Redis 双重释放（CVE-2026-25589）上 27 分钟自主挖出 0day
- 看雪实测三模型中误报最少、精度最高

【关键约束——必须遵守】
1. 输出必须极度简洁：你的原生长链推理（动辄数万 token 的调用链追踪）8B 模型学不会。本次输出必须压成 ≤5 步、≤590 token
2. 每步锚定行号：不要展开调用链细节，只保留"第 X 行 free(ptr) → 第 Y 行 return *ptr"这种关键锚点
3. 三段式格式：[代码片段] → [≤5步推理] → [JSON结论]
4. 负样本 1:3 配比：每生成 1 条漏洞样本，必须生成 3 条同类无漏洞样本

【输出压扁示例】
错误（你的原生风格，8B 学不会）：
"从 main() 进入 process_request()，在第 42 行调用 parse_header()，该函数在第 87 行 malloc 了 64 字节给 header_buf，然后在第 92 行通过 strncpy 拷贝数据，接着在第 105 行 free(header_buf)，但第 108 行的 error_handler 路径仍引用 header_buf..."

正确（压扁后，8B 可学）：
"1. 第 105 行 free(header_buf) 释放内存
2. 第 108 行 error_handler 路径仍解引用 header_buf
3. free 后未置 NULL
4. 错误路径触发 UAF
5. CWE-416 UAF，Critical"

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

JSON 字段（统一 schema，与 GLM/DeepSeek 一致）：has_vulnerability / vulnerability_type / risk_level / cvss_vector / cvss_score / source / sink / explanation / fix_suggestion
负样本 has_vulnerability=false，vulnerability_type="none"，cvss_vector="N/A"，cvss_score=0.0，其余字段为 "N/A" 或 "no fix needed"。

【CVSS 3.1 向量格式】
格式：CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{H|L|N}/I:{H|L|N}/A:{H|L|N}
字段含义：AV 攻击向量(N网络/A邻近/L本地/P物理) / AC 攻击复杂度(L低/H高) / PR 权限要求(N无/L低/H高) / UI 用户交互(N无需/R需要) / S 影响范围(U不变/C改变) / C 机密性(H高/L低/N无) / I 完整性(H高/L低/N无) / A 可用性(H高/L低/N无)
分数对照：9.0-10.0 Critical / 7.0-8.9 High / 4.0-6.9 Medium / 0.1-3.9 Low / 0.0 None"""


# ===========================================================================
# user 模板构建器
# ===========================================================================

def _fmt_bool(has_vuln):
    return "是" if has_vuln else "否"


def _tpl_cc_memory(t):
    """C/C++ 内存漏洞重构（kimi_prompt.md 第 60-85 行）。"""
    return (
        "请生成 1 条 " + t.cwe + " 内存漏洞的训练样本：\n"
        "- 语言：" + t.lang + "\n"
        "- 场景：" + t.scene + "\n"
        "- 难度：" + t.difficulty + "（必须跨函数或跨文件）\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n\n"
        "CWE 覆盖：CWE-416 UAF / CWE-415 Double Free / CWE-122 Heap Overflow / "
        "CWE-367 TOCTOU / CWE-190 Integer Overflow / CWE-787 Out-of-bounds Write\n\n"
        "要求：\n"
        "1. 代码场景真实：网络协议解析、文件系统驱动、内存池、对象生命周期管理\n"
        "2. 漏洞必须涉及跨函数或跨文件的调用链，但输出必须压扁为 ≤5 步\n"
        "3. 安全样本：使用 RAII、智能指针、free 后置 NULL、边界检查、原子操作\n"
        "4. CoT 必须压成以下格式：\n"
        "   [漏洞类型] {CWE-XXX}\n"
        "   [位置] file.c:{行号}\n"
        "   [关键证据] {1 句话核心}\n"
        "   [3-5 步推理] 1) ... 2) ... 3) ...\n"
        "   [修复] {1 句话}\n\n"
        "【关键】输出必须压成 ≤5 步，不要展开调用链细节。8B 模型学不会数万 token 的追踪。\n\n"
        "输出严格三段式格式。"
    )


def _tpl_cross_file(t):
    """跨文件分块审计（kimi_prompt.md 第 87-116 行）。

    输入特殊：user 消息含【当前文件块】+【上游调用方摘要】两部分。
    本类样本教 8B 在单块内识别漏洞 + 结合上游摘要判断跨文件风险。
    """
    return (
        "请生成 1 条跨文件分块审计样本：\n"
        "- 漏洞类型：" + t.cwe + "\n"
        "- 场景：" + t.scene + "\n"
        "- 文件角色：" + t.file_role + "\n"
        "- 上游调用方：" + t.upstream_summary + "\n"
        "- 是否有漏洞：" + _fmt_bool(t.has_vuln) + "\n\n"
        "CWE 覆盖：CWE-441 信任边界绕过 / CWE-639 IDOR / CWE-862 缺失授权 / "
        "CWE-918 SSRF / CWE-89 跨文件 SQL 注入\n\n"
        "【这是新增类别——模拟文件切割工具的产出】\n"
        "8B 模型上下文有限，无法处理长文件。本类样本教模型：\n"
        "1. 在单个文件块（≤4K token）内识别漏洞\n"
        "2. 结合\"上游调用方摘要\"判断跨文件风险\n"
        "3. 标注\"需结合上游 X 函数验证\"的待确认项\n\n"
        "【输入格式特殊】\n"
        "user 消息包含两部分：\n"
        "1. 【当前文件块】{≤4K token 的代码片段}\n"
        "2. 【上游调用方摘要】{200 token 内的调用方信息}\n\n"
        "【输出格式特殊】\n"
        "分析过程必须包含：\n"
        "1. 本块内的数据流分析（≤3 步）\n"
        "2. 跨文件风险标注：\"需结合上游 {X 函数} 验证 {Y 条件}\"\n"
        "3. 待确认项（如有）：\"本块内未见 {Z}，但需确认上游调用方是否 {条件}\"\n\n"
        "输出严格三段式格式，CoT ≤5 步。"
    )


_BUILDERS = {
    "cc_memory": _tpl_cc_memory,
    "cross_file": _tpl_cross_file,
}


def build_kimi_user(template_name, task):
    """根据 template_name 选择 builder，返回 user 消息。

    template_name: cc_memory | cross_file
    task: TaskSpec dataclass 实例（见 task_specs.py）
    """
    builder = _BUILDERS.get(template_name)
    if builder is None:
        raise ValueError(f"未知 Kimi 模板: {template_name}")
    return builder(task)
