"""
统一 Prompt 模板 —— 全项目所有漏洞分析调用必须使用本模块的构建函数。

提供三种复用粒度：
- SYSTEM_PROMPT：角色 + 分析范围 + 安全模式白名单 + 硬编码凭证规则 + schema + 输出要求（system 字段用）
- build_user_prompt()：代码块 + 可选 RAG 上下文 + 收尾（user prompt）
- build_full_prompt()：SYSTEM_PROMPT + user prompt 拼接（给不用 system 字段的单 prompt 调用用）

schema 字段说明通过 graduation_project.schema.format_schema_for_prompt() 渲染，确保全项目一致。

DeepSeek 安全样本优化（2026-06-30）：
- 在 SYSTEM_PROMPT 中加入 SAFE_PATTERN_WHITELIST，显式声明常见安全写法（通用领域知识，不含测试样本代码）
- 不使用 Few-shot 示例，避免与测试样本代码重叠导致答案泄露
- 目标：把 deepseek-coder-v2:16b 在 exp_01 安全样本上的误报率从 100% 降到 ≤10%
"""

from typing import Optional

from graduation_project.schema import format_schema_for_prompt


# ---------------------------------------------------------------------------
# 分析范围（统一文本，避免各处不一致）
# ---------------------------------------------------------------------------
ANALYSIS_SCOPE = (
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化等"
)

# ---------------------------------------------------------------------------
# 安全模式白名单 —— 显式声明常见安全写法，避免模型对安全样本误报。
# 模型判定前必须自检：代码是否命中以下任一安全模式？若命中且无其他漏洞，应判 false。
# ---------------------------------------------------------------------------
SAFE_PATTERN_WHITELIST = """\
【安全模式白名单（命中以下模式且无其他漏洞时，应判 has_vulnerability=false）】
1. SQL 参数化查询：cursor.execute("... WHERE id=?", (user_id,))，占位符 + 参数元组，非字符串拼接。
2. subprocess 列表参数：subprocess.run(["cmd", arg])，shell 默认 False，列表形式不触发 shell 解释。不要捏造 shell=True。
3. 路径校验：os.path.abspath + startswith 限定目录，或白名单文件名集合。
4. XSS 防护：html.escape() / 模板自动转义 / textContent。
5. 反序列化：json.loads 替代 pickle.loads，yaml.safe_load 替代 yaml.load。
判断要点：用户输入到达 sink 不等于漏洞，必须看 sink 前的防御是否有效。但也不要因为代码"看起来安全"就忽略实际存在的漏洞。"""

# ---------------------------------------------------------------------------
# 硬编码凭证判定标准 —— 单独列出，避免与"安全模式白名单"混淆。
# ---------------------------------------------------------------------------
HARDCODED_SECRET_RULE = """\
【硬编码凭证判定标准（CWE-798）】
- 凡是源码中出现字面量形式的密码 / API Key / Secret / Token / AWS 密钥对 / 数据库连接串密码，
  无论是否被实际使用、无论是否在生产环境，都**本身就是漏洞**，应判 has_vulnerability=true。
- 不要因为"代码没有 SQL 注入、命令注入等其他风险"就把硬编码凭证降级为"敏感但非漏洞"。
- 安全的写法是：从 os.environ / 配置文件 / KMS 读取，而不是硬编码字面量。
- 检测特征：变量名含 key/secret/password/token/credential/passphrase，且赋值为字符串字面量。
- **不是凭证的常见字符串**：数据库名（如 "users.db"）、文件名、表名、URL 路径、主机名、
  端口号、SQL 语句、HTML 模板、错误消息文本。严禁把这些当成硬编码凭证强行找漏洞。
- **严禁钻空子**：当代码命中安全模式白名单（如参数化查询）时，严禁为了判 True 而强行
  在代码中挑剔其他"漏洞"（如把 "users.db" 当硬编码凭证）。若代码确实只命中安全模式而无
  真实漏洞，必须判 has_vulnerability=false。"""

# ---------------------------------------------------------------------------
# System Prompt：默认完整版
# 角色 + 分析范围 + 安全模式白名单 + 硬编码凭证规则 + schema + 输出要求。
# 注意：不使用 Few-shot 示例，避免与测试样本代码重叠导致答案泄露。
# 当前主模型 qwen2.5-coder:7b 依赖该完整 prompt 在 exp_01/exp_03 上达到 100% 准确率。
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    + ANALYSIS_SCOPE
    + "。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 判定前必须自检：代码是否命中下文「安全模式白名单」中的任一安全写法？"
    "若命中且无其他漏洞，必须判 has_vulnerability=false。\n"
    "4. 严禁把已经是安全写法的代码（如参数化查询、列表参数 subprocess、abspath+startswith 路径校验）"
    "误判为漏洞；同时严禁为了让安全代码“看起来有风险”而在 fix_suggestion 中推荐与原代码等价的写法。\n"
    "5. 严禁在判定中捏造代码中不存在的 API 参数（如 shell=True、debug=True）。"
    "判定必须基于代码实际内容，不能凭空臆造。\n"
    "6. 硬编码凭证本身就是漏洞（详见下文「硬编码凭证判定标准」），"
    "不要因为代码没有其他风险就降级为“敏感但非漏洞”。\n\n"
    + SAFE_PATTERN_WHITELIST
    + "\n\n"
    + HARDCODED_SECRET_RULE
    + "\n\n在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
    "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
    + format_schema_for_prompt()
    + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
)


def build_user_prompt(
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建 user prompt：代码块 + 可选 RAG 上下文 + 收尾要求。

    与 SYSTEM_PROMPT 配合使用。filename 用于给模型额外上下文，可不传。
    """
    parts = []
    header = f"代码片段（文件名: {filename}，语言: {language}）：" if filename else f"代码片段（语言: {language}）："
    parts.append(header)
    parts.append("```" + (language or "text") + "\n" + code + "\n```")

    if rag_context:
        parts.append(
            f"\n【知识库检索结果（仅供参考，可能与当前代码相关也可能无关）】\n{rag_context}\n"
            f"使用要求：\n"
            f"1. 上述知识可能命中「危险模式」或「安全模式」两类，请根据知识标题与内容自行判断。\n"
            f"2. 若知识标注 safe_pattern=true 或描述的是安全写法，应作为「避免误报」的依据，而非漏洞证据。\n"
            f"3. 若知识与当前代码漏洞类型不匹配（如代码是 SSRF 但检索到路径穿越知识），请忽略该知识，独立判断。\n"
            f"4. 严禁因为知识中提到某类漏洞就在代码中强行寻找该类漏洞；以代码实际语义为准。"
        )

    parts.append("请先给出分析过程，然后在最后给出 JSON 结论。")
    return "\n".join(parts)


def build_full_prompt(
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建单条完整 prompt（system + user 拼接）。

    供不支持 system 字段或希望单 prompt 调用的场景使用（如 exp_01 的批量脚本
    通过 client.generate(prompt=...) 调用）。语义上等价于 system=SYSTEM_PROMPT
    + prompt=build_user_prompt(...)。
    """
    return SYSTEM_PROMPT + "\n\n" + build_user_prompt(
        code=code, language=language, filename=filename, rag_context=rag_context
    )


# ---------------------------------------------------------------------------
# Prompt 工程消融变体（exp_05_prompt_ablation 使用）
# ---------------------------------------------------------------------------
# 5 个变体用于系统对比不同 Prompt 策略对难样本召回与安全样本误报的影响：
#   1. zero_shot      当前完整版 SYSTEM_PROMPT（含白名单+硬编码规则+多条要求+schema）
#   2. whitelist_only 仅角色 + SAFE_PATTERN_WHITELIST + schema（去掉其他规则）
#                     验证白名单本身的独立价值（与 zero_shot 对比看其他规则的增量）
#   3. few_shot       在 zero_shot 基础上加 3 组示例（漏洞/安全/漏洞）
#                     示例代码刻意与 manifest 样本不同，避免答案泄露
#   4. cot            在 zero_shot 基础上显式要求按 5 步思维链分析
#   5. combined       zero_shot + few_shot + cot 三合一
# ---------------------------------------------------------------------------
PROMPT_VARIANTS = ("zero_shot", "whitelist_only", "few_shot", "cot", "combined")


# Few-shot 示例：刻意选用与 manifest 样本不同的简短代码，避免答案泄露。
# 3 组示例覆盖：SQL 注入漏洞 → 参数化查询安全 → 命令注入漏洞
FEW_SHOT_EXAMPLES = """\
【示例 1（漏洞）】
代码：
```python
def auth(user, pwd):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + user + "' AND pwd='" + pwd + "'")
    return cur.fetchone()
```
分析：用户输入 user/pwd 通过字符串拼接直接进入 SQL 语句，未使用参数化查询。
结论：
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-89 SQL注入", "risk_level": "Critical", "source": "函数参数 user/pwd", "sink": "cur.execute 拼接 SQL", "explanation": "字符串拼接 SQL 允许注入", "fix_suggestion": "改用占位符参数化查询"}
```

【示例 2（安全）】
代码：
```python
def auth(user, pwd):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE name=? AND pwd=?", (user, pwd))
    return cur.fetchone()
```
分析：使用 ? 占位符 + 参数元组，是参数化查询标准写法，数据库驱动会自动转义。
结论：
```json
{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None", "source": "N/A", "sink": "N/A", "explanation": "参数化查询已正确防护", "fix_suggestion": "no fix needed"}
```

【示例 3（漏洞）】
代码：
```python
import os
def lookup(host):
    os.system("nslookup " + host)
```
分析：用户输入 host 直接拼接到 os.system 命令字符串，可注入 shell 元字符（如 ; rm -rf）。
结论：
```json
{"has_vulnerability": true, "vulnerability_type": "CWE-78 命令注入", "risk_level": "Critical", "source": "函数参数 host", "sink": "os.system 拼接命令", "explanation": "os.system 拼接用户输入可触发 shell 注入", "fix_suggestion": "改用 subprocess.run(['nslookup', host]) 列表形式"}
```
"""


# 思维链（CoT）分析步骤要求
COT_STEPS = """\
【分析步骤要求（必须逐步执行）】
请严格按以下 5 步分析后再下结论：
1. 识别代码中所有用户可控输入点（source），如 request.args / 函数参数 / 文件读取等。
2. 追踪这些输入的数据流，判断是否到达危险函数（sink），如 execute / system / open / pickle.loads 等。
3. 检查 source 到 sink 之间是否存在防御措施（参数化查询、白名单校验、转义、abspath+startswith 等）。
4. 若有防御措施，评估其是否有效（如参数化查询是有效的，简单 replace/strip 过滤通常无效）。
5. 综合以上分析得出最终结论，并在 JSON 中体现 source/sink/explanation 字段。
注意：分析过程必须真实展现上述步骤，不能跳步直接给结论。"""


def _build_whitelist_only_prompt() -> str:
    """变体 2：仅角色 + 白名单 + schema（去掉其他规则）。"""
    return (
        "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
        "判断其中是否存在安全漏洞。分析范围包括但不限于："
        + ANALYSIS_SCOPE
        + "。\n\n"
        + SAFE_PATTERN_WHITELIST
        + "\n\n在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
        "JSON 块用 ```json 包裹，字段如下（统一 schema，全项目一致）：\n"
        + format_schema_for_prompt()
        + "\n\n请先给出分析过程，然后在最后给出 JSON 结论。"
    )


def _build_few_shot_prompt() -> str:
    """变体 3：在 zero_shot 基础上加入 3 组 few-shot 示例。"""
    return (
        SYSTEM_PROMPT
        + "\n\n"
        + FEW_SHOT_EXAMPLES
    )


def _apply_cot_to_system_prompt(base: str) -> str:
    """把 SYSTEM_PROMPT 末尾的"请先给出分析过程..."替换为 CoT 步骤版本。

    内部辅助函数，供 _build_cot_prompt 与 _build_combined_prompt 复用。
    """
    cot_suffix = (
        "\n\n" + COT_STEPS
        + "\n\n请按上述步骤逐步分析，然后在最后给出 JSON 结论。"
    )
    old_tail = "请先给出分析过程，然后在最后给出 JSON 结论。"
    if old_tail in base:
        # 用 rfind 定位最后一次出现（避免与 user prompt 中相同文本冲突）
        idx = base.rfind(old_tail)
        return base[:idx] + cot_suffix
    return base + cot_suffix


def _build_cot_prompt() -> str:
    """变体 4：在 zero_shot 基础上加入 CoT 思维链要求。"""
    return _apply_cot_to_system_prompt(SYSTEM_PROMPT)


def _build_combined_prompt() -> str:
    """变体 5：zero_shot + few_shot + cot 三合一。

    构造顺序：把 SYSTEM_PROMPT 的尾部替换为 CoT 版本，再追加 few-shot 示例。
    这样既保留了 CoT 步骤要求，又保留了 few-shot 示例。
    """
    cot_system = _apply_cot_to_system_prompt(SYSTEM_PROMPT)
    return cot_system + "\n\n" + FEW_SHOT_EXAMPLES


def build_system_prompt_variant(variant: str) -> str:
    """根据变体名返回对应的 system prompt。

    Args:
        variant: 变体名，取值见 PROMPT_VARIANTS
            - zero_shot      完整版 SYSTEM_PROMPT（基线）
            - whitelist_only 仅白名单 + schema
            - few_shot       zero_shot + 3 组示例
            - cot            zero_shot + CoT 步骤要求
            - combined       zero_shot + few_shot + cot

    Returns:
        对应的 system prompt 字符串。未知 variant 抛 ValueError。
    """
    if variant == "zero_shot":
        return SYSTEM_PROMPT
    if variant == "whitelist_only":
        return _build_whitelist_only_prompt()
    if variant == "few_shot":
        return _build_few_shot_prompt()
    if variant == "cot":
        return _build_cot_prompt()
    if variant == "combined":
        return _build_combined_prompt()
    raise ValueError(f"未知 prompt 变体: {variant}（合法值: {PROMPT_VARIANTS}）")


def build_full_prompt_variant(
    variant: str,
    code: str,
    language: str = "python",
    filename: Optional[str] = None,
    rag_context: Optional[str] = None,
) -> str:
    """构建指定变体的完整单条 prompt（system + user 拼接）。

    供 exp_05_prompt_ablation 等消融实验使用。
    """
    system = build_system_prompt_variant(variant)
    user = build_user_prompt(
        code=code, language=language, filename=filename, rag_context=rag_context
    )
    return system + "\n\n" + user


if __name__ == "__main__":
    # 自检
    test_code = "cursor.execute(\"SELECT * FROM u WHERE name='\" + name + \"'\")"
    print("=== SYSTEM_PROMPT 预览（前 300 字）===")
    print(SYSTEM_PROMPT[:300] + "...")
    print(f"\n=== SYSTEM_PROMPT 总长度: {len(SYSTEM_PROMPT)} 字符 ===")
    print("\n=== build_full_prompt 预览 ===")
    print(build_full_prompt(test_code, "python", "demo.py"))

    # 自检：5 个变体
    print("\n=== 5 个 Prompt 变体长度对比 ===")
    for v in PROMPT_VARIANTS:
        sp = build_system_prompt_variant(v)
        print(f"  {v:15s}: {len(sp):5d} 字符")
