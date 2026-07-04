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
1. SQL 注入防护：
   - 参数化查询 / 占位符 + 参数元组：cursor.execute("SELECT ... WHERE id = ?", (user_id,))
     关键：? / %s / :name 是 SQL 占位符，参数元组中的值会被数据库驱动自动转义，
     不会进入 SQL 语法层。**这不是字符串拼接**，是参数化查询的标准写法。
   - ORM 查询构造器：Model.objects.filter(name=q) / session.query(User).filter_by(name=q)
   - 注意：query = "SELECT ... WHERE id = ?"; cursor.execute(query, (user_id,)) 也是参数化查询，
     即使 SQL 字符串先赋值给变量再传入 execute，依然安全。
2. 命令注入防护：
   - subprocess.run/Popen 列表参数 + 未启用 shell：subprocess.run(["cmd", "arg1", arg2])
     关键：Python 文档明确规定 subprocess.run/Popen 的 shell 参数**默认值为 False**。
     **不显式写 shell=True 就是 shell=False**，这是 Python 语言事实，不是"未设置"。
     列表形式 + shell=False 时，元字符被当作普通字符传递给程序，不会触发 shell 解释，
     即使用户输入作为参数也是安全的。
   - 严禁以"没有显式设置 shell=False"为由判漏洞——这是对 Python 语义的误解。
   - 严禁捏造代码中不存在的 shell=True：判定前必须确认代码中确实出现 shell=True 才能据此判漏洞。
   - shlex.quote() 对拼接场景做转义：cmd = "grep " + shlex.quote(keyword)
   - 输入白名单校验（isalnum / 正则白名单）后 再进入命令参数
3. 路径穿越防护：
   - os.path.abspath 规范化 + startswith 校验是否在允许目录内
   - 白名单文件名集合：if filename not in ALLOWED_FILES: abort(403)
4. XSS 防护：
   - HTML 模板自动转义（Jinja2 autoescape=True、Django 模板默认转义）
   - 显式调用 html.escape() / htmlspecialchars(..., ENT_QUOTES, 'UTF-8')
   - 使用 textContent 而非 innerHTML
5. 反序列化防护：
   - json.loads 替代 pickle.loads
   - yaml.safe_load 替代 yaml.load
   - hmac 签名校验 + 白名单类反序列化
判断要点：以上模式只要使用得当，用户可控输入进入 sink 也是安全的。不要因为"用户输入到达 sink"就一律判漏洞，必须看 sink 之前的防御措施是否有效。"""

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


if __name__ == "__main__":
    # 自检
    test_code = "cursor.execute(\"SELECT * FROM u WHERE name='\" + name + \"'\")"
    print("=== SYSTEM_PROMPT 预览（前 300 字）===")
    print(SYSTEM_PROMPT[:300] + "...")
    print(f"\n=== SYSTEM_PROMPT 总长度: {len(SYSTEM_PROMPT)} 字符 ===")
    print("\n=== build_full_prompt 预览 ===")
    print(build_full_prompt(test_code, "python", "demo.py"))
