"""
统一 Prompt 模板 —— 全项目所有漏洞分析调用必须使用本模块的构建函数。

提供三种复用粒度：
- SYSTEM_PROMPT：角色 + 分析范围 + schema 字段说明 + 输出要求（system 字段用）
- build_user_prompt()：代码块 + 可选 RAG 上下文 + 收尾（user prompt）
- build_full_prompt()：SYSTEM_PROMPT + user prompt 拼接（给不用 system 字段的单 prompt 调用用）

schema 字段说明通过 src.schema.format_schema_for_prompt() 渲染，确保全项目一致。
"""

from typing import Optional

from src.schema import format_schema_for_prompt


# ---------------------------------------------------------------------------
# 分析范围（统一文本，避免各处不一致）
# ---------------------------------------------------------------------------
ANALYSIS_SCOPE = (
    "SQL 注入、跨站脚本（XSS）、命令注入、路径穿越、"
    "硬编码敏感信息（密钥/密码/Token）、不安全的反序列化等"
)

# ---------------------------------------------------------------------------
# System Prompt：角色 + 分析范围 + schema + 输出要求
# 复用于 llm_client.analyze_vulnerability 的 system 字段，以及 build_full_prompt。
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "你是一名资深的代码安全审计专家。请对给出的代码片段进行安全分析，"
    "判断其中是否存在安全漏洞。分析范围包括但不限于："
    + ANALYSIS_SCOPE
    + "。\n\n"
    "要求：\n"
    "1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。\n"
    "2. 不要夸大风险，也不要遗漏明显的漏洞。\n"
    "3. 在回答的最后，必须严格输出一个 JSON 对象作为最终结论，"
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
            f"\n【相关知识参考】\n{rag_context}\n"
            f"请结合以上知识，更准确地分析代码漏洞。"
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
    print("\n=== build_full_prompt 预览 ===")
    print(build_full_prompt(test_code, "python", "demo.py"))
