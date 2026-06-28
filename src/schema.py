"""
统一输出 schema —— 全项目所有实验脚本必须使用此 schema 解析模型结论。

模型在分析代码漏洞后，必须在回答末尾输出一个 ```json``` 包裹的 JSON 对象，
字段定义见 VERDICT_SCHEMA。本模块提供：
- VERDICT_SCHEMA：字段定义字典（唯一来源）
- format_schema_for_prompt()：把 schema 渲染成 prompt 用的字段说明文本
- parse_verdict()：从模型原始输出中抽取 JSON 结论
- normalize_has_vulnerability()：把 has_vulnerability 字段归一化为 bool
"""

import json
import re
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 统一 schema 定义（全项目唯一来源）
# ---------------------------------------------------------------------------
VERDICT_SCHEMA: dict[str, str] = {
    "has_vulnerability": "bool, true 表示存在漏洞，false 表示未发现漏洞",
    "vulnerability_type": "str, CWE 编号 + 中文名；无漏洞填 'none'",
    "risk_level": "str, Critical/High/Medium/Low；无漏洞填 'None'",
    "source": "str, 污染来源（用户可控输入点）；无漏洞填 'N/A'",
    "sink": "str, 危险函数或触发点；无漏洞填 'N/A'",
    "explanation": "str, 漏洞或安全现状说明",
    "fix_suggestion": "str, 修复建议；无漏洞填 'no fix needed'",
}


def format_schema_for_prompt() -> str:
    """把 VERDICT_SCHEMA 渲染成 prompt 用的字段说明文本（多行字符串）。

    供所有 prompt 模板复用，确保 schema 说明全项目一致，避免重复维护。
    """
    lines = []
    for field, desc in VERDICT_SCHEMA.items():
        lines.append(f"   - {field}: {desc}")
    return "\n".join(lines)


def normalize_has_vulnerability(value: Any) -> Optional[bool]:
    """把 has_vulnerability 字段的各种形式归一化为 bool。

    支持 bool / "true"/"false" / "yes"/"no" / "1"/"0"；无法识别返回 None。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


def parse_verdict(raw_output: str) -> dict:
    """从模型输出中抽取最后的 JSON 结论（统一 schema）。

    优先匹配 ```json ... ``` 代码块；兜底匹配含 has_vulnerability 字段的 JSON 片段。
    解析失败返回空 dict。
    """
    if not raw_output:
        return {}

    # 优先匹配 ```json ... ``` 代码块
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", raw_output, re.DOTALL)
    # 兜底：含 has_vulnerability 字段的任意 JSON 片段
    candidates = blocks if blocks else re.findall(
        r"\{[^{}]*\"has_vulnerability\"[^{}]*\}", raw_output, re.DOTALL
    )
    for cand in candidates[-1:] if candidates else []:
        try:
            parsed = json.loads(cand)
            if "has_vulnerability" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue

    # 最后兜底：扫描所有完整 { ... } 片段
    for match in re.finditer(r"\{[^{}]*\}", raw_output, re.DOTALL):
        try:
            parsed = json.loads(match.group(0))
            if "has_vulnerability" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    return {}


if __name__ == "__main__":
    # 自检：schema 渲染 + 解析
    print("=== schema 字段说明 ===")
    print(format_schema_for_prompt())
    print("\n=== parse_verdict 自检 ===")
    sample = '分析过程...\n```json\n{"has_vulnerability": true, "vulnerability_type": "CWE-89 SQL注入"}\n```'
    v = parse_verdict(sample)
    print("解析结果:", v)
    print("归一化:", normalize_has_vulnerability(v.get("has_vulnerability")))
