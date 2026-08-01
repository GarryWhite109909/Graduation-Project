"""分层审查共享工具模块。

提供所有 L1-L4 审查层共用的工具函数：
  - 样本解析（jsonl 读写）
  - CoT 提取与统计
  - verdict JSON 提取与校验
  - CWE 合法性检查
  - metadata 提取
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


# ============================================================
# CWE 合法编号集合（覆盖项目 + 文档涉及的所有 CWE）
# ============================================================
VALID_CWE_SET = {
    # 注入类
    "CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-88", "CWE-89", "CWE-90",
    "CWE-94", "CWE-95", "CWE-113", "CWE-117", "CWE-134", "CWE-643",
    "CWE-917", "CWE-943", "CWE-1336",
    # 路径与资源
    "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-215",
    "CWE-276", "CWE-601", "CWE-732", "CWE-749", "CWE-1188",
    # 访问控制
    "CWE-287", "CWE-306", "CWE-384", "CWE-441", "CWE-639", "CWE-862", "CWE-863",
    # 密码学
    "CWE-208", "CWE-326", "CWE-327", "CWE-329", "CWE-330", "CWE-347", "CWE-798",
    # 内存与缓冲区
    "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-190", "CWE-367", "CWE-415",
    "CWE-416", "CWE-476", "CWE-787", "CWE-788",
    # 反序列化与 XML
    "CWE-502", "CWE-611", "CWE-610",
    # 并发与逻辑
    "CWE-362", "CWE-843", "CWE-915", "CWE-1321",
    # Web 与信息
    "CWE-79", "CWE-352", "CWE-532", "CWE-912", "CWE-918",
    # 其他
    "CWE-107", "CWE-745",
    # v9 数据审计补充（L1 首次运行发现的合法 CWE）
    "CWE-73", "CWE-98", "CWE-123", "CWE-209", "CWE-319", "CWE-338",
    "CWE-400", "CWE-409", "CWE-434", "CWE-613", "CWE-770", "CWE-916",
    "CWE-1333",
}


# ============================================================
# jsonl 读写
# ============================================================
def read_jsonl(path: Path | str) -> list[dict]:
    """读取 jsonl 文件，返回 dict 列表。"""
    path = Path(path)
    samples = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError as e:
                    samples.append({"_parse_error": str(e), "_raw": line})
    return samples


def write_jsonl(path: Path | str, samples: Iterable[dict]) -> int:
    """写入 jsonl 文件，返回写入条数。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
            count += 1
    return count


# ============================================================
# 样本结构提取
# ============================================================
def get_assistant_content(sample: dict) -> str:
    """提取 assistant 消息内容。"""
    for m in sample.get("messages", []):
        if m.get("role") == "assistant":
            return m.get("content", "")
    return ""


def get_user_content(sample: dict) -> str:
    """提取 user 消息内容（代码片段）。"""
    for m in sample.get("messages", []):
        if m.get("role") == "user":
            return m.get("content", "")
    return ""


def get_metadata(sample: dict) -> dict:
    """提取 metadata 字段（生成器标记）。"""
    return sample.get("metadata", {})


def extract_cot(assistant_content: str) -> str:
    """提取 assistant 响应中 JSON 之前的 CoT 部分。"""
    match = re.search(r"```json\s*\{", assistant_content)
    if match:
        return assistant_content[: match.start()].strip()
    matches = list(re.finditer(r'\{\s*"has_vulnerability"', assistant_content))
    if matches:
        return assistant_content[: matches[-1].start()].strip()
    return assistant_content.strip()


def extract_verdict(assistant_content: str) -> dict | None:
    """提取 verdict JSON 对象。返回 None 表示无法解析。"""
    match = re.search(r"```json\s*(\{.*?\})\s*```", assistant_content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    matches = re.findall(r'\{\s*"has_vulnerability".*?\}', assistant_content, re.DOTALL)
    for m in reversed(matches):
        try:
            return json.loads(m)
        except json.JSONDecodeError:
            continue
    return None


# ============================================================
# CoT 统计
# ============================================================
def count_reasoning_steps(cot: str) -> int:
    """统计显式编号的推理步数。"""
    numbered = re.findall(r"(?:^|\n)\s*(\d+)[\.\)、]", cot)
    step_kw = re.findall(r"步骤\s*(\d+)", cot)
    chinese_num = "一二三四五六七八九十"
    chinese_steps = re.findall(r"第([{}])步".format(chinese_num), cot)
    return max(len(numbered), len(step_kw), len(chinese_steps))


def estimate_tokens(text: str) -> float:
    """粗略估算 token 数（中英混合代码约 2.5 字符/token）。"""
    return len(text) / 2.5 if text else 0.0


# ============================================================
# CWE 提取与校验
# ============================================================
def extract_cwe_list(vulnerability_type: str) -> list[str]:
    """从 vulnerability_type 字段提取 CWE 编号列表。

    示例输入: "CWE-1336; CWE-94 SSTI模板注入"
    示例输出: ["CWE-1336", "CWE-94"]
    """
    if not vulnerability_type or vulnerability_type == "none":
        return []
    return re.findall(r"CWE-\d+", vulnerability_type)


def is_valid_cwe(cwe: str) -> bool:
    """检查 CWE 编号是否在合法集合内。"""
    return cwe in VALID_CWE_SET


# ============================================================
# 代码行数统计（用于行号校验）
# ============================================================
def get_code_line_count(user_content: str) -> int:
    """从 user 消息中提取代码块并返回行数。"""
    code_blocks = re.findall(r"```(?:\w+)?\s*\n(.*?)```", user_content, re.DOTALL)
    if code_blocks:
        return code_blocks[0].count("\n") + 1
    return user_content.count("\n") + 1


def extract_cited_lines(cot: str) -> list[int]:
    """提取 CoT 中引用的行号（如"第 42 行"、"line 42"、":42"）。"""
    lines = []
    # "第 42 行" / "第42行"
    lines.extend(int(m) for m in re.findall(r"第\s*(\d+)\s*行", cot))
    # "line 42" / "Line 42"
    lines.extend(int(m) for m in re.findall(r"[Ll]ine\s+(\d+)", cot))
    # "L42"
    lines.extend(int(m) for m in re.findall(r"(?<![A-Za-z])L(\d+)\b", cot))
    return lines
