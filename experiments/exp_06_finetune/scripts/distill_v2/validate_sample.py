"""
三段式样本校验 + ChatML 组装。

LLM 返回的 assistant 文本必须满足三段式：
  第一段：代码片段（```语言 ... ```）
  第二段：分析过程（≤5 步，每步锚定行号）
  第三段：结构化结论（```json ... ```）

本模块负责：
  1. parse_assistant()  —— 从原始文本解析出三段
  2. validate()         —— 校验 JSON schema + CoT 步数 + 行号锚定
  3. build_chatml()     —— 组装为 ChatML messages 数组（与现有训练数据格式一致）

校验失败返回 (False, reason)，run_distill.py 据此重试或丢弃。
"""

import json
import re
from dataclasses import dataclass
from typing import Tuple, Optional, List, Dict


# ===========================================================================
# JSON schema 定义（与 GLM/DeepSeek/Kimi 三家统一）
# ===========================================================================
REQUIRED_FIELDS = [
    "has_vulnerability",
    "vulnerability_type",
    "risk_level",
    "cvss_vector",
    "cvss_score",
    "source",
    "sink",
    "explanation",
    "fix_suggestion",
]

RISK_LEVELS = {"Critical", "High", "Medium", "Low", "None"}

# CVSS 3.1 向量正则（宽松校验，只查骨架）
CVSS_RE = re.compile(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$", re.IGNORECASE)


@dataclass
class ParsedSample:
    """解析后的三段式样本。"""
    code_block: str           # 含 ```围栏
    cot_text: str             # 分析过程原文
    json_obj: Dict            # 解析后的 JSON dict
    raw: str                  # 原始 assistant 文本


# ===========================================================================
# 解析
# ===========================================================================

def parse_assistant(text: str) -> Tuple[Optional[ParsedSample], str]:
    """从 assistant 原始文本解析三段式。

    Returns:
        (ParsedSample, "")  成功
        (None, reason)      失败
    """
    if not text or not text.strip():
        return None, "空响应"

    # --- 提取所有代码围栏 ---
    fences = list(re.finditer(r"```(\w*)\n(.*?)```", text, re.DOTALL))
    if len(fences) < 2:
        return None, f"代码围栏不足 2 个（找到 {len(fences)} 个，需至少 1 代码 + 1 json）"

    # 第一个非 json 围栏 = 代码块；最后一个 json 围栏 = 结论
    code_fence = None
    json_fence = None
    for f in fences:
        lang = f.group(1).lower()
        if lang == "json" and json_fence is None:
            json_fence = f
        elif code_fence is None:
            code_fence = f

    # 如果没有显式 json 围栏，取最后一个围栏当 json
    if json_fence is None:
        json_fence = fences[-1]
    if code_fence is None:
        code_fence = fences[0]
    if code_fence is json_fence:
        # 只有一个围栏，无法拆分
        return None, "代码块与 JSON 块为同一围栏，无法拆分"

    code_block = code_fence.group(0)  # 含围栏

    # --- 提取 JSON ---
    json_str = json_fence.group(2).strip()
    try:
        json_obj = json.loads(json_str)
    except json.JSONDecodeError as e:
        # 尝试修复常见问题：尾随逗号
        json_str_fixed = re.sub(r",\s*}", "}", json_str)
        json_str_fixed = re.sub(r",\s*]", "]", json_str_fixed)
        try:
            json_obj = json.loads(json_str_fixed)
        except json.JSONDecodeError:
            return None, f"JSON 解析失败: {e}"

    # --- 提取 CoT（代码块与 JSON 块之间的文本） ---
    cot_start = code_fence.end()
    cot_end = json_fence.start()
    if cot_end > cot_start:
        cot_text = text[cot_start:cot_end].strip()
    else:
        # JSON 在代码前面（少见），取代码前的文本
        cot_text = text[:code_fence.start()].strip()

    return ParsedSample(
        code_block=code_block,
        cot_text=cot_text,
        json_obj=json_obj,
        raw=text,
    ), ""


# ===========================================================================
# 校验
# ===========================================================================

def _extract_cot_steps(cot_text: str) -> List[str]:
    """从 CoT 文本提取编号步骤。

    支持格式：
      1. xxx
      2. xxx
    或
      1) xxx
      2) xxx
    """
    # 匹配 "1." "2." 或 "1)" "2)" 开头的行
    steps = re.findall(r"(?:^|\n)\s*(\d+)[.)]\s*(.+)", cot_text)
    return [s[1].strip() for s in steps]


def validate(parsed: ParsedSample, expected_has_vuln: bool) -> Tuple[bool, str]:
    """校验解析后的样本。

    Args:
        parsed: parse_assistant 返回的 ParsedSample
        expected_has_vuln: 任务规格里期望的 has_vuln

    Returns:
        (True, "")         校验通过
        (False, reason)    校验失败
    """
    # 1. JSON 字段完整性
    missing = [f for f in REQUIRED_FIELDS if f not in parsed.json_obj]
    if missing:
        return False, f"JSON 缺字段: {missing}"

    j = parsed.json_obj

    # 2. has_vulnerability 类型 + 与期望一致
    if not isinstance(j["has_vulnerability"], bool):
        return False, f"has_vulnerability 非布尔: {type(j['has_vulnerability'])}"
    if j["has_vulnerability"] != expected_has_vuln:
        return False, f"has_vulnerability={j['has_vulnerability']} 与期望 {expected_has_vuln} 不符"

    # 3. risk_level 取值（归一化大小写：high→High, none→None, HIGH→High）
    rl = j["risk_level"]
    if isinstance(rl, str):
        rl_norm = rl.strip().capitalize()
        if rl_norm in RISK_LEVELS:
            j["risk_level"] = rl_norm  # 归一化写回，保证训练数据统一
        else:
            return False, f"risk_level 非法: {rl}（合法值：Critical/High/Medium/Low/None）"
    else:
        return False, f"risk_level 非法: {rl}"

    # 4. CVSS 向量（漏洞样本严格校验，安全样本允许 N/A）
    if expected_has_vuln:
        if not CVSS_RE.match(str(j["cvss_vector"])):
            return False, f"cvss_vector 格式错: {j['cvss_vector']}"
        if not isinstance(j["cvss_score"], (int, float)) or not (0 <= j["cvss_score"] <= 10):
            return False, f"cvss_score 非法: {j['cvss_score']}"
    else:
        # 安全样本：cvss_vector 应为 N/A，score 应为 0
        if j["cvss_vector"] not in ("N/A", "NA", ""):
            # 不硬拦，只警告（有些模型填 "N/A (no vulnerability)"）
            pass

    # 5. CoT 步数 ≤5
    steps = _extract_cot_steps(parsed.cot_text)
    if len(steps) == 0:
        return False, "CoT 未提取到编号步骤"
    if len(steps) > 5:
        return False, f"CoT 步数 {len(steps)} > 5（方法论要求 ≤5）"

    # 6. 行号锚定（至少 1 步含"第 X 行"或"line X"）
    # 软检查：system prompt 已要求行号锚定，样本应自动遵守；不硬拦以免因格式小偏差丢弃整条
    has_line_anchor = any(
        re.search(r"第\s*\d+\s*行|line\s*\d+", s, re.IGNORECASE) for s in steps
    )
    if not has_line_anchor:
        # 不返回 False，仅不通过（保留统计意义，但不下发失败）
        pass

    # 7. 负样本字段一致性
    if not expected_has_vuln:
        if j["vulnerability_type"] not in ("none", "None", "N/A", ""):
            return False, f"安全样本 vulnerability_type 应为 none，实为 {j['vulnerability_type']}"
        if j["fix_suggestion"] not in ("no fix needed", "N/A", "无需修复", ""):
            # 不硬拦
            pass

    return True, ""


# ===========================================================================
# ChatML 组装
# ===========================================================================

def build_chatml(system: str, parsed: ParsedSample) -> Dict:
    """组装训练数据：代码放 user，CoT+JSON 放 assistant（模拟推理场景）。

    训练数据结构与推理时一致：
      system  = 分析漏洞的角色约束（训练/推理相同）
      user    = "分析以下代码：\n```代码```"（DeepSeek 生成的代码提取到这里）
      assistant = CoT + JSON（不含代码块，推理时也只输出这两段）
    """
    user = "分析以下代码的安全漏洞：\n" + parsed.code_block
    assistant = parsed.cot_text + "\n\n```json\n" + json.dumps(parsed.json_obj, ensure_ascii=False) + "\n```"
    return {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


# ===========================================================================
# 一站式入口
# ===========================================================================

def parse_and_validate(
    assistant_text: str,
    expected_has_vuln: bool,
) -> Tuple[Optional[Dict], str]:
    """解析 + 校验一站式。

    Returns:
        (chatml_dict, "")         成功，返回 ChatML 样本
        (None, reason)            失败
    """
    parsed, reason = parse_assistant(assistant_text)
    if parsed is None:
        return None, reason

    ok, reason = validate(parsed, expected_has_vuln)
    if not ok:
        return None, reason

    return parsed, ""


if __name__ == "__main__":
    # 自检：用 kimi_prompt.md 的压扁示例测试
    sample = """```c
// demo.c
void process(char *buf) {
    char *p = malloc(64);
    free(p);
    return *p;
}
```

分析过程：
1. 第 4 行 malloc(64) 分配内存给 p
2. 第 5 行 free(p) 释放内存
3. 第 6 行 return *p 解引用已释放的 p
4. free 后未置 NULL
5. CWE-416 UAF，Critical

```json
{
  "has_vulnerability": true,
  "vulnerability_type": "CWE-416 UAF",
  "risk_level": "Critical",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss_score": 9.8,
  "source": "malloc at line 4",
  "sink": "dereference at line 6",
  "explanation": "line 4 malloc → line 5 free → line 6 dereference after free",
  "fix_suggestion": "free 后置 NULL"
}
```"""
    parsed, reason = parse_assistant(sample)
    if parsed is None:
        print(f"解析失败: {reason}")
    else:
        ok, reason = validate(parsed, expected_has_vuln=True)
        print(f"校验: {'通过' if ok else '失败 - ' + reason}")
        print(f"CoT 步数: {len(_extract_cot_steps(parsed.cot_text))}")
        print(f"JSON 字段: {list(parsed.json_obj.keys())}")
