"""
训练数据修复脚本 v2 → v3。

修复规则：
  1. NoSQL 注入 CWE 统一（CWE-643 → CWE-943 / 保持 / → CWE-94）
  2. SSTI CWE 统一（CWE-94 + 模板标志 → CWE-1336）
  3. eval() 注入 CWE 统一（CWE-94 + eval( → CWE-95）
  4. CoT-vs-JSON 一致性修复
  5. 标记模板化 CoT（只记录到报告，不修改数据）

用法：
  cd <project_root>
  python3 \
      experiments/exp_06_finetune/scripts/fix_train_data_v3.py --dry-run
  python3 \
      experiments/exp_06_finetune/scripts/fix_train_data_v3.py
"""

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
INPUT_FILE = DATA_DIR / "train_chatml_v2.jsonl"
OUTPUT_FILE = DATA_DIR / "train_chatml_v3.jsonl"
REPORT_FILE = DATA_DIR / "fix_report.json"

# 规则 2：SSTI 模板标志
SSTI_FLAGS = [
    "render_template_string", "Template(", "jinja2", "Jinja2",
    "mako", "django_template", "ejs", "pug", "thymeleaf",
    "velocity", "freemarker", "MakoTemplate", "Environment(",
]

# 规则 5：模板化 CoT 短语
TEMPLATE_COT_PHRASES = [
    "无有效防御措施（无参数化、无转义、无校验）",
    "无参数化、无转义、无校验",
    "输入检查：识别代码中的用户输入点与处理逻辑",
    "sink 评估：N/A",
    "防御确认：N/A",
]

# CWE 标签映射（用于 rule 4 非批次场景的标签构造）
CWE_LABELS = {
    "CWE-1336": "SSTI",
    "CWE-943": "NoSQL注入",
    "CWE-643": "XPath注入",
    "CWE-94": "代码注入",
    "CWE-95": "eval注入",
    "CWE-917": "表达式注入",
    "CWE-89": "SQL注入",
    "CWE-78": "命令注入",
}


def extract_code(user_content: str) -> str:
    """从 user content 中提取 ```language ... ``` 之间的代码。"""
    m = re.search(r"```[a-zA-Z]*\n(.*?)\n```", user_content, re.DOTALL)
    return m.group(1) if m else ""


def extract_filename(user_content: str) -> str:
    """从 user content 中提取文件名。"""
    m = re.search(r"文件名:\s*([^，,\s]+)", user_content)
    return m.group(1) if m else ""


def extract_json_block(assistant_content: str) -> str:
    """提取 assistant content 中的 ```json ... ``` 块内容。"""
    m = re.search(r"```json\n(.*?)\n```", assistant_content, re.DOTALL)
    return m.group(1) if m else ""


def extract_cot_text(assistant_content: str) -> str:
    """提取 CoT 文本（```json 之前的部分，含尾部空白）。"""
    idx = assistant_content.find("```json")
    if idx == -1:
        return assistant_content
    return assistant_content[:idx]


def extract_cwe_number(vuln_type: str) -> str:
    """从 vulnerability_type 提取 CWE 编号（如 CWE-94）。"""
    m = re.search(r"(CWE-\d+)", vuln_type)
    return m.group(1) if m else ""


def extract_determined_cwe(cot_text: str) -> tuple:
    """从 CoT 文本中提取确定的 CWE 编号和标签。

    返回 (cwe_number, label)，如 ("CWE-94", "代码注入")。
    优先匹配 "确定 CWE-X（label）"，其次 "存在 CWE-X label"。
    找不到明确模式时返回 ("", "")，避免误取被排除的 CWE。
    """
    # 优先：确定 CWE-94（代码注入）
    m = re.search(r"确定\s*(CWE-\d+)（([^）]*)）", cot_text)
    if m:
        return m.group(1), m.group(2)
    # 其次：存在 CWE-1336 SSTI / 存在 CWE-89 SQL注入（标签遇标点截断）
    m = re.search(r"(?<!不)存在\s*(CWE-\d+)\s*([^\s，,。：:]+)", cot_text)
    if m:
        return m.group(1), m.group(2)
    return "", ""


def apply_rules_1_3(vuln_type: str, code: str) -> tuple:
    """应用规则 1-3，返回 (new_vuln_type, rule_name)。

    无修改时返回 (vuln_type, None)。
    """
    if not vuln_type or vuln_type == "none":
        return vuln_type, None

    # 规则 1：CWE-643
    if "CWE-643" in vuln_type:
        if any(kw in code for kw in ["mongo", "MongoDB", "$where", "find_one", "pymongo", "aggregate"]):
            return "CWE-943 NoSQL注入", "rule1_nosql"
        if any(kw in code for kw in ["xpath", "xpath_eval", "lxml.xpath"]):
            return vuln_type, None  # 保持 CWE-643 XPath注入
        if any(kw in code for kw in ["redis", "EVAL", "redis-cli"]):
            return "CWE-94 代码注入", "rule1_nosql"
        return vuln_type, None

    # 规则 2-3：CWE-94
    if "CWE-94" in vuln_type:
        has_ssti_flag = any(flag in code for flag in SSTI_FLAGS)
        has_eval = "eval(" in code
        if has_ssti_flag:
            return "CWE-1336 SSTI", "rule2_ssti"
        if has_eval:
            return "CWE-95 eval注入", "rule3_eval"
        # exec( 或无匹配 → 保持 CWE-94 代码注入
        return vuln_type, None

    return vuln_type, None


def update_cot_determined_cwe(cot_text: str, old_cwe_num: str, new_vuln_type: str) -> str:
    """在 CoT 中把 "确定 CWE-{old}（...）" 替换为 "确定 CWE-{new}（{new_label}）"。"""
    new_cwe_num = extract_cwe_number(new_vuln_type)
    new_label = new_vuln_type.replace(new_cwe_num, "").strip()
    pattern = rf"确定\s*{re.escape(old_cwe_num)}（[^）]*）"
    replacement = f"确定 {new_cwe_num}（{new_label}）"
    return re.sub(pattern, replacement, cot_text, count=1)


def replace_vuln_type_in_json_block(json_block: str, new_vuln_type: str) -> str:
    """在 JSON 块文本中替换 vulnerability_type 的值（保持其余格式不变）。"""
    return re.sub(
        r'("vulnerability_type":\s*")[^"]*(")',
        rf"\1{new_vuln_type}\2",
        json_block,
        count=1,
    )


def is_template_cot(assistant_content: str) -> bool:
    """检测是否含模板化 CoT 短语。"""
    return any(phrase in assistant_content for phrase in TEMPLATE_COT_PHRASES)


def process_sample(line_num: int, record: dict) -> tuple:
    """处理单条样本。

    返回 (new_record, fixes, template_cot_info)：
      - fixes: [{line, filename, old_cwe, new_cwe, rule}] 列表
      - template_cot_info: None 或 {line, filename, is_vuln, vulnerability_type}
    """
    messages = record.get("messages", [])
    if len(messages) < 3:
        return record, [], None

    # 浅拷贝，避免修改原始 record
    new_record = {"messages": [dict(m) for m in messages]}
    new_messages = new_record["messages"]

    user_content = messages[1].get("content", "")
    assistant_content = messages[2].get("content", "")

    code = extract_code(user_content)
    filename = extract_filename(user_content)
    json_block = extract_json_block(assistant_content)
    cot_text = extract_cot_text(assistant_content)

    # 无法提取 JSON 块时只做模板检测
    if not json_block:
        template_info = None
        if is_template_cot(assistant_content):
            template_info = {
                "line": line_num,
                "filename": filename,
                "is_vuln": None,
                "vulnerability_type": "",
            }
        return new_record, [], template_info

    try:
        verdict = json.loads(json_block)
    except json.JSONDecodeError:
        return new_record, [], None

    old_vuln_type = verdict.get("vulnerability_type", "none")
    is_vuln = verdict.get("has_vulnerability", False)

    fixes = []
    current_vuln_type = old_vuln_type
    current_json_block = json_block
    current_cot = cot_text
    modified = False

    # ---- 规则 1-3 ----
    new_vuln_type, rule_name = apply_rules_1_3(current_vuln_type, code)
    if rule_name and new_vuln_type != current_vuln_type:
        fixes.append({
            "line": line_num,
            "filename": filename,
            "old_cwe": current_vuln_type,
            "new_cwe": new_vuln_type,
            "rule": rule_name,
        })
        current_vuln_type = new_vuln_type
        current_json_block = replace_vuln_type_in_json_block(current_json_block, new_vuln_type)
        modified = True

    # ---- 规则 4：CoT-vs-JSON 一致性 ----
    cot_cwe_num, cot_label = extract_determined_cwe(current_cot)
    json_cwe_num = extract_cwe_number(current_vuln_type)
    is_batch = any(prefix in filename for prefix in ["ssti_", "nosql_", "spel_"])

    if cot_cwe_num and json_cwe_num and cot_cwe_num != json_cwe_num:
        if is_batch:
            # 批次样本：保留 JSON CWE（规则 1-3 已修复），更新 CoT
            new_cot = update_cot_determined_cwe(current_cot, cot_cwe_num, current_vuln_type)
            if new_cot != current_cot:
                fixes.append({
                    "line": line_num,
                    "filename": filename,
                    "old_cwe": cot_cwe_num,
                    "new_cwe": json_cwe_num,
                    "rule": "rule4_cot_consistency",
                })
                current_cot = new_cot
                modified = True
        elif not modified:
            # 非批次样本且规则 1-3 未修改：把 JSON 改为 CoT 中最具体的 CWE
            # （规则 1-3 已修改的样本以代码分析为准，不被 CoT 覆盖）
            label = cot_label or CWE_LABELS.get(cot_cwe_num, "")
            new_vt = f"{cot_cwe_num} {label}" if label else cot_cwe_num
            if new_vt != current_vuln_type:
                fixes.append({
                    "line": line_num,
                    "filename": filename,
                    "old_cwe": current_vuln_type,
                    "new_cwe": new_vt,
                    "rule": "rule4_cot_consistency",
                })
                current_vuln_type = new_vt
                current_json_block = replace_vuln_type_in_json_block(current_json_block, new_vt)
                modified = True

    # 重建 assistant content
    if modified:
        new_messages[2]["content"] = current_cot + "```json\n" + current_json_block + "\n```"

    # ---- 规则 5：模板化 CoT 检测（只记录，不修改） ----
    template_info = None
    if is_template_cot(assistant_content):
        template_info = {
            "line": line_num,
            "filename": filename,
            "is_vuln": is_vuln,
            "vulnerability_type": current_vuln_type,
        }

    return new_record, fixes, template_info


def main():
    parser = argparse.ArgumentParser(description="修复训练数据 v2 → v3")
    parser.add_argument("--dry-run", action="store_true",
                        help="只输出报告，不写 v3 文件")
    args = parser.parse_args()

    if not INPUT_FILE.exists():
        print(f"错误：输入文件不存在: {INPUT_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(INPUT_FILE, encoding="utf-8") as f:
        lines = f.readlines()

    samples = []
    for i, line in enumerate(lines, 1):
        if line.strip():
            try:
                samples.append((i, json.loads(line)))
            except json.JSONDecodeError as e:
                print(f"⚠️ 第 {i} 行 JSON 解析失败: {e}", file=sys.stderr)

    total = len(samples)
    print(f"读取样本: {total} 条")

    output_samples = []
    fixed_details = []
    template_cot_samples = []
    fixes_by_rule = {
        "rule1_nosql": 0,
        "rule2_ssti": 0,
        "rule3_eval": 0,
        "rule4_cot_consistency": 0,
    }
    fixed_lines = set()

    for line_num, record in samples:
        new_record, fixes, template_info = process_sample(line_num, record)
        output_samples.append(new_record)

        for fix in fixes:
            fixed_details.append(fix)
            fixes_by_rule[fix["rule"]] = fixes_by_rule.get(fix["rule"], 0) + 1
            fixed_lines.add(line_num)

        if template_info:
            template_cot_samples.append(template_info)

    fixed_samples = len(fixed_lines)

    report = {
        "total_samples": total,
        "fixed_samples": fixed_samples,
        "fixes_by_rule": fixes_by_rule,
        "fixed_details": fixed_details,
        "template_cot_samples": template_cot_samples,
    }

    # 打印摘要
    print(f"\n{'=' * 50}")
    print(f"修复报告摘要")
    print(f"{'=' * 50}")
    print(f"总样本数: {total}")
    print(f"修复样本数: {fixed_samples}")
    print(f"按规则分类:")
    for rule, count in fixes_by_rule.items():
        print(f"  {rule}: {count}")
    print(f"模板化 CoT 样本: {len(template_cot_samples)}")

    print(f"\n前 30 条修复详情:")
    for d in fixed_details[:30]:
        print(f"  行 {d['line']:>3} {d['filename']:<40} {d['old_cwe']:<20} → {d['new_cwe']:<20} ({d['rule']})")

    if args.dry_run:
        print(f"\n[Dry-run] 仅输出报告，不写 v3 文件。")
        return

    # 写入 v3 文件
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for rec in output_samples:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 写入报告
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"已写入: {REPORT_FILE}")


if __name__ == "__main__":
    main()
