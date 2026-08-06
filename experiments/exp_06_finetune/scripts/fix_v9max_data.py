"""v9max 训练数据修复脚本。

修复两类问题：
1. 标签不一致（30 条）：has_vulnerability=False 但 vulnerability_type != 'none'
   → 强制归一化为负样本 schema
2. 确认误报（正则实际有效但 CoT 声称被绕过）：
   → 转为负样本，重写 CoT 说明正则防御有效

用法：
  python3 fix_v9max_data.py --input data/final_train_chatml_v3.jsonl --output data/final_train_chatml_v4_clean.jsonl
  python3 fix_v9max_data.py --input ... --dry-run  # 只报告，不写文件
"""
import argparse
import json
import re
import shutil
from pathlib import Path


def fix_label_inconsistency(record):
    """修复标签不一致：has_vulnerability=False 但字段非负样本 schema。

    返回 (修复后的 record, 是否修改)。
    """
    msgs = record["messages"]
    asst = msgs[2]["content"]
    blocks = re.findall(r'```json\s*(.*?)\s*```', asst, re.DOTALL)
    if not blocks:
        return record, False
    try:
        j = json.loads(blocks[-1])
    except Exception:
        return record, False

    if j.get("has_vulnerability") is not False:
        return record, False

    # 检查是否不一致
    vt = str(j.get("vulnerability_type", ""))
    rl = j.get("risk_level")
    needs_fix = False
    if vt.lower() != "none":
        needs_fix = True
    if rl != "None" and rl is not None:
        needs_fix = True
    # risk_level 是 Python None（不是字符串 'None'）
    if rl is None:
        needs_fix = True

    if not needs_fix:
        return record, False

    # 修复 JSON
    j_fixed = {
        "has_vulnerability": False,
        "vulnerability_type": "none",
        "risk_level": "None",
        "source": "N/A",
        "sink": "N/A",
        "explanation": "N/A",
        "fix_suggestion": "no fix needed",
    }
    # 保留 cvss 字段（如果有）但归一化
    if "cvss_vector" in j:
        j_fixed["cvss_vector"] = "N/A"
    if "cvss_score" in j:
        j_fixed["cvss_score"] = 0.0

    new_json = json.dumps(j_fixed, ensure_ascii=False)
    new_block = f"```json\n{new_json}\n```"

    # 替换最后一个 json block
    parts = asst.rsplit('```json', 1)
    if len(parts) == 2:
        # 去掉旧的 json 内容和结尾的 ```
        old_content = parts[1]
        # 找到闭合的 ```
        close_idx = old_content.rfind('```')
        if close_idx >= 0:
            new_asst = parts[0] + new_block
        else:
            new_asst = parts[0] + new_block
    else:
        new_asst = asst + "\n" + new_block

    record_fixed = dict(record)
    record_fixed["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
    return record_fixed, True


def detect_regex_false_positive(record):
    """检测正则误报：CoT 明确声称锚定正则被绕过，但正则实际有效。

    返回 (line_no, regex_pattern, claimed_payload, is_false_positive) 或 None。
    """
    user = record["messages"][1]["content"]
    asst = record["messages"][2]["content"]
    blocks = re.findall(r'```json\s*(.*?)\s*```', asst, re.DOTALL)
    if not blocks:
        return None
    try:
        j = json.loads(blocks[-1])
    except Exception:
        return None
    if j.get("has_vulnerability") is not True:
        return None

    code_match = re.search(r'```(\w+)\n(.*?)```', user, re.DOTALL)
    if not code_match:
        return None
    code = code_match.group(2)

    # 找严格锚定正则：^[字符类]+$
    strict_regexes = []
    # JS 风格: /^[chars]+$/
    for m in re.finditer(r'/\^(\[[^\]]+\])\+\$/', code):
        strict_regexes.append('^' + m.group(1) + '+$')
    # Python/通用风格: "^[chars]+$" 或 '^[chars]+$'
    for m in re.finditer(r'["\'](\^\[[^\]]+\]\+\$)["\']', code):
        pat = m.group(1)
        if pat not in strict_regexes:
            strict_regexes.append(pat)

    if not strict_regexes:
        return None

    # 检查 CoT 是否明确声称"正则被绕过/允许"
    cot = asst.split('```json')[0]
    bypass_patterns = [
        r'正则.{0,30}(允许|通过|可被绕过|可绕过|无效|形同虚设|未识别)',
        r'(允许|通过).{0,20}正则',
        r'校验.{0,20}(可被绕过|可绕过|无效|形同虚设)',
        r'正则.{0,30}只.{0,10}未',
        r'正则.{0,30}不.{0,10}(拦截|阻止|过滤)',
    ]
    bypass_claim = any(re.search(pat, cot) for pat in bypass_patterns)
    if not bypass_claim:
        return None

    # 检查是否说"另一个参数无校验"（如果是，则不是误报）
    # 注意：只匹配明确说"另一个参数/变量无校验"的情况，不匹配"而"这种通用连接词
    has_other_param = bool(re.search(
        r'(另一.{0,10}(参数|变量|输入|字段)|其他.{0,10}(参数|变量|输入|字段)|未校验.{0,20}(参数|变量|输入|字段)|无校验.{0,20}(参数|变量|输入|字段)|未经过.{0,20}(参数|变量|输入|字段)|无任何.{0,20}(校验|过滤|验证))',
        cot))

    if has_other_param:
        return None  # 漏洞在另一个参数，不是误报

    # 提取声称能通过正则的 payload
    claimed_payloads = []
    # 模式 1: "如/为/传入 + payload"（引号/反引号包裹）
    for m in re.finditer(r'(?:如|例如|传入|构造|为|设置|发送)[：\s]*[`"\']([\w$;|&\s\.\(\)/\-]{3,50})[`"\']', cot):
        p = m.group(1).strip().rstrip('。，；\n')
        if len(p) < 3 or len(p) > 50:
            continue
        if any(c in p for c in '$();|&`') or '..' in p or "'" in p or '"' in p:
            claimed_payloads.append(p)
    # 模式 2: 反引号包裹的含特殊字符的 payload（如 `web$(id)`）
    for m in re.finditer(r'`([\w$;|&\s\.\(\)/\-]{3,50})`', cot):
        p = m.group(1).strip()
        if len(p) < 3 or len(p) > 50:
            continue
        if any(c in p for c in '$();|&') or '..' in p:
            if p not in claimed_payloads:
                claimed_payloads.append(p)

    # 测试每个 payload 是否真的被正则拒绝
    for regex_pat in strict_regexes:
        regex_pat = regex_pat.replace('^^', '^').replace('$$', '$')
        cls_m = re.match(r'\^(\[[^\]]+\])\+\$', regex_pat)
        if not cls_m:
            continue
        py_pat = '^' + cls_m.group(1) + '+$'
        for payload in claimed_payloads:
            try:
                matched = bool(re.match(py_pat, payload))
            except Exception:
                continue
            if not matched:
                # 正则拒绝 payload → CoT 声称错误 → 误报
                return (regex_pat, payload)

    return None


def fix_false_positive(record, regex_pat, payload):
    """将误报样本转为负样本，重写 CoT。"""
    user = record["messages"][1]["content"]
    code_match = re.search(r'```(\w+)\n(.*?)```', user, re.DOTALL)
    if not code_match:
        return record, False
    code = code_match.group(2)
    lang = code_match.group(1)

    # 提取正则的字符类
    cls_m = re.match(r'\^(\[[^\]]+\])\+\$', regex_pat)
    if not cls_m:
        return record, False
    char_class = cls_m.group(1)

    # 生成修正后的 CoT
    new_cot = f"""分析过程：
1. 输入校验：代码使用严格锚定正则 `{regex_pat}` 校验用户输入，仅允许字符类 {char_class}。
2. 防御有效性：该正则使用 `^...$` 锚定，要求整个字符串匹配。攻击 payload `{payload}` 含有字符类外的字符（如 `$();|&` 等 shell 元字符），会被正则拒绝，无法通过校验。
3. 数据流：用户输入 → 正则校验（拦截非法字符）→ 拼接到命令/查询字符串 → 执行。
4. 结论：正则校验有效阻断了所有含 shell 元字符的输入，未发现可利用路径，无漏洞。

```json
{{"has_vulnerability": false, "vulnerability_type": "none", "risk_level": "None", "source": "N/A", "sink": "N/A", "explanation": "N/A", "fix_suggestion": "no fix needed"}}
```"""

    record_fixed = dict(record)
    record_fixed["messages"] = [
        record["messages"][0],
        record["messages"][1],
        {"role": "assistant", "content": new_cot},
    ]
    return record_fixed, True


def main():
    parser = argparse.ArgumentParser(description="修复 v9max 训练数据")
    parser.add_argument("--input", type=str,
                        default="experiments/exp_06_finetune/data/final_train_chatml_v3.jsonl",
                        help="输入 jsonl 路径")
    parser.add_argument("--output", type=str,
                        default="experiments/exp_06_finetune/data/final_train_chatml_v4_clean.jsonl",
                        help="输出 jsonl 路径")
    parser.add_argument("--dry-run", action="store_true",
                        help="只报告，不写文件")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    # 加载数据
    records = []
    with open(input_path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                r = json.loads(line)
                r["_line"] = i
                records.append(r)

    print(f"加载 {len(records)} 条样本 from {input_path}")

    # ============ 1. 修复标签不一致 ============
    print(f"\n=== 1. 修复标签不一致 ===")
    label_fix_count = 0
    label_fix_lines = []
    for i, r in enumerate(records):
        fixed, changed = fix_label_inconsistency(r)
        if changed:
            records[i] = fixed
            label_fix_count += 1
            label_fix_lines.append(r["_line"])
    print(f"修复标签不一致: {label_fix_count} 条")
    print(f"  行号: {label_fix_lines}")

    # ============ 2. 检测并修复正则误报 ============
    print(f"\n=== 2. 检测并修复正则误报 ===")
    fp_fix_count = 0
    fp_fix_details = []
    for i, r in enumerate(records):
        result = detect_regex_false_positive(r)
        if result is None:
            continue
        regex_pat, payload = result
        fixed, changed = fix_false_positive(r, regex_pat, payload)
        if changed:
            records[i] = fixed
            fp_fix_count += 1
            fp_fix_details.append((r["_line"], regex_pat, payload))

    print(f"修复正则误报: {fp_fix_count} 条")
    for ln, pat, payload in fp_fix_details:
        print(f"  data line {ln}: 正则 {pat}, 声称通过的 payload {payload!r}")

    # ============ 3. 写文件 ============
    print(f"\n=== 3. 输出 ===")
    total_fixed = label_fix_count + fp_fix_count
    print(f"总修复: {total_fixed} 条")
    print(f"修复率: {total_fixed/len(records)*100:.2f}%")

    if args.dry_run:
        print("\n[dry-run 模式] 未写入文件")
        return

    # 备份原文件
    backup_path = input_path.with_suffix('.jsonl.bak')
    if not backup_path.exists():
        shutil.copy2(input_path, backup_path)
        print(f"原文件已备份到: {backup_path}")

    # 写新文件
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for r in records:
            # 去掉 _line 字段
            r_out = {k: v for k, v in r.items() if k != "_line"}
            f.write(json.dumps(r_out, ensure_ascii=False) + "\n")

    print(f"修复后数据已写入: {output_path}")

    # 验证
    with open(output_path, encoding="utf-8") as f:
        n = sum(1 for line in f if line.strip())
    print(f"验证: 输出文件 {n} 条样本")

    # 统计修复后的标签分布
    pos = neg = 0
    with open(output_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            blocks = re.findall(r'```json\s*(.*?)\s*```', r["messages"][2]["content"], re.DOTALL)
            if not blocks:
                continue
            try:
                j = json.loads(blocks[-1])
                if j.get("has_vulnerability") is True:
                    pos += 1
                elif j.get("has_vulnerability") is False:
                    neg += 1
            except Exception:
                pass
    print(f"修复后标签分布: 漏洞={pos} 安全={neg} (比例 1:{neg/max(pos,1):.2f})")


if __name__ == "__main__":
    main()
