"""
蒸馏标注格式化器 —— 把用户补好 CoT 的 JSONL 转为 ChatML 训练格式。

输入 JSONL（每行字段，由用户在 IDE 中补全）：
  code, language, filename,
  cot_analysis,                         # CoT 分析文本
  has_vulnerability, vuln_type, risk_level,
  source, sink, taint_path, fix_idea

输出（与 build_dataset.py 的 train_chatml.jsonl 完全一致）：
  {"messages": [
      {"role":"system","content": SYSTEM_PROMPT},
      {"role":"user","content": build_user_prompt(code, language, filename)},
      {"role":"assistant","content": cot_analysis + "\\n\\n" + json_block}
  ]}

JSON 结论块复用 build_dataset.py 的 build_json_verdict 逻辑：
  verdict = {
    "has_vulnerability": ...,
    "vulnerability_type": vuln_type,   # 蒸馏标注用 vuln_type，输出 JSON 用 vulnerability_type
    "risk_level": ...,
    "source": ..., "sink": ...,
    "explanation": taint_path if has_vulnerability else "代码使用了安全写法，未发现漏洞。",
    "fix_suggestion": fix_idea
  }

用法：
  # 生成独立文件（默认）
  python format_distilled.py --input distill_corpus_annotated.jsonl --output train_chatml_distilled.jsonl

  # 追加到主训练集
  python format_distilled.py --input distill_corpus_annotated.jsonl --append

依赖：需要导入 graduation_project.prompts（SYSTEM_PROMPT / build_user_prompt），
      脚本通过 sys.path.insert PROJECT_ROOT 自动处理，参考 evaluate.py 开头写法。
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
DEFAULT_INPUT = DATA_DIR / "distill_corpus_annotated.jsonl"
DEFAULT_OUTPUT = DATA_DIR / "train_chatml_distilled.jsonl"
APPEND_TARGET = DATA_DIR / "train_chatml.jsonl"


def build_json_verdict(rec: dict) -> str:
    """根据标注字段构造 JSON 结论块（与 build_dataset.py 的 build_json_verdict 一致）。

    输入字段使用 vuln_type（蒸馏标注约定），输出 JSON 使用 vulnerability_type（schema 约定）。
    缺失字段会填充安全/中性的默认值，保证 schema 完整。
    """
    has_vuln = bool(rec.get("has_vulnerability", False))
    vuln_type = rec.get("vuln_type") or ("none" if not has_vuln else "unknown")
    risk_level = rec.get("risk_level") or ("None" if not has_vuln else "Medium")
    source = rec.get("source") or "N/A"
    sink = rec.get("sink") or "N/A"
    taint_path = rec.get("taint_path") or ""
    fix_idea = rec.get("fix_idea") or ("no fix needed" if not has_vuln else "N/A")

    # 安全样本的 explanation 不能用统一模板（会导致模型学会"无脑判安全"），
    # 必须根据 taint_path 字段生成具体的防御说明。若 taint_path 为空则用 fallback。
    if has_vuln:
        explanation = taint_path or f"存在 {vuln_type}，风险等级 {risk_level}。"
    else:
        explanation = taint_path if taint_path else "代码中未发现可利用的安全漏洞。"
    verdict = {
        "has_vulnerability": has_vuln,
        "vulnerability_type": vuln_type,
        "risk_level": risk_level,
        "source": source,
        "sink": sink,
        "explanation": explanation,
        "fix_suggestion": fix_idea,
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_messages(rec: dict) -> dict:
    """把一条标注记录转为 ChatML messages 结构。"""
    code = rec.get("code", "")
    language = rec.get("language", "python")
    filename = rec.get("filename", "sample.py")
    cot_analysis = (rec.get("cot_analysis") or "").rstrip()

    user_content = build_user_prompt(code=code, language=language, filename=filename)
    json_block = build_json_verdict(rec)
    assistant_content = f"{cot_analysis}\n\n{json_block}"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


def validate_record(rec: dict) -> list:
    """校验必填字段，返回缺失字段列表。

    has_vulnerability 必须是 bool（True/False），其他字段为非空字符串。
    """
    required_str = ["code", "language", "filename", "cot_analysis",
                    "vuln_type", "risk_level"]
    missing = [f for f in required_str if not rec.get(f)]
    if "has_vulnerability" not in rec or not isinstance(rec["has_vulnerability"], bool):
        missing.append("has_vulnerability")
    return missing


def main():
    parser = argparse.ArgumentParser(
        description="把蒸馏标注 JSONL 格式化为 ChatML 训练数据"
    )
    parser.add_argument("--input", type=str, default=str(DEFAULT_INPUT),
                        help=f"输入 JSONL（默认 {DEFAULT_INPUT.name}）")
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT),
                        help=f"输出 JSONL（默认 {DEFAULT_OUTPUT.name}，与 --append 互斥）")
    parser.add_argument("--append", action="store_true",
                        help=f"追加到 {APPEND_TARGET.name}（主训练集）而非写 --output")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"错误：输入文件不存在: {in_path}", file=sys.stderr)
        print(f"提示：请先运行 prepare_distill_corpus.py 生成 corpus，再在 IDE 中补 CoT 标注。", file=sys.stderr)
        sys.exit(1)

    if args.append:
        out_path = APPEND_TARGET
        mode = "a"
        print(f"追加模式：写入 {out_path}")
    else:
        out_path = Path(args.output)
        mode = "w"
        print(f"覆盖模式：写入 {out_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    skipped = 0
    with in_path.open("r", encoding="utf-8") as fin, \
         out_path.open(mode, encoding="utf-8") as fout:
        for line_no, line in enumerate(fin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[行 {line_no}] JSON 解析失败: {e}", file=sys.stderr)
                skipped += 1
                continue

            missing = validate_record(rec)
            if missing:
                print(f"[行 {line_no}] 缺失字段 {missing}，跳过", file=sys.stderr)
                skipped += 1
                continue

            messages = build_messages(rec)
            fout.write(json.dumps(messages, ensure_ascii=False) + "\n")
            total += 1

    print(f"\n完成：写入 {total} 条到 {out_path}（跳过 {skipped} 条）")
    if args.append:
        print(f"主训练集 {APPEND_TARGET.name} 现可重新训练（参见 train_qlora.py）")


if __name__ == "__main__":
    main()
