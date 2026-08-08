#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把训练数据里的完整修复代码 fix_suggestion 转换为行号锚定的局部修复建议。

背景（2026-08-08 决策）：
  schema 的 fix_suggestion 从"完整可运行修复代码（``` 围栏）"改为
  "行号锚定的简短修复建议（单行，如 'line 3: 应改为 ...'）"。原因是完整代码
  在客户端 6K~8K 上下文下会被截断，且 FixVerifier 已证伪（瓶颈在模型没输出）。

本脚本只处理仍含代码围栏的 fix_suggestion：
  1. 从 user 消息提取漏洞代码（原文）；
  2. 从 fix_suggestion 提取修复代码（取最后一个代码围栏块）；
  3. 用 difflib 对原文/修复文逐 hunk 生成 "line N: 应改为 ..." 建议；
  4. 简单单行替换 hunk 直接转换；多行/插入 hunk 标记 needs_review，由人工复核。
已经是局部建议（无代码围栏）的样本原样保留。

用法：
  python experiments/exp_06_finetune/scripts/convert_fix_to_localized.py \
      --input final_train_chatml_quality_final.jsonl \
      --output final_train_chatml_quality_final_localized.jsonl
  # 只统计不落盘：
  python ... --input ... --output ... --dry-run
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path


_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def extract_code(text: str) -> str | None:
    """从 user 消息或 fix_suggestion 中提取最后一个代码围栏块。"""
    if not text:
        return None
    blocks = _FENCE_RE.findall(text)
    return blocks[-1].strip() if blocks else None


def extract_json_block(text: str) -> tuple[dict | None, str | None]:
    """从 assistant 内容提取最后一个 ```json 块。"""
    if not text:
        return None, None
    for raw in reversed(_JSON_BLOCK_RE.findall(text)):
        try:
            return json.loads(raw), raw
        except json.JSONDecodeError:
            continue
    return None, None


def build_localized_suggestions(original: str, fixed: str) -> tuple[list[str], bool]:
    """对原文/修复文做 diff，生成行号锚定的局部建议。

    Returns:
        (suggestions, needs_review)
        needs_review=True 表示存在多行/插入 hunk，自动转换有失真风险，需人工复核。
    """
    orig_lines = original.splitlines()
    fix_lines = fixed.splitlines()
    if not orig_lines or not fix_lines:
        return [], True

    diff = difflib.unified_diff(
        orig_lines, fix_lines, fromfile="orig", tofile="fixed", n=1, lineterm=""
    )
    suggestions: list[str] = []
    needs_review = False
    cur_orig_start: int | None = None
    removed: list[str] = []
    added: list[str] = []

    def flush() -> None:
        nonlocal cur_orig_start, removed, added
        if cur_orig_start is None or (not removed and not added):
            cur_orig_start, removed, added = None, [], []
            return
        anchor = cur_orig_start
        if added and len(added) == 1 and len(removed) <= 1:
            # 单行替换/新增：最常见、可自动转换的场景
            if removed:
                suggestions.append(f"line {anchor}: 应改为 {added[0].strip()}")
            else:
                suggestions.append(f"line {anchor}: 建议插入 {added[0].strip()}")
        elif added:
            # 多行替换/插入：取首行作为改法摘要，标记人工复核
            head = added[0].strip()
            tail = "" if len(added) == 1 else f"（另 {len(added) - 1} 行，见完整改法）"
            suggestions.append(f"line {anchor}: 应改为 {head}{tail}")
            needs_review = True
        else:
            # 纯删除
            suggestions.append(f"line {anchor}: 建议删除该行（{removed[0].strip()}）")
            needs_review = True
        cur_orig_start, removed, added = None, [], []

    for line in diff:
        if line.startswith("@@"):
            flush()
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if m:
                cur_orig_start = int(m.group(1))
        elif line.startswith("---") or line.startswith("+++"):
            continue
        elif line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        # 上下文行：不处理
    flush()
    return suggestions, needs_review


def convert_record(rec: dict) -> tuple[dict, dict]:
    """转换单条训练样本，返回 (record, stats)。"""
    stats = {"converted": 0, "kept": 0, "empty": 0, "needs_review": 0, "no_code": 0}
    msgs = rec.get("messages", [])
    if len(msgs) < 3:
        stats["no_code"] += 1
        return rec, stats

    user_text = msgs[1].get("content", "")
    original = extract_code(user_text)
    if not original:
        stats["no_code"] += 1
        return rec, stats

    asst = msgs[2].get("content", "")
    verdict, raw = extract_json_block(asst)
    if verdict is None or raw is None:
        stats["kept"] += 1
        return rec, stats
    if verdict.get("has_vulnerability") is not True:
        stats["kept"] += 1
        return rec, stats

    suggestion = verdict.get("fix_suggestion", "")
    if not (suggestion or "").strip():
        stats["empty"] += 1
        return rec, stats

    fixed = extract_code(suggestion)
    if fixed is None:
        # 已经是局部建议（无代码围栏）：原样保留
        stats["kept"] += 1
        return rec, stats

    suggestions, needs_review = build_localized_suggestions(original, fixed)
    if not suggestions:
        # 没有可用的行号锚点（例如修复代码与原文完全一致），保留原文并标记复核
        stats["needs_review"] += 1
        return rec, stats

    new_suggestion = "；".join(suggestions)
    verdict = dict(verdict)
    verdict["fix_suggestion"] = new_suggestion
    new_json = json.dumps(verdict, ensure_ascii=False)
    new_asst = asst.rsplit("```json", 1)[0] + "```json\n" + new_json + "\n```"
    new_rec = dict(rec)
    new_rec["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
    if needs_review:
        stats["needs_review"] += 1
        new_rec["fix_converted_needs_review"] = True
    stats["converted"] += 1
    return new_rec, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="训练数据 fix_suggestion 完整代码 → 行号局部建议")
    ap.add_argument("--input", required=True, help="训练 ChatML jsonl")
    ap.add_argument("--output", required=True, help="转换后 jsonl")
    ap.add_argument("--dry-run", action="store_true", help="只统计不写文件")
    args = ap.parse_args()

    in_path = Path(args.input)
    records = [json.loads(l) for l in in_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    total = {"converted": 0, "kept": 0, "empty": 0, "needs_review": 0, "no_code": 0}
    out_records = []
    for rec in records:
        new_rec, s = convert_record(rec)
        for k in total:
            total[k] += s[k]
        out_records.append(new_rec)

    print(f"输入 {len(records)} 条")
    print(f"  转换（完整代码→行号建议）: {total['converted']}")
    print(f"  已是局部建议/无需转换: {total['kept']}")
    print(f"  漏洞样本但 fix_suggestion 为空: {total['empty']}")
    print(f"  转换后需人工复核: {total['needs_review']}")
    print(f"  无法提取代码: {total['no_code']}")

    if not args.dry_run:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for rec in out_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"已写出: {out_path} ({len(out_records)} 条)")
    else:
        print("[dry-run] 未写文件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
