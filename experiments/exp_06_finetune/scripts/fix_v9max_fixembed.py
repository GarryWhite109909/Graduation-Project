#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 fix-example 样本中的完整修复代码嵌入 fix_suggestion 字段。

背景：deepseek_fix 类别（1200 条）里，约 300 条在 assistant 分析中带一个 ```fix 代码块
（完整修复后的代码），但 fix_suggestion 字段仍是纯文本。导致：
  - FixVerifier.extract_code 从 fix_suggestion 抽不到代码 → 修复可用性无法验证/强化
  - 模型学到的固定输出格式里，修复代码不在 fix_suggestion 里

本脚本：对 assistant 含非 json 代码块（=修复后代码）的正样本，
  1) 把该代码块嵌入 fix_suggestion（```lang 包裹）
  2) 从分析文本中移除原独立代码块，避免重复输出、让模型学会把代码放进 fix_suggestion

用法：
  python3 fix_v9max_fixembed.py --input data/distill_v2/train_chatml_v9max_clean.jsonl \
      --output data/distill_v2/train_chatml_v9max_clean.jsonl
"""
import argparse
import json
import re
import sys
from pathlib import Path

JSON_BLOCK = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)
CODE_BLOCK = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)


def extract_json(asst):
    blocks = JSON_BLOCK.findall(asst)
    for b in reversed(blocks):
        try:
            return json.loads(b.strip())
        except Exception:
            continue
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str,
                        default="experiments/exp_06_finetune/data/distill_v2/train_chatml_v9max_clean.jsonl")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()
    out = Path(args.output) if args.output else Path(args.input)

    recs = [json.loads(l) for l in open(args.input, encoding="utf-8") if l.strip()]
    print(f"加载 {len(recs)} 条")

    embedded = 0
    modified = 0
    for idx, r in enumerate(recs):
        msgs = r["messages"]
        if len(msgs) < 3:
            continue
        asst = msgs[2]["content"]
        j = extract_json(asst)
        if j is None or j.get("has_vulnerability") is not True:
            continue

        # 找 assistant 中最后一个非 json 代码块（=修复后代码）
        code_blocks = [b for b in CODE_BLOCK.findall(asst) if b[0].lower() != "json"]
        if not code_blocks:
            continue
        lang, code = code_blocks[-1]
        lang = lang or "text"

        # 1) 嵌入 fix_suggestion
        new_fs = f"```{lang}\n{code.strip()}\n```"
        if not j.get("fix_suggestion") or j["fix_suggestion"] == "no fix needed":
            j["fix_suggestion"] = new_fs
            embedded += 1
        else:
            j["fix_suggestion"] = new_fs  # 覆盖为完整代码

        modified += 1

        # 2) 重建 assistant：移除全部代码块（含旧 json 与独立 fix 块），只保留分析 + 新 JSON
        new_json = json.dumps(j, ensure_ascii=False)
        analysis = CODE_BLOCK.sub("", asst)
        analysis = re.sub(r"\n{3,}", "\n\n", analysis).strip()
        new_asst = analysis + "\n```json\n" + new_json + "\n```"
        # 关键修复：写回原列表（旧代码 r = dict(r) 只改了副本，未写回 recs）
        recs[idx] = dict(r)
        recs[idx]["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]

    print(f"嵌入完整修复代码到 fix_suggestion: {embedded} 条")
    print(f"修改样本: {modified} 条")

    with open(out, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"输出: {out} ({len(recs)} 条)")

    # 验证（用官方 parse_verdict，正确处理 fix_suggestion 内含代码块的情况）
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from graduation_project.schema import parse_verdict
    fs_code = 0
    for r in recs:
        j = parse_verdict(r["messages"][2]["content"])
        if j and j.get("has_vulnerability") is True:
            fs = j.get("fix_suggestion", "")
            if re.search(r"```[a-zA-Z0-9_+-]*\n", fs):
                fs_code += 1
    print(f"验证：正样本 fix_suggestion 含代码块: {fs_code} 条")


if __name__ == "__main__":
    main()