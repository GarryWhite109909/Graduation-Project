#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""精准重蒸馏：只把 fix_suggestion 为完整代码块(含```围栏)的漏洞样本转为 line N 最小局部改正。

背景：distill_fix_suggestions.py 曾把 456 条 idx（0-570）标记进 DONE，但实际未正确写回
（ORIG 里仍是完整代码块 fix）。本脚本读取 ORIG(final_train_chatml_quality_final_fix.jsonl)，
仅对指定 idx 重新调用 DeepSeek 教师，成功则写回 line N 建议，不影响其余已蒸馏样本。

用法：
  python _redistill_codeblock.py                    # 全量 456 条
  python _redistill_codeblock.py --limit 5          # 先验证 5 条
  python _redistill_codeblock.py --dry-run          # 只预览不调 API
"""
import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "experiments/exp_06_finetune/scripts"))

# 复用 distill_fix_suggestions 的教师逻辑
from distill_fix_suggestions import (  # noqa: E402
    call_teacher, extract_code, extract_verdict, process_task, FIX_SYSTEM_PROMPT,
)

BASE = Path(__file__).resolve().parents[1] / "data"
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"
IDX_FILE = BASE / "_codeblock_fix_idx.json"

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="最多处理 N 条（0=不限）")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--model", default="deepseek-v4-flash")
    args = ap.parse_args()

    import os
    api_key = args.api_key or os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key and not args.dry_run:
        print("[错误] 缺少 DEEPSEEK_API_KEY")
        return 1

    recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]
    # 待处理 = ORIG 中当前 fix_suggestion 仍含代码围栏的漏洞样本 idx（天然跳过已成功转写的）
    idxs = []
    for i, rec in enumerate(recs):
        v = extract_verdict(rec["messages"][2].get("content", ""))
        if v is None or v.get("has_vulnerability") is not True:
            continue
        if "```" in (v.get("fix_suggestion") or ""):
            idxs.append(i)
    if args.limit:
        idxs = idxs[: args.limit]

    print(f"ORIG {len(recs)} 条 | 待重蒸馏 {len(idxs)} 条")

    if args.dry_run:
        for i in idxs[:3]:
            rec = recs[i]
            code = extract_code(rec["messages"][1].get("content", "")) or ""
            verdict = extract_verdict(rec["messages"][2].get("content", "")) or {}
            print(f"--- idx={i} CWE={verdict.get('vulnerability_type')} ---")
            print("code 首行:", code.splitlines()[0][:60] if code else "<空>")
            print("当前 fix:", str(verdict.get("fix_suggestion"))[:80])
        return 0

    api_fn = lambda s, u: call_teacher(  # noqa: E731
        s, u, api_key=api_key, model=args.model,
    )

    from concurrent.futures import ThreadPoolExecutor, as_completed
    success = failed = 0
    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(process_task, i, recs[i], api_fn, "deepseek-redistill", False): i
                   for i in idxs}
        done = 0
        for fut in as_completed(futures):
            i = futures[fut]
            idx_out, new_rec, error = fut.result()
            if new_rec is not None:
                success += 1
                results[i] = new_rec
            else:
                failed += 1
                print(f"  idx {i} 失败: {error}")
            done += 1
            if done % 20 == 0 or done == len(idxs):
                print(f"  进度 {done}/{len(idxs)} | 成功 {success} | 失败 {failed}", flush=True)

    # 写回
    for i, new_rec in results.items():
        recs[i] = new_rec
    with ORIG.open("w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n完成: 成功 {success} | 失败 {failed}")
    print(f"写回: {ORIG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())