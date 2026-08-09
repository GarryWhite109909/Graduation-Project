#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 3 条重蒸馏失败样本（157/413/566）手动编写 line N 最小局部改正建议。"""
import json, re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "data"
ORIG = BASE / "final_train_chatml_quality_final_fix.jsonl"

_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

def extract_verdict(assistant):
    for raw in reversed(_JSON_BLOCK_RE.findall(assistant or "")):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            continue
    return None

MAPPING = {
    157: ("line 25: 应改为在 memcpy 前基于同一把锁内读取的 size 检查 len，并将 resize 与 write 的 size 读写都纳入同一临界区，避免检查后 size 被并发改小导致堆溢出；line 29: 应改为 memcpy 复制长度 min(len, size) 取二者较小值",
          "CWE-122 Heap-based Buffer Overflow"),
    413: ("line 44: 应改为用 execFile('docker',['start',containerName,'&&','docker','logs','-f',containerName],...) 传参数数组不经 shell，或在 shell 前置白名单精确匹配 containerName，禁止拼接进 shell",
          "CWE-77 Command Injection"),
    566: ("line 20-21: 应改为对 project_name 做白名单校验后用 subprocess.run(['bash',build_script,'--deploy']) 列表参数不经 shell；line 36-37: 应改为对 test_cmd 做白名单映射，禁止拼接进 subprocess.Popen(shell=True)",
          "CWE-77 Command Injection"),
}

recs = [json.loads(l) for l in ORIG.read_text(encoding="utf-8").splitlines() if l.strip()]
applied = 0
for idx, (sug, cwe) in MAPPING.items():
    rec = recs[idx]
    msgs = rec.get("messages", [])
    asst = msgs[2].get("content", "")
    m = _JSON_BLOCK_RE.search(asst)
    if m is None:
        print(f"idx {idx}: 无 JSON 块，跳过")
        continue
    verdict = extract_verdict(asst)
    if verdict is None:
        print(f"idx {idx}: verdict 解析失败，跳过")
        continue
    verdict = dict(verdict)
    verdict["fix_suggestion"] = sug
    new_json = json.dumps(verdict, ensure_ascii=False)
    new_asst = asst.rsplit("```json", 1)[0] + "```json\n" + new_json + "\n```"
    recs[idx]["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
    recs[idx]["fix_distill"] = {"teacher": "manual-redistill-fix", "cwe": cwe, "generated_at": "2026-08-09"}
    applied += 1
    print(f"idx {idx}: 已改写 fix_suggestion")

with ORIG.open("w", encoding="utf-8") as f:
    for rec in recs:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"完成: 应用 {applied}")