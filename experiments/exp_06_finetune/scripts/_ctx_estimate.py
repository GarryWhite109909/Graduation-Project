#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""估算测试集(cve_fix 20)与训练集 v3 的 prompt 上下文区间 + 回答占用。

Qwen3 tokenizer 不可用，用字符估算换算：
  - 英文/代码/数字：约 1 token ≈ 3.5~4 字符
  - 中文：约 1 字符 ≈ 0.6~1 token
给出一个保守区间（低=按4字符/token，高=按3字符/token 的英文加权混算）。
"""
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.prompts import build_system_prompt_variant

COMBINED = build_system_prompt_variant("combined")
BASE = PROJECT_ROOT / "experiments/exp_06_finetune"
DATA = BASE / "data"
TEST_DIR = BASE / "testset_cve_fix"

# Qwen3 中文字符 token 换算：中文约 0.85 token/字符，英文约 0.28 token/字符
CJK_RE = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")


def est_tokens(text: str) -> float:
    """估算 token 数：中文字符按 0.85，其余按 0.28（≈3.5字符/token）。"""
    cjk = len(CJK_RE.findall(text))
    other = len(text) - cjk
    return cjk * 0.85 + other * 0.28


def est_tokens_hi(text: str) -> float:
    """高估：中文按 1.0，其余按 0.33（≈3字符/token）。"""
    cjk = len(CJK_RE.findall(text))
    other = len(text) - cjk
    return cjk * 1.0 + other * 0.33


# ---------- 测试集：20 个代码文件 ----------
print("=" * 70)
print("【测试集 testset_cve_fix（20 个真实代码文件）】")
print("=" * 70)
test_rows = []
for f in sorted(TEST_DIR.glob("cve_fix_*.py")) + sorted(TEST_DIR.glob("cve_fix_*.js")) + \
        sorted(TEST_DIR.glob("cve_fix_*.java")) + sorted(TEST_DIR.glob("cve_fix_*.php")):
    code = f.read_text(encoding="utf-8", errors="replace")
    lang = f.suffix[1:]
    # user prompt 与 evaluate.py build_user_prompt 一致
    user = f"代码片段（语言: {lang}）：\n```{lang}\n{code}\n```\n请先给出分析过程，然后在最后给出 JSON 结论。"
    prompt = COMBINED + "\n\n" + user  # system + user
    lo = est_tokens(prompt)
    hi = est_tokens_hi(prompt)
    test_rows.append((f.name, lo, hi, len(code)))
    print(f"{f.name:<18} 代码{len(code):>6}字符 | prompt估算 {lo:6.0f}~{hi:6.0f} token")

t_lo = sum(r[1] for r in test_rows) / len(test_rows)
t_hi = sum(r[2] for r in test_rows) / len(test_rows)
t_min = min(r[1] for r in test_rows)
t_max = max(r[2] for r in test_rows)
print(f"\n测试集 prompt 上下文：平均 {t_lo:.0f}~{t_hi:.0f} token，区间 {t_min:.0f}~{t_max:.0f} token")

# ---------- 训练集 v3 ----------
print("\n" + "=" * 70)
print("【训练集 final_train_chatml_v3.jsonl（8616 条）】")
print("=" * 70)
recs = [json.loads(l) for l in (DATA / "final_train_chatml_v3.jsonl")
        .read_text(encoding="utf-8").splitlines() if l.strip()]

in_lo, in_hi = [], []       # prompt 输入（system+user）
out_lo, out_hi = [], []     # 模型回答（assistant）
tot_lo, tot_hi = [], []     # 整条（输入+回答）
for rec in recs:
    msgs = rec.get("messages", [])
    if len(msgs) < 3:
        continue
    sysc = msgs[0].get("content", "")
    userc = msgs[1].get("content", "")
    asst = msgs[2].get("content", "")
    prompt = sysc + "\n\n" + userc
    in_lo.append(est_tokens(prompt)); in_hi.append(est_tokens_hi(prompt))
    out_lo.append(est_tokens(asst)); out_hi.append(est_tokens_hi(asst))
    tot_lo.append(in_lo[-1] + out_lo[-1]); tot_hi.append(in_hi[-1] + out_hi[-1])

def pct(v):
    return f"{v:.0f}"

print(f"样本数: {len(recs)}")
print(f"\n[Prompt 输入 (system+user)]")
print(f"  平均: {pct(sum(in_lo)/len(in_lo))}~{pct(sum(in_hi)/len(in_hi))} token")
print(f"  P5  : {pct(sorted(in_lo)[int(len(in_lo)*0.05)])}~{pct(sorted(in_hi)[int(len(in_hi)*0.05)])}")
print(f"  P50 : {pct(sorted(in_lo)[int(len(in_lo)*0.5)])}~{pct(sorted(in_hi)[int(len(in_hi)*0.5)])}")
print(f"  P95 : {pct(sorted(in_lo)[int(len(in_lo)*0.95)])}~{pct(sorted(in_hi)[int(len(in_hi)*0.95)])}")
print(f"  max : {pct(max(in_lo))}~{pct(max(in_hi))}")

print(f"\n[模型回答 (assistant)]")
print(f"  平均: {pct(sum(out_lo)/len(out_lo))}~{pct(sum(out_hi)/len(out_hi))} token")
print(f"  P50 : {pct(sorted(out_lo)[int(len(out_lo)*0.5)])}~{pct(sorted(out_hi)[int(len(out_hi)*0.5)])}")
print(f"  P95 : {pct(sorted(out_lo)[int(len(out_lo)*0.95)])}~{pct(sorted(out_hi)[int(len(out_hi)*0.95)])}")
print(f"  max : {pct(max(out_lo))}~{pct(max(out_hi))}")

print(f"\n[整条 (prompt+回答)]")
print(f"  平均: {pct(sum(tot_lo)/len(tot_lo))}~{pct(sum(tot_hi)/len(tot_hi))} token")
print(f"  P95 : {pct(sorted(tot_lo)[int(len(tot_lo)*0.95)])}~{pct(sorted(tot_hi)[int(len(tot_hi)*0.95)])}")
print(f"  max : {pct(max(tot_lo))}~{pct(max(tot_hi))}")

# ---------- 回答占整条比例 ----------
ratio = sum(out_lo) / sum(tot_lo)
print(f"\n[回答占整条 token 比例] 平均约 {ratio*100:.1f}%")