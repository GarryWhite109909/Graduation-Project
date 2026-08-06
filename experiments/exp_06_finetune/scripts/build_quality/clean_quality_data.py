#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase A：清洗基础数据 → 干净、去模板占位、去重、重平衡后的高质量基础集。

输入基底：data/distill_v2/train_chatml_v9max_clean.jsonl（7698 条，DeepSeek 蒸馏，多样且代码相关）
该文件是干净基础源（仅 44 条模板占位）。v5_fixembed（10575）是被合并其他源污染过的，
不应作为基底。

清洗步骤：
  1. 剔除模板占位（"污染源/危险sink/命中安全模式白名单/输入检查/sink评估/防御确认/综合判定"等通用套话）
  2. 剔除空泛安全样本（CoT 无行号、无具体构造引用、大量 N/A 的"安全模板"）
  3. 按 assistant 内容去重（保留代表）
  4. 负样本按可配置比例上限截断（只保留质量最高的，避免淹没正样本）

用 parse_verdict 解析 JSON 判定正负，与官方 schema 一致。

用法：
  python3 clean_quality_data.py --input data/distill_v2/train_chatml_v9max_clean.jsonl \
      --output data/quality/clean_base.jsonl --max-neg-scale 1.5
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT_ROOT))
from graduation_project.schema import parse_verdict

# 通用模板占位特征（出现即判为低质量占位/套话）
PLACEHOLDER_PATTERNS = [
    r"污染源", r"危险\s*sink", r"命中安全模式白名单",
    r"输入检查", r"sink\s*评估", r"防御确认", r"综合判定",
    r"追踪输入到\s*sink\s*的路径",
    r"识别该操作应具备的安全控制",
    r"控制是否缺失",
]
# 空泛安全样本特征：分析中既无行号、也无具体代码构造引用
SAFE_EMPTY_PATTERNS = [
    r"未发现可利用路径", r"未发现漏洞", r"防御措施有效",
]
LINE_REF = re.compile(r"(?:第\s*\d+\s*行|line\s*\d+|:\s*\d+)", re.I)
CONSTRUCT_REF = re.compile(r"\b(?:func|function|class|def|var|const|let|new|malloc|free|strcpy|strcat|exec|eval|system|sql|query|execute|sink|source|request|input|user|password|token|query)\b", re.I)


def is_placeholder(content: str) -> bool:
    return any(re.search(p, content) for p in PLACEHOLDER_PATTERNS)


def is_safe_empty(content: str, j: dict) -> bool:
    """安全样本若分析无行号、无具体构造引用，判为低质量空泛样本。"""
    analysis = content.split("```json")[0]
    if LINE_REF.search(analysis):
        return False
    # 有具体构造引用（函数/变量名）→ 有信息量
    if CONSTRUCT_REF.search(analysis):
        return False
    # 否则是空泛安全模板
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str,
                        default="data/distill_v2/train_chatml_v9max_clean.jsonl")
    parser.add_argument("--output", type=str,
                        default="data/quality/clean_base.jsonl")
    parser.add_argument("--max-neg-scale", type=float, default=1.5,
                        help="负样本上限倍数（相对正样本数），None=不截断")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    recs = [json.loads(l) for l in open(in_path, encoding="utf-8") if l.strip()]
    print(f"加载 {len(recs)} 条 from {in_path}")

    pos, neg, unk = [], [], []
    for r in recs:
        j = parse_verdict(r["messages"][2]["content"])
        if j is None:
            unk.append(r)
        elif j.get("has_vulnerability") is True:
            pos.append(r)
        elif j.get("has_vulnerability") is False:
            neg.append(r)
        else:
            unk.append(r)
    print(f"原始: 漏洞={len(pos)} 安全={len(neg)} 未知={len(unk)}")

    # 1. 剔除模板占位（正负都剔）
    ph_pos = [r for r in pos if is_placeholder(r["messages"][2]["content"])]
    ph_neg = [r for r in neg if is_placeholder(r["messages"][2]["content"])]
    pos = [r for r in pos if not is_placeholder(r["messages"][2]["content"])]
    neg = [r for r in neg if not is_placeholder(r["messages"][2]["content"])]
    print(f"剔除模板占位: 漏洞 {len(ph_pos)} 安全 {len(ph_neg)}")

    # 2. 剔除空泛安全样本
    empty_neg = [r for r in neg if is_safe_empty(r["messages"][2]["content"],
                 parse_verdict(r["messages"][2]["content"]))]
    neg = [r for r in neg if not is_safe_empty(r["messages"][2]["content"],
            parse_verdict(r["messages"][2]["content"]))]
    print(f"剔除空泛安全样本: {len(empty_neg)}")

    # 3. 按 assistant 去重（保留首见）
    seen = set()
    def dedupe(recs):
        out = []
        for r in recs:
            h = r["messages"][2]["content"]
            if h in seen:
                continue
            seen.add(h)
            out.append(r)
        return out
    pos = dedupe(pos)
    neg = dedupe(neg)
    print(f"去重后: 漏洞={len(pos)} 安全={len(neg)}")

    # 4. 负样本重平衡（只保留质量最高的，按信息量排序）
    if args.max_neg_scale is not None and neg:
        cap = int(len(pos) * args.max_neg_scale)
        if len(neg) > cap:
            # 质量分：分析长度 + 行号引用数 + 构造引用数
            def score(r):
                a = r["messages"][2]["content"].split("```json")[0]
                return len(a) + 40 * len(LINE_REF.findall(a)) + 10 * len(CONSTRUCT_REF.findall(a))
            neg.sort(key=score, reverse=True)
            trimmed = neg[cap:]
            neg = neg[:cap]
            print(f"负样本截断: 从 {len(trimmed)+cap} → {cap}（丢弃 {len(trimmed)} 条信息量最低的）")

    # 写文件
    out_path.parent.mkdir(parents=True, exist_ok=True)
    all_recs = pos + neg + unk
    with open(out_path, "w", encoding="utf-8") as f:
        for r in all_recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n输出: {out_path} ({len(all_recs)} 条)")
    print(f"最终: 漏洞={len(pos)} 安全={len(neg)} 未知={len(unk)} 比例 1:{len(neg)/max(len(pos),1):.2f}")

    # 语言分布
    langs = Counter()
    for r in all_recs:
        m = re.search(r"```(\w+)", r["messages"][1]["content"])
        langs[m.group(1) if m else "?"] += 1
    print(f"语言分布: {dict(langs)}")


if __name__ == "__main__":
    main()