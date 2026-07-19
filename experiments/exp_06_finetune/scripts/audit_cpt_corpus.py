"""
CPT 语料审计脚本（一次性体检）

输出 7 个维度的体检报告：
  1. 体量：总条数/字节/估算 token，按 layer/priority 分布
  2. 重复：exact text 重复、近似重复（hash 前 200 字符）
  3. 测试集泄露：与 exp_04 测试集代码片段的 overlap 检测
  4. 格式一致性：字段完整性、JSON 合法性
  5. 源文件存在性：prepare_cpt_corpus.py 引用的所有 source 是否就位
  6. 类别分布：Layer A 知识 / Layer B 推理 / Layer C 代码 的内容类别细分
  7. 长尾与异常：超长样本、空样本、过短样本

用法：
  python audit_cpt_corpus.py
  python audit_cpt_corpus.py --corpus path/to/cpt_corpus.jsonl
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
HARD_SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples/samples"
DEFAULT_CORPUS = DATA_DIR / "cpt_corpus.jsonl"

# prepare_cpt_corpus.py 引用的所有 source（用于存在性检查）
SOURCES_TO_CHECK = [
    "knowledge.json",  # 在 exp_03_rag_knowledge/knowledge_data/
    "train_chatml_v2.jsonl",
    "distill_corpus_annotated_v2.jsonl",
    "supplement_ccot_contrastive_v2.jsonl",
    "supplement_ccot_contrastive.jsonl",
    "supplement_ccot_v3_expansion.jsonl",
    "supplement_longfile_defense.jsonl",
    "supplement_longtail_cwe.jsonl",
    "supplement_cwe_attribution_ssti.jsonl",
    "supplement_cwe_attribution_nosql.jsonl",
    "supplement_cwe_attribution_spel.jsonl",
    "supplement_crypto_noise.jsonl",
    "supplement_chatml.jsonl",
    "supplement_7b_weakness.jsonl",
    "supplement_blindspot_cwe.jsonl",
    "distill_corpus_annotated.jsonl",
    "dpo_preference_pairs_v3.jsonl",
    "dpo_v3_expansion.jsonl",
    "dpo_preference_pairs.jsonl",
    "manifest.json",  # 在 exp_04_hard_samples/samples/
]

RAG_KNOWLEDGE_FILE = PROJECT_ROOT / "experiments/exp_03_rag_knowledge/knowledge_data/knowledge.json"


def estimate_tokens(text: str) -> int:
    """粗略估算 token 数：英文 ~4 字符/token，中文 ~1.5 字符/token。"""
    chinese = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    other = len(text) - chinese
    return int(chinese / 1.5 + other / 4)


def md5_short(text: str, n: int = 0) -> str:
    """返回 text 的 md5；n>0 时只取前 n 字符做 hash（用于近似重复检测）。"""
    s = text[:n] if n > 0 else text
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def load_corpus(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as fp:
        for i, line in enumerate(fp, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                rec["_line"] = i
                records.append(rec)
            except json.JSONDecodeError as e:
                records.append({"_line": i, "_parse_error": str(e)})
    return records


def load_testset_code() -> dict[str, str]:
    """加载 exp_04 测试集代码，返回 {filename: code}。"""
    out = {}
    if not HARD_SAMPLES_DIR.exists():
        return out
    for f in HARD_SAMPLES_DIR.glob("*.py"):
        try:
            out[f.name] = f.read_text(encoding="utf-8")
        except Exception:
            pass
    return out


def find_code_fragments_in_text(text: str, min_len: int = 80) -> list[str]:
    """从文本中提取 ```...``` 包围的代码片段（用于泄露检测）。"""
    fragments = []
    for m in re.finditer(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL):
        frag = m.group(1).strip()
        if len(frag) >= min_len:
            fragments.append(frag)
    return fragments


def audit_volume(records: list[dict]):
    print("\n" + "=" * 60)
    print("【1/7】体量审计")
    print("=" * 60)
    ok = [r for r in records if "_parse_error" not in r]
    total_bytes = sum(len(r.get("text", "").encode("utf-8")) for r in ok)
    total_tokens = sum(estimate_tokens(r.get("text", "")) for r in ok)
    print(f"  总条数: {len(records)}  (合法 {len(ok)}, 解析失败 {len(records) - len(ok)})")
    print(f"  总字节: {total_bytes:,} ({total_bytes / 1024 / 1024:.2f} MB)")
    print(f"  估算 token: {total_tokens:,} (~{total_tokens / 1000:.0f}K)")

    by_layer = Counter(r.get("layer", "?") for r in ok)
    by_priority = Counter(r.get("priority", "?") for r in ok)
    by_lp = Counter((r.get("layer", "?"), r.get("priority", "?")) for r in ok)

    print(f"\n  按 layer 分布:")
    for layer in sorted(by_layer):
        name = {"A": "知识层", "B": "推理层", "C": "代码层"}.get(layer, "?")
        cnt = by_layer[layer]
        bytes_ = sum(len(r.get("text", "").encode("utf-8"))
                     for r in ok if r.get("layer") == layer)
        print(f"    Layer {layer} {name}: {cnt} 条, {bytes_ / 1024:.1f} KB")

    print(f"\n  按 priority 分布:")
    for p in sorted(by_priority):
        print(f"    {p}: {by_priority[p]} 条")

    print(f"\n  按 layer × priority:")
    for (l, p), c in sorted(by_lp.items()):
        print(f"    Layer {l} / {p}: {c} 条")

    # KnItLM 论文经验：CPT 语料建议 >5K 条 / >10MB
    print(f"\n  体量评估:")
    if len(ok) < 500:
        print(f"    ⚠️ 条数偏少（<500），KnItLM 论文建议 >5K 条")
    elif len(ok) < 5000:
        print(f"    ⚠️ 条数中等（500~5000），KnItLM 论文建议 >5K 条，注意过拟合")
    else:
        print(f"    ✅ 条数充足（>5K）")
    if total_bytes < 5 * 1024 * 1024:
        print(f"    ⚠️ 字节偏少（<5MB），CPT 效果可能有限")
    elif total_bytes < 20 * 1024 * 1024:
        print(f"    ⚠️ 字节中等（5~20MB），勉强可用")
    else:
        print(f"    ✅ 字节充足（>20MB）")


def audit_duplicates(records: list[dict]):
    print("\n" + "=" * 60)
    print("【2/7】重复审计")
    print("=" * 60)
    ok = [r for r in records if "_parse_error" not in r]

    # 精确重复（完整 text）
    full_hash = Counter(md5_short(r.get("text", "")) for r in ok)
    exact_dup = {h: c for h, c in full_hash.items() if c > 1}
    exact_dup_count = sum(c - 1 for c in exact_dup.values())
    print(f"  精确重复（完整 text 一致）: {len(exact_dup)} 组, 多余 {exact_dup_count} 条")

    if exact_dup:
        print(f"  Top 5 重复组:")
        text_by_hash = defaultdict(list)
        for r in ok:
            text_by_hash[md5_short(r.get("text", ""))].append(r)
        sorted_groups = sorted(exact_dup.items(),
                               key=lambda x: full_hash[x[0]], reverse=True)[:5]
        for h, _ in sorted_groups:
            group = text_by_hash[h]
            sample = group[0].get("text", "")[:100].replace("\n", " ")
            print(f"    [{full_hash[h]} 重复] {sample}...")

    # 近似重复（前 200 字符）
    prefix_hash = Counter(md5_short(r.get("text", ""), 200) for r in ok)
    approx_dup = {h: c for h, c in prefix_hash.items() if c > 1}
    approx_dup_count = sum(c - 1 for c in approx_dup.values())
    print(f"\n  近似重复（前 200 字符一致）: {len(approx_dup)} 组, 多余 {approx_dup_count} 条")

    # 按 layer 看重复分布
    if exact_dup_count > 0:
        print(f"\n  按 layer 的精确重复分布:")
        text_by_hash = defaultdict(list)
        for r in ok:
            text_by_hash[md5_short(r.get("text", ""))].append(r)
        layer_dup = Counter()
        for h, group in text_by_hash.items():
            if len(group) > 1:
                for r in group:
                    layer_dup[r.get("layer", "?")] += 1
        for l, c in sorted(layer_dup.items()):
            print(f"    Layer {l}: {c} 条 (含重复)")

    print(f"\n  重复评估:")
    if exact_dup_count == 0:
        print(f"    ✅ 无精确重复")
    elif exact_dup_count < len(ok) * 0.05:
        print(f"    ✅ 重复率 <5%，可接受")
    else:
        print(f"    ⚠️ 重复率 ≥5%，建议去重")


def audit_testset_leak(records: list[dict], testset_code: dict[str, str]):
    print("\n" + "=" * 60)
    print("【3/7】测试集泄露审计")
    print("=" * 60)
    ok = [r for r in records if "_parse_error" not in r]

    if not testset_code:
        print(f"  ⚠️ 未找到 exp_04 测试集代码 ({HARD_SAMPLES_DIR})，跳过")
        return

    print(f"  测试集代码文件数: {len(testset_code)}")

    # 对每条 CPT 语料，提取其代码片段，与测试集代码做 overlap
    leak_hits = []
    for r in ok:
        text = r.get("text", "")
        fragments = find_code_fragments_in_text(text)
        for frag in fragments:
            # 取代码片段的前 60 字符做指纹
            fingerprint = frag[:60].strip()
            if len(fingerprint) < 30:
                continue
            for fname, code in testset_code.items():
                if fingerprint in code:
                    leak_hits.append({
                        "line": r.get("_line"),
                        "layer": r.get("layer"),
                        "priority": r.get("priority"),
                        "test_file": fname,
                        "fingerprint": fingerprint[:80].replace("\n", " "),
                    })

    print(f"\n  泄露命中数: {len(leak_hits)}")
    if leak_hits:
        print(f"  Top 10 命中:")
        for h in leak_hits[:10]:
            print(f"    L{h['line']} [{h['layer']}/{h['priority']}] "
                  f"↔ {h['test_file']}")
            print(f"      指纹: {h['fingerprint']}...")

    print(f"\n  泄露评估:")
    if len(leak_hits) == 0:
        print(f"    ✅ 未检测到测试集代码片段泄露")
    elif len(leak_hits) < 5:
        print(f"    ⚠️ 检测到 {len(leak_hits)} 处可能泄露，需人工核查")
    else:
        print(f"    ❌ 检测到 {len(leak_hits)} 处泄露，必须清理")


def audit_format(records: list[dict]):
    print("\n" + "=" * 60)
    print("【4/7】格式一致性审计")
    print("=" * 60)

    field_issues = []
    for r in records:
        if "_parse_error" in r:
            field_issues.append((r["_line"], "JSON 解析失败", r["_parse_error"]))
            continue
        for f in ("text", "priority", "layer"):
            if f not in r:
                field_issues.append((r.get("_line"), f"缺字段 {f}", ""))
            elif f == "text" and not r["text"].strip():
                field_issues.append((r.get("_line"), "text 为空", ""))
        # priority/layer 合法取值
        if r.get("priority") not in ("high", "medium", "low", None):
            field_issues.append((r.get("_line"), f"priority 非法: {r.get('priority')}", ""))
        if r.get("layer") not in ("A", "B", "C", None):
            field_issues.append((r.get("_line"), f"layer 非法: {r.get('layer')}", ""))

    print(f"  格式问题数: {len(field_issues)}")
    if field_issues:
        print(f"  Top 10 问题:")
        for line, issue, extra in field_issues[:10]:
            print(f"    L{line}: {issue} {extra[:80]}")

    # 长度分布
    ok = [r for r in records if "_parse_error" not in r]
    lengths = [len(r.get("text", "")) for r in ok]
    lengths.sort()
    if lengths:
        print(f"\n  text 长度分布:")
        print(f"    min: {lengths[0]}")
        print(f"    p25: {lengths[len(lengths) // 4]}")
        print(f"    median: {lengths[len(lengths) // 2]}")
        print(f"    p75: {lengths[3 * len(lengths) // 4]}")
        print(f"    p95: {lengths[int(len(lengths) * 0.95)]}")
        print(f"    max: {lengths[-1]}")
        over_limit = sum(1 for l in lengths if l > 6000)
        empty = sum(1 for l in lengths if l < 50)
        print(f"    超长 (>6000 字符): {over_limit} 条")
        print(f"    过短 (<50 字符): {empty} 条")

    print(f"\n  格式评估:")
    if not field_issues:
        print(f"    ✅ 格式一致")
    else:
        print(f"    ⚠️ 有 {len(field_issues)} 处格式问题")


def audit_sources():
    print("\n" + "=" * 60)
    print("【5/7】源文件存在性审计")
    print("=" * 60)
    missing = []
    for name in SOURCES_TO_CHECK:
        # 在 data 目录或子目录找
        candidates = [
            DATA_DIR / name,
            RAG_KNOWLEDGE_FILE if name == "knowledge.json" else None,
            HARD_SAMPLES_DIR / name if name == "manifest.json" else None,
        ]
        found = any(c and c.exists() for c in candidates if c)
        status = "✅" if found else "❌"
        print(f"  {status} {name}")
        if not found:
            missing.append(name)

    print(f"\n  源文件评估:")
    if not missing:
        print(f"    ✅ 全部源文件就位")
    else:
        print(f"    ⚠️ 缺失 {len(missing)} 个: {missing}")


def audit_content_categories(records: list[dict]):
    print("\n" + "=" * 60)
    print("【6/7】内容类别细分审计")
    print("=" * 60)
    ok = [r for r in records if "_parse_error" not in r]

    # 按 layer 细分内容类别
    print(f"  Layer A 知识层细分:")
    a_records = [r for r in ok if r.get("layer") == "A"]
    a_categories = Counter()
    for r in a_records:
        text = r.get("text", "")
        if "安全模式白名单" in text or "SAFE_PATTERN" in text:
            a_categories["安全模式白名单"] += 1
        elif "漏洞领域知识" in text and "CWE-" in text:
            # 提取 CWE 编号
            cwes = re.findall(r"CWE-\d+", text)
            if cwes:
                a_categories[f"CWE 百科条目 ({cwes[0]})"] += 1
            else:
                a_categories["CWE 百科条目 (无编号)"] += 1
        elif "### SYSTEM" in text:
            a_categories["SYSTEM 规则（不该出现！）"] += 1
        elif "方法.md" in text or "训练方法论" in text:
            a_categories["方法论文档"] += 1
        else:
            a_categories["其他"] += 1
    for cat, c in a_categories.most_common():
        print(f"    {cat}: {c} 条")

    print(f"\n  Layer B 推理层细分:")
    b_records = [r for r in ok if r.get("layer") == "B"]
    b_categories = Counter()
    for r in b_records:
        text = r.get("text", "")
        if "### SYSTEM" in text:
            b_categories["含 SYSTEM 规则（不该出现！）"] += 1
        elif "### CHOSEN RESPONSE" in text:
            b_categories["DPO chosen 响应"] += 1
        elif "### USER" in text and "### ASSISTANT" in text:
            b_categories["ChatML user+assistant"] += 1
        else:
            b_categories["其他"] += 1
    for cat, c in b_categories.most_common():
        print(f"    {cat}: {c} 条")

    print(f"\n  Layer C 代码层细分:")
    c_records = [r for r in ok if r.get("layer") == "C"]
    c_categories = Counter()
    for r in c_records:
        text = r.get("text", "")
        if "漏洞示例" in text:
            c_categories["漏洞示例"] += 1
        elif "安全示例" in text:
            c_categories["安全示例"] += 1
        else:
            c_categories["其他"] += 1
    for cat, c in c_categories.most_common():
        print(f"    {cat}: {c} 条")

    # 关键校验：SYSTEM 规则不应出现在任何 layer（已抽到 A 知识层）
    sys_in_b = sum(1 for r in b_records if "### SYSTEM" in r.get("text", ""))
    sys_in_a = sum(1 for r in a_records if "### SYSTEM" in r.get("text", ""))
    print(f"\n  关键校验:")
    print(f"    Layer A 中含 '### SYSTEM' 标记: {sys_in_a} 条 "
          f"({'✅ 应为 0（system 已剥离）' if sys_in_a == 0 else '❌ 异常'})")
    print(f"    Layer B 中含 '### SYSTEM' 标记: {sys_in_b} 条 "
          f"({'✅ 应为 0（system 已剥离）' if sys_in_b == 0 else '❌ 异常'})")


def audit_outliers(records: list[dict]):
    print("\n" + "=" * 60)
    print("【7/7】长尾与异常审计")
    print("=" * 60)
    ok = [r for r in records if "_parse_error" not in r]

    # 最长的 5 条
    by_len = sorted(ok, key=lambda r: len(r.get("text", "")), reverse=True)
    print(f"  Top 5 最长样本:")
    for r in by_len[:5]:
        preview = r.get("text", "")[:80].replace("\n", " ")
        print(f"    L{r.get('_line')} [{r.get('layer')}/{r.get('priority')}] "
              f"{len(r.get('text', ''))} 字符: {preview}...")

    # 最短的 5 条
    print(f"\n  Top 5 最短样本:")
    by_len_asc = sorted(ok, key=lambda r: len(r.get("text", "")))
    for r in by_len_asc[:5]:
        preview = r.get("text", "")[:80].replace("\n", " ")
        print(f"    L{r.get('_line')} [{r.get('layer')}/{r.get('priority')}] "
              f"{len(r.get('text', ''))} 字符: {preview}...")

    # 检查 max_seq_length=2048 会不会截断
    over_2048 = sum(1 for r in ok if estimate_tokens(r.get("text", "")) > 2048)
    print(f"\n  估算 token > 2048（会被 max_seq_length 截断）: {over_2048} 条")
    over_6000_chars = sum(1 for r in ok if len(r.get("text", "")) > 6000)
    print(f"  字符 > 6000（prepare_cpt_corpus.py 切分上限）: {over_6000_chars} 条 "
          f"({'✅ 应为 0' if over_6000_chars == 0 else '⚠️ 切分可能失效'})")


def main():
    parser = argparse.ArgumentParser(description="CPT 语料审计")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args()

    print("=" * 60)
    print(f"CPT 语料审计报告")
    print(f"  语料: {args.corpus}")
    print(f"  存在: {'✅' if args.corpus.exists() else '❌'}")
    print("=" * 60)

    if not args.corpus.exists():
        print(f"\n❌ 语料不存在，先运行 prepare_cpt_corpus.py")
        sys.exit(1)

    records = load_corpus(args.corpus)
    testset_code = load_testset_code()

    audit_volume(records)
    audit_duplicates(records)
    audit_testset_leak(records, testset_code)
    audit_format(records)
    audit_sources()
    audit_content_categories(records)
    audit_outliers(records)

    print("\n" + "=" * 60)
    print("审计完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
