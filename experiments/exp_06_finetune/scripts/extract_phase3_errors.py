"""Phase 3 KnItLM 错题分析与 Phase 1 回归检查

对比 Phase 1 baseline (lr1e-5_base) 与 Phase 3 KnItLM (knitlm_merged) 的逐样本判定，
产出三类信息（论文错误分析章节素材）：

1. Phase 3 仍错的样本（FP / FN / CWE 错标）—— KnItLM 残留问题
2. Phase 1 答对、Phase 3 答错的样本 —— KnItLM 引入的回归（保守化副作用？）
3. Phase 1 答错、Phase 3 答对的样本 —— KnItLM 修复的样本（验证 CPT 价值）

输出：
- results/phase3_error_analysis.md：人工审阅用的 markdown 报告
- results/phase3_vs_phase1_regression.json：结构化数据，供后续 supplement_*.py 用

用法：
    PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
        experiments/exp_06_finetune/scripts/extract_phase3_errors.py

注：脚本只读 result JSON，不依赖模型权重，笔记本可直接跑。
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

RESULTS_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/results"
OUTPUT_MD = RESULTS_DIR / "phase3_error_analysis.md"
OUTPUT_JSON = RESULTS_DIR / "phase3_vs_phase1_regression.json"

# Phase 1 baseline 与 Phase 3 KnItLM 的 eval 文件
# Phase 1 取 20260718_151305（正式重跑版，与 phase1_sweep_summary.md 一致）
PHASE1_EVAL = RESULTS_DIR / "exp_06_eval.phase1_lr1e-5_base.20260718_151305.json"
PHASE3_EVAL = RESULTS_DIR / "exp_06_eval.knitlm_merged.20260719_070818.json"

_CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def extract_cwe(vt: str) -> str:
    if not vt:
        return ""
    m = _CWE_PATTERN.search(vt)
    return m.group(1).upper() if m else ""


def cwe_matches(model_cwe: str, expected_cwe: str) -> bool:
    if not expected_cwe or expected_cwe.upper() == "N/A":
        return True
    if not model_cwe:
        return False
    expected = [c.strip().upper() for c in expected_cwe.split(";") if c.strip()]
    return model_cwe in expected


# 错误类别关键词（用于自动分类提示，非绝对判定）
# 参考 docs/改进.md §1 的根因分类
CATEGORY_KEYWORDS = {
    "shell偏见": ["shell=true", "shell = true", "subprocess", "shell 解释"],
    "SSTI概念混淆": ["ssti", "from_string", "jinja", "template"],
    "CWE-89错标SSTI": ["cwe-89"],  # 单独检查：把 SSTI 标成 CWE-89
    "结论漂移": ["secrets", "已用", "secure", "安全的方法"],
    "跨文件认知": ["base_dir", "调用方", "函数参数"],
    "missing_feature": ["csrf", "未授权", "session", "整数溢出", "integer_overflow",
                       "missing_auth", "认证缺失", "授权缺失"],
}


def classify_error(sample: dict) -> list[str]:
    """根据 raw_output 关键词给出错误类别提示（启发式，非精判）"""
    raw = (sample.get("raw_output") or "").lower()
    cats = []
    for cat, kws in CATEGORY_KEYWORDS.items():
        if any(kw.lower() in raw for kw in kws):
            cats.append(cat)
    return cats or ["未分类"]


def load_samples(path: Path) -> dict[str, dict]:
    """按 file 名建立索引"""
    data = json.loads(path.read_text())
    return {s["file"]: s for s in data.get("samples", [])}


def main():
    if not PHASE1_EVAL.exists():
        print(f"❌ Phase 1 eval 不存在: {PHASE1_EVAL}")
        return
    if not PHASE3_EVAL.exists():
        print(f"❌ Phase 3 eval 不存在: {PHASE3_EVAL}")
        return

    p1 = load_samples(PHASE1_EVAL)
    p3 = load_samples(PHASE3_EVAL)
    print(f"Phase 1 样本数: {len(p1)}，Phase 3 样本数: {len(p3)}")

    common_files = sorted(set(p1.keys()) & set(p3.keys()))
    print(f"共有样本: {len(common_files)}")

    # ---- 1. Phase 3 仍错的样本 ----
    p3_errors = []
    for f in common_files:
        s = p3[f]
        outcome = s.get("outcome", "")
        expected_cwe = s.get("expected_cwe", "")
        model_vt = s.get("model_vulnerability_type", "") or ""
        model_cwe = extract_cwe(model_vt)
        cwe_wrong = (outcome == "TP") and expected_cwe and \
                    expected_cwe.upper() != "N/A" and \
                    not cwe_matches(model_cwe, expected_cwe)
        if outcome in ("FP", "FN") or cwe_wrong:
            p3_errors.append({
                "file": f,
                "category": s.get("category", ""),
                "difficulty": s.get("difficulty", ""),
                "expected_present": s.get("expected_present"),
                "expected_cwe": expected_cwe,
                "expected_vulnerability": s.get("expected_vulnerability", ""),
                "outcome": outcome,
                "model_vulnerability_type": model_vt,
                "model_cwe": model_cwe,
                "cwe_wrong": cwe_wrong,
                "category_hints": classify_error(s),
                "raw_output_excerpt": (s.get("raw_output") or "")[:600],
            })

    # ---- 2. Phase 1 → Phase 3 回归分析 ----
    regressions = []   # Phase 1 对 → Phase 3 错
    fixes = []         # Phase 1 错 → Phase 3 对
    for f in common_files:
        s1 = p1[f]
        s3 = p3[f]
        o1 = s1.get("outcome", "")
        o3 = s3.get("outcome", "")

        def is_correct(o, s):
            """TP 且 CWE 对 / TN"""
            if o == "TN":
                return True
            if o == "TP":
                expected_cwe = s.get("expected_cwe", "")
                if not expected_cwe or expected_cwe.upper() == "N/A":
                    return True
                model_cwe = extract_cwe(s.get("model_vulnerability_type", "") or "")
                return cwe_matches(model_cwe, expected_cwe)
            return False

        c1 = is_correct(o1, s1)
        c3 = is_correct(o3, s3)
        if c1 and not c3:
            regressions.append({
                "file": f,
                "category": s3.get("category", ""),
                "p1_outcome": o1,
                "p3_outcome": o3,
                "expected_present": s3.get("expected_present"),
                "expected_cwe": s3.get("expected_cwe", ""),
                "p3_model_vulnerability_type": s3.get("model_vulnerability_type", ""),
                "category_hints": classify_error(s3),
                "raw_output_excerpt": (s3.get("raw_output") or "")[:800],
            })
        elif not c1 and c3:
            fixes.append({
                "file": f,
                "category": s3.get("category", ""),
                "p1_outcome": o1,
                "p3_outcome": o3,
                "expected_cwe": s3.get("expected_cwe", ""),
            })

    # ---- 3. 输出 markdown 报告 ----
    lines = []
    lines.append("# Phase 3 KnItLM 错题分析与 Phase 1 回归检查\n")
    lines.append(f"> 自动生成：对比 Phase 1 baseline ({PHASE1_EVAL.name}) vs Phase 3 KnItLM ({PHASE3_EVAL.name})")
    lines.append(f"> 共有样本 {len(common_files)} 个，Phase 3 残留错题 {len(p3_errors)} 个，"
                 f"Phase 1→3 回归 {len(regressions)} 个，Phase 1→3 修复 {len(fixes)} 个\n")

    # Section 1: Phase 3 残留错题
    lines.append("## 1. Phase 3 KnItLM 残留错题（论文错误分析章节素材）\n")
    lines.append("| file | category | outcome | expected_cwe | model_cwe | 类别提示 |")
    lines.append("|------|----------|---------|--------------|-----------|----------|")
    for e in p3_errors:
        lines.append(
            f"| {e['file']} | {e['category']} | {e['outcome']} "
            f"{'(CWE错)' if e['cwe_wrong'] else ''} | {e['expected_cwe']} | "
            f"{e['model_cwe']} | {', '.join(e['category_hints'])} |"
        )
    lines.append("")

    # 错题类别分布
    cat_counter = Counter()
    for e in p3_errors:
        for c in e["category_hints"]:
            cat_counter[c] += 1
    lines.append("### 1.1 错题类别分布\n")
    lines.append("| 类别 | 数量 |")
    lines.append("|------|------|")
    for c, n in cat_counter.most_common():
        lines.append(f"| {c} | {n} |")
    lines.append("")

    # Section 2: Phase 1 → Phase 3 回归（关键！KnItLM 引入的副作用）
    lines.append("## 2. Phase 1 答对、Phase 3 答错的样本（KnItLM 回归）\n")
    if not regressions:
        lines.append("✅ 无回归样本——Phase 3 在所有 Phase 1 答对的样本上仍答对。\n")
    else:
        lines.append(f"⚠️ 共 {len(regressions)} 个回归样本。需检查是否 KnItLM CPT 引入了保守化倾向。\n")
        lines.append("| file | category | P1→P3 outcome | expected_cwe | 类别提示 |")
        lines.append("|------|----------|---------------|--------------|----------|")
        for r in regressions:
            lines.append(
                f"| {r['file']} | {r['category']} | {r['p1_outcome']}→{r['p3_outcome']} | "
                f"{r['expected_cwe']} | {', '.join(r['category_hints'])} |"
            )
        lines.append("")
        lines.append("### 2.1 回归样本 raw_output 摘录（人工审阅）\n")
        for r in regressions:
            lines.append(f"#### {r['file']}（{r['p1_outcome']}→{r['p3_outcome']}）")
            lines.append(f"- expected_present: {r['expected_present']}, expected_cwe: {r['expected_cwe']}")
            lines.append(f"- P3 model_vulnerability_type: {r['p3_model_vulnerability_type']}")
            lines.append(f"- 类别提示: {', '.join(r['category_hints'])}")
            lines.append("\n```\n" + r["raw_output_excerpt"] + "\n```\n")

    # Section 3: Phase 1 → Phase 3 修复
    lines.append("## 3. Phase 1 答错、Phase 3 答对的样本（KnItLM 修复）\n")
    if not fixes:
        lines.append("（无修复样本）\n")
    else:
        lines.append(f"共 {len(fixes)} 个修复样本——验证 KnItLM CPT 的价值。\n")
        lines.append("| file | category | P1→P3 outcome | expected_cwe |")
        lines.append("|------|----------|---------------|--------------|")
        for r in fixes:
            lines.append(
                f"| {r['file']} | {r['category']} | {r['p1_outcome']}→{r['p3_outcome']} | "
                f"{r['expected_cwe']} |"
            )
        lines.append("")

    # Section 4: 总结与建议
    lines.append("## 4. 总结\n")
    lines.append(f"- **Phase 3 残留错题**：{len(p3_errors)} 个")
    lines.append(f"- **Phase 1→3 回归**：{len(regressions)} 个（KnItLM 是否保守化的关键证据）")
    lines.append(f"- **Phase 1→3 修复**：{len(fixes)} 个（KnItLM CPT 价值的直接证据）\n")
    if regressions:
        lines.append("**下一步行动**：")
        lines.append("1. 逐个审阅 §2.1 的回归样本 raw_output，判断是否为保守化倾向")
        lines.append("2. 若回归集中某类漏洞（如 SSTI/CSRF），需 supplement_*.py 针对性补强")
        lines.append("3. Phase 4 PD 完成后，用本脚本对比 Phase 3 vs Phase 4，检查 PD 是否修复回归")
    else:
        lines.append("**结论**：Phase 3 KnItLM 无回归——CPT 注入的知识没有引入副作用，"
                     "严格 recall +23pp 是纯增益。可作为论文 KnItLM 章节的关键论据。")
    lines.append("")

    OUTPUT_MD.write_text("\n".join(lines))
    print(f"\n✅ Markdown 报告：{OUTPUT_MD}")

    # ---- 4. 输出 JSON（供后续脚本使用）----
    OUTPUT_JSON.write_text(json.dumps({
        "phase1_eval": PHASE1_EVAL.name,
        "phase3_eval": PHASE3_EVAL.name,
        "common_samples": len(common_files),
        "p3_errors": p3_errors,
        "regressions": regressions,
        "fixes": fixes,
    }, ensure_ascii=False, indent=2))
    print(f"✅ 结构化数据：{OUTPUT_JSON}")

    # ---- 5. 控制台摘要 ----
    print("\n" + "=" * 60)
    print(f"Phase 3 残留错题：{len(p3_errors)}")
    print(f"Phase 1→3 回归：{len(regressions)}")
    print(f"Phase 1→3 修复：{len(fixes)}")
    if regressions:
        print("\n回归样本（Phase 1 对 → Phase 3 错）：")
        for r in regressions:
            print(f"  - {r['file']} ({r['p1_outcome']}→{r['p3_outcome']})")


if __name__ == "__main__":
    main()
