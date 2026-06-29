"""
exp_04 报告生成器：扫描 results/ 下所有结果文件，生成 exp_04_report.md。

读取：
- results.p1-4.repeat3.*.json        P1-4 重复实验 + 置信区间
- results.ablation.{rag,pure,random,irrelevant}.topk3.json   P1-5 消融对照
- results.ablation.rag.topk{1,5,10}.json                      P2-8 Top-K 对比

输出：exp_04_report.md
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR / "results"
REPORT_PATH = SCRIPT_DIR / "exp_04_report.md"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def fmt_pct(x, default="N/A"):
    if x is None:
        return default
    return f"{x*100:.1f}%"


def fmt_ci(ci, default="N/A"):
    if ci is None or len(ci) != 2:
        return default
    return f"[{ci[0]*100:.1f}%, {ci[1]*100:.1f}%]"


def fmt_time(x, default="N/A"):
    if x is None:
        return default
    return f"{x:.1f}s"


def collect_metrics_single(results_data: dict) -> dict:
    """从结果 JSON 中提取单次口径指标。

    compute_detection_metrics 返回的字段名为：
        tp / tn / fp / fn / recall / false_positive_rate / accuracy /
        vuln_total / safe_total / elapsed_stats.{avg,max,min,sum,count}
    """
    m = results_data.get("metrics_single_run", {})
    es = m.get("elapsed_stats", {}) or {}
    return {
        "recall": m.get("recall"),
        "fpr": m.get("false_positive_rate"),
        "accuracy": m.get("accuracy"),
        "tp": m.get("tp"),
        "tn": m.get("tn"),
        "fp": m.get("fp"),
        "fn": m.get("fn"),
        "vuln_total": m.get("vuln_total"),
        "safe_total": m.get("safe_total"),
        "elapsed_mean": es.get("avg"),
        "elapsed_median": es.get("avg"),  # 单次口径没有中位数，用 avg 近似
        "elapsed_max": es.get("max"),
    }


def collect_metrics_majority(results_data: dict) -> dict:
    """从结果 JSON 中提取多数表决口径指标（含 Wilson 95% CI）。"""
    m = results_data.get("metrics_majority_vote", {})
    elapsed = m.get("elapsed_overall", {}) or {}
    return {
        "recall": m.get("recall"),
        "fpr": m.get("false_positive_rate"),
        "accuracy": m.get("accuracy"),
        "recall_ci": m.get("recall_ci_95"),
        "fpr_ci": m.get("fpr_ci_95"),
        "accuracy_ci": m.get("accuracy_ci_95"),
        "tp": m.get("tp"),
        "tn": m.get("tn"),
        "fp": m.get("fp"),
        "fn": m.get("fn"),
        "elapsed_mean": elapsed.get("mean"),
        "elapsed_median": elapsed.get("median"),
        "elapsed_std": elapsed.get("std"),
        "elapsed_p95": elapsed.get("p95"),
        "elapsed_max": elapsed.get("max"),
        "total_runs": m.get("total_runs"),
    }


def collect_topk_retrieval(results_data: dict) -> dict:
    """从 RAG 模式结果中收集检索质量指标（Top-K 类型命中率 + 平均距离）。"""
    samples = results_data.get("samples", [])
    type_hit_count = 0
    type_total = 0
    distances = []
    for s in samples:
        expected_cwe = s.get("expected_cwe", "")
        # 跨文件 helper 样本 expected_present=False，跳过
        if not s.get("expected_present"):
            continue
        if not expected_cwe or expected_cwe == "N/A":
            continue
        for run in s.get("runs", []):
            retrieval = run.get("rag_retrieval", []) or []
            if not retrieval:
                continue
            type_total += 1
            # 检查 Top-1 是否命中（按 CWE 匹配）
            top1 = retrieval[0] if retrieval else {}
            top1_cwe = top1.get("cwe", "") or ""
            if expected_cwe and expected_cwe in top1_cwe:
                type_hit_count += 1
            # 收集距离
            for r in retrieval:
                d = r.get("distance")
                if isinstance(d, (int, float)):
                    distances.append(d)
    return {
        "top1_hit_rate": type_hit_count / type_total if type_total else None,
        "top1_hits": type_hit_count,
        "top1_total": type_total,
        "avg_distance": sum(distances) / len(distances) if distances else None,
        "distance_count": len(distances),
    }


def main() -> int:
    # 收集所有结果文件
    p1_4_path = RESULTS_DIR / "results.p1-4.repeat3.qwen2.5-coder-14b.json"
    ablation_paths = {
        "rag (A组)": RESULTS_DIR / "results.ablation.rag.topk3.json",
        "pure (B组)": RESULTS_DIR / "results.ablation.pure.topk3.json",
        "random (C组)": RESULTS_DIR / "results.ablation.random.topk3.json",
        "irrelevant (D组)": RESULTS_DIR / "results.ablation.irrelevant.topk3.json",
    }
    topk_paths = {
        "K=1": RESULTS_DIR / "results.ablation.rag.topk1.json",
        "K=3": RESULTS_DIR / "results.ablation.rag.topk3.json",
        "K=5": RESULTS_DIR / "results.ablation.rag.topk5.json",
        "K=10": RESULTS_DIR / "results.ablation.rag.topk10.json",
    }

    p1_4 = load_json(p1_4_path)
    ablation_data = {k: load_json(v) for k, v in ablation_paths.items()}
    topk_data = {k: load_json(v) for k, v in topk_paths.items()}

    found = []
    if p1_4:
        found.append(("P1-4", p1_4_path.name))
    for k, v in ablation_data.items():
        if v:
            found.append((f"P1-5 {k}", ablation_paths[k].name))
    for k, v in topk_data.items():
        if v:
            found.append((f"P2-8 {k}", topk_paths[k].name))

    print(f"[信息] 找到 {len(found)} 个结果文件:")
    for name, fname in found:
        print(f"  - {name}: {fname}")

    if not found:
        print("[错误] 没有找到任何结果文件，请先跑实验", file=sys.stderr)
        return 1

    # -----------------------------------------------------------------
    # 组装报告
    # -----------------------------------------------------------------
    lines = []
    lines.append("# exp_04 难样本压力测试实验报告")
    lines.append("")
    lines.append("> 在扩充后的 42 段难样本集上系统评估 LLM 漏洞检测能力，覆盖三大维度：")
    lines.append("> - **P1-4 重复性与置信区间**：每样本跑 3 次，多数表决 + Wilson 95% CI")
    lines.append("> - **P1-5 RAG 消融对照**：A组(RAG+LLM) vs B组(纯LLM) vs C组(随机知识) vs D组(无关文本)")
    lines.append("> - **P2-8 Top-K 对比**：K=1,3,5,10 对检出率/检索质量/耗时的影响")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 一、实验设置")
    lines.append("")
    lines.append("| 项目 | 值 |")
    lines.append("| --- | --- |")
    lines.append("| 样本集 | exp_04_hard_samples（42 段） |")
    lines.append("| 样本分布 | 典型漏洞 12 + 安全对照 8 + 难样本 16 + 混淆噪音 6 |")
    lines.append("| 难样本类型 | 绕过过滤 4 / 跨文件污点 4 / 真实 CVE 4 / 长文件隐藏 2 / OWASP 风格 2 |")
    lines.append("| 模型 | `qwen2.5-coder:14b` |")
    lines.append("| 采样温度 | 0.1 |")
    lines.append("| 评估口径 | 单次口径 + 多数表决口径（含 Wilson 95% CI） |")
    lines.append("| 跨文件样本 | sink 文件分析时注入对应 input 文件作为上下文 |")
    lines.append("")

    # -----------------------------------------------------------------
    # P1-4
    # -----------------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## 二、P1-4：重复性与置信区间")
    lines.append("")
    if p1_4:
        env = p1_4.get("environment", p1_4)
        lines.append(f"**实验**：{p1_4.get('experiment', 'exp_04')}  ")
        lines.append(f"**模型**：{env.get('model', 'qwen2.5-coder:14b')}  ")
        lines.append(f"**重复次数**：{env.get('repeat', 3)}  ")
        lines.append(f"**总运行数**：{env.get('total_runs', 'N/A')}  ")
        lines.append("")
        lines.append("### 2.1 单次口径 vs 多数表决口径")
        lines.append("")
        single = collect_metrics_single(p1_4)
        majority = collect_metrics_majority(p1_4)
        lines.append("| 指标 | 单次口径（所有 run 拉平） | 多数表决口径（每样本 N 次投票） |")
        lines.append("| --- | --- | --- |")
        lines.append(f"| 召回率 | {fmt_pct(single['recall'])} | {fmt_pct(majority['recall'])} (95% CI {fmt_ci(majority['recall_ci'])}) |")
        lines.append(f"| 误报率 | {fmt_pct(single['fpr'])} | {fmt_pct(majority['fpr'])} (95% CI {fmt_ci(majority['fpr_ci'])}) |")
        lines.append(f"| 准确率 | {fmt_pct(single['accuracy'])} | {fmt_pct(majority['accuracy'])} (95% CI {fmt_ci(majority['accuracy_ci'])}) |")
        lines.append(f"| TP/TN/FP/FN | {single['tp']}/{single['tn']}/{single['fp']}/{single['fn']} | {majority['tp']}/{majority['tn']}/{majority['fp']}/{majority['fn']} |")
        lines.append("")
        lines.append("### 2.2 耗时分布")
        lines.append("")
        lines.append("| 统计量 | 值 |")
        lines.append("| --- | --- |")
        lines.append(f"| 总运行数 | {majority['total_runs']} |")
        lines.append(f"| 平均耗时 | {fmt_time(majority['elapsed_mean'])} |")
        lines.append(f"| 中位数耗时 | {fmt_time(majority['elapsed_median'])} |")
        lines.append(f"| 标准差 | {fmt_time(majority['elapsed_std'])} |")
        lines.append(f"| p95 耗时 | {fmt_time(majority['elapsed_p95'])} |")
        lines.append(f"| 最长耗时 | {fmt_time(majority['elapsed_max'])} |")
        lines.append("")
        lines.append("### 2.3 单样本一致率分布")
        lines.append("")
        # 一致率统计
        per_sample = p1_4.get("metrics_majority_vote", {}).get("per_sample", [])
        if per_sample:
            agreements = [s.get("agreement_rate", 0) for s in per_sample]
            full_agree = sum(1 for a in agreements if a >= 1.0)
            high_agree = sum(1 for a in agreements if a >= 2/3)
            low_agree = [s for s in per_sample if s.get("agreement_rate", 1) < 2/3]
            lines.append(f"- 完全一致（agreement=1.0）：{full_agree}/{len(per_sample)}")
            lines.append(f"- 高一致（agreement≥2/3）：{high_agree}/{len(per_sample)}")
            lines.append(f"- 低一致（agreement<2/3，模型判定不稳定）：{len(low_agree)}")
            if low_agree:
                lines.append("")
                lines.append("**判定不稳定的样本**：")
                lines.append("")
                lines.append("| 文件 | 期望 | 多数表决 | 一致率 | True 次数 / 总次数 |")
                lines.append("| --- | --- | --- | --- | --- |")
                for s in low_agree:
                    lines.append(f"| {s['file']} | {s['expected_present']} | {s['majority_verdict']} | {s['agreement_rate']} | {s.get('true_count_in_runs', 0)}/{s['runs']} |")
        lines.append("")
    else:
        lines.append("> P1-4 结果未找到，跳过本节。")
        lines.append("")

    # -----------------------------------------------------------------
    # P1-5
    # -----------------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## 三、P1-5：RAG 消融对照实验")
    lines.append("")
    lines.append("在相同 42 段样本上对比 4 组，验证 RAG 提升是否来自知识相关性：")
    lines.append("")
    lines.append("- **A 组 (rag)**：RAG+LLM，按代码语义检索 Top-3")
    lines.append("- **B 组 (pure)**：纯 LLM，无 RAG 上下文")
    lines.append("- **C 组 (random)**：随机从知识库抽 3 条（与样本无关）")
    lines.append("- **D 组 (irrelevant)**：等长无关文本（与漏洞完全无关）")
    lines.append("")
    lines.append("### 3.1 总体指标对比")
    lines.append("")
    lines.append("| 组别 | 召回率 | 误报率 | 准确率 | TP/TN/FP/FN | 平均耗时 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for label, data in ablation_data.items():
        if not data:
            lines.append(f"| {label} | (未运行) | - | - | - | - |")
            continue
        m = collect_metrics_single(data)
        lines.append(
            f"| {label} | {fmt_pct(m['recall'])} | {fmt_pct(m['fpr'])} | "
            f"{fmt_pct(m['accuracy'])} | {m['tp']}/{m['tn']}/{m['fp']}/{m['fn']} | "
            f"{fmt_time(m['elapsed_mean'])} |"
        )
    lines.append("")
    lines.append("### 3.2 结论判断")
    lines.append("")
    lines.append("按以下逻辑判断 RAG 是否真正有用：")
    lines.append("")
    lines.append("- 若 A > B：RAG 注入知识确实带来提升")
    lines.append("- 若 A ≈ B：RAG 在该样本集上无明显作用（可能因模型已具备知识）")
    lines.append("- 若 A > C 且 A > D：提升来自知识相关性，而非 prompt 变长")
    lines.append("- 若 A ≈ C 或 A ≈ D：提升仅来自 prompt 变长，RAG 无实质价值")
    lines.append("")

    # -----------------------------------------------------------------
    # P2-8
    # -----------------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## 四、P2-8：RAG Top-K 对比")
    lines.append("")
    lines.append("在相同 42 段样本上对比 K=1,3,5,10 对检出率、检索质量、耗时的影响。")
    lines.append("")
    lines.append("### 4.1 检出率与耗时")
    lines.append("")
    lines.append("| Top-K | 召回率 | 误报率 | 准确率 | TP/TN/FP/FN | 平均耗时 | 中位数耗时 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for label, data in topk_data.items():
        if not data:
            lines.append(f"| {label} | (未运行) | - | - | - | - | - |")
            continue
        m = collect_metrics_single(data)
        lines.append(
            f"| {label} | {fmt_pct(m['recall'])} | {fmt_pct(m['fpr'])} | "
            f"{fmt_pct(m['accuracy'])} | {m['tp']}/{m['tn']}/{m['fp']}/{m['fn']} | "
            f"{fmt_time(m['elapsed_mean'])} | {fmt_time(m['elapsed_median'])} |"
        )
    lines.append("")
    lines.append("### 4.2 检索质量（Top-1 类型命中率 + 平均距离）")
    lines.append("")
    lines.append("| Top-K | Top-1 类型命中率 | Top-1 命中数 / 总数 | 平均检索距离 |")
    lines.append("| --- | --- | --- | --- |")
    for label, data in topk_data.items():
        if not data:
            lines.append(f"| {label} | (未运行) | - | - |")
            continue
        r = collect_topk_retrieval(data)
        avg_dist = f"{r['avg_distance']:.4f}" if r['avg_distance'] is not None else "N/A"
        lines.append(
            f"| {label} | {fmt_pct(r['top1_hit_rate'])} | "
            f"{r['top1_hits']}/{r['top1_total']} | "
            f"{avg_dist} |"
        )
    lines.append("")
    lines.append("### 4.3 推荐 K 值")
    lines.append("")
    lines.append("综合检出率、检索质量与耗时权衡，给出后续系统推荐使用的 K 值及理由。")
    lines.append("")

    # -----------------------------------------------------------------
    # 收尾
    # -----------------------------------------------------------------
    lines.append("---")
    lines.append("")
    lines.append("## 五、与 exp_01 基线对比")
    lines.append("")
    lines.append("| 实验 | 样本数 | 召回率 | 误报率 | 准确率 | 备注 |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    lines.append("| exp_01（14 段典型样本） | 14 | 100% | 0% | 100% | 教科书式漏洞，能力下限 |")
    if p1_4:
        m = collect_metrics_majority(p1_4)
        lines.append(f"| exp_04 P1-4（42 段难样本，repeat=3） | 42 | {fmt_pct(m['recall'])} | {fmt_pct(m['fpr'])} | {fmt_pct(m['accuracy'])} | 多数表决 + 95% CI |")
    lines.append("")
    lines.append("> 若 exp_04 准确率明显低于 exp_01，说明难样本确实测出了模型的边界，")
    lines.append('> 而非"样本太简单导致 100%"。这正是本实验设计的核心目的。')
    lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[完成] 报告已生成: {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
