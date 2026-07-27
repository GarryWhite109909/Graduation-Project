"""课程学习调度器 —— 将训练数据按 CWE 难度分为三个阶段，支持阶段间回放。

依据 docs/对话.md 的"类人学习范式"：由易到难，先学基础注入模式，
再学语义推理，最后攻克缺失控制类（需"反证"推理）。

课程阶段设计：
  Phase A（注入类基础）: CWE-89/79/78/22 — 模式清晰（source→sink 直接映射），易学
  Phase B（语义推理类）: CWE-502/1336/94/611 — 需理解 API 语义（如 pickle.loads = RCE）
  Phase C（缺失控制类）: CWE-352/200/798/639/190 — 需"反证"推理（代码里缺什么）

设计原则：
  - 难度评分基于 CWE 类别（0.0=易 → 1.0=难），而非超参调优
  - 安全样本（has_vulnerability=false）比漏洞样本难 0.1（需"反证"）
  - 含防御代码但仍有漏洞的场景最难（+0.15，绕过场景）
  - 阶段间回放 replay_ratio=0.3，防止灾难性遗忘
  - 可选：基于 probe_report 的 mastered/fuzzy/error 动态调整阶段

用法：
  # 生成课程学习配置
  python3 curriculum_scheduler.py \\
      --data data/train_chatml_v2.jsonl \\
      --output data/curriculum_phases.json

  # 结合探测报告动态调整
  python3 curriculum_scheduler.py \\
      --data data/train_chatml_v2.jsonl \\
      --probe-report data/probe_report.json \\
      --output data/curriculum_phases.json

  # 仅分析数据集的难度分布（不生成配置）
  python3 curriculum_scheduler.py \\
      --data data/train_chatml_v2.jsonl \\
      --analyze-only

输出格式（curriculum_phases.json）：
  {
    "phases": [
      {
        "name": "Phase A: 注入类基础",
        "description": "CWE-89/79/78/22，source→sink 直接映射，模式清晰",
        "sample_indices": [0, 3, 7, ...],
        "difficulty_range": [0.0, 0.3],
        "sample_count": 100,
        "cwe_distribution": {"CWE-89": 30, "CWE-79": 25, ...}
      },
      ...
    ],
    "phase_sizes": [0.4, 0.35, 0.25],
    "replay_ratio": 0.3,
    "total_samples": 250
  }
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"

# ---------------------------------------------------------------------------
# CWE → 课程阶段 + 难度分数映射
# ---------------------------------------------------------------------------

# Phase A: 注入类基础（source→sink 直接映射，模式清晰）
PHASE_A_CWES = {
    "CWE-89": 0.15,   # SQL 注入：字符串拼接 → execute，模式最清晰
    "CWE-79": 0.20,   # XSS：未转义输出，模式清晰
    "CWE-78": 0.20,   # 命令注入：shell=True + 字符串拼接
    "CWE-22": 0.25,   # 路径穿越：用户输入 + open，略需路径语义
}

# Phase B: 语义推理类（需理解 API 语义）
PHASE_B_CWES = {
    "CWE-502": 0.45,  # 反序列化：需理解 pickle.loads = RCE
    "CWE-1336": 0.50, # SSTI：需理解 from_string vs render
    "CWE-94": 0.50,   # 代码注入：eval/exec
    "CWE-95": 0.50,   # eval 注入
    "CWE-611": 0.55,  # XXE：需理解 XML 解析器配置
    "CWE-327": 0.50,  # 弱密码学：需理解算法语义
    "CWE-330": 0.50,  # 弱随机
    "CWE-918": 0.55,  # SSRF
}

# Phase C: 缺失控制类（需"反证"推理：代码里缺什么）
PHASE_C_CWES = {
    "CWE-352": 0.70,  # CSRF：缺 token 验证
    "CWE-200": 0.75,  # 敏感数据泄露：缺错误处理/脱敏
    "CWE-209": 0.75,  # 错误信息泄露
    "CWE-798": 0.80,  # 硬编码凭证：需识别变量名+字面量
    "CWE-639": 0.80,  # IDOR：缺权限检查
    "CWE-862": 0.85,  # 缺少授权
    "CWE-863": 0.85,  # 授权不正确
    "CWE-190": 0.85,  # 整数溢出：缺边界检查
    "CWE-306": 0.80,  # 缺少认证
}

# 合并为完整映射
CWE_DIFFICULTY: dict[str, float] = {}
CWE_DIFFICULTY.update(PHASE_A_CWES)
CWE_DIFFICULTY.update(PHASE_B_CWES)
CWE_DIFFICULTY.update(PHASE_C_CWES)

# 阶段描述
PHASE_DESCRIPTIONS = {
    "Phase A": "注入类基础（CWE-89/79/78/22），source→sink 直接映射，模式清晰，易学",
    "Phase B": "语义推理类（CWE-502/1336/94/611），需理解 API 语义（如 pickle.loads=RCE）",
    "Phase C": "缺失控制类（CWE-352/798/639/190），需反证推理（代码里缺什么）",
}

# 安全模式关键词（用于识别安全样本中的防御代码）
SAFE_PATTERN_KEYWORDS = [
    "参数化", "parameterized", "prepared", "placeholder",
    "html.escape", "markupsafe", "autoescape", "textContent",
    "shell=False", "列表形式", "shlex.quote",
    "abspath", "startswith", "secure_filename",
    "json.loads", "safe_load", "hmac",
    "os.environ", "getenv",
]


def extract_cwe_from_sample(sample: dict) -> str | None:
    """从训练样本中提取 CWE 编号。

    查找路径：
    1. messages 中 assistant 的 vulnerability_type 字段
    2. messages 中 user 的代码上下文暗示
    3. 其他 metadata 字段
    """
    _CWE_PATTERN = re.compile(r"(CWE-\d+)", re.IGNORECASE)

    if "messages" in sample:
        for msg in sample.get("messages", []):
            role = msg.get("role", "")
            content = msg.get("content", "")
            # 优先从 assistant 的 JSON 结论中提取
            if role == "assistant":
                m = _CWE_PATTERN.search(content)
                if m:
                    return m.group(1).upper()

    # 从其他字段查找
    for key in ("cwe", "expected_cwe", "vulnerability_type"):
        val = sample.get(key, "")
        if val:
            m = _CWE_PATTERN.search(str(val))
            if m:
                return m.group(1).upper()

    return None


def is_safe_sample(sample: dict) -> bool:
    """判断样本是否为安全样本（has_vulnerability=false）。"""
    if "messages" in sample:
        for msg in sample.get("messages", []):
            if msg.get("role") == "assistant":
                content = msg.get("content", "").lower()
                # 检查 JSON 结论中 has_vulnerability=false
                if '"has_vulnerability": false' in content or \
                   '"has_vulnerability":false' in content or \
                   'has_vulnerability=false' in content:
                    return True
                if '"has_vulnerability": true' in content or \
                   '"has_vulnerability":true' in content or \
                   'has_vulnerability=true' in content:
                    return False
                # 检查中文判断
                if "无漏洞" in content or re.search(r"(?<!不)安全", content.split("has_vulnerability")[0][-50:]):
                    return True

    # 其他字段
    if sample.get("has_vulnerability") is False:
        return True
    if sample.get("expected_present") is False:
        return True

    return False


def has_defense_code(sample: dict) -> bool:
    """判断样本是否包含防御代码（但仍可能有漏洞）。"""
    if "messages" in sample:
        for msg in sample.get("messages", []):
            if msg.get("role") == "user":
                content = msg.get("content", "").lower()
                for kw in SAFE_PATTERN_KEYWORDS:
                    if kw.lower() in content:
                        return True
    return False


def score_sample_difficulty(sample: dict) -> float:
    """为训练样本计算难度分数（0.0=易 → 1.0=难）。

    评分维度：
    1. CWE 类别基础分（Phase A: 0.15-0.25, Phase B: 0.45-0.55, Phase C: 0.70-0.85）
    2. 安全样本 +0.10（需"反证"推理，更难）
    3. 含防御代码但仍有漏洞 +0.15（绕过场景，最难）
    4. 未知 CWE → 默认 0.50（中间难度）
    """
    # 基础分
    cwe = extract_cwe_from_sample(sample)
    if cwe and cwe in CWE_DIFFICULTY:
        base_score = CWE_DIFFICULTY[cwe]
    else:
        base_score = 0.50  # 未知 CWE，中间难度

    # 安全样本加难度
    if is_safe_sample(sample):
        base_score += 0.10

    # 含防御代码但仍有漏洞（绕过场景），最难点
    if not is_safe_sample(sample) and has_defense_code(sample):
        base_score += 0.15

    # 限制在 [0.0, 1.0]
    return min(1.0, max(0.0, base_score))


def build_curriculum_phases(
    samples: list[dict],
    phase_sizes: list[float] | None = None,
    probe_report: dict | None = None,
) -> list[dict]:
    """按难度分数将训练集切分为课程阶段。

    Args:
        samples: 训练样本列表
        phase_sizes: 各阶段样本占比（默认 [0.4, 0.35, 0.25]）
        probe_report: 可选的探测报告，用于动态调整阶段

    Returns:
        各阶段的配置信息（含样本索引、难度范围、CWE 分布）
    """
    if phase_sizes is None:
        phase_sizes = [0.4, 0.35, 0.25]

    # TODO: replay_ratio 当前仅写入配置，采样逻辑未实现阶段间回放

    # 为每个样本计算难度
    indexed_scores = []
    for i, sample in enumerate(samples):
        score = score_sample_difficulty(sample)
        cwe = extract_cwe_from_sample(sample)
        indexed_scores.append((i, score, cwe))

    # 按难度排序
    indexed_scores.sort(key=lambda x: x[1])

    # 可选：基于 probe_report 调整
    # 对 fuzzy/error 的 CWE 降低难度分（让它们更早被训练）
    if probe_report:
        summary = probe_report.get("summary", {})
        fuzzy_cwes = set(summary.get("fuzzy_cwes", []))
        error_cwes = set(summary.get("error_cwes", []))
        # error CWE → 降难度到 Phase A（最先学）
        # fuzzy CWE → 降难度到 Phase A/B
        adjusted = []
        for idx, score, cwe in indexed_scores:
            if cwe and cwe in error_cwes:
                score = min(score, 0.20)  # 降到 Phase A
            elif cwe and cwe in fuzzy_cwes:
                score = min(score, 0.35)  # 降到 Phase A/B 交界
            adjusted.append((idx, score, cwe))
        adjusted.sort(key=lambda x: x[1])
        indexed_scores = adjusted

    # 切分阶段
    n = len(indexed_scores)
    phase_names = ["Phase A: 注入类基础", "Phase B: 语义推理类", "Phase C: 缺失控制类"]
    phases = []

    start = 0
    for phase_idx, (name, size) in enumerate(zip(phase_names, phase_sizes)):
        end = start + int(n * size) if phase_idx < len(phase_sizes) - 1 else n
        phase_samples = indexed_scores[start:end]

        # 收集阶段信息
        sample_indices = [s[0] for s in phase_samples]
        difficulties = [s[1] for s in phase_samples]
        cwe_counter = Counter()
        for _, _, cwe in phase_samples:
            if cwe:
                cwe_counter[cwe] += 1

        phase_info = {
            "name": name,
            "description": PHASE_DESCRIPTIONS.get(name.split(":")[0], ""),
            "sample_indices": sample_indices,
            "difficulty_range": [
                min(difficulties) if difficulties else 0.0,
                max(difficulties) if difficulties else 0.0,
            ],
            "difficulty_mean": sum(difficulties) / len(difficulties) if difficulties else 0.0,
            "sample_count": len(sample_indices),
            "cwe_distribution": dict(cwe_counter.most_common()),
        }
        phases.append(phase_info)
        start = end

    return phases


def analyze_difficulty_distribution(samples: list[dict]) -> None:
    """打印数据集的难度分布分析。"""
    scores = [score_sample_difficulty(s) for s in samples]
    cwe_counter = Counter()
    safe_count = 0
    defense_count = 0

    for sample in samples:
        cwe = extract_cwe_from_sample(sample)
        if cwe:
            cwe_counter[cwe] += 1
        if is_safe_sample(sample):
            safe_count += 1
        if has_defense_code(sample):
            defense_count += 1

    print(f"\n{'='*60}")
    print(f"数据集难度分布分析")
    print(f"{'='*60}")
    print(f"总样本数: {len(samples)}")
    print(f"安全样本: {safe_count} ({safe_count/len(samples)*100:.1f}%)")
    print(f"含防御代码: {defense_count} ({defense_count/len(samples)*100:.1f}%)")
    print(f"难度均值: {sum(scores)/len(scores):.3f}")
    print(f"难度中位数: {sorted(scores)[len(scores)//2]:.3f}")

    print(f"\nCWE 分布（Top 15）：")
    for cwe, count in cwe_counter.most_common(15):
        diff = CWE_DIFFICULTY.get(cwe, 0.50)
        phase = "A" if diff < 0.3 else ("B" if diff < 0.6 else "C")
        print(f"  {cwe}: {count} 条 (难度={diff:.2f}, Phase {phase})")

    # 阶段分布
    print(f"\n三阶段分布：")
    for name, cwes in [("Phase A", PHASE_A_CWES), ("Phase B", PHASE_B_CWES), ("Phase C", PHASE_C_CWES)]:
        count = sum(cwe_counter.get(cwe, 0) for cwe in cwes)
        other = len(samples) - count
        print(f"  {name}: {count} 条 ({count/len(samples)*100:.1f}%) + 其他/未知 {other}")


def main():
    parser = argparse.ArgumentParser(
        description="课程学习调度器：将训练数据按 CWE 难度分阶段",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=DATA_DIR / "train_chatml_v2.jsonl",
        help=f"训练数据路径（默认 train_chatml_v2.jsonl）",
    )
    parser.add_argument(
        "--probe-report",
        type=Path,
        default=None,
        help="探测报告路径（可选，动态调整阶段）",
    )
    parser.add_argument(
        "--phase-sizes",
        type=str,
        default="0.4,0.35,0.25",
        help="各阶段样本占比（默认 0.4,0.35,0.25）",
    )
    parser.add_argument(
        "--replay-ratio",
        type=float,
        default=0.3,
        help="阶段间回放比例（默认 0.3）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "curriculum_phases.json",
        help=f"输出路径（默认 curriculum_phases.json）",
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="仅分析数据集难度分布，不生成配置",
    )

    args = parser.parse_args()

    # 解析 phase_sizes
    phase_sizes = [float(x) for x in args.phase_sizes.split(",")]
    assert len(phase_sizes) == 3, f"phase_sizes 需 3 个值，得到 {len(phase_sizes)}"

    # 加载数据
    print(f"加载数据: {args.data}")
    if not args.data.exists():
        print(f"❌ 数据文件不存在: {args.data}", file=sys.stderr)
        sys.exit(1)

    samples = []
    with open(args.data, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                samples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    print(f"  加载 {len(samples)} 条样本")

    # 仅分析模式
    if args.analyze_only:
        analyze_difficulty_distribution(samples)
        return

    # 加载探测报告
    probe_report = None
    if args.probe_report:
        print(f"加载探测报告: {args.probe_report}")
        with open(args.probe_report, encoding="utf-8") as f:
            probe_report = json.load(f)
        summary = probe_report.get("summary", {})
        print(f"  mastered: {summary.get('mastered_count', 0)}, "
              f"fuzzy: {summary.get('fuzzy_count', 0)}, "
              f"error: {summary.get('error_count', 0)}")

    # 构建课程阶段
    print(f"\n构建课程阶段（phase_sizes={phase_sizes}, replay_ratio={args.replay_ratio})...")
    phases = build_curriculum_phases(samples, phase_sizes, probe_report)

    # 打印阶段信息
    print(f"\n{'='*60}")
    print(f"课程学习阶段配置")
    print(f"{'='*60}")
    for phase in phases:
        print(f"\n{phase['name']}")
        print(f"  描述: {phase['description']}")
        print(f"  样本数: {phase['sample_count']} ({phase['sample_count']/len(samples)*100:.1f}%)")
        print(f"  难度范围: [{phase['difficulty_range'][0]:.2f}, {phase['difficulty_range'][1]:.2f}]"
              f" (均值={phase['difficulty_mean']:.2f})")
        if phase['cwe_distribution']:
            top_cwes = list(phase['cwe_distribution'].items())[:8]
            print(f"  CWE 分布: {', '.join(f'{cwe}={n}' for cwe, n in top_cwes)}")

    # 构建输出
    output = {
        "source": str(args.data),
        "total_samples": len(samples),
        "phase_sizes": phase_sizes,
        "replay_ratio": args.replay_ratio,
        "probe_report_used": str(args.probe_report) if args.probe_report else None,
        "phases": phases,
    }

    # 保存
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 课程学习配置已保存: {args.output}")
    # 注意：replay 采样逻辑与 train_qlora.py 的 --curriculum-phase/--curriculum-config
    # 集成尚未实现，以下命令仅为预期用法，当前不可直接运行。
    print("  [待实现] replay 采样与 train_qlora.py 的课程学习参数集成尚未完成")


if __name__ == "__main__":
    main()
