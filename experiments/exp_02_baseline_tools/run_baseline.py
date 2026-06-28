"""
exp_02_baseline_tools - 传统静态分析工具对比基线

复用 exp_01 的 14 段样本，分别调用 Bandit（仅 Python）和 Semgrep（多语言），
输出与 exp_01 统一格式的 JSON 结果，便于横向对比 LLM vs 传统工具。

判定口径：
- 工具输出 results 数组非空 → tool_has_vulnerability = True
- 工具输出 results 数组为空 → tool_has_vulnerability = False
- 工具不支持该语言（Bandit 跑非 Python） → tool_has_vulnerability = None（invalid）

用法:
    python run_baseline.py                          # 跑全部工具 + 全部样本
    python run_baseline.py --tool bandit            # 只跑 Bandit
    python run_baseline.py --tool semgrep           # 只跑 Semgrep
    python run_baseline.py --limit 3                # 只跑前 3 个样本（调试）
    python run_baseline.py --semgrep-config p/default   # 指定 Semgrep 规则集
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# 把项目根加入 sys.path，保证可从任意目录运行
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# 把当前 Python 解释器所在目录加入 PATH，确保能找到同环境的 CLI 工具
# （如 bandit/semgrep 装在同一个 conda/venv 环境时，subprocess 能定位到）
_PYTHON_BIN_DIR = os.path.dirname(sys.executable)
if _PYTHON_BIN_DIR not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _PYTHON_BIN_DIR + os.pathsep + os.environ.get("PATH", "")

from experiments.utils import (
    load_manifest,
    save_results_json,
    new_results_envelope,
    compute_detection_metrics,
    print_summary,
)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
# 复用 exp_01 的样本集，保证对比公平
SAMPLES_DIR = SCRIPT_DIR.parent / "exp_01_basic_scan" / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_DIR = SCRIPT_DIR / "results"


# ---------------------------------------------------------------------------
# 工具调用封装
# ---------------------------------------------------------------------------
def run_bandit(sample_path: Path) -> dict:
    """调用 Bandit 分析单个 Python 文件，返回统一结构。

    Returns:
        {
            "tool": "bandit",
            "supported": bool,          # 该语言是否被工具支持
            "findings": list[dict],     # 解析后的告警列表（每条含 rule_id/severity/message/line）
            "raw_output": dict|str,     # 工具原始 JSON 输出（解析失败时为字符串）
            "error": str|None,
            "elapsed_seconds": float,
        }
    """
    result = {
        "tool": "bandit",
        "supported": True,
        "findings": [],
        "raw_output": None,
        "error": None,
        "elapsed_seconds": 0.0,
    }

    if sample_path.suffix != ".py":
        result["supported"] = False
        result["error"] = f"Bandit 仅支持 Python，跳过 {sample_path.name}"
        return result

    start = time.time()
    try:
        # -f json 输出 JSON；-q 安静模式，不打印 banner
        proc = subprocess.run(
            ["bandit", "-f", "json", "-q", str(sample_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        result["elapsed_seconds"] = round(time.time() - start, 3)

        # Bandit 即使发现漏洞也返回非 0 退出码（有告警时 exit=1），
        # 所以不能靠 returncode 判断成败，要看 stdout 是否为合法 JSON
        try:
            parsed = json.loads(proc.stdout)
            result["raw_output"] = parsed
        except json.JSONDecodeError:
            result["error"] = f"Bandit 输出不是合法 JSON。stderr={proc.stderr[:300]}"
            return result

        # 解析告警
        for issue in parsed.get("results", []):
            result["findings"].append({
                "rule_id": issue.get("test_id"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "message": issue.get("issue_text"),
                "line": issue.get("line_number"),
                "cwe": (issue.get("issue_cwe") or {}).get("link"),
            })
    except FileNotFoundError:
        result["error"] = "Bandit 未安装（pip install bandit）"
    except subprocess.TimeoutExpired:
        result["error"] = "Bandit 执行超时（>60s）"
    except Exception as e:
        result["error"] = f"Bandit 异常: {e}"
    return result


def run_semgrep(sample_path: Path, config: str = "auto") -> dict:
    """调用 Semgrep 分析单个文件，返回统一结构。

    Args:
        sample_path: 待测文件
        config: Semgrep 规则集，默认 auto（自动从 registry 拉取）
    """
    result = {
        "tool": "semgrep",
        "supported": True,
        "findings": [],
        "raw_output": None,
        "error": None,
        "elapsed_seconds": 0.0,
    }

    start = time.time()
    try:
        # --json 输出 JSON；--config 指定规则集；--quiet 抑制进度条
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", config, str(sample_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        result["elapsed_seconds"] = round(time.time() - start, 3)

        if proc.returncode not in (0, 1):
            # returncode=1 表示有 finding，是正常情况；其他非 0 才算错误
            result["error"] = f"Semgrep 退出码 {proc.returncode}。stderr={proc.stderr[:300]}"
            return result

        try:
            parsed = json.loads(proc.stdout)
            result["raw_output"] = parsed
        except json.JSONDecodeError:
            result["error"] = f"Semgrep 输出不是合法 JSON。stdout[:200]={proc.stdout[:200]}"
            return result

        # 解析告警
        for issue in parsed.get("results", []):
            result["findings"].append({
                "rule_id": issue.get("check_id"),
                "severity": (issue.get("extra") or {}).get("severity"),
                "message": (issue.get("extra") or {}).get("message"),
                "line": issue.get("start", {}).get("line"),
                "path": issue.get("path"),
            })
    except FileNotFoundError:
        result["error"] = "Semgrep 未安装（pip install semgrep）"
    except subprocess.TimeoutExpired:
        result["error"] = "Semgrep 执行超时（>120s）"
    except Exception as e:
        result["error"] = f"Semgrep 异常: {e}"
    return result


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="传统静态分析工具对比基线")
    parser.add_argument("--tool", choices=["bandit", "semgrep", "all"], default="all",
                        help="选择工具（默认 all，两个都跑）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--semgrep-config", default="auto",
                        help="Semgrep 规则集（默认 auto，可选 p/default、p/owasp 等）")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    tools_to_run = ["bandit", "semgrep"] if args.tool == "all" else [args.tool]

    results = new_results_envelope(
        experiment="exp_02_baseline_tools",
        tools=tools_to_run,
        semgrep_config=args.semgrep_config,
        samples_source=str(SAMPLES_DIR.relative_to(SCRIPT_DIR.parent)),
    )

    total = len(samples)
    print(f"[信息] 共 {total} 个样本，工具: {tools_to_run}")
    print(f"[信息] 样本目录: {SAMPLES_DIR}")

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        sample_path = SAMPLES_DIR / filename
        if not sample_path.exists():
            print(f"[{idx}/{total}] [跳过] 样本不存在: {sample_path}", file=sys.stderr)
            continue

        language = sample_meta.get("language", "text")
        print(f"[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)

        record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "tools": {},
        }

        for tool in tools_to_run:
            if tool == "bandit":
                t_result = run_bandit(sample_path)
            else:
                t_result = run_semgrep(sample_path, config=args.semgrep_config)

            # 判定：有 finding → True；无 finding 且 supported → False；不支持 → None
            if not t_result["supported"]:
                verdict = None
            elif t_result["error"]:
                verdict = None
            else:
                verdict = len(t_result["findings"]) > 0

            record["tools"][tool] = {
                "tool_has_vulnerability": verdict,
                "findings": t_result["findings"],
                "findings_count": len(t_result["findings"]),
                "elapsed_seconds": t_result["elapsed_seconds"],
                "error": t_result["error"],
                "supported": t_result["supported"],
            }
            status = "有漏洞" if verdict else ("无漏洞" if verdict is False else "N/A")
            print(f"        {tool}: {status}, {len(t_result['findings'])} 条告警, {t_result['elapsed_seconds']}s")

        results["samples"].append(record)
        # 每跑完一个样本立即落盘
        save_results_json(RESULTS_DIR / "results.json", results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # 汇总指标（每个工具分别统计）
    metrics_per_tool = {}
    for tool in tools_to_run:
        # 构造与 compute_detection_metrics 兼容的记录列表
        flat_records = []
        for s in results["samples"]:
            t_data = s.get("tools", {}).get(tool, {})
            flat_records.append({
                "expected_present": s.get("expected_present"),
                "model_has_vulnerability": t_data.get("tool_has_vulnerability"),
                "elapsed_seconds": t_data.get("elapsed_seconds"),
            })
        metrics_per_tool[tool] = compute_detection_metrics(flat_records)

    results["metrics"] = metrics_per_tool
    save_results_json(RESULTS_DIR / "results.json", results)
    print(f"\n[完成] 结果已写入 {RESULTS_DIR / 'results.json'}")

    for tool, m in metrics_per_tool.items():
        print(f"\n=== {tool} 汇总 ===")
        print_summary(m)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
