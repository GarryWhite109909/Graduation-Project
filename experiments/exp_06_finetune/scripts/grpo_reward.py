"""GRPO 可验证奖励函数 —— Nivis-α1 Stage B 核心组件。

设计依据：docs/方法论_Nivis-α1训练.md §4.1。漏洞检测是少数奖励可程序化
验证的 LLM 任务（ground truth 明确），奖励全部来自规则，不依赖奖励模型。

奖励组成（总分 1.0，五道分量）：
  1. 格式门（+0.1）：解析失败直接近零分，防格式崩塌与解析器取巧
  2. 判定正确性（±0.5）：TP/TN +0.5，FN -0.3，FP -0.5
     —— FP 惩罚 ≥ FN 惩罚，防"全判漏洞"刷 recall 的 reward hacking
  3. CWE 匹配（+0.2）：vulnerability_type 与 expected_cwe 编号一致
  4. 证据接地（+0.1）：sink/source 非 N/A 且在代码中真实出现，防幻觉证据
  5. 长度约束（+0.1）：CoT 不超过阈值，防推理膨胀

配套 TRL GRPOTrainer：把 reward_fn 注册为自定义 reward function 即可。

自检（不依赖 GPU / 第三方库）：
  cd <project_root>
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/grpo_reward.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import normalize_has_vulnerability, parse_verdict

# ---------------------------------------------------------------------------
# 奖励权重（改动需同步 docs/方法论_Nivis-α1训练.md §4.1）
# ---------------------------------------------------------------------------
W_FORMAT = 0.1        # 格式门
W_VERDICT = 0.5       # 判定正确（TP/TN）
PEN_FN = -0.3         # 漏报惩罚
PEN_FP = -0.5         # 误报惩罚（≥ FN，防全判漏洞）
W_CWE = 0.2           # CWE 编号匹配
W_EVIDENCE = 0.1      # 证据接地
W_LENGTH = 0.1        # 长度约束
FORMAT_FLOOR = 0.05   # 解析失败但有 JSON 块的保底分（区分"完全乱输出"）

# CoT 长度阈值（近似 token 数）。中英混合文本按 len/3 粗估，
# 与评估侧 max_tokens=2048 的口径无冲突（此处仅约束推理段）。
COT_TOKEN_THRESHOLD = 300

_NA_VALUES = {"", "n/a", "none", "无", "null"}


def has_json_block(output: str) -> bool:
    """输出中是否含 ```json 围栏块。"""
    return bool(output) and "```json" in output


def extract_cwe(text: str) -> str | None:
    """从文本中提取 CWE 编号（统一大写，如 CWE-89）。"""
    if not text:
        return None
    m = re.search(r"CWE-?(\d+)", text, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else None


def cwe_match(pred_type: str, expected_cwe: str) -> bool:
    """预测的 vulnerability_type 与期望 CWE 编号是否一致。"""
    p, e = extract_cwe(pred_type), extract_cwe(expected_cwe)
    return p is not None and e is not None and p == e


def evidence_grounded(verdict: dict, code: str) -> bool:
    """sink/source 证据是否接地：非 N/A 且关键标识符真实出现在代码中。

    判漏洞时必须 sink 接地（sink 是结论的直接依据）；source 可放宽
    （有些漏洞模型只定位到 sink）。判安全时无需证据，返回 False（不得分）。
    """
    has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
    if has_vuln is not True:
        return False
    sink = str(verdict.get("sink", "") or "")
    if sink.strip().lower() in _NA_VALUES:
        return False
    # 先剥离 "line N:" 行号锚点（否则锚点词本身会在代码注释里误命中），
    # 再取标识符 token 在代码中验证
    sink_body = re.sub(r"line\s*\d+\s*[:：]", " ", sink)
    tokens = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{2,}", sink_body)
              if t.lower() not in ("line", "nan", "none")]
    return any(t in code for t in tokens) if tokens else False


def approx_token_len(text: str) -> int:
    """中英混合文本的粗 token 估计（len/3），仅用于奖励整形，不作精确计量。"""
    return len(text) // 3


def cot_text(output: str) -> str:
    """提取 JSON 结论块之前的推理段文本。"""
    idx = output.find("```json")
    return output[:idx] if idx > 0 else output


def reward_breakdown(output: str, sample: dict) -> dict:
    """计算奖励分量明细，便于调试与日志。

    Args:
        output: 模型原始输出文本
        sample: 含 expected_present(bool) / expected_cwe(str) / code(str) 的样本

    Returns:
        {"total": float, "format": ..., "verdict": ..., "cwe": ...,
         "evidence": ..., "length": ..., "parsed": bool, "outcome": str}
    """
    parts = {"format": 0.0, "verdict": 0.0, "cwe": 0.0, "evidence": 0.0, "length": 0.0}
    outcome = "parse_fail"

    verdict = parse_verdict(output) if output else None
    predicted = normalize_has_vulnerability(verdict.get("has_vulnerability")) if verdict else None

    if predicted is None:
        # 格式门：解析失败几乎零分（有 JSON 块给保底，区分完全乱输出）
        parts["format"] = FORMAT_FLOOR if has_json_block(output) else 0.0
        parts["total"] = round(parts["format"], 4)
        parts.update(parsed=False, outcome=outcome)
        return parts

    parts["format"] = W_FORMAT

    expected = bool(sample.get("expected_present"))
    if predicted and expected:
        parts["verdict"] = W_VERDICT
        outcome = "TP"
    elif not predicted and not expected:
        parts["verdict"] = W_VERDICT
        outcome = "TN"
    elif not predicted and expected:
        parts["verdict"] = PEN_FN
        outcome = "FN"
    else:
        parts["verdict"] = PEN_FP
        outcome = "FP"

    # 后续分量仅在判定正确时授予（错误判定不给 CWE/证据分，防"错得漂亮"）
    if outcome in ("TP", "TN"):
        if outcome == "TP" and cwe_match(
            str(verdict.get("vulnerability_type", "")), str(sample.get("expected_cwe", ""))
        ):
            parts["cwe"] = W_CWE
        if outcome == "TP" and evidence_grounded(verdict, str(sample.get("code", ""))):
            parts["evidence"] = W_EVIDENCE
        if approx_token_len(cot_text(output)) <= COT_TOKEN_THRESHOLD:
            parts["length"] = W_LENGTH

    parts["total"] = round(sum(v for k, v in parts.items() if k != "total"), 4)
    parts.update(parsed=True, outcome=outcome)
    return parts


def reward_fn(output: str, sample: dict) -> float:
    """TRL GRPOTrainer 兼容入口：单样本奖励标量。"""
    return reward_breakdown(output, sample)["total"]


def trl_reward_adapter(prompts, completions, expected_present, expected_cwe, code, **kwargs):
    """TRL GRPOTrainer 批量签名适配器。

    用法（datasets 需含 expected_present/expected_cwe/code 三列）：
        trainer = GRPOTrainer(..., reward_funcs=trl_reward_adapter)
    """
    return [
        reward_fn(c, {"expected_present": e, "expected_cwe": w, "code": c_src})
        for c, e, w, c_src in zip(completions, expected_present, expected_cwe, code)
    ]


# ---------------------------------------------------------------------------
# 自检（纯规则逻辑，可离线验证）
# ---------------------------------------------------------------------------
def _selftest() -> None:
    code_vuln = (
        "import os\nfrom flask import request\n\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    os.system('ping ' + host)   # line 6: sink\n"
    )
    code_safe = (
        "import subprocess\n\n"
        "def ping(host: str):\n"
        "    subprocess.run(['ping', host], check=True)\n"
    )

    def make_output(has_vuln, cwe="CWE-78 命令注入", sink="line 6: os.system('ping ' + host)",
                    cot="分析：host 来自 request.args，未校验直接拼接进 os.system。"):
        verdict = {
            "has_vulnerability": has_vuln,
            "vulnerability_type": cwe if has_vuln else "none",
            "risk_level": "Critical" if has_vuln else "None",
            "source": "line 4: request.args.get('host')" if has_vuln else "N/A",
            "sink": sink if has_vuln else "N/A",
            "explanation": "x", "fix_suggestion": "y",
        }
        return cot + "\n```json\n" + json.dumps(verdict, ensure_ascii=False) + "\n```"

    cases = []

    # 1. TP 全分量：应得满分 1.0
    r = reward_breakdown(make_output(True), {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("TP 满分", abs(r["total"] - 1.0) < 1e-6, r))

    # 2. TN：无 CWE/证据分，应得 0.7
    r = reward_breakdown(make_output(False), {
        "expected_present": False, "expected_cwe": "", "code": code_safe})
    cases.append(("TN 0.7", abs(r["total"] - 0.7) < 1e-6, r))

    # 3. FP 重罚：0.1 - 0.5 = -0.4
    r = reward_breakdown(make_output(True), {
        "expected_present": False, "expected_cwe": "", "code": code_safe})
    cases.append(("FP -0.4", abs(r["total"] - (-0.4)) < 1e-6, r))

    # 4. FN 轻罚：0.1 - 0.3 = -0.2
    r = reward_breakdown(make_output(False), {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("FN -0.2", abs(r["total"] - (-0.2)) < 1e-6, r))

    # 5. 完全乱输出：0 分
    r = reward_breakdown("我不知道这段代码怎么了", {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("乱输出 0 分", r["total"] == 0.0, r))

    # 6. 有 JSON 块但解析失败：保底 0.05
    r = reward_breakdown("分析中...\n```json\n{broken", {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("破 JSON 保底", abs(r["total"] - FORMAT_FLOOR) < 1e-6, r))

    # 7. 幻觉证据（sink 不在代码中）：扣证据分
    r = reward_breakdown(make_output(True, sink="line 9: cursor.execute(query)"), {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("幻觉证据扣分", r["evidence"] == 0.0 and r["total"] < 1.0, r))

    # 8. CWE 不匹配：扣 CWE 分
    r = reward_breakdown(make_output(True, cwe="CWE-89 SQL注入"), {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("CWE 不符扣分", r["cwe"] == 0.0, r))

    # 9. 超长 CoT：扣长度分
    long_cot = "冗长分析。" * 500
    r = reward_breakdown(long_cot + "\n" + make_output(True), {
        "expected_present": True, "expected_cwe": "CWE-78", "code": code_vuln})
    cases.append(("超长 CoT 扣分", r["length"] == 0.0, r))

    # 10. 防黑客行为：全判漏洞在安全样本上必须负分
    r_hack = reward_fn(make_output(True), {
        "expected_present": False, "expected_cwe": "", "code": code_safe})
    r_honest = reward_fn(make_output(False), {
        "expected_present": False, "expected_cwe": "", "code": code_safe})
    cases.append(("防全判漏洞", r_hack < 0 < r_honest, {"hack": r_hack, "honest": r_honest}))

    failed = 0
    for name, ok, detail in cases:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"  [{status}] {name}: {detail}")
    print(f"\n自检完成: {len(cases) - failed}/{len(cases)} 通过")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="GRPO 奖励函数")
    ap.add_argument("--selftest", action="store_true", help="运行离线自检")
    args = ap.parse_args()
    if args.selftest:
        _selftest()
    else:
        ap.print_help()
