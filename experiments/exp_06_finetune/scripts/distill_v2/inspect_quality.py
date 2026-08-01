"""抽样查看蒸馏数据的内容质量。

从 cc_memory 和 pentest 各抽 6 条（前2+中2+后2），覆盖漏洞/安全样本，
重点评估：
  1. CoT 推理深度（是否说清"为什么"，而非只是"是什么"）
  2. 代码真实度（是否模拟真实项目结构，而非玩具代码）
  3. 防御有效性（安全样本是否真有防御 + 否定推理）
  4. 推理路径多样化（A数据流/B模式识别/C假设验证）
  5. JSON 语义一致性（CVSS评分与risk_level是否对齐，source/sink是否锚定CoT）
  6. 模板化痕迹（是否反复用同一套话术）
"""

import json
import random
from pathlib import Path

DATA_DIR = Path(r"D:\code\毕业设计\Graduation-Project\experiments\exp_06_finetune\data\distill_v2")


def load_jsonl(path):
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def fmt_sample(s, idx):
    """格式化单条样本便于阅读。"""
    msgs = s["messages"]
    meta = s.get("_meta", {})
    system = msgs[0]["content"]
    user = msgs[1]["content"]
    assistant = msgs[2]["content"]

    # 从 user 提取代码
    code_start = user.find("```")
    code_end = user.rfind("```")
    code = user[code_start:code_end+3] if code_start != -1 else user

    # 统计代码行数
    code_lines = code.count("\n")

    # 从 assistant 提取 CoT 和 JSON
    json_start = assistant.rfind("```json")
    if json_start != -1:
        cot = assistant[:json_start].strip()
        json_part = assistant[json_start:].strip()
        try:
            j = json.loads(json_part.replace("```json", "").replace("```", "").strip())
        except Exception:
            j = {}
    else:
        cot = assistant
        json_part = ""
        j = {}

    has_vuln = j.get("has_vulnerability", "?")
    vuln_type = j.get("vulnerability_type", "?")
    risk = j.get("risk_level", "?")
    cvss_v = j.get("cvss_vector", "?")
    cvss_s = j.get("cvss_score", "?")
    source = j.get("source", "?")
    sink = j.get("sink", "?")

    # CoT 步数
    import re
    steps = re.findall(r"(?:^|\n)\s*(\d+)[.)]\s*(.+)", cot)
    n_steps = len(steps)

    out = []
    out.append("=" * 80)
    out.append(f"[{idx}] task_id={meta.get('task_id','?')} | cwe={meta.get('cwe','?')} | lang={meta.get('lang','?')} | has_vuln={meta.get('has_vuln','?')}")
    out.append(f"    代码 {code_lines} 行 | CoT {n_steps} 步 | risk={risk} | cvss={cvss_s} ({cvss_v})")
    out.append(f"    vulnerability_type: {vuln_type}")
    out.append(f"    source: {source}")
    out.append(f"    sink:   {sink}")
    out.append("")
    out.append("--- 代码 ---")
    out.append(code)
    out.append("")
    out.append("--- CoT ---")
    out.append(cot)
    out.append("")
    out.append("--- JSON ---")
    out.append(json.dumps(j, ensure_ascii=False, indent=2))
    return "\n".join(out)


def sample_front_mid_back(samples, n_each=2, seed=42):
    """前中后各抽 n_each 条，尽量覆盖 has_vuln True/False。"""
    total = len(samples)
    front = samples[:max(total//10, 20)]
    mid = samples[total//2 - 10 : total//2 + 10]
    back = samples[-max(total//10, 20):]

    rng = random.Random(seed)

    def pick(pool, n):
        # 优先挑 has_vuln=True 和 False 各一条
        true_pool = [s for s in pool if s.get("_meta",{}).get("has_vuln") is True]
        false_pool = [s for s in pool if s.get("_meta",{}).get("has_vuln") is False]
        result = []
        if true_pool:
            result.append(rng.choice(true_pool))
        if n >= 2 and false_pool:
            result.append(rng.choice(false_pool))
        while len(result) < n:
            result.append(rng.choice(pool))
        return result

    return pick(front, n_each), pick(mid, n_each), pick(back, n_each)


def main():
    for pack_name in ["deepseek_cc_memory", "deepseek_pentest"]:
        path = DATA_DIR / f"{pack_name}.jsonl"
        if not path.exists():
            print(f"\n[跳过] {pack_name} 不存在")
            continue

        samples = load_jsonl(path)
        print("\n" + "#" * 80)
        print(f"# 包: {pack_name} | 总样本数: {len(samples)}")
        print("#" * 80)

        front, mid, back = sample_front_mid_back(samples, n_each=2)

        print("\n========== 前部抽样 ==========")
        for i, s in enumerate(front):
            print(fmt_sample(s, f"前{i+1}"))

        print("\n========== 中部抽样 ==========")
        for i, s in enumerate(mid):
            print(fmt_sample(s, f"中{i+1}"))

        print("\n========== 后部抽样 ==========")
        for i, s in enumerate(back):
            print(fmt_sample(s, f"后{i+1}"))


if __name__ == "__main__":
    main()
