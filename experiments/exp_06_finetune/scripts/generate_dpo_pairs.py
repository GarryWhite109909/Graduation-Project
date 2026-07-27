"""
DPO 偏好对数据生成 —— 从 CCoT 对比样本转换为 DPO 格式。

设计依据：docs/_archive/改进_历史分析_20260710.md 第三节方案 A（DPO）
  BiasDPO（2024, arXiv:2407.13928）已证明 DPO 能有效减少 LLM 偏见。
  DPO 的损失函数直接最大化 chosen（正确判断）的概率、最小化 rejected
  （错误判断）的概率，比 SFT 更直接地"惩罚"偏见。

数据来源：supplement_ccot_contrastive.py 生成的 22 条 CCoT 样本
  每条 CCoT 样本天然包含一对偏好：
    - chosen = 正确推理路径 + 正确 JSON 结论
    - rejected = 错误推理路径 + 错误 JSON 结论（has_vulnerability 取反）

DPO 数据格式（TRL DPOTrainer 期望）：
  {
    "prompt": "system + user 消息拼接",
    "chosen": "正确 assistant 回复",
    "rejected": "错误 assistant 回复"
  }

输出：experiments/exp_06_finetune/data/dpo_preference_pairs.jsonl

用法：
  cd <project_root>
  PYTHONPATH=. python3 \
      experiments/exp_06_finetune/scripts/generate_dpo_pairs.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT_LITE, build_user_prompt

# 导入 CCoT 样本定义
sys.path.insert(0, str(PROJECT_ROOT / "experiments/exp_06_finetune/scripts"))
from supplement_ccot_contrastive import SAMPLES as SAMPLES_V1
from supplement_ccot_contrastive_v2 import SAMPLES as SAMPLES_V2
from supplement_ccot_contrastive_v2 import build_json_verdict

OUTPUT_FILE = PROJECT_ROOT / "experiments/exp_06_finetune/data/dpo_preference_pairs.jsonl"

# 合并 v1 (22) + v2 (40) = 62 对 DPO 偏好对
SAMPLES = SAMPLES_V1 + SAMPLES_V2


# TODO: 当前所有安全样本的 rejected 完全相同（CWE-78 命令注入），
# DPO 会学到"压制固定文本"而非"为什么错"。未来应按样本 CWE 类型生成语义相关的错误结论。
def build_wrong_verdict(sample):
    """构造错误 JSON 结论块（has_vulnerability 取反）。

    DPO 的 rejected 需要是一个完整的错误回复，包含错误的 JSON 结论。
    """
    wrong_has_vuln = not sample["has_vulnerability"]
    if wrong_has_vuln:
        # 错误地判为有漏洞
        wrong_vuln_type = sample["vulnerability_type"] if sample["has_vulnerability"] else "CWE-78 命令注入"
        wrong_risk = sample["risk_level"] if sample["has_vulnerability"] else "High"
        wrong_source = sample["source"] if sample["has_vulnerability"] else "用户输入"
        wrong_sink = sample["sink"] if sample["has_vulnerability"] else "subprocess/system 执行"
        wrong_explanation = sample["explanation"] if sample["has_vulnerability"] else "代码存在安全风险，用户输入可能导致命令注入"
        wrong_fix = sample["fix_suggestion"] if sample["has_vulnerability"] else "改用参数化查询或白名单校验"
    else:
        # 错误地判为安全
        wrong_vuln_type = "none"
        wrong_risk = "None"
        wrong_source = "N/A"
        wrong_sink = "N/A"
        wrong_explanation = "代码经检查未发现安全漏洞，使用了安全写法"
        wrong_fix = "no fix needed"

    verdict = {
        "has_vulnerability": wrong_has_vuln,
        "vulnerability_type": wrong_vuln_type,
        "risk_level": wrong_risk,
        "source": wrong_source,
        "sink": wrong_sink,
        "explanation": wrong_explanation,
        "fix_suggestion": wrong_fix,
    }
    return "```json\n" + json.dumps(verdict, ensure_ascii=False, indent=2) + "\n```"


def build_dpo_pair(sample):
    """将 CCoT 样本转为 DPO 偏好对。

    Returns:
        {
            "prompt": system + user 消息,
            "chosen": 正确推理 + 正确 JSON,
            "rejected": 错误推理 + 错误 JSON
        }
    """
    user_content = build_user_prompt(
        code=sample["code"], language=sample["language"],
        filename=sample["filename"],
    )

    # DPO prompt 格式：system + user 拼接（DPOTrainer 会处理 chat template）
    prompt = f"<|im_start|>system\n{SYSTEM_PROMPT_LITE}<|im_end|>\n<|im_start|>user\n{user_content}<|im_end|>\n<|im_start|>assistant\n"

    # chosen: 正确推理路径 + 正确 JSON
    correct_json = build_json_verdict(sample)
    chosen = (
        f"{sample['correct_reasoning']}\n\n"
        f"### 最终结论：\n{correct_json}<|im_end|>"
    )

    # rejected: 错误推理路径 + 错误 JSON
    wrong_json = build_wrong_verdict(sample)
    rejected = (
        f"{sample['incorrect_reasoning']}\n\n"
        f"### 最终结论：\n{wrong_json}<|im_end|>"
    )

    return {
        "prompt": prompt,
        "chosen": chosen,
        "rejected": rejected,
    }


def validate(pairs):
    """验证 DPO 偏好对。"""
    print("\n" + "=" * 60)
    print("验证 DPO 偏好对")
    print("=" * 60)

    # 注意：用 if + raise ValueError 而非 assert，避免 python -O 下失效
    if len(pairs) < 20:
        raise ValueError(f"偏好对数应 >= 20，实际 {len(pairs)}")
    print(f"[OK] 偏好对数: {len(pairs)}")

    import re
    for i, pair in enumerate(pairs):
        # 必须有 prompt / chosen / rejected
        if "prompt" not in pair:
            raise ValueError(f"对{i}: 缺少 prompt")
        if "chosen" not in pair:
            raise ValueError(f"对{i}: 缺少 chosen")
        if "rejected" not in pair:
            raise ValueError(f"对{i}: 缺少 rejected")

        # prompt 必须含 ChatML 标记
        if "<|im_start|>" not in pair["prompt"]:
            raise ValueError(f"对{i}: prompt 缺少 ChatML 标记")

        # chosen 和 rejected 必须含 JSON 块
        if "```json" not in pair["chosen"]:
            raise ValueError(f"对{i}: chosen 缺少 json 块")
        if "```json" not in pair["rejected"]:
            raise ValueError(f"对{i}: rejected 缺少 json 块")

        # chosen 和 rejected 必须不同
        if pair["chosen"] == pair["rejected"]:
            raise ValueError(f"对{i}: chosen 和 rejected 相同")

        # 提取 chosen 和 rejected 的 has_vulnerability，必须相反
        chosen_match = re.search(r'"has_vulnerability":\s*(true|false)', pair["chosen"], re.IGNORECASE)
        rejected_match = re.search(r'"has_vulnerability":\s*(true|false)', pair["rejected"], re.IGNORECASE)
        if not chosen_match:
            raise ValueError(f"对{i}: chosen 无法提取 has_vulnerability")
        if not rejected_match:
            raise ValueError(f"对{i}: rejected 无法提取 has_vulnerability")
        chosen_hv = chosen_match.group(1).lower() == "true"
        rejected_hv = rejected_match.group(1).lower() == "true"
        if chosen_hv == rejected_hv:
            raise ValueError(
                f"对{i}: chosen({chosen_hv}) 和 rejected({rejected_hv}) 的 has_vulnerability 应相反"
            )

    print(f"[OK] 所有 {len(pairs)} 对偏好对格式合规（chosen/rejected 结论相反）")

    # 统计
    chosen_true = sum(1 for p in pairs if '"has_vulnerability": true' in p["chosen"].lower() or '"has_vulnerability":true' in p["chosen"].lower().replace(" ", ""))
    chosen_false = len(pairs) - chosen_true
    print(f"[OK] chosen 分布: vuln(true)={chosen_true}, safe(false)={chosen_false}")

    print(f"\n[OK] 所有验证通过")
    return True


def main():
    print(f"从 CCoT 样本生成 DPO 偏好对...")
    print(f"源数据: {len(SAMPLES)} 条 CCoT 样本")

    pairs = [build_dpo_pair(s) for s in SAMPLES]
    print(f"生成: {len(pairs)} 对偏好对")

    # 验证
    validate(pairs)

    # 写入
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for pair in pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")
    print(f"\n已写入: {OUTPUT_FILE}")

    # 验证写入的文件
    print("\n验证写入文件...")
    count = 0
    with open(OUTPUT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            assert "prompt" in rec and "chosen" in rec and "rejected" in rec
            count += 1
    assert count == len(pairs), f"写入行数应为 {len(pairs)}，实际 {count}"
    print(f"[OK] 文件包含 {count} 条有效 DPO 偏好对")


if __name__ == "__main__":
    main()
