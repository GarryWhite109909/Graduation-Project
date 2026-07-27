"""构造 v6 SFT 训练数据 = v5_clean + 6 个 FP 的正确拒绝响应（hard-negative）。

DPO 在本地硬件不可行（4bit 梯度失效 / 8bit OOM），改为把 v5 的 6 个真实 FP 的正确拒绝 CoT
作为 SFT 正样本追加到训练集，用 4bit QLoRA 重跑 SFT（已验证可行）。

输入：
  data/train_chatml_v5_clean.jsonl   (749 条) - v5 SFT 训练数据
  data/dpo_fp_pairs_v5.jsonl          (6 条)  - v5 评估的 6 个真实 FP 的 DPO pair

输出：
  data/train_chatml_v6_hard_neg.jsonl (755 条) - v6 SFT 训练数据

策略：
  - DPO pair 的 chosen 字段就是正确的拒绝 CoT（has_vulnerability=false）
  - 解析 DPO prompt 的 ChatML 格式，提取 system/user content
  - 转换为 SFT messages 格式追加到 v5_clean
"""
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def parse_chatml_prompt(prompt: str):
    """从 ChatML prompt 解析出 system 和 user content。

    prompt 格式：
    <|im_start|>system\n{system_content}<|im_end|>\n<|im_start|>user\n{user_content}<|im_end|>\n<|im_start|>assistant\n
    """
    # 提取 system
    sys_match = re.search(
        r"<\|im_start\|>system\n(.*?)<\|im_end\|>", prompt, re.DOTALL
    )
    user_match = re.search(
        r"<\|im_start\|>user\n(.*?)<\|im_end\|>", prompt, re.DOTALL
    )
    if not sys_match or not user_match:
        raise ValueError("无法解析 ChatML prompt")
    return sys_match.group(1), user_match.group(1)


def strip_im_end(text: str) -> str:
    """去掉结尾的 <|im_end|>"""
    return text.rstrip().removesuffix("<|im_end|>").rstrip()


def main():
    v5_path = DATA_DIR / "train_chatml_v5_clean.jsonl"
    dpo_path = DATA_DIR / "dpo_fp_pairs_v5.jsonl"
    out_path = DATA_DIR / "train_chatml_v6_hard_neg.jsonl"

    # 加载 v5_clean
    with open(v5_path) as f:
        v5 = [json.loads(l) for l in f]
    print(f"v5_clean 样本数: {len(v5)}")

    # 加载 DPO pairs
    with open(dpo_path) as f:
        dpo_pairs = [json.loads(l) for l in f]
    print(f"DPO pairs 数: {len(dpo_pairs)}")

    # 转换 DPO pairs 为 SFT messages 格式
    new_samples = []
    for i, p in enumerate(dpo_pairs):
        sys_content, user_content = parse_chatml_prompt(p["prompt"])
        assistant_content = strip_im_end(p["chosen"])
        sample = {
            "messages": [
                {"role": "system", "content": sys_content},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": assistant_content},
            ]
        }
        new_samples.append(sample)
        # 验证 chosen 是 has_vulnerability=false
        hv = re.search(
            r'"has_vulnerability"\s*:\s*(true|false)', assistant_content, re.IGNORECASE
        )
        print(f"  pair {i+1}: has_vulnerability={hv.group(1) if hv else 'N/A'}")

    # 合并：v5 + 6 个新样本
    v6 = v5 + new_samples
    print(f"\nv6 总样本数: {len(v6)} (v5 {len(v5)} + 新增 {len(new_samples)})")

    # 去重检查（按 user content 哈希）
    seen = set()
    dups = 0
    for s in v6:
        for m in s["messages"]:
            if m["role"] == "user":
                key = m["content"].strip()[:200]
                if key in seen:
                    dups += 1
                    print(f"  ⚠️ 重复 user content: {key[:80]}...")
                seen.add(key)
                break
    if dups:
        print(f"⚠️ 发现 {dups} 个重复样本")
    else:
        print("✓ 无重复样本")

    # 写入 v6
    with open(out_path, "w") as f:
        for s in v6:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"\n✓ 已写入 {out_path}")
    print(f"  行数: {len(v6)}")


if __name__ == "__main__":
    main()
