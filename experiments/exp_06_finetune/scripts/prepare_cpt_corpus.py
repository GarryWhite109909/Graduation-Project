"""
KnItLM CPT 语料准备脚本 —— 把项目内所有漏洞领域文本整合为 CPT 训练集。

对应 docs/方法.md §9 Phase 3 KnItLM 知识注入。

数据来源（网络不可达，全部用本地数据）：
  1. 训练数据中的 CoT 推理文本（assistant 部分即漏洞分析推理链）
  2. 补充训练数据（各类 supplement_*.jsonl）
  3. 蒸馏语料（distill_corpus_*.jsonl）
  4. 已有 DPO 偏好对的 chosen 文本（高质量漏洞判定）
  5. docs/ 下的方法/改进文档（漏洞领域术语和规则描述）
  6. exp_04_hard_samples/ 下的漏洞代码样本（含 CVE 描述）

输出格式：jsonl，每行一个 {"text": "..."} 字段，供 trl SFTTrainer 做 causal LM CPT。

设计考虑：
  - CPT 不需要 instruction/response 区分，全部当 causal LM 文本学
  - 但保留 CoT 推理链的完整性（"污染源→sink→数据流→防御→结论"）
  - 控制单条文本长度在 4096 tokens 以内（超长切分）
  - 总语料目标 10-30MB（项目本地数据上限）

用法：
  /home/zane/miniconda3/envs/AI/bin/python prepare_cpt_corpus.py
  /home/zane/miniconda3/envs/AI/bin/python prepare_cpt_corpus.py --dry-run
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
DOCS_DIR = PROJECT_ROOT / "docs"
HARD_SAMPLES_DIR = PROJECT_ROOT / "experiments/exp_04_hard_samples"

OUTPUT_FILE = DATA_DIR / "cpt_corpus.jsonl"

# 输入数据源（按优先级）
# - high: 高质量漏洞推理文本（CoT + chosen）
# - medium: 漏洞相关补充数据
# - low: 文档/代码（漏洞领域术语学习）
CHATML_SOURCES = [
    ("high", DATA_DIR / "train_chatml_v2.jsonl"),       # 823 条主训练 CoT
    ("high", DATA_DIR / "distill_corpus_annotated_v2.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_contrastive_v2.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_contrastive.jsonl"),
    ("medium", DATA_DIR / "supplement_ccot_v3_expansion.jsonl"),
    ("medium", DATA_DIR / "supplement_longfile_defense.jsonl"),
    ("medium", DATA_DIR / "supplement_longtail_cwe.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_ssti.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_nosql.jsonl"),
    ("medium", DATA_DIR / "supplement_cwe_attribution_spel.jsonl"),
    ("medium", DATA_DIR / "supplement_crypto_noise.jsonl"),
    ("medium", DATA_DIR / "supplement_chatml.jsonl"),
    ("medium", DATA_DIR / "supplement_7b_weakness.jsonl"),
    ("medium", DATA_DIR / "supplement_blindspot_cwe.jsonl"),
    ("medium", DATA_DIR / "glm_cot_map.jsonl"),
    ("low", DATA_DIR / "distill_corpus_annotated.jsonl"),
]

DPO_SOURCES = [
    ("high", DATA_DIR / "dpo_preference_pairs_v3.jsonl"),       # chosen 文本
    ("high", DATA_DIR / "dpo_v3_expansion.jsonl"),
    ("high", DATA_DIR / "dpo_preference_pairs.jsonl"),
]

DOC_SOURCES = [
    ("low", DOCS_DIR / "方法.md"),
    ("low", DOCS_DIR / "改进.md"),
    ("low", DOCS_DIR / "过程.md"),
    ("low", DOCS_DIR / "必须手动学习的地方.md"),
]

MAX_TEXT_LEN = 6000  # 字符级切分上限（约 2000 tokens）


def truncate_text(text: str, max_len: int = MAX_TEXT_LEN) -> list[str]:
    """超长文本按段落边界切分。"""
    if len(text) <= max_len:
        return [text]
    # 按双换行切分，再合并
    paragraphs = text.split("\n\n")
    chunks = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 > max_len and current:
            chunks.append(current.strip())
            current = para
        else:
            current = current + "\n\n" + para if current else para
    if current.strip():
        chunks.append(current.strip())
    return chunks


def extract_text_from_chatml(record: dict) -> str | None:
    """从 ChatML 记录提取 assistant 推理文本（含 system+user 上下文）。

    ChatML 格式：messages = [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]
    """
    if "messages" not in record:
        # DPO 格式：{prompt, chosen, rejected}
        if "chosen" in record:
            return record["chosen"]
        return None

    parts = []
    for msg in record["messages"]:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if not content:
            continue
        # 保留 system/user/assistant 全部内容，作为漏洞领域文本学习
        parts.append(f"### {role.upper()}\n{content}")
    return "\n\n".join(parts) if parts else None


def extract_text_from_dpo(record: dict) -> str | None:
    """从 DPO 记录提取 chosen（高质量漏洞判定）。"""
    if "chosen" not in record:
        return None
    prompt = record.get("prompt", "")
    chosen = record["chosen"]
    # 把 prompt + chosen 拼起来作为完整推理文本
    return f"{prompt}\n\n### CHOSEN RESPONSE\n{chosen}"


def extract_text_from_doc(path: Path) -> str:
    """读取 markdown 文档全文。"""
    return path.read_text(encoding="utf-8")


def extract_from_hard_samples() -> list[str]:
    """从 exp_04_hard_samples 提取漏洞代码 + CVE 描述。"""
    texts = []
    if not HARD_SAMPLES_DIR.exists():
        return texts
    # 只取 samples 目录下的代码文件
    samples_dir = HARD_SAMPLES_DIR / "samples"
    if not samples_dir.exists():
        return texts
    for code_file in samples_dir.glob("*.py"):
        try:
            content = code_file.read_text(encoding="utf-8")
            # 文件名通常含 CVE 编号，作为标题
            title = code_file.stem
            texts.append(f"### CVE/漏洞样本: {title}\n\n```\n{content}\n```")
        except Exception as e:
            print(f"  ⚠️ 跳过 {code_file.name}: {e}", file=sys.stderr)
    return texts


def main():
    parser = argparse.ArgumentParser(description="准备 KnItLM CPT 语料")
    parser.add_argument("--dry-run", action="store_true", help="仅统计，不写文件")
    args = parser.parse_args()

    print("=" * 60)
    print("KnItLM CPT 语料准备")
    print("=" * 60)

    all_texts: list[tuple[str, str]] = []  # (priority, text)
    stats: dict[str, int] = {"high": 0, "medium": 0, "low": 0}

    # 1. ChatML 数据
    print("\n[1/4] 提取 ChatML/DPO 推理文本...")
    for priority, path in CHATML_SOURCES + DPO_SOURCES:
        if not path.exists():
            print(f"  ⚠️ 跳过不存在的文件: {path.name}")
            continue
        count = 0
        with open(path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "chosen" in rec:
                    text = extract_text_from_dpo(rec)
                else:
                    text = extract_text_from_chatml(rec)

                if not text:
                    continue
                for chunk in truncate_text(text):
                    all_texts.append((priority, chunk))
                    count += 1
                    stats[priority] += 1
        print(f"  {priority:6s} {path.name}: +{count} 段")

    # 2. 文档
    print("\n[2/4] 提取 docs/ 文档...")
    for priority, path in DOC_SOURCES:
        if not path.exists():
            continue
        content = extract_text_from_doc(path)
        for chunk in truncate_text(content):
            all_texts.append((priority, chunk))
            stats[priority] += 1
        print(f"  {priority:6s} {path.name}: +{len(truncate_text(content))} 段")

    # 3. hard samples 代码
    print("\n[3/4] 提取 exp_04_hard_samples 代码...")
    hard_texts = extract_from_hard_samples()
    for t in hard_texts:
        for chunk in truncate_text(t):
            all_texts.append(("low", chunk))
            stats["low"] += 1
    print(f"  low    exp_04_hard_samples: +{len(hard_texts)} 段")

    # 4. 统计总字节
    total_bytes = sum(len(t.encode("utf-8")) for _, t in all_texts)
    print("\n" + "=" * 60)
    print("语料统计")
    print("=" * 60)
    print(f"优先级分布: high={stats['high']}, medium={stats['medium']}, low={stats['low']}")
    print(f"总段数: {len(all_texts)}")
    print(f"总字节: {total_bytes:,} ({total_bytes / 1024 / 1024:.2f} MB)")

    # 与论文建议的 10-50MB 对比
    if total_bytes < 10 * 1024 * 1024:
        print(f"⚠️ 语料偏少（<10MB），KnItLM 效果可能有限")
        print(f"   建议后续联网补充 CVE/CWE 官方描述文档")
    elif total_bytes > 50 * 1024 * 1024:
        print(f"⚠️ 语料偏多（>50MB），CPT 训练时间会较长")

    if args.dry_run:
        print("\n[dry-run] 不写文件")
        return

    # 写出
    print(f"\n写入: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fp:
        for priority, text in all_texts:
            rec = {"text": text, "priority": priority}
            fp.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"✅ 已写入 {len(all_texts)} 段到 {OUTPUT_FILE}")
    print(f"   下一步用 train_knitlm_cpt.py 加载此语料做 CPT")


if __name__ == "__main__":
    main()
