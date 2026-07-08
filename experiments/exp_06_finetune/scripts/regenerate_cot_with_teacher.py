"""
教师模型蒸馏脚本 —— 用 qwen2.5-coder:7b 重新生成多样化、非模板化的 CoT 分析。

核心问题：
  原始训练数据的安全样本全部使用同一个模板 "代码使用了安全写法，未发现漏洞。"，
  导致微调后模型学会"无脑判安全"的退化策略（11/11 FN 全部输出此模板）。

本脚本：
  1. 读取 distill_corpus_annotated.jsonl（400 条标注样本）
  2. 用 Ollama qwen2.5-coder:7b 作为教师模型，对每条代码生成真实分析
  3. 教师模型的回复天然多样化——同类漏洞的分析角度、措辞、推理路径各不相同
  4. 从教师回复中提取 CoT 分析 + JSON 结论，与原始标签做交叉校验
  5. 若教师结论与标注标签冲突，保留标注标签但采用教师的分析文本（人工标注更可信）
  6. 输出新的 annotated jsonl，替换 build_cot() 模板生成的 cot_analysis

用法：
  cd /home/zane/文档/code/毕业设计
  PYTHONPATH=. /home/zane/miniconda3/envs/AI/bin/python \
      experiments/exp_06_finetune/scripts/regenerate_cot_with_teacher.py

  # 指定其他教师模型
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/regenerate_cot_with_teacher.py \
      --teacher qwen2.5-coder:14b

  # 断点续跑（跳过已处理的样本）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/regenerate_cot_with_teacher.py \
      --resume
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
INPUT_FILE = DATA_DIR / "distill_corpus_annotated.jsonl"
OUTPUT_FILE = DATA_DIR / "distill_corpus_annotated_v2.jsonl"
PROGRESS_FILE = DATA_DIR / "distill_cot_progress.jsonl"

DEFAULT_TEACHER = "qwen2.5-coder:7b"
OLLAMA_URL = "http://localhost:11434"


def call_ollama(teacher: str, system_prompt: str, user_prompt: str,
                temperature: float = 0.3, timeout: int = 120) -> str:
    """调用 Ollama chat API，返回教师模型的回复文本。"""
    import requests
    payload = {
        "model": teacher,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_ctx": 8192,
            "num_predict": 1024,
        },
        "keep_alive": "5m",
    }
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data.get("message", {}).get("content", "")


def extract_cot_and_verdict(raw_output: str) -> tuple[str, dict | None]:
    """从教师回复中分离 CoT 分析文本和 JSON 结论。

    返回 (cot_text, verdict_dict)。
    cot_text 是 JSON 块之前的分析过程。
    verdict_dict 是从 JSON 块解析出的结论。
    """
    # 找 JSON 块
    json_match = re.search(r"```json\s*\n(.*?)\n```", raw_output, re.DOTALL)
    if json_match:
        json_str = json_match.group(1).strip()
        cot_text = raw_output[:json_match.start()].rstrip()
        try:
            verdict = json.loads(json_str)
            return cot_text, verdict
        except json.JSONDecodeError:
            # 尝试宽松解析
            verdict = parse_verdict(raw_output)
            if verdict:
                return cot_text, verdict
            return cot_text, None
    else:
        # 没有 JSON 块，尝试 parse_verdict
        verdict = parse_verdict(raw_output)
        if verdict:
            # 找到 verdict 出现的位置
            cot_text = raw_output.rstrip()
            return cot_text, verdict
        return raw_output, None


def process_sample(rec: dict, teacher: str, idx: int, total: int) -> dict:
    """处理单条样本：用教师模型生成 CoT，与标注标签交叉校验。"""
    code = rec["code"]
    language = rec.get("language", "python")
    filename = rec.get("filename", "sample.py")
    expected_vuln = rec.get("has_vulnerability", False)

    user_prompt = build_user_prompt(code=code, language=language, filename=filename)

    # 调用教师模型（temperature=0.3 增加多样性，不像模板那样千篇一律）
    try:
        raw_output = call_ollama(teacher, SYSTEM_PROMPT, user_prompt, temperature=0.3)
    except Exception as e:
        print(f"  [{idx+1}/{total}] {filename}: 教师调用失败 {e}，保留原始 CoT")
        return rec  # 失败则保留原始数据

    cot_text, teacher_verdict = extract_cot_and_verdict(raw_output)

    if not cot_text or len(cot_text) < 20:
        print(f"  [{idx+1}/{total}] {filename}: 教师回复过短，保留原始 CoT")
        return rec

    # 交叉校验：教师结论与标注标签是否一致
    teacher_vuln = None
    if teacher_verdict:
        teacher_vuln = normalize_has_vulnerability(
            teacher_verdict.get("has_vulnerability")
        )

    if teacher_vuln is not None and teacher_vuln != expected_vuln:
        # 冲突：教师判安全但标注是漏洞，或教师判漏洞但标注是安全
        # 保留人工标注标签（更可信），但采用教师的分析文本
        # 在 CoT 末尾追加标注修正，保持一致性
        conflict_note = (
            f"\n\n（注：经人工复核，最终判定为 {'存在' if expected_vuln else '不存在'}"
            f"漏洞，与教师模型初步判断不同。）"
        )
        cot_text = cot_text + conflict_note
        print(f"  [{idx+1}/{total}] {filename}: 教师结论与标注冲突（教师={teacher_vuln}），"
              f"保留标注={expected_vuln}，采用教师分析+修正注")
    else:
        print(f"  [{idx+1}/{total}] {filename}: 教师分析已生成（{len(cot_text)} 字）")

    # 更新记录
    new_rec = dict(rec)
    new_rec["cot_analysis"] = cot_text

    # 如果教师提供了更丰富的字段，也更新（但保留标注标签作为 ground truth）
    if teacher_verdict and teacher_vuln == expected_vuln:
        # 教师和标注一致，可以采用教师的 source/sink/explanation（更具体）
        if teacher_verdict.get("source") and teacher_verdict["source"] != "N/A":
            new_rec["source"] = teacher_verdict["source"]
        if teacher_verdict.get("sink") and teacher_verdict["sink"] != "N/A":
            new_rec["sink"] = teacher_verdict["sink"]
        teacher_expl = teacher_verdict.get("explanation", "")
        if teacher_expl and teacher_expl != "代码使用了安全写法，未发现漏洞。":
            new_rec["taint_path"] = teacher_expl
        if teacher_verdict.get("fix_suggestion") and teacher_verdict["fix_suggestion"] != "no fix needed":
            new_rec["fix_idea"] = teacher_verdict["fix_suggestion"]

    return new_rec


def load_progress() -> dict:
    """加载断点续跑进度。"""
    if PROGRESS_FILE.exists():
        progress = {}
        with open(PROGRESS_FILE, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    d = json.loads(line)
                    progress[d["filename"]] = d
        return progress
    return {}


def main():
    parser = argparse.ArgumentParser(description="用教师模型重新生成多样化 CoT")
    parser.add_argument("--teacher", type=str, default=DEFAULT_TEACHER,
                        help=f"教师模型（默认 {DEFAULT_TEACHER}）")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑（跳过已处理的样本）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只处理前 N 条（0=全部，用于测试）")
    parser.add_argument("--temperature", type=float, default=0.3,
                        help="教师模型采样温度（默认 0.3，增加多样性）")
    args = parser.parse_args()

    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"错误：输入文件不存在: {INPUT_FILE}")
        sys.exit(1)

    # 加载样本
    with open(INPUT_FILE, encoding="utf-8") as f:
        samples = [json.loads(l) for l in f if l.strip()]
    print(f"加载 {len(samples)} 条样本")

    if args.limit > 0:
        samples = samples[:args.limit]
        print(f"限制处理前 {args.limit} 条")

    # 断点续跑
    progress = load_progress() if args.resume else {}
    if progress:
        print(f"断点续跑：已完成 {len(progress)} 条")

    # 处理每条样本
    processed = 0
    skipped = 0
    conflicts = 0
    output_samples = []

    # 先加载已完成的
    for s in samples:
        if s["filename"] in progress:
            output_samples.append(progress[s["filename"]])
            skipped += 1

    # 处理未完成的
    with open(PROGRESS_FILE, "a", encoding="utf-8") as prog_f:
        for i, rec in enumerate(samples):
            if rec["filename"] in progress:
                continue

            # 调用教师模型
            result = process_sample(rec, args.teacher, i, len(samples))
            output_samples.append(result)
            processed += 1

            # 保存进度
            prog_f.write(json.dumps(result, ensure_ascii=False) + "\n")
            prog_f.flush()

            # 小延迟避免请求过快
            time.sleep(0.5)

    # 按原始顺序排列
    filename_to_sample = {s["filename"]: s for s in output_samples}
    ordered_samples = [filename_to_sample[s["filename"]] for s in samples
                       if s["filename"] in filename_to_sample]

    # 写入最终输出
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for rec in ordered_samples:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n完成：处理 {processed} 条，跳过 {skipped} 条（断点续跑）")
    print(f"输出: {OUTPUT_FILE}")
    print(f"进度文件: {PROGRESS_FILE}")

    # 统计 CoT 多样性
    cot_texts = [s.get("cot_analysis", "") for s in ordered_samples]
    unique_texts = len(set(cot_texts))
    print(f"CoT 多样性: {unique_texts}/{len(cot_texts)} 条唯一文本")

    # 检查安全样本的 explanation 是否多样化
    safe_samples = [s for s in ordered_samples if not s.get("has_vulnerability")]
    safe_expls = [s.get("taint_path", "") for s in safe_samples]
    unique_expls = len(set(safe_expls))
    print(f"安全样本 explanation 多样性: {unique_expls}/{len(safe_samples)} 条唯一")


if __name__ == "__main__":
    main()
