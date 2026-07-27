"""
重写模板化 CoT 脚本 —— 用 Ollama qwen3:8b 重写训练数据中的模板化 CoT 分析。

问题：
  train_chatml_v3.jsonl 中有 107 条样本的 CoT 是模板化的：
  - 漏洞样本套用 "代码中无有效防御措施（无参数化、无转义、无校验）" 空话
  - 安全样本套用 4 步 N/A 模板（"sink 评估：N/A" / "防御确认：N/A"）
  需要用 LLM 逐条重写为针对具体代码的高质量分析。

本脚本：
  1. 读取 fix_report.json 获取模板化样本的行号（1-indexed）和文件名
  2. 读取 train_chatml_v3.jsonl
  3. 对每条模板化样本，用 Ollama qwen3:8b 生成新的 CoT 分析
  4. 保留原始 JSON verdict 不变，只替换 CoT 文本
  5. 输出 train_chatml_v3_fixed.jsonl（全部样本，模板化部分被重写）
  6. 输出 rewrite_report.json（记录每条重写的行号、文件名、CoT 长度变化）

用法：
  cd <project_root>
  python3 \
      experiments/exp_06_finetune/scripts/rewrite_template_cot.py --limit 3

  # 运行全部
  python3 \
      experiments/exp_06_finetune/scripts/rewrite_template_cot.py

  # 断点续跑
  python3 \
      experiments/exp_06_finetune/scripts/rewrite_template_cot.py --resume
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
INPUT_FILE = DATA_DIR / "train_chatml_v3.jsonl"
FIX_REPORT = DATA_DIR / "fix_report.json"
OUTPUT_FILE = DATA_DIR / "train_chatml_v3_fixed.jsonl"
PROGRESS_FILE = DATA_DIR / "rewrite_progress.jsonl"
REPORT_FILE = DATA_DIR / "rewrite_report.json"

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen3:8b"


# ---------------------------------------------------------------------------
# Ollama 调用
# ---------------------------------------------------------------------------

def call_ollama(prompt, model=MODEL, timeout=120):
    """调用 Ollama chat API，返回模型回复文本。"""
    import requests
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json={
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.7, "num_ctx": 8192},
        "think": False,  # 禁用 Qwen3 thinking 模式
    }, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["message"]["content"]


# ---------------------------------------------------------------------------
# 解析辅助
# ---------------------------------------------------------------------------

def parse_user_content(content):
    """从 user content 提取 filename, language, code。

    格式: "代码片段（文件名: xxx.py，语言: python）：\n```python\n{code}\n```\n..."
    """
    m = re.search(r'文件名:\s*([^，]+)，', content)
    filename = m.group(1).strip() if m else "unknown"
    m = re.search(r'语言:\s*([^）]+)）', content)
    language = m.group(1).strip() if m else "python"
    pattern = r'```' + re.escape(language) + r'\n(.*?)\n```'
    m = re.search(pattern, content, re.DOTALL)
    code = m.group(1) if m else ""
    return filename, language, code


def extract_json_block(assistant_content):
    """提取 assistant content 中的 ```json ... ``` 块（原始文本，含标记）。"""
    m = re.search(r'```json\s*\n(.*?)\n```', assistant_content, re.DOTALL)
    if m:
        return m.group(0)
    return None


def extract_verdict(assistant_content):
    """从 assistant content 的 JSON 块中解析 verdict dict。"""
    m = re.search(r'```json\s*\n(.*?)\n```', assistant_content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            return None
    return None


def extract_cot(assistant_content):
    """提取 CoT 文本（JSON 块之前的部分）。"""
    idx = assistant_content.find("```json")
    if idx == -1:
        return assistant_content.rstrip()
    return assistant_content[:idx].rstrip()


def clean_ollama_response(text):
    """清理 Ollama 返回：移除 think 块和 JSON 块，只保留分析过程。"""
    # 移除 <think>...</think> 块（Qwen3 thinking 模式）
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    # 移除残留的 <think> 或 </think> 标签
    text = re.sub(r'</?think>', '', text)
    # 如果有 ```json 块，只取之前的部分
    idx = text.find("```json")
    if idx != -1:
        text = text[:idx]
    text = text.strip()
    return text


# ---------------------------------------------------------------------------
# Prompt 构造
# ---------------------------------------------------------------------------

def build_prompt(filename, language, code, has_vuln, vuln_type, risk_level):
    """构造 Ollama prompt。"""
    vuln_line = f"漏洞类型: {vuln_type}" if has_vuln else ""
    risk_line = f"风险等级: {risk_level}" if has_vuln else ""

    prompt = (
        f"你是代码安全审计专家。请对以下代码进行安全分析，生成 5 步 CoT 分析过程。\n\n"
        f"代码片段（文件名: {filename}，语言: {language}）：\n"
        f"```{language}\n{code}\n```\n\n"
        f"已知结论：{'存在漏洞' if has_vuln else '无漏洞'}\n"
        f"{vuln_line}\n"
        f"{risk_line}\n\n"
        f"请生成分析过程，要求：\n"
        f"1. 污染源识别：指出代码中的用户可控输入点（source）\n"
        f"2. 危险 sink 识别：指出危险函数或触发点（sink）\n"
        f"3. 数据流追踪：从 source 到 sink 的数据流路径\n"
        f"4. 防御检查：检查是否存在有效防御措施（参数化查询/转义/白名单/校验等）\n"
        f"5. 结论：综合判断是否存在漏洞\n\n"
        f"要求：\n"
        f"- 分析必须针对具体代码内容，不要套用通用模板\n"
        f"- 措辞要自然多样，不要每次都用相同的句式\n"
        f"- 只输出分析过程（5 步），不要输出 JSON 块\n"
        f"- 分析过程长度 5-8 行\n"
        f"- 用中文回答"
    )
    return prompt


# ---------------------------------------------------------------------------
# 核心重写逻辑
# ---------------------------------------------------------------------------

def rewrite_sample(sample, template_entry, idx, total):
    """重写单条样本的 CoT。

    返回 dict: {status, new_assistant_content, old_cot_len, new_cot_len, old_cot, new_cot}
    """
    messages = sample["messages"]
    user_content = ""
    assistant_content = ""
    for msg in messages:
        if msg["role"] == "user":
            user_content = msg["content"]
        elif msg["role"] == "assistant":
            assistant_content = msg["content"]

    filename, language, code = parse_user_content(user_content)

    # 验证文件名匹配
    expected_filename = template_entry["filename"]
    if filename != expected_filename:
        print(f"  ⚠️ 文件名不匹配: 期望 {expected_filename}, 实际 {filename}")

    # 提取原始 JSON verdict（不修改）
    json_block = extract_json_block(assistant_content)
    verdict = extract_verdict(assistant_content)

    if not json_block or not verdict:
        print(f"  [{idx+1}/{total}] {filename}: 无法提取 JSON verdict，跳过")
        return {"status": "failed", "old_cot": extract_cot(assistant_content),
                "new_cot": "", "old_cot_len": len(extract_cot(assistant_content)),
                "new_cot_len": 0}

    has_vuln = verdict.get("has_vulnerability", False)
    vuln_type = verdict.get("vulnerability_type", "none")
    risk_level = verdict.get("risk_level", "None")

    # 提取原始 CoT
    old_cot = extract_cot(assistant_content)
    old_cot_len = len(old_cot)

    # 构造 prompt 并调用 Ollama
    prompt = build_prompt(filename, language, code, has_vuln, vuln_type, risk_level)

    try:
        raw_response = call_ollama(prompt)
    except Exception as e:
        print(f"  [{idx+1}/{total}] {filename}: Ollama 调用失败 {e}")
        return {"status": "failed", "new_assistant_content": None,
                "old_cot": old_cot, "new_cot": "",
                "old_cot_len": old_cot_len, "new_cot_len": 0}

    # 清理响应
    new_cot = clean_ollama_response(raw_response)

    # 确保以 "分析过程：" 开头（与训练数据格式一致）
    if new_cot and not new_cot.startswith("分析过程"):
        new_cot = "分析过程：\n" + new_cot

    if not new_cot or len(new_cot) < 20:
        print(f"  [{idx+1}/{total}] {filename}: Ollama 返回过短（{len(new_cot)} 字），跳过")
        return {"status": "failed", "new_assistant_content": None,
                "old_cot": old_cot, "new_cot": new_cot,
                "old_cot_len": old_cot_len, "new_cot_len": len(new_cot)}

    # 组合新的 assistant content = 新 CoT + 原始 JSON verdict
    new_assistant_content = new_cot + "\n\n" + json_block

    return {
        "status": "success",
        "new_assistant_content": new_assistant_content,
        "old_cot": old_cot,
        "new_cot": new_cot,
        "old_cot_len": old_cot_len,
        "new_cot_len": len(new_cot),
    }


# ---------------------------------------------------------------------------
# 进度管理
# ---------------------------------------------------------------------------

def load_progress():
    """加载断点续跑进度。返回 dict: line(int) -> entry(dict)。

    同一行多次出现时，取最后一条（覆盖）。
    """
    if not PROGRESS_FILE.exists():
        return {}
    progress = {}
    with open(PROGRESS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            progress[entry["line"]] = entry
    return progress


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="用 Ollama qwen3:8b 重写模板化 CoT")
    parser.add_argument("--resume", action="store_true",
                        help="断点续跑（跳过已成功的样本）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只重写前 N 条模板样本（0=全部，用于测试）")
    args = parser.parse_args()

    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"错误：输入文件不存在: {INPUT_FILE}")
        sys.exit(1)
    if not FIX_REPORT.exists():
        print(f"错误：修复报告不存在: {FIX_REPORT}")
        sys.exit(1)

    # 加载训练数据
    with open(INPUT_FILE, encoding="utf-8") as f:
        samples = [json.loads(l) for l in f if l.strip()]
    print(f"加载 {len(samples)} 条训练样本")

    # 加载模板化样本列表
    with open(FIX_REPORT, encoding="utf-8") as f:
        report = json.load(f)
    template_samples = report.get("template_cot_samples", [])
    print(f"发现 {len(template_samples)} 条模板化 CoT 样本")

    # 限制数量（用于测试）
    if args.limit > 0:
        template_samples = template_samples[:args.limit]
        print(f"限制处理前 {args.limit} 条")

    # 断点续跑
    progress = load_progress() if args.resume else {}
    if progress:
        done = sum(1 for v in progress.values() if v["status"] == "success")
        print(f"断点续跑：已完成 {done} 条")

    # 处理每条模板化样本
    total = len(template_samples)
    results = {}  # line -> result_entry

    # 先加载已成功完成的（从进度文件）
    for line, entry in progress.items():
        if entry["status"] == "success" and "new_assistant_content" in entry:
            results[line] = entry

    # 打开进度文件（resume 追加，否则覆盖）
    prog_mode = "a" if args.resume else "w"
    with open(PROGRESS_FILE, prog_mode, encoding="utf-8") as prog_f:
        for i, tmpl in enumerate(template_samples):
            line = tmpl["line"]
            filename = tmpl["filename"]

            # 跳过已完成
            if line in results:
                print(f"[{i+1}/{total}] 行 {line} ({filename}): 已完成，跳过")
                continue

            print(f"\n[{i+1}/{total}] 行 {line} ({filename})")

            # 获取样本（line 是 1-indexed 文件行号）
            if line < 1 or line > len(samples):
                print(f"  ⚠️ 行号超出范围: {line}")
                continue

            sample = samples[line - 1]  # 转为 0-indexed 数组访问

            result = rewrite_sample(sample, tmpl, i, total)

            if result["status"] == "success":
                results[line] = {
                    "status": "success",
                    "new_assistant_content": result["new_assistant_content"],
                    "old_cot": result["old_cot"],
                    "new_cot": result["new_cot"],
                    "old_cot_len": result["old_cot_len"],
                    "new_cot_len": result["new_cot_len"],
                    "filename": filename,
                    "line": line,
                }
                print(f"  ✓ CoT 长度: {result['old_cot_len']} → {result['new_cot_len']}")
            else:
                print(f"  ✗ 重写失败，保留原始 CoT")

            # 保存进度
            entry = {
                "line": line,
                "filename": filename,
                "status": result["status"],
                "old_cot_len": result["old_cot_len"],
                "new_cot_len": result["new_cot_len"],
                "new_assistant_content": result.get("new_assistant_content"),
                "old_cot": result.get("old_cot", ""),
                "new_cot": result.get("new_cot", ""),
            }
            prog_f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            prog_f.flush()

            # 延迟避免请求过快
            time.sleep(1)

    # 应用所有重写到 samples
    rewritten_count = 0
    failed_count = 0
    report_entries = []

    for tmpl in template_samples:
        line = tmpl["line"]
        filename = tmpl["filename"]

        if line in results and results[line]["status"] == "success":
            idx = line - 1  # 0-indexed
            new_content = results[line]["new_assistant_content"]
            for msg in samples[idx]["messages"]:
                if msg["role"] == "assistant":
                    msg["content"] = new_content
                    break
            report_entries.append({
                "line": line,
                "filename": filename,
                "status": "success",
                "old_cot_len": results[line]["old_cot_len"],
                "new_cot_len": results[line]["new_cot_len"],
            })
            rewritten_count += 1
        else:
            report_entries.append({
                "line": line,
                "filename": filename,
                "status": "failed",
                "old_cot_len": 0,
                "new_cot_len": 0,
            })
            failed_count += 1

    # 写入输出文件（全部样本）
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for rec in samples:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\n输出: {OUTPUT_FILE} ({len(samples)} 条样本)")

    # 写入重写报告
    report_data = {
        "total_template_samples": len(template_samples),
        "rewritten": rewritten_count,
        "failed": failed_count,
        "entries": report_entries,
    }
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
    print(f"报告: {REPORT_FILE}")
    print(f"成功重写 {rewritten_count} 条，失败 {failed_count} 条")


if __name__ == "__main__":
    main()
