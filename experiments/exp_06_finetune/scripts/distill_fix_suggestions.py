#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 DeepSeek 教师为训练数据统一生成"行号锚定的局部修复建议"。

背景（2026-08-08 决策）：
  schema 的 fix_suggestion 从"完整可运行修复代码"改为"行号锚定的单行局部建议"
  （如 'line 3: 应改为 ...'）。现有 7692 条训练数据里 fix_suggestion 风格混乱：
  部分为空、部分为完整代码围栏、部分是无行号的短建议。本脚本把所有漏洞样本
  交给 DeepSeek 教师按统一格式重生成，保证训练标签与 schema/推理口径一致。

流程：
  1. 从 ChatML jsonl 提取漏洞样本：user 代码 + assistant 的 verdict
     （CWE/risk/source/sink/explanation）；
  2. 代码渲染为带行号前缀（1| ...），与推理侧口径一致；
  3. 调 DeepSeek chat/completions，只要求输出 {"fix_suggestion": "..."}；
  4. 校验：JSON 可解析、无代码围栏、无换行、长度 ≤300、行号全部落在真实行数内、
     锚点数 ≤3；失败自动重试（MAX_RETRIES 次）；
  5. 写回原样本 assistant 的 JSON 块，并打溯源 tag fix_distill；
  6. 断点续传：已完成 idx 写入 <output>.done.jsonl，中断后重跑自动跳过；
     失败写入 <output>.failed.jsonl。

安全样本（has_vulnerability=false）原样保留（fix_suggestion 保持 no fix needed）。

用法：
  $env:DEEPSEEK_API_KEY="sk-xxx"
  python experiments/exp_06_finetune/scripts/distill_fix_suggestions.py \
      --input final_train_chatml_quality_final.jsonl \
      --output final_train_chatml_quality_final_fix.jsonl \
      --workers 8
  # 只预览不调 API：
  python ... --input ... --output ... --dry-run
  # 只补空建议（默认全量重生成）：
  python ... --input ... --output ... --only-empty
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "experiments/exp_06_finetune/scripts"))

from graduation_project.fix_verifier import extract_line_refs  # noqa: E402

try:
    from distill_v2.config import (  # noqa: E402
        DEEPSEEK_API_KEY,
        DEEPSEEK_BASE_URL,
        DEEPSEEK_CHAT_URL,
        DEEPSEEK_MODEL,
        MAX_RETRIES,
        REQUEST_TIMEOUT,
        RETRY_BACKOFF,
    )
except Exception:  # 独立运行兜底
    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")
    DEEPSEEK_CHAT_URL = f"{DEEPSEEK_BASE_URL}/v1/chat/completions"
    MAX_RETRIES = 2
    REQUEST_TIMEOUT = 180
    RETRY_BACKOFF = 4

MAX_SUGGESTION_CHARS = 500
MAX_ANCHORS = 3

FIX_SYSTEM_PROMPT = """\
你是代码安全修复专家。对给定漏洞代码，只给出**行号锚定的最小局部修复建议**，不要重写整个文件。

硬性要求：
1. 只输出一个 JSON 对象：{"fix_suggestion": "..."}，不要输出其他文字、不要 ```json 围栏。
2. fix_suggestion 必须是单行字符串；有多处要改时，用中文分号「；」连接多个 "line N: ..."。
3. 每条建议必须锚定代码中真实存在的行号，格式统一为：
   line N: 应改为 ...
   （或 line N: 建议改为 ...）
4. 只指出错误行及其最小改法（一两行代码即可），禁止输出完整文件、补丁、省略号或"见下文"。
5. 不得虚构代码中不存在的行号、API、参数。
6. 若漏洞需要多处配合修改，最多给 3 个行号锚点，每个锚点给出该行改法。
7. 该代码已被确认存在漏洞，禁止输出 "no fix needed"。"""


# ---------------------------------------------------------------------------
# 解析与渲染
# ---------------------------------------------------------------------------
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def extract_code(text: str) -> Optional[str]:
    """从 user 消息提取最后一个代码围栏块。"""
    if not text:
        return None
    blocks = _FENCE_RE.findall(text)
    return blocks[-1].strip() if blocks else None


def extract_verdict(assistant: str) -> Optional[dict]:
    """从 assistant 内容提取最后一个 ```json 块并解析。"""
    if not assistant:
        return None
    for raw in reversed(_JSON_BLOCK_RE.findall(assistant)):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            continue
    return None


def render_numbered(code: str) -> str:
    """给代码加行号前缀：1| import os ...（与两阶段裁决切片口径一致）。"""
    return "\n".join(f"{i}| {line}" for i, line in enumerate(code.split("\n"), 1))


def build_verdict_summary(verdict: dict) -> str:
    """把 verdict 压缩成教师参考的漏洞结论。"""
    lines = []
    lines.append(f"- CWE: {verdict.get('vulnerability_type') or '未知'}")
    lines.append(f"- 风险等级: {verdict.get('risk_level') or '未知'}")
    lines.append(f"- 污染源: {verdict.get('source') or 'N/A'}")
    lines.append(f"- 危险点: {verdict.get('sink') or 'N/A'}")
    expl = (verdict.get("explanation") or "").strip()
    if expl:
        lines.append(f"- 成因: {expl}")
    return "\n".join(lines)


def build_teacher_prompt(code: str, verdict: dict) -> tuple[str, str]:
    """构造教师请求。返回 (system, user)。"""
    user = (
        "以下是存在漏洞的代码（每行带行号）：\n\n"
        "```python\n"
        f"{render_numbered(code)}\n"
        "```\n\n"
        "漏洞信息（已确认，无需重新检测）：\n"
        f"{build_verdict_summary(verdict)}\n\n"
        "请按系统要求给出修复建议。"
    )
    return FIX_SYSTEM_PROMPT, user


# ---------------------------------------------------------------------------
# 输出解析与校验
# ---------------------------------------------------------------------------
_JSON_OBJ_RE = re.compile(r'\{\s*"fix_suggestion"\s*:\s*"((?:[^"\\]|\\.)*)"\s*\}')


def extract_suggestion(content: str) -> tuple[Optional[str], str]:
    """从教师回复中提取 fix_suggestion 文本。

    Returns:
        (suggestion, reason)；suggestion=None 表示提取失败。
    """
    if not content:
        return None, "教师返回空内容"
    # 1) ```json 围栏块
    for raw in reversed(_JSON_BLOCK_RE.findall(content)):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and "fix_suggestion" in obj:
                return str(obj["fix_suggestion"]).strip(), "ok"
        except json.JSONDecodeError:
            continue
    # 2) 裸 JSON 对象
    m = _JSON_OBJ_RE.search(content)
    if m:
        return m.group(1).strip(), "ok"
    # 3) 教师未包 JSON、直接给建议文本：仅当看起来是行号锚定建议时接受
    stripped = content.strip()
    if re.match(r"^(line\s*\d+|第\s*\d+\s*行)", stripped, re.IGNORECASE):
        return stripped, "ok_raw_text"
    return None, "未找到 fix_suggestion 字段"


def validate_suggestion(suggestion: str, code: str) -> tuple[bool, str]:
    """校验建议是否符合新 schema。

    Returns:
        (ok, reason)
    """
    if not suggestion:
        return False, "建议为空"
    if "```" in suggestion:
        return False, "建议含代码围栏"
    if "\n" in suggestion or "\r" in suggestion:
        return False, "建议含换行"
    if len(suggestion) > MAX_SUGGESTION_CHARS:
        return False, f"建议超长（>{MAX_SUGGESTION_CHARS} 字符）"
    if "no fix needed" in suggestion.lower():
        return False, "漏洞样本输出 no fix needed"
    refs = extract_line_refs(suggestion)
    if not refs:
        return False, "建议未锚定行号"
    if len(refs) > MAX_ANCHORS:
        return False, f"行号锚点超过 {MAX_ANCHORS} 个"
    total = len(code.split("\n"))
    if not all(1 <= n <= total for n in refs):
        return False, f"行号超出代码范围（1..{total}）: {sorted(refs)}"
    return True, "ok"


def merge_suggestion(rec: dict, suggestion: str, teacher: str) -> dict:
    """把新建议写回 assistant 的 JSON 块，并打溯源 tag。"""
    msgs = rec.get("messages", [])
    asst = msgs[2].get("content", "")
    raw_match = _JSON_BLOCK_RE.search(asst)
    if raw_match is None:
        return rec
    raw = raw_match.group(1)
    verdict = extract_verdict(asst)
    if verdict is None:
        return rec
    verdict = dict(verdict)
    verdict["fix_suggestion"] = suggestion
    new_json = json.dumps(verdict, ensure_ascii=False)
    new_asst = asst.rsplit("```json", 1)[0] + "```json\n" + new_json + "\n```"
    new_rec = dict(rec)
    new_rec["messages"] = [msgs[0], msgs[1], {"role": "assistant", "content": new_asst}]
    new_rec["fix_distill"] = {
        "teacher": teacher,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return new_rec


# ---------------------------------------------------------------------------
# 教师调用
# ---------------------------------------------------------------------------
def call_teacher(
    system: str,
    user: str,
    *,
    api_key: str = DEEPSEEK_API_KEY,
    base_url: str = DEEPSEEK_BASE_URL,
    model: str = DEEPSEEK_MODEL,
    timeout: int = REQUEST_TIMEOUT,
) -> str:
    """调用 DeepSeek chat/completions，返回回复文本；失败抛异常。"""
    import requests

    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        # 关闭思考链：V4-Flash 思考会占满 max_tokens 导致 content 为空（见 config.py 注释）
        "thinking": {"type": "disabled"},
        "temperature": 0.3,
        "max_tokens": 1024,
        "stream": False,
    }
    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_key}"},
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def process_task(
    idx: int,
    rec: dict,
    api_fn: Callable[[str, str], str],
    teacher: str,
    only_empty: bool,
) -> tuple[int, Optional[dict], Optional[str]]:
    """处理单条漏洞样本。返回 (idx, 更新后的 record 或 None, error 或 None)。"""
    msgs = rec.get("messages", [])
    if len(msgs) < 3:
        return idx, None, "消息结构不完整"
    code = extract_code(msgs[1].get("content", ""))
    if not code:
        return idx, None, "无法从 user 消息提取代码"
    verdict = extract_verdict(msgs[2].get("content", ""))
    if verdict is None:
        return idx, None, "无法从 assistant 提取 verdict"
    if verdict.get("has_vulnerability") is not True:
        return idx, None, None  # 安全样本：原样保留
    if only_empty and (verdict.get("fix_suggestion") or "").strip():
        return idx, None, None  # 已有建议且只补空：跳过

    system, user = build_teacher_prompt(code, verdict)
    last_error = ""
    for attempt in range(MAX_RETRIES + 1):
        try:
            content = api_fn(system, user)
            suggestion, extract_reason = extract_suggestion(content)
            if suggestion is None:
                last_error = f"提取失败: {extract_reason}"
            else:
                ok, reason = validate_suggestion(suggestion, code)
                if ok:
                    return idx, merge_suggestion(rec, suggestion, teacher), None
                last_error = f"校验失败: {reason}"
        except Exception as e:  # noqa: BLE001
            last_error = f"API 异常: {type(e).__name__}: {e}"
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF * (attempt + 1))
    return idx, None, last_error


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_done_indices(path: Path) -> set[int]:
    path = Path(path)
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.add(int(json.loads(line)["idx"]))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="DeepSeek 教师统一生成行号锚定修复建议")
    ap.add_argument("--input", required=True, help="训练 ChatML jsonl")
    ap.add_argument("--output", required=True, help="输出 jsonl")
    ap.add_argument("--only-empty", action="store_true",
                    help="只处理 fix_suggestion 为空的样本（默认全量重生成漏洞样本）")
    ap.add_argument("--limit", type=int, default=0, help="最多处理 N 条（0=不限）")
    ap.add_argument("--workers", type=int, default=8, help="并发数")
    ap.add_argument("--dry-run", action="store_true", help="只打印预览，不调 API 不写文件")
    ap.add_argument("--api-key", default=None, help="DeepSeek API Key（默认读 DEEPSEEK_API_KEY）")
    ap.add_argument("--model", default=DEEPSEEK_MODEL, help=f"教师模型（默认 {DEEPSEEK_MODEL}）")
    ap.add_argument("--base-url", default=DEEPSEEK_BASE_URL, help=f"API 地址（默认 {DEEPSEEK_BASE_URL}）")
    args = ap.parse_args()

    api_key = args.api_key or DEEPSEEK_API_KEY
    if not api_key and not args.dry_run:
        print("[错误] 缺少 DEEPSEEK_API_KEY（或 --api-key）")
        return 1

    in_path, out_path = Path(args.input), Path(args.output)
    records = load_jsonl(in_path)
    done_path = Path(str(out_path) + ".done.jsonl")
    failed_path = Path(str(out_path) + ".failed.jsonl")
    done = load_done_indices(done_path)

    tasks: list[tuple[int, dict]] = []
    for idx, rec in enumerate(records):
        msgs = rec.get("messages", [])
        if len(msgs) < 3:
            continue
        verdict = extract_verdict(msgs[2].get("content", ""))
        if verdict and verdict.get("has_vulnerability") is True and idx not in done:
            tasks.append((idx, rec))
    if args.limit:
        tasks = tasks[: args.limit]

    print(f"输入 {len(records)} 条 | 漏洞样本待处理 {len(tasks)} | 已完成跳过 {len(done)}")
    if args.dry_run:
        print("\n=== 预览前 3 条教师请求 ===")
        for idx, rec in tasks[:3]:
            code = extract_code(rec["messages"][1].get("content", "")) or ""
            verdict = extract_verdict(rec["messages"][2].get("content", "")) or {}
            system, user = build_teacher_prompt(code, verdict)
            print(f"--- idx={idx} ---")
            print(system[:200] + "...")
            print(user[:600])
        print(f"\n[dry-run] 未调 API、未写文件。预计调用 {len(tasks)} 次。")
        return 0

    if not tasks:
        print("没有待处理样本（全部已完成或输入里没有漏洞样本）")
        _write_output(records, out_path)
        return 0

    api_fn = lambda s, u: call_teacher(  # noqa: E731
        s, u, api_key=api_key, base_url=args.base_url, model=args.model,
    )
    write_lock = threading.Lock()
    success_count = failed_count = 0

    def save_done(idx: int, rec: dict) -> None:
        with write_lock:
            with done_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"idx": idx}, ensure_ascii=False) + "\n")
        records[idx] = rec

    def save_failed(idx: int, error: str) -> None:
        nonlocal failed_count
        with write_lock:
            failed_count += 1
            with failed_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"idx": idx, "error": error}, ensure_ascii=False) + "\n")

    completed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(process_task, idx, rec, api_fn, args.model, args.only_empty): idx
            for idx, rec in tasks
        }
        for fut in as_completed(futures):
            idx, new_rec, error = fut.result()
            if new_rec is not None:
                success_count += 1
                save_done(idx, new_rec)
            elif error:
                save_failed(idx, error)
            completed += 1
            if completed % 20 == 0 or completed == len(tasks):
                print(f"  进度 {completed}/{len(tasks)} | 成功 {success_count} | 失败 {failed_count}",
                      flush=True)

    _write_output(records, out_path)
    print(f"\n完成: 成功 {success_count} | 失败 {failed_count} | 跳过 {len(tasks) - success_count - failed_count}")
    if failed_count:
        print(f"失败明细: {failed_path}")
    print(f"输出: {out_path} ({len(records)} 条)")
    return 0


def _write_output(records: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
