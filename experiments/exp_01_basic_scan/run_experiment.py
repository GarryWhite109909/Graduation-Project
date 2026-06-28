"""
exp_01_basic_scan - 批量漏洞检测摸底测试脚本

读取 samples/manifest.json 中登记的代码样本，依次调用本地 Ollama API
（默认模型 gemma4:26b）进行漏洞分析，将每次推理的原始输出、耗时、解析
后的判定结果统一写入 results/results.json，便于后续人工复核与统计。

用法:
    python run_experiment.py                          # 使用默认配置运行全部样本
    python run_experiment.py --model gemma4:26b       # 指定模型
    python run_experiment.py --limit 3                # 只跑前 3 个样本（调试用）
    python run_experiment.py --host http://localhost:11434
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"

# ---------------------------------------------------------------------------
# 统一 Prompt 模板
# ---------------------------------------------------------------------------
PROMPT_TEMPLATE = """你是一名资深的代码安全审计专家。请对下面给出的代码片段进行安全分析，
判断其中是否存在安全漏洞。分析范围包括但不限于：SQL 注入、跨站脚本（XSS）、
命令注入、路径穿越、硬编码敏感信息（密钥/密码/Token）、不安全的反序列化等。

要求：
1. 仔细阅读代码语义，结合上下文判断用户可控输入是否被安全处理。
2. 不要夸大风险，也不要遗漏明显的漏洞。
3. 在回答的最后，必须严格输出一个 JSON 对象作为最终结论，JSON 块用 ```json 包裹，
   字段如下：
   - vulnerability_found: 布尔值，true 表示存在漏洞，false 表示未发现漏洞
   - vulnerability_type: 字符串，漏洞类型；若未发现漏洞，填 "none"
   - explanation: 字符串，对漏洞或安全现状的简短说明
   - fix_suggestion: 字符串，修复建议；若未发现漏洞，填 "no fix needed"

代码片段（文件名: {filename}，语言: {language}）：
```{language}
{code}
```

请先给出分析过程，然后在最后给出 JSON 结论。
"""


def build_prompt(code: str, filename: str, language: str) -> str:
    """构造单次推理的 prompt。"""
    return PROMPT_TEMPLATE.format(
        code=code, filename=filename, language=language or "text"
    )


def call_ollama(
    host: str,
    model: str,
    prompt: str,
    timeout: int = 300,
    temperature: float = 0.1,
) -> tuple[str, dict]:
    """调用 Ollama /api/generate 接口，返回 (响应文本, 元信息)。"""
    url = host.rstrip("/") + "/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = data.get("response", "")
    meta = {
        "eval_count": data.get("eval_count"),
        "eval_duration_ns": data.get("eval_duration"),
        "load_duration_ns": data.get("load_duration"),
        "total_duration_ns": data.get("total_duration"),
        "prompt_eval_count": data.get("prompt_eval_count"),
    }
    return text, meta


def unload_model(host: str, model: str, timeout: int = 60) -> bool:
    """主动从显存卸载模型（keep_alive=0）。多模型场景下避免爆显存。

    通过向 /api/generate 发送一个 keep_alive=0 的空请求，Ollama 会立即
    释放该模型占用的显存。返回 True 表示卸载请求成功发出。
    """
    url = host.rstrip("/") + "/api/generate"
    payload = {"model": model, "keep_alive": 0}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return True
    except Exception as e:  # noqa: BLE001
        print(f"[警告] 卸载模型失败: {e}", file=sys.stderr)
        return False


def parse_verdict(raw_output: str) -> dict:
    """从模型输出中抽取最后的 JSON 结论。"""
    # 优先匹配 ```json ... ``` 代码块
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", raw_output, re.DOTALL)
    candidates = blocks if blocks else re.findall(r"\{[^{}]*\"vulnerability_found\"[^{}]*\}", raw_output, re.DOTALL)
    for cand in candidates[-1:] if candidates else []:
        try:
            parsed = json.loads(cand)
            if "vulnerability_found" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    # 兜底：尝试找最后一个完整的 { ... } 片段
    for match in re.finditer(r"\{[^{}]*\}", raw_output, re.DOTALL):
        try:
            parsed = json.loads(match.group(0))
            if "vulnerability_found" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description="批量漏洞检测摸底测试")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址（默认 http://localhost:11434）")
    parser.add_argument("--model", default="gemma4:26b",
                        help="Ollama 中模型名（默认 gemma4:26b）")
    parser.add_argument("--temperature", type=float, default=0.1,
                        help="采样温度（默认 0.1，更稳定）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--timeout", type=int, default=600,
                        help="单次请求超时秒数（默认 600）")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载，多模型场景避免爆显存）")
    args = parser.parse_args()

    if not MANIFEST_PATH.exists():
        print(f"[错误] 找不到 manifest: {MANIFEST_PATH}", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = manifest["samples"]
    if args.limit > 0:
        samples = samples[: args.limit]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = {
        "experiment": manifest.get("experiment", "exp_01_basic_scan"),
        "model": args.model,
        "host": args.host,
        "temperature": args.temperature,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": [],
    }

    total = len(samples)
    print(f"[信息] 共 {total} 个样本，模型 {args.model}，host {args.host}")

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        sample_path = SAMPLES_DIR / filename
        if not sample_path.exists():
            print(f"[跳过] 样本文件不存在: {sample_path}", file=sys.stderr)
            continue
        code = sample_path.read_text(encoding="utf-8")
        language = sample_meta.get("language", "text")

        prompt = build_prompt(code, filename, language)
        print(f"[{idx}/{total}] 分析 {filename} ({language}, expected_present={sample_meta['expected_present']}) ...", flush=True)

        record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "prompt_chars": len(prompt),
            "elapsed_seconds": None,
            "raw_output": None,
            "parsed_verdict": {},
            "model_vulnerability_found": None,
            "error": None,
        }

        t0 = time.time()
        try:
            text, meta = call_ollama(
                host=args.host,
                model=args.model,
                prompt=prompt,
                timeout=args.timeout,
                temperature=args.temperature,
            )
            elapsed = round(time.time() - t0, 2)
            record["elapsed_seconds"] = elapsed
            record["raw_output"] = text
            record["meta"] = meta
            verdict = parse_verdict(text)
            record["parsed_verdict"] = verdict
            if verdict:
                found = verdict.get("vulnerability_found")
                if isinstance(found, str):
                    found = found.strip().lower() in ("true", "yes", "1")
                record["model_vulnerability_found"] = bool(found) if found is not None else None
            print(f"        -> 用时 {elapsed}s, 判定={record['model_vulnerability_found']}")
        except urllib.error.URLError as e:
            record["error"] = f"URLError: {e}"
            print(f"        [错误] 无法连接 Ollama：{e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            record["error"] = f"{type(e).__name__}: {e}"
            print(f"        [错误] {e}", file=sys.stderr)

        results["samples"].append(record)
        # 每跑完一个样本立即落盘，避免中途崩溃丢失结果
        (RESULTS_DIR / "results.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (RESULTS_DIR / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[完成] 结果已写入 {RESULTS_DIR / 'results.json'}")

    # 默认跑完立即从显存卸载模型，多模型场景下避免爆显存
    if args.keep_loaded:
        print(f"[信息] --keep-loaded 已启用，模型 {args.model} 保留在显存中")
    else:
        if unload_model(args.host, args.model):
            print(f"[信息] 模型 {args.model} 已从显存卸载（如需保留请加 --keep-loaded）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
