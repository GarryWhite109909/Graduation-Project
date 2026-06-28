"""
exp_03_rag_knowledge - RAG 增强漏洞检测批量对比实验

复用 exp_01 的 14 段样本，对每个样本：
1. 用样本代码查询 Chroma 知识库，检索 Top-K 相关漏洞知识
2. 把检索到的知识作为 rag_context 注入 prompt
3. 调用 Gemma 4 26B 分析（RAG+LLM 版本）
4. 记录结果，与 exp_01 纯 LLM 结果对比

输出格式与 exp_01 对齐，便于横向对比检出率、耗时、输出质量。

用法:
    python run_rag_experiment.py                          # 跑全部 14 样本
    python run_rag_experiment.py --limit 3                # 只跑前 3 个（调试）
    python run_rag_experiment.py --top-k 5                # 检索 Top-5 知识
    python run_rag_experiment.py --model gemma4:26b       # 指定模型
    python run_rag_experiment.py --keep-loaded            # 跑完不卸载模型
"""

import argparse
import json
import sys
import time
from pathlib import Path

# 把项目根加入 sys.path，保证可从任意目录运行
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.chroma_manager import ChromaManager
from src.llm_client import OllamaClient
from src.prompts import SYSTEM_PROMPT, build_user_prompt
from src.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest,
    read_sample_code,
    save_results_json,
    new_results_envelope,
    compute_detection_metrics,
    print_summary,
)

# ---------------------------------------------------------------------------
# 路径常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
# 复用 exp_01 的样本集，保证与纯 LLM 基线对比公平
SAMPLES_DIR = SCRIPT_DIR.parent / "exp_01_basic_scan" / "samples"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
RESULTS_DIR = SCRIPT_DIR / "results"
KNOWLEDGE_COLLECTION = "vulnerability_knowledge"


def build_rag_context(query_code: str, cm: ChromaManager, top_k: int = 3) -> tuple[str, list[dict]]:
    """用代码内容查询知识库，构建 RAG 上下文。

    Args:
        query_code: 待分析的代码全文（作为查询文本）
        cm: ChromaManager 实例
        top_k: 检索 Top-K 条相关知识

    Returns:
        (rag_context_str, retrieval_records)
        - rag_context_str: 拼接好的知识上下文，注入 prompt
        - retrieval_records: 每条检索结果的元信息（id/type/distance），用于结果记录
    """
    # 用代码全文查询。embedding 模型会截断到 256 token，但前半段通常含关键特征
    results = cm.query(KNOWLEDGE_COLLECTION, query_code, n_results=top_k)

    retrieval_records = []
    context_parts = []
    for i, (doc, dist, meta) in enumerate(zip(
        results["documents"],
        results["distances"],
        results["metadatas"],
    )):
        retrieval_records.append({
            "rank": i + 1,
            "id": results["ids"][i] if i < len(results.get("ids", [])) else None,
            "type": meta.get("type"),
            "cwe": meta.get("cwe"),
            "distance": round(dist, 4),
        })
        context_parts.append(f"【知识 {i+1}】({meta.get('type', '未知')} / {meta.get('cwe', '')})\n{doc}")

    rag_context = "\n\n".join(context_parts) if context_parts else ""
    return rag_context, retrieval_records


def main() -> int:
    parser = argparse.ArgumentParser(description="RAG 增强漏洞检测批量对比实验")
    parser.add_argument("--host", default="http://localhost:11434",
                        help="Ollama 服务地址")
    parser.add_argument("--model", default="gemma4:26b",
                        help="Ollama 模型名")
    parser.add_argument("--temperature", type=float, default=0.1,
                        help="采样温度（默认 0.1）")
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--top-k", type=int, default=3,
                        help="RAG 检索 Top-K 条知识（默认 3）")
    parser.add_argument("--timeout", type=int, default=600,
                        help="单次请求超时秒数")
    parser.add_argument("--keep-loaded", action="store_true",
                        help="跑完后保持模型在显存中（默认卸载）")
    args = parser.parse_args()

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    # 初始化知识库客户端
    print("[信息] 初始化 Chroma 知识库客户端...")
    cm = ChromaManager()
    try:
        kb_count = cm.count(KNOWLEDGE_COLLECTION)
    except Exception as e:
        print(f"[错误] 知识库集合 {KNOWLEDGE_COLLECTION} 不存在，请先运行 build_knowledge.py: {e}", file=sys.stderr)
        return 1
    print(f"[信息] 知识库 {KNOWLEDGE_COLLECTION} 共 {kb_count} 条知识，Top-K={args.top_k}")

    if kb_count == 0:
        print(f"[错误] 知识库为空，请先运行 build_knowledge.py", file=sys.stderr)
        return 1

    # 初始化 LLM 客户端
    client = OllamaClient(base_url=args.host, model=args.model)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama（{args.host}），请先运行 ollama serve", file=sys.stderr)
        return 1

    results = new_results_envelope(
        experiment="exp_03_rag_knowledge",
        model=args.model,
        host=args.host,
        temperature=args.temperature,
        top_k=args.top_k,
        knowledge_count=kb_count,
        baseline="exp_01_basic_scan (纯 LLM)",
    )

    total = len(samples)
    print(f"[信息] 共 {total} 个样本，模型 {args.model}，RAG Top-{args.top_k}")

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        code = read_sample_code(SAMPLES_DIR, filename)
        if code is None:
            continue
        language = sample_meta.get("language", "text")

        print(f"[{idx}/{total}] {filename} ({language}, expected_present={sample_meta['expected_present']})", flush=True)

        # 1. RAG 检索
        rag_context, retrieval_records = build_rag_context(code, cm, top_k=args.top_k)
        if retrieval_records:
            top_types = [r["type"] for r in retrieval_records]
            top_dists = [r["distance"] for r in retrieval_records]
            print(f"        检索 Top-{args.top_k}: {top_types}, distances={top_dists}")
        else:
            print(f"        [警告] 未检索到任何知识，将以纯 LLM 模式分析")

        # 2. LLM 分析（RAG 增强）
        record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "rag_retrieval": retrieval_records,
            "rag_context_chars": len(rag_context) if rag_context else 0,
            "elapsed_seconds": None,
            "raw_output": None,
            "parsed_verdict": {},
            "model_has_vulnerability": None,
            "error": None,
        }

        # 直接调用 generate 以控制 keep_alive="-1"（批量期间常驻，跑完统一卸载）
        prompt = build_user_prompt(
            code=code, language=language, filename=filename, rag_context=rag_context,
        )
        result = client.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            temperature=args.temperature,
            max_tokens=None,
            keep_alive=-1,  # 批量期间常驻（int -1 表示永久，字符串 "-1" 会 400）
            timeout=args.timeout,
        )

        elapsed = round(result["duration"], 2)
        record["elapsed_seconds"] = elapsed

        if result["error"]:
            record["error"] = result["error"]
            print(f"        [错误] {result['error']}", file=sys.stderr)
        else:
            text = result["text"]
            record["raw_output"] = text
            record["meta"] = result["meta"]
            verdict = parse_verdict(text)
            record["parsed_verdict"] = verdict
            if verdict:
                record["model_has_vulnerability"] = normalize_has_vulnerability(
                    verdict.get("has_vulnerability")
                )
            print(f"        -> 用时 {elapsed}s, 判定={record['model_has_vulnerability']}")

        results["samples"].append(record)
        save_results_json(RESULTS_DIR / "results.json", results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    metrics = compute_detection_metrics(results["samples"])
    results["metrics"] = metrics
    save_results_json(RESULTS_DIR / "results.json", results)
    print(f"\n[完成] 结果已写入 {RESULTS_DIR / 'results.json'}")
    print("\n=== RAG+LLM 汇总指标 ===")
    print_summary(metrics)

    # 卸载模型（项目规则：默认卸载，避免爆显存）
    if args.keep_loaded:
        print(f"[信息] --keep-loaded 已启用，模型 {args.model} 保留在显存中")
    else:
        if client.unload_model():
            print(f"[信息] 模型 {args.model} 已从显存卸载（如需保留请加 --keep-loaded）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
