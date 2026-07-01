"""
exp_04_hard_samples - RAG 消融对照实验（P1-5）

在 exp_04 难样本集上对比 4 组实验，验证 RAG 提升是否来自知识相关性：

- A 组 (rag)        : RAG+LLM（当前实现，按代码语义检索 Top-K）
- B 组 (pure)       : 纯 LLM（无 RAG 上下文）
- C 组 (random)     : 随机知识注入（从知识库随机抽 K 条，与样本无关）
- D 组 (irrelevant) : 等长无关文本注入（与漏洞无关但长度相近的说明文字）

只有当 A 组显著优于 B/C/D 时，才能论证"RAG 有用"而非"注入文本有用"。

用法:
    python run_rag_experiment.py --mode rag          # A 组
    python run_rag_experiment.py --mode pure         # B 组
    python run_rag_experiment.py --mode random       # C 组
    python run_rag_experiment.py --mode irrelevant   # D 组
    python run_rag_experiment.py --top-k 5           # 调整 Top-K（P2-8 用）
    python run_rag_experiment.py --repeat 1          # 重复次数（P1-5 默认 1 次）
"""

import argparse
import random as random_lib
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from graduation_project.chroma_manager import ChromaManager
from graduation_project.llm_client import OllamaClient
from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from experiments.utils import (
    load_manifest,
    save_results_json,
    new_results_envelope,
    build_rag_context,
    upsert_sample,
    default_results_path,
    compute_detection_metrics,
    compute_repeat_metrics,
    print_summary,
    print_repeat_summary,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = SCRIPT_DIR / "samples"
RESULTS_DIR = SCRIPT_DIR / "results"
MANIFEST_PATH = SAMPLES_DIR / "manifest.json"
KNOWLEDGE_COLLECTION = "vulnerability_knowledge"

VALID_MODES = ("rag", "pure", "random", "irrelevant")


# ---------------------------------------------------------------------------
# 等长无关文本（D 组）：与漏洞完全无关但长度与典型 RAG 上下文相近
# 内容为 Python 数据结构教程片段，刻意选与安全审计无关的话题
# ---------------------------------------------------------------------------
IRRELEVANT_TEXT_BLOCK = """【参考资料 1】（数据结构 / 链表）
链表是一种线性数据结构，其中的元素通过指针连接。与数组不同，链表的元素在内存中不必连续存储。
单链表每个节点包含数据域和指向下一个节点的指针域。插入和删除操作在已知位置时为 O(1)，
但随机访问需要 O(n)。Python 中可手动实现 ListNode 类。

【参考资料 2】（算法 / 二分查找）
二分查找要求数组已排序，时间复杂度 O(log n)。基本思路：取中间元素与目标比较，
若目标更小则在左半部分递归，更大则在右半部分递归。注意边界处理：
- 左闭右开 [lo, hi) 写法：循环条件 lo < hi，中点 mid = (lo + hi) // 2
- 左闭右闭 [lo, hi] 写法：循环条件 lo <= hi，更新 hi = mid - 1 / lo = mid + 1

【参考资料 3】（设计模式 / 工厂方法）
工厂方法模式定义一个创建对象的接口，让子类决定实例化哪个类。
优点：客户端不需要知道具体类名，只需知道工厂；新增产品类型时无需修改现有工厂代码。
示例：ShapeFactory.get_shape("circle") 返回 Circle 实例。"""


# ---------------------------------------------------------------------------
# 上下文构建器：根据 mode 返回不同的 RAG 上下文
# ---------------------------------------------------------------------------
def build_random_context(cm: ChromaManager, top_k: int, rng: random_lib.Random) -> tuple[str, list[dict]]:
    """C 组：从知识库随机抽取 K 条（与查询无关）。

    用 chromadb collection.get() 拉全部条目再随机抽样，确保与代码语义无关。
    """
    collection = cm.client.get_collection(
        name=KNOWLEDGE_COLLECTION, embedding_function=cm.embedding_fn
    )
    total = collection.count()
    if total == 0:
        return "", []
    k = min(top_k, total)
    # 直接用 collection.get() 拿全部，再随机抽 K
    all_docs = collection.get(include=["documents", "metadatas"])
    indices = rng.sample(range(len(all_docs["ids"])), k)
    retrieval_records = []
    context_parts = []
    for rank, i in enumerate(indices, 1):
        meta = all_docs["metadatas"][i] if i < len(all_docs["metadatas"]) else {}
        retrieval_records.append({
            "rank": rank,
            "id": all_docs["ids"][i],
            "type": meta.get("type"),
            "cwe": meta.get("cwe"),
            "distance": None,  # 随机抽取，无距离
            "note": "random_sample",
        })
        context_parts.append(
            f"【知识 {rank}】({meta.get('type', '未知')} / {meta.get('cwe', '')})\n{all_docs['documents'][i]}"
        )
    return "\n\n".join(context_parts), retrieval_records


def build_irrelevant_context(target_chars: int = 1500) -> tuple[str, list[dict]]:
    """D 组：注入与漏洞无关但长度相近的说明文字。

    把 IRRELEVANT_TEXT_BLOCK 重复到目标长度，模拟 RAG 上下文的体积
    但内容上完全无关，用于隔离"prompt 变长"的影响。
    """
    block = IRRELEVANT_TEXT_BLOCK
    repeats = max(1, target_chars // len(block) + 1)
    text = (block + "\n\n").replace("【参考资料", "【参考资料")  # placeholder
    text = (block + "\n\n") * repeats
    # 截断到目标长度
    text = text[:target_chars]
    retrieval_records = [{
        "rank": 1,
        "id": "irrelevant_text",
        "type": "无关参考资料",
        "cwe": "N/A",
        "distance": None,
        "note": "irrelevant_text_injection",
        "chars": len(text),
    }]
    return text, retrieval_records


def build_context_for_mode(
    mode: str,
    query_code: str,
    cm: ChromaManager,
    top_k: int,
    rng: random_lib.Random,
) -> tuple[str, list[dict]]:
    """根据 mode 返回对应的 RAG 上下文。"""
    if mode == "rag":
        return build_rag_context(
            query_code, cm, collection_name=KNOWLEDGE_COLLECTION, top_k=top_k
        )
    if mode == "pure":
        return "", []
    if mode == "random":
        return build_random_context(cm, top_k=top_k, rng=rng)
    if mode == "irrelevant":
        return build_irrelevant_context(target_chars=1500)
    raise ValueError(f"unknown mode: {mode}")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="exp_04 RAG 消融对照实验（P1-5）")
    parser.add_argument("--mode", choices=VALID_MODES, default="rag",
                        help="消融组：rag(A) / pure(B) / random(C) / irrelevant(D)")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--limit", type=int, default=0,
                        help="只跑前 N 个样本，0 表示全部")
    parser.add_argument("--top-k", type=int, default=3,
                        help="RAG 检索 Top-K（P2-8 用，仅对 rag/random 模式生效）")
    parser.add_argument("--repeat", type=int, default=1,
                        help="每个样本重复跑 N 次（默认 1，P1-5 主实验无需重复）")
    parser.add_argument("--seed", type=int, default=42,
                        help="random 模式抽样种子（可复现）")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--keep-loaded", action="store_true")
    parser.add_argument("--output", default=None,
                        help="结果输出路径（默认 results/exp_04_hard_samples.<model>.<mode>.topk<K>.repeat<N>.<timestamp>.json）")
    args = parser.parse_args()

    repeat = max(1, args.repeat)
    results_path = Path(args.output) if args.output else default_results_path(
        RESULTS_DIR,
        experiment="exp_04_hard_samples",
        model=args.model,
        extra_tag=f"{args.mode}.topk{args.top_k}.repeat{repeat}",
    )

    try:
        manifest, samples = load_manifest(MANIFEST_PATH)
    except (FileNotFoundError, KeyError) as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1
    if args.limit > 0:
        samples = samples[: args.limit]

    rng = random_lib.Random(args.seed)

    # A/C 组需要知识库；B/D 组不需要
    cm = None
    kb_count = 0
    if args.mode in ("rag", "random"):
        print("[信息] 初始化 Chroma 知识库客户端...")
        cm = ChromaManager()
        try:
            kb_count = cm.count(KNOWLEDGE_COLLECTION)
        except Exception as e:
            print(f"[错误] 知识库集合 {KNOWLEDGE_COLLECTION} 不存在: {e}", file=sys.stderr)
            return 1
        if kb_count == 0:
            print("[错误] 知识库为空，请先运行 build_knowledge.py", file=sys.stderr)
            return 1
        print(f"[信息] 知识库共 {kb_count} 条，Top-K={args.top_k}")

    total = len(samples)
    total_runs = total * repeat
    print(f"[信息] 模式 = {args.mode}（{['A:RAG+LLM','B:纯LLM','C:随机知识','D:无关文本'][VALID_MODES.index(args.mode)]}）")
    print(f"[信息] 共 {total} 样本，每样本 {repeat} 次，共 {total_runs} 次推理")
    print(f"[信息] 模型 {args.model}，预计耗时 {total_runs * 45 / 60:.1f} 分钟")

    client = OllamaClient(base_url=args.host, model=args.model)
    if not client.check_connection():
        print(f"[错误] 无法连接 Ollama（{args.host}）", file=sys.stderr)
        return 1

    results = new_results_envelope(
        experiment=f"exp_04_ablation_{args.mode}",
        model=args.model,
        host=args.host,
        temperature=args.temperature,
        mode=args.mode,
        top_k=args.top_k,
        repeat=repeat,
        knowledge_count=kb_count,
        sample_count=total,
        total_runs=total_runs,
        seed=args.seed,
    )

    for idx, sample_meta in enumerate(samples, 1):
        filename = sample_meta["file"]
        path = SAMPLES_DIR / filename
        if not path.exists():
            print(f"[跳过] 文件不存在: {path}", file=sys.stderr)
            continue
        code = path.read_text(encoding="utf-8")
        language = sample_meta.get("language", "text")

        print(f"\n[{idx}/{total}] {filename} ({language})", flush=True)

        sample_record = {
            "file": filename,
            "language": language,
            "category": sample_meta.get("category"),
            "difficulty": sample_meta.get("difficulty"),
            "expected_present": sample_meta.get("expected_present"),
            "expected_vulnerability": sample_meta.get("expected_vulnerability"),
            "expected_cwe": sample_meta.get("expected_cwe"),
            "runs": [],
            "majority_verdict": None,
            "agreement_rate": None,
        }

        for r in range(repeat):
            # 1. 构建 RAG 上下文
            rag_context, retrieval_records = build_context_for_mode(
                args.mode, code, cm, args.top_k, rng,
            )
            if retrieval_records and args.mode != "irrelevant":
                top_types = [r.get("type") for r in retrieval_records]
                top_dists = [r.get("distance") for r in retrieval_records]
                print(f"  [{r+1}/{repeat}] 检索 {args.mode} Top-{args.top_k}: {top_types}, distances={top_dists}")
            elif args.mode == "irrelevant":
                print(f"  [{r+1}/{repeat}] 注入无关文本 {len(rag_context)} 字符")
            else:
                print(f"  [{r+1}/{repeat}] 纯 LLM 模式（无 RAG）")

            # 2. 调用 LLM
            prompt = build_user_prompt(
                code=code, language=language, filename=filename, rag_context=rag_context,
            )
            result = client.generate(
                prompt=prompt, system_prompt=SYSTEM_PROMPT,
                temperature=args.temperature, max_tokens=None,
                keep_alive=-1, timeout=args.timeout,
            )
            elapsed = round(result["duration"], 2)

            run_record = {
                "run_index": r + 1,
                "rag_retrieval": retrieval_records,
                "rag_context_chars": len(rag_context) if rag_context else 0,
                "elapsed_seconds": elapsed,
                "raw_output": None,
                "parsed_verdict": {},
                "model_has_vulnerability": None,
                "error": None,
            }

            if result["error"]:
                run_record["error"] = result["error"]
                print(f"        [错误] {result['error']}", file=sys.stderr)
            else:
                text = result["text"]
                run_record["raw_output"] = text
                run_record["meta"] = result["meta"]
                verdict = parse_verdict(text)
                run_record["parsed_verdict"] = verdict
                if verdict:
                    run_record["model_has_vulnerability"] = normalize_has_vulnerability(
                        verdict.get("has_vulnerability")
                    )
                print(f"        -> 用时 {elapsed}s, 判定={run_record['model_has_vulnerability']}")

            sample_record["runs"].append(run_record)
            upsert_sample(results["samples"], sample_record)
            save_results_json(results_path, results)

        # 多数表决
        verdicts = [r.get("model_has_vulnerability") for r in sample_record["runs"]]
        valid = [v for v in verdicts if v is not None]
        if valid:
            true_count = sum(1 for v in valid if v)
            sample_record["majority_verdict"] = true_count >= len(valid) / 2
            sample_record["agreement_rate"] = round(
                max(true_count, len(valid) - true_count) / len(valid), 4
            )
            save_results_json(results_path, results)

    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    flat_records = []
    for s in results["samples"]:
        for run in s["runs"]:
            flat_records.append({
                "file": s["file"],
                "expected_present": s["expected_present"],
                "model_has_vulnerability": run.get("model_has_vulnerability"),
                "elapsed_seconds": run.get("elapsed_seconds"),
            })
    results["metrics_single_run"] = compute_detection_metrics(flat_records)
    results["metrics_majority_vote"] = compute_repeat_metrics(flat_records)
    save_results_json(results_path, results)

    print(f"\n[完成] 结果已写入 {results_path}")
    print(f"\n=== 消融组 {args.mode.upper()}：单次口径 ===")
    print_summary(results["metrics_single_run"])
    if repeat > 1:
        print(f"\n=== 消融组 {args.mode.upper()}：多数表决口径 ===")
        print_repeat_summary(results["metrics_majority_vote"])

    if args.keep_loaded:
        print(f"\n[信息] --keep-loaded 已启用，模型保留在显存")
    else:
        if client.unload_model():
            print(f"[信息] 模型 {args.model} 已从显存卸载")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
