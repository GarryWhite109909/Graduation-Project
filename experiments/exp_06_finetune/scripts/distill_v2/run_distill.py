"""
蒸馏 v2 主调度器。

流水线：
  task_specs.generate_tasks(pack)
    → 跳过已完成的 task_id（断点续传）
    → ThreadPoolExecutor 并发调 API
    → validate_sample.parse_and_validate
    → 失败重试 MAX_RETRIES 次
    → 追加写入 {pack.output_file}
    → 仍失败写入 _progress/{pack_id}_failed.jsonl

用法：
  python run_distill.py                                # 跑全部 7 个 pack
  python run_distill.py --pack deepseek_cc_memory      # 只跑一个 pack
  python run_distill.py --pack deepseek_cc_memory,kimi_cross_file  # 跑多个
  python run_distill.py --list                         # 列出所有 pack
  python run_distill.py --dry-run                      # 只打印任务规格，不调 API
  python run_distill.py --workers 4                    # 覆盖默认并发数

环境变量（必需）：
  DEEPSEEK_API_KEY=sk-xxx
  MOONSHOT_API_KEY=sk-yyy
"""

import argparse
import json
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

import requests

# 同目录模块
from config import (
    DEEPSEEK_API_KEY, DEEPSEEK_CHAT_URL, DEEPSEEK_MODEL,
    DEEPSEEK_CONCURRENCY, DEEPSEEK_THINKING, DEEPSEEK_TEMPERATURE, DEEPSEEK_MAX_TOKENS,
    MOONSHOT_API_KEY, KIMI_CHAT_URL, KIMI_MODEL,
    KIMI_CONCURRENCY, KIMI_TEMPERATURE, KIMI_MAX_TOKENS,
    MAX_RETRIES, REQUEST_TIMEOUT, RETRY_BACKOFF,
    DATA_DIR, PROGRESS_DIR, check_api_keys,
)
from prompts import DEEPSEEK_DISTILL_SYSTEM, STUDENT_SYSTEM, build_deepseek_user, KIMI_SYSTEM, build_kimi_user
from task_specs import PACKS, PackDef, generate_tasks, _self_check
from validate_sample import parse_and_validate, build_chatml


# ===========================================================================
# API 调用
# ===========================================================================

# ===========================================================================
# Token 用量统计（线程安全）
# ===========================================================================
_token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
_usage_lock = Lock()


def _update_usage(usage_data: dict):
    """线程安全地累加 token 用量。"""
    if not usage_data:
        return
    with _usage_lock:
        _token_usage["prompt_tokens"] += usage_data.get("prompt_tokens", 0)
        _token_usage["completion_tokens"] += usage_data.get("completion_tokens", 0)
        _token_usage["total_tokens"] += usage_data.get("total_tokens", 0)


def print_usage_stats():
    """打印累计 token 用量与估算费用。"""
    p = _token_usage["prompt_tokens"]
    c = _token_usage["completion_tokens"]
    t = _token_usage["total_tokens"]
    # DeepSeek V4-Flash 价格：输入 ¥0.5/M，输出 ¥2/M（缓存命中 ¥0.1/M）
    cost = p / 1_000_000 * 0.5 + c / 1_000_000 * 2
    print(f"\n  Token 用量: 输入 {p:,} | 输出 {c:,} | 总计 {t:,}")
    print(f"  估算费用: ¥{cost:.2f}（按无缓存全价）")


# ===========================================================================
# API 调用
# ===========================================================================

def call_deepseek(system: str, user: str) -> tuple:
    """调 DeepSeek V4-Flash。返回 (content, error)。

    thinking=enabled：思考链 reasoning_content 计费但不入训练（只取 content）。
    漏洞检测是推理任务，思考后输出质量更高，值得这笔钱。
    注：思考模式下 temperature 不生效（官方文档明确），保留以备关思考时复用。
    """
    try:
        resp = requests.post(
            DEEPSEEK_CHAT_URL,
            headers={
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": DEEPSEEK_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "thinking": {"type": DEEPSEEK_THINKING},
                "temperature": DEEPSEEK_TEMPERATURE,
                "max_tokens": DEEPSEEK_MAX_TOKENS,
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        _update_usage(data.get("usage"))
        return content, None
    except requests.exceptions.HTTPError as e:
        body = ""
        try:
            body = resp.text[:500]
        except Exception:
            pass
        return None, f"HTTP {e} | body={body}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def call_kimi(system: str, user: str) -> tuple:
    """调 Kimi K3。返回 (content, error)。

    K3 思考模式始终开启：
      message.reasoning_content = 思考链（不计入训练，但计费）
      message.content           = 最终输出（训练只取这个）
    """
    try:
        resp = requests.post(
            KIMI_CHAT_URL,
            headers={
                "Authorization": f"Bearer {MOONSHOT_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": KIMI_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": KIMI_TEMPERATURE,
                "max_tokens": KIMI_MAX_TOKENS,
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        msg = data["choices"][0]["message"]
        # 只取 content，不取 reasoning_content（思考链）
        content = msg.get("content", "")
        if not content:
            return None, "K3 返回 content 为空（可能只有 reasoning_content）"
        _update_usage(data.get("usage"))
        return content, None
    except requests.exceptions.HTTPError as e:
        body = ""
        try:
            body = resp.text[:500]
        except Exception:
            pass
        return None, f"HTTP {e} | body={body}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def call_api(model: str, system: str, user: str) -> tuple:
    """统一入口。"""
    if model == "deepseek":
        return call_deepseek(system, user)
    elif model == "kimi":
        return call_kimi(system, user)
    else:
        return None, f"未知 model: {model}"


# ===========================================================================
# 单任务处理
# ===========================================================================

def process_task(task) -> tuple:
    """处理单个任务：调 API → 解析校验 → 失败重试。

    Returns:
        (chatml_dict, None)         成功
        (None, error_reason)        失败（已重试 MAX_RETRIES 次）
    """
    # 教师 system（调 API 用）+ 学生 system（组装训练数据用）
    student_system = STUDENT_SYSTEM  # 训练+推理一致，跨模型统一
    if task.model == "deepseek":
        distill_system = DEEPSEEK_DISTILL_SYSTEM
        user = build_deepseek_user(task.template, task)
    else:  # kimi
        distill_system = KIMI_SYSTEM
        user = build_kimi_user(task.template, task)

    last_error = ""
    last_reason = ""  # 简短原因，用于重试时告知模型
    for attempt in range(1, MAX_RETRIES + 2):  # 初次 + MAX_RETRIES 次重试
        retry_user = user
        if attempt > 1 and last_reason:
            retry_user = user + f"\n\n注意：上次尝试的校验失败原因：{last_reason}。请严格按三段式格式输出，确保 JSON 格式正确。"
        content, err = call_api(task.model, distill_system, retry_user)
        if err:
            last_error = f"[attempt {attempt}] API 调用失败: {err}"
            last_reason = f"API 调用失败: {err}"
            if attempt <= MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)
            continue

        # 解析 + 校验
        parsed, vreason = parse_and_validate(content, expected_has_vuln=task.has_vuln)
        if parsed is not None:
            chatml = build_chatml(student_system, parsed)
            # 附带元数据（训练时不消费，供审计用）
            chatml["_meta"] = {
                "task_id": task.task_id,
                "pack_id": task.pack_id,
                "model": task.model,
                "template": task.template,
                "cwe": task.cwe,
                "lang": task.lang,
                "has_vuln": task.has_vuln,
                "attempts": attempt,
            }
            return chatml, None

        last_error = f"[attempt {attempt}] 校验失败: {vreason}\n原始输出(前800字):\n{content[:800]}"
        last_reason = f"校验失败: {vreason}"
        if attempt <= MAX_RETRIES:
            print(f"    [{task.task_id}] attempt {attempt}/{MAX_RETRIES+1} 失败: {vreason}", flush=True)
            time.sleep(RETRY_BACKOFF * attempt)

    return None, last_error


# ===========================================================================
# 断点续传
# ===========================================================================

def load_done_task_ids(output_path: Path) -> set:
    """读取已落盘的 jsonl，提取 _meta.task_id 集合。"""
    done = set()
    if not output_path.exists():
        return done
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                tid = obj.get("_meta", {}).get("task_id", "")
                if tid:
                    done.add(tid)
            except json.JSONDecodeError:
                continue
    return done


# ===========================================================================
# 单 pack 执行
# ===========================================================================

def run_pack(pack: PackDef, workers: int = None, limit: int = None, verbose: bool = False) -> dict:
    """跑一个 pack。

    Returns:
        stats dict: {total, done_before, success, failed, skipped}
    """
    output_path = DATA_DIR / pack.output_file
    failed_path = PROGRESS_DIR / f"{pack.pack_id}_failed.jsonl"

    # 默认并发数
    if workers is None:
        workers = DEEPSEEK_CONCURRENCY if pack.model == "deepseek" else KIMI_CONCURRENCY

    # 生成全部任务
    all_tasks = generate_tasks(pack)
    total = len(all_tasks)

    # 断点续传：跳过已完成
    done_ids = load_done_task_ids(output_path)
    pending = [t for t in all_tasks if t.task_id not in done_ids]
    if limit:
        pending = pending[:limit]

    print(f"\n{'='*70}")
    print(f"[{pack.pack_id}] model={pack.model} template={pack.template}")
    print(f"  总任务: {total} | 已完成: {len(done_ids)} | 待跑: {len(pending)} | 并发: {workers}")
    print(f"  输出: {output_path}")
    print(f"{'='*70}")

    if not pending:
        print(f"  ✅ 全部已完成，跳过")
        return {"total": total, "done_before": len(done_ids), "success": 0, "failed": 0, "skipped": len(done_ids)}

    # 追加写入锁
    write_lock = Lock()
    success_count = 0
    failed_count = 0

    def write_result(chatml, task, error):
        nonlocal success_count, failed_count
        with write_lock:
            if chatml is not None:
                with open(output_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(chatml, ensure_ascii=False) + "\n")
                success_count += 1
            else:
                with open(failed_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "task_id": task.task_id,
                        "task": task.to_dict(),
                        "error": error,
                    }, ensure_ascii=False) + "\n")
                failed_count += 1

    # 并发执行
    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(process_task, t): t for t in pending}
        for fut in as_completed(futures):
            task = futures[fut]
            completed += 1
            try:
                chatml, err = fut.result()
            except Exception as e:
                chatml, err = None, f"异常: {e}\n{traceback.format_exc()}"
            write_result(chatml, task, err)

            # 进度日志
            if completed % 10 == 0 or completed == len(pending):
                print(f"  [{completed}/{len(pending)}] 成功 {success_count} | 失败 {failed_count} | "
                      f"最近 task={task.task_id}", flush=True)

            # verbose：打印 assistant 输出 + token 估算
            if verbose and chatml is not None:
                content = chatml["messages"][2]["content"]
                token_est = len(content) // 3
                sweet = "✅合理" if 300 <= token_est <= 1000 else ("⚠️偏短" if token_est < 300 else "⚠️偏长")
                print(f"\n  ── {task.task_id} | token≈{token_est} {sweet} ──")
                print("  " + content.replace("\n", "\n  ")[:1200])
                print()

    stats = {
        "total": total,
        "done_before": len(done_ids),
        "success": success_count,
        "failed": failed_count,
        "skipped": len(done_ids),
    }
    print(f"\n  ✅ {pack.pack_id} 完成: 新增成功 {success_count} | 失败 {failed_count} | "
          f"累计 {len(done_ids) + success_count}/{total}")

    if failed_count > 0:
        print(f"  ⚠️  失败记录: {failed_path}")

    return stats


# ===========================================================================
# 主入口
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="蒸馏 v2 主调度器")
    parser.add_argument("--model", type=str, default="",
                        help="只跑指定模型的 pack（deepseek/kimi，逗号分隔），如 --model deepseek")
    parser.add_argument("--pack", type=str, default="",
                        help="只跑指定 pack（逗号分隔多个），如 deepseek_cc_memory,kimi_cross_file")
    parser.add_argument("--list", action="store_true", help="列出所有 pack 后退出")
    parser.add_argument("--dry-run", action="store_true", help="只打印任务规格，不调 API")
    parser.add_argument("--workers", type=int, default=None,
                        help="覆盖默认并发数（DeepSeek 默认 8，Kimi 默认 2）")
    parser.add_argument("--limit", type=int, default=None,
                        help="每个 pack 最多跑 N 条（测试用，如 --limit 1）")
    parser.add_argument("--verbose", action="store_true",
                        help="打印每条 assistant 输出 + token 估算")
    args = parser.parse_args()

    # --list
    if args.list:
        _self_check()
        return

    # 筛选 pack：--model 和 --pack 可组合（AND 关系）
    packs_to_run = PACKS
    if args.model:
        models_wanted = set(args.model.split(","))
        packs_to_run = [p for p in packs_to_run if p.model in models_wanted]
    if args.pack:
        wanted = set(args.pack.split(","))
        packs_to_run = [p for p in packs_to_run if p.pack_id in wanted]
    if not packs_to_run:
        print("没有匹配的 pack，请检查 --model / --pack 参数")
        print(f"可用 --model: deepseek, kimi")
        print(f"可用 --pack:  {[p.pack_id for p in PACKS]}")
        sys.exit(1)

    # --dry-run（用筛选后的 packs）
    if args.dry_run:
        _self_check()
        print(f"\n[dry-run] 将预览 {len(packs_to_run)} 个 pack: {[p.pack_id for p in packs_to_run]}")
        for pack in packs_to_run:
            tasks = generate_tasks(pack)
            print(f"\n--- {pack.pack_id} ({len(tasks)} 条) ---")
            for t in tasks[:3]:
                print(f"  {t.task_id}: cwe={t.cwe} lang={t.lang} has_vuln={t.has_vuln} "
                      f"difficulty={t.difficulty} scene={t.scene}")
        return

    # 校验 API Key（只校验用到的 model 的 key）
    needed_models = {p.model for p in packs_to_run}
    check_api_keys(needed_models)

    # 打印总览
    print("=" * 70)
    print("蒸馏 v2 启动")
    print("=" * 70)
    _self_check()
    print(f"\n将跑 {len(packs_to_run)} 个 pack: {[p.pack_id for p in packs_to_run]}")
    print(f"输出目录: {DATA_DIR}")

    # 逐 pack 执行
    all_stats = {}
    start_time = time.time()
    for pack in packs_to_run:
        stats = run_pack(pack, workers=args.workers, limit=args.limit, verbose=args.verbose)
        all_stats[pack.pack_id] = stats

    # 汇总
    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print("全部完成，汇总:")
    print("=" * 70)
    print(f"{'pack_id':<24} {'total':>6} {'success':>8} {'failed':>8} {'skipped':>8}")
    print("-" * 60)
    g_total = g_success = g_failed = g_skipped = 0
    for pid, s in all_stats.items():
        print(f"{pid:<24} {s['total']:>6} {s['success']:>8} {s['failed']:>8} {s['skipped']:>8}")
        g_total += s["total"]
        g_success += s["success"]
        g_failed += s["failed"]
        g_skipped += s["skipped"]
    print("-" * 60)
    print(f"{'合计':<24} {g_total:>6} {g_success:>8} {g_failed:>8} {g_skipped:>8}")
    print(f"\n耗时: {elapsed/60:.1f} 分钟")
    print_usage_stats()
    print(f"最终合并: python merge_to_chatml.py")


if __name__ == "__main__":
    main()
