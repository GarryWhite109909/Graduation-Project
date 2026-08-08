"""数据飞轮入库管道 —— Nivis-α1 数据飞轮铁律 2-5 的执行工具。

设计依据：docs/方法论_Nivis-α1训练.md §五。
新样本（线上错题重生成 / 教师蒸馏 / 人工补充）入训练池前必须过四道闸：

  1. 冻结集完好性验证（调 freeze_testset.py verify 逻辑，锁文件损坏即拒绝入库）
  2. 格式校验：必须具备 code + 结论字段且结论可解析
  3. 去重：与训练池现有样本按规范化代码哈希比对
  4. 泄漏审计：样本代码与冻结集文件做 ≥200 字符指纹 substring 匹配
     （多语言覆盖，与 audit_leakage_precise.py 修复后的口径一致）

通过后：
  - 回流上限：单次入库 ≤ 训练池总量的 10%（防自产数据淹没分布）
  - 每条样本打版本 tag（如 flywheel_r3），追加写入训练池
  - 全流程记录写入 flywheel_log.json（数据版本、数量、拒绝原因，论文可复现）

输入样本格式（jsonl，每行）：
  {"code": "...", "language": "python", "has_vulnerability": true,
   "vulnerability_type": "CWE-89 ...", "cot_analysis": "...(可选)", "source_tag": "..."}

用法：
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/flywheel_ingest.py \
      --input new_samples.jsonl --tag flywheel_r1
  # 干跑（只审计不入库）：
  PYTHONPATH=. python ... --input new_samples.jsonl --tag flywheel_r1 --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Windows 默认 GBK 控制台无法编码 ✓ 等字符，会抛 UnicodeEncodeError 导致
# 入库流程中断。强制 stdout/stderr 使用 UTF-8（带 replace 兜底）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from graduation_project.schema import normalize_has_vulnerability

DATA_DIR = PROJECT_ROOT / "experiments/exp_06_finetune/data"
DEFAULT_POOL = DATA_DIR / "flywheel_pool.jsonl"
DEFAULT_LOCK = DATA_DIR / "frozen_lock.json"
DEFAULT_LOG = DATA_DIR / "flywheel_log.json"

MAX_INFLOW_FRAC = 0.10          # 铁律 2：单轮回流 ≤ 训练池 10%
LEAK_FINGERPRINT_LEN = 200      # 泄漏指纹长度（与 audit_leakage_precise.py 一致）
_FROZEN_GLOBS = ("*.py", "*.java", "*.js", "*.php", "*.ts", "*.jsx", "*.tsx",
                 "*.vue", "*.go", "*.rb")  # 多语言，勿回退为仅 *.py


def normalize_code(code: str) -> str:
    """代码规范化（去空白差异）用于去重哈希。"""
    return re.sub(r"\s+", " ", code).strip()


def code_hash(code: str) -> str:
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[警告] {path.name} 第 {i} 行 JSON 解析失败，跳过: {e}")
    return records


def verify_frozen(lock_path: Path) -> bool:
    """铁律 1：冻结集必须完好。就地复用 freeze_testset 的快照逻辑。"""
    if not lock_path.exists():
        print(f"[拒绝入库] 冻结锁文件不存在: {lock_path}，先运行 freeze_testset.py lock")
        return False
    sys.path.insert(0, str(Path(__file__).parent))
    from freeze_testset import snapshot  # 复用同一哈希逻辑，避免双实现漂移

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    for name, s in lock.get("sets", {}).items():
        current = snapshot(Path(s["dir"]))
        locked = s["files"]
        if any(r not in current or current[r]["sha256"] != m["sha256"]
               for r, m in locked.items()) or len(current) != len(locked):
            print(f"[拒绝入库] 冻结集 {name} 已被改动，先查明原因")
            return False
    return True


def load_frozen_corpus(lock_path: Path) -> list[str]:
    """加载冻结集全部文件内容，用于泄漏指纹匹配。"""
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    texts = []
    for s in lock.get("sets", {}).values():
        d = Path(s["dir"])
        for glob in _FROZEN_GLOBS:
            for p in d.rglob(glob):
                try:
                    texts.append(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
    return texts


def fingerprints(code: str) -> list[str]:
    """从代码提取定长滑动指纹（步长减半，覆盖任意起点）。"""
    norm = normalize_code(code)
    if len(norm) <= LEAK_FINGERPRINT_LEN:
        return [norm] if norm else []
    step = LEAK_FINGERPRINT_LEN // 2
    return [norm[i:i + LEAK_FINGERPRINT_LEN]
            for i in range(0, len(norm) - LEAK_FINGERPRINT_LEN + 1, step)]


def main() -> int:
    ap = argparse.ArgumentParser(description="数据飞轮入库管道")
    ap.add_argument("--input", required=True, help="新样本 jsonl")
    ap.add_argument("--tag", required=True, help="版本标签，如 flywheel_r1")
    ap.add_argument("--pool", default=str(DEFAULT_POOL), help="训练池 jsonl")
    ap.add_argument("--lock", default=str(DEFAULT_LOCK), help="冻结锁文件")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="飞轮日志 json")
    ap.add_argument("--dry-run", action="store_true", help="只审计不入库")
    args = ap.parse_args()

    # 闸 1：冻结集完好
    if not verify_frozen(Path(args.lock)):
        return 1
    print("[闸1] 冻结集完好 ✓")

    new_records = load_jsonl(Path(args.input))
    pool_path = Path(args.pool)
    pool = load_jsonl(pool_path) if pool_path.exists() else []
    pool_hashes = {code_hash(r.get("code", "")) for r in pool}
    frozen_corpus = load_frozen_corpus(Path(args.lock))
    # 合并为单一语料串加速匹配（\x00 分隔符不会出现在规范化代码中，
    # 且能阻止跨文件边界的假命中）
    joined_corpus = "\x00".join(normalize_code(t) for t in frozen_corpus)

    accepted, rejected = [], {"format": 0, "dup": 0, "leak": 0}
    for rec in new_records:
        code = rec.get("code", "")
        # 闸 2：格式
        if (not code or normalize_has_vulnerability(rec.get("has_vulnerability")) is None):
            rejected["format"] += 1
            continue
        # 闸 3：去重
        if code_hash(code) in pool_hashes:
            rejected["dup"] += 1
            continue
        # 闸 4：泄漏（任一指纹命中冻结集即拒）
        if any(fp in joined_corpus for fp in fingerprints(code)):
            rejected["leak"] += 1
            continue
        rec["flywheel_tag"] = args.tag
        rec["ingested_at"] = datetime.now(timezone.utc).isoformat()
        accepted.append(rec)

    # 铁律 2：回流上限
    cap = max(1, int(len(pool) * MAX_INFLOW_FRAC)) if pool else len(accepted)
    overflow = max(0, len(accepted) - cap)
    if overflow:
        print(f"[铁律2] 回流上限 {cap}（池 {len(pool)} × {MAX_INFLOW_FRAC}），截断 {overflow} 条")
        accepted = accepted[:cap]

    print(f"\n审计结果: 输入 {len(new_records)} → 入库 {len(accepted)} "
          f"（格式拒 {rejected['format']}，重复拒 {rejected['dup']}，泄漏拒 {rejected['leak']}）")

    # 铁律 4：版本化日志（dry-run 也记录意图）
    log_path = Path(args.log)
    log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else {"rounds": []}
    log["rounds"].append({
        "tag": args.tag,
        "at": datetime.now(timezone.utc).isoformat(),
        "input": len(new_records), "accepted": len(accepted),
        "rejected": rejected, "overflow_truncated": overflow,
        "dry_run": args.dry_run,
    })

    if not args.dry_run:
        pool_path.parent.mkdir(parents=True, exist_ok=True)
        with pool_path.open("a", encoding="utf-8") as f:
            for rec in accepted:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"已追加写入训练池: {pool_path}（池总量 {len(pool)} → {len(pool) + len(accepted)}）")
    else:
        print("[dry-run] 未写入训练池")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"日志已更新: {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
