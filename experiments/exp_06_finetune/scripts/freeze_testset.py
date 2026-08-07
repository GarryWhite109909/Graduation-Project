"""冻结测试集隔离脚本 —— Nivis-α1 数据飞轮铁律 1 的执行工具。

设计依据：docs/方法论_Nivis-α1训练.md §五（冻结集永不入轮）。
对测试集目录生成 SHA-256 哈希清单（freeze lock），之后任何时刻可验证：
  - 文件被改动（hash 不符）→ 冻结失效，评估结论不可信
  - 文件被增删 → 同上
  - 训练数据入库前，flywheel_ingest.py 会先调用本脚本 verify 冻结集完好

锁文件格式（frozen_lock.json）：
  {
    "version": 1,
    "frozen_at": "ISO 时间",
    "sets": {
      "<集合名>": {
        "dir": "<绝对路径>",
        "files": {"<相对路径>": {"sha256": ..., "size": ...}, ...}
      }
    }
  }

用法：
  # 创建/更新锁（冻结 CVE-fix 测试集 + 任意 held-out 目录）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/freeze_testset.py lock \
      --set cve_fix=experiments/exp_06_finetune/testset_cve_fix

  # 验证（飞轮入库前 / 评估前必跑）
  PYTHONPATH=. python experiments/exp_06_finetune/scripts/freeze_testset.py verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOCK = PROJECT_ROOT / "experiments/exp_06_finetune/data/frozen_lock.json"

# 测试集内不计入锁的文件（元数据可改，样本不可改）
_EXEMPT_NAMES = {"manifest.json.lock", ".gitkeep"}


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(dir_path: Path) -> dict:
    """对目录生成 {相对路径: {sha256, size}} 快照（含 manifest.json）。"""
    files = {}
    for p in sorted(dir_path.rglob("*")):
        if not p.is_file() or p.name in _EXEMPT_NAMES:
            continue
        rel = p.relative_to(dir_path).as_posix()
        files[rel] = {"sha256": hash_file(p), "size": p.stat().st_size}
    return files


def cmd_lock(args) -> int:
    lock_path = Path(args.lock)
    lock = {"version": 1, "frozen_at": "", "sets": {}}
    if lock_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))

    for spec in args.set:
        name, _, dir_str = spec.partition("=")
        if not name or not dir_str:
            print(f"[错误] --set 格式应为 名称=目录，收到: {spec}")
            return 1
        dir_path = (PROJECT_ROOT / dir_str).resolve()
        if not dir_path.is_dir():
            print(f"[错误] 目录不存在: {dir_path}")
            return 1
        files = snapshot(dir_path)
        lock["sets"][name] = {"dir": str(dir_path), "files": files}
        print(f"[冻结] {name}: {len(files)} 个文件 ← {dir_path}")

    lock["frozen_at"] = datetime.now(timezone.utc).isoformat()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(lock, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n锁文件已写入: {lock_path}")
    print("⚠ 冻结后请勿改动上述目录内任何文件；改动需重新 lock 并在论文中注明版本变化")
    return 0


def cmd_verify(args) -> int:
    lock_path = Path(args.lock)
    if not lock_path.exists():
        print(f"[错误] 锁文件不存在: {lock_path}（先运行 lock 子命令）")
        return 1
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    bad = 0
    for name, s in lock.get("sets", {}).items():
        dir_path = Path(s["dir"])
        locked = s["files"]
        current = snapshot(dir_path) if dir_path.is_dir() else {}

        modified = [r for r, meta in locked.items()
                    if r in current and current[r]["sha256"] != meta["sha256"]]
        missing = [r for r in locked if r not in current]
        added = [r for r in current if r not in locked]

        if not modified and not missing and not added:
            print(f"[完好] {name}: {len(locked)} 个文件全部一致")
        else:
            bad += 1
            print(f"[破坏] {name}:")
            for r in modified:
                print(f"    已修改: {r}")
            for r in missing:
                print(f"    已删除: {r}")
            for r in added:
                print(f"    新增未登记: {r}")

    if bad:
        print(f"\n✗ {bad} 个冻结集被改动——相关评估结论不可信，需查明原因或重新 lock")
        return 1
    print("\n✓ 所有冻结集完好")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="冻结测试集隔离")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("lock", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--lock", default=str(DEFAULT_LOCK), help="锁文件路径")
        if name == "lock":
            p.add_argument("--set", action="append", required=True,
                           help="名称=目录（可多次），如 cve_fix=experiments/exp_06_finetune/testset_cve_fix")
    args = ap.parse_args()
    return cmd_lock(args) if args.cmd == "lock" else cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
