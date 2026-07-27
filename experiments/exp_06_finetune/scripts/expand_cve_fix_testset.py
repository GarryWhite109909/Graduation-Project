"""
扩充 CVE-fix 测试集到 20 样本（2026-07-25）

背景：
  原 8 样本中有 2 条标注错误（0001.java CWE 标错、0008.py 跨文件误标），
  修复后剩 7 条有效样本。本脚本扩充到 20 条，覆盖训练数据中的主要 CWE。

策略：
  1. 保留现有 7 个样本（0001-0007），从 0009 开始编号（0008 已移除）
  2. 按优先级抓取训练数据中样本最多但 CVE-fix 缺失的 CWE：
     CWE-89(46) → CWE-78(33) → CWE-79(33) → CWE-22(32) →
     CWE-798(27) → CWE-1336(22) → CWE-918(14) → CWE-611(13)
  3. 每个 CVE 最多取 1 个文件（max_per_cve=1，最大化 CVE 多样性）
  4. **硬性验证**：下载的文件必须含可检测的漏洞模式（正则匹配），
     避免跨文件上下文样本（如 cve_fix_0008 问题）混入

用法：
  export GITHUB_TOKEN=ghp_xxx
  python expand_cve_fix_testset.py --max-samples 20 --resume

依赖：仅 Python 标准库 + prepare_cve_fix_testset.py（同目录）
"""

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

# 复用现有脚本的 API 函数
sys.path.insert(0, str(Path(__file__).parent))
from prepare_cve_fix_testset import (
    check_token,
    github_request,
    search_nvd_by_cwe,
    extract_github_commit_url,
    get_repo_stars,
    get_commit_detail,
    get_file_content,
    lang_of_file,
    detect_vuln_patterns,
    is_excluded_file,
    save_manifest,
    load_existing_manifest,
    LANG_EXT_MAP,
    LANG_FILTER,
)

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "testset_cve_fix"

# 扩充目标 CWE（按训练数据样本数降序，只选 CVE-fix 中缺失的）
# 括号内为训练数据中的样本数
TARGET_CWES = [
    ("CWE-89", "SQL注入", 3),       # 训练 46 条，目标 3 个 CVE-fix
    ("CWE-78", "命令注入", 2),       # 训练 33 条，目标 2 个
    ("CWE-79", "XSS", 2),           # 训练 33 条，目标 2 个
    ("CWE-22", "路径穿越", 2),       # 训练 32 条，目标 2 个
    ("CWE-798", "硬编码凭证", 1),    # 训练 27 条，目标 1 个
    ("CWE-1336", "SSTI", 1),        # 训练 22 条，目标 1 个
    ("CWE-918", "SSRF", 1),         # 训练 14 条，目标 1 个
    ("CWE-611", "XXE", 1),          # 训练 13 条，目标 1 个
]
# 合计目标新增 13 个，加现有 7 个 = 20 个

# 这些 CWE 的漏洞模式必须可被正则检测到（硬性验证）
# 如果下载的文件不匹配任何 VULN_PATTERNS，则跳过（避免跨文件上下文混入）
CWE_REQUIRES_PATTERN_MATCH = {
    "CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-798",
    "CWE-1336", "CWE-918", "CWE-611", "CWE-502", "CWE-95",
    "CWE-90", "CWE-917", "CWE-98", "CWE-327", "CWE-330",
}

# 排除已有的 CVE ID（避免重复抓取同一 CVE）
# 将在运行时从 manifest 中动态读取


def get_next_index(manifest: dict) -> int:
    """获取下一个可用的样本编号（跳过已移除的 0008）。"""
    existing_indices = set()
    for s in manifest.get("samples", []):
        fname = s.get("file", "")
        m = re.match(r"cve_fix_(\d+)", fname)
        if m:
            existing_indices.add(int(m.group(1)))
    # 从 9 开始（0008 已移除，不复用）
    idx = 9
    while idx in existing_indices:
        idx += 1
    return idx


def main():
    parser = argparse.ArgumentParser(
        description="扩充 CVE-fix 测试集（NVD-by-CWE 策略，硬性验证漏洞模式）"
    )
    parser.add_argument("--max-samples", type=int, default=20,
                        help="目标总样本数（默认 20）")
    parser.add_argument("--resume", action="store_true",
                        help="从已有 manifest 继续（跳过已下载的样本）")
    parser.add_argument("--min-stars", type=int, default=3,
                        help="仓库最低 star 数（默认 3）")
    parser.add_argument("--min-file-size", type=int, default=500,
                        help="文件最小字节数（默认 500）")
    parser.add_argument("--max-file-size", type=int, default=15000,
                        help="文件最大字节数（默认 15000）")
    parser.add_argument("--nvd-proxy", type=str, default="http://127.0.0.1:7897",
                        help="NVD API 代理地址")
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR),
                        help="输出目录")
    args = parser.parse_args()

    token = check_token()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"

    if args.resume:
        manifest = load_existing_manifest(manifest_path)
    else:
        print("错误：扩充脚本必须使用 --resume 以保留现有 7 个样本", file=sys.stderr)
        sys.exit(1)

    # 收集已有的 CVE ID 和 sha
    existing_shas = {s.get("source_sha") for s in manifest.get("samples", [])}
    existing_cves = {s.get("cve_id") for s in manifest.get("samples", [])}
    existing_cwe_counts = {}
    for s in manifest.get("samples", []):
        cwe = s.get("expected_cwe", "")
        existing_cwe_counts[cwe] = existing_cwe_counts.get(cwe, 0) + 1

    collected = len(manifest.get("samples", []))
    target = args.max_samples
    needed = target - collected

    print(f"当前 {collected} 个样本，目标 {target}，需新增 {needed} 个")
    print(f"已有 CWE 分布: {existing_cwe_counts}")
    print(f"已有 CVE: {existing_cves}")

    if needed <= 0:
        print("已达到目标，无需扩充")
        return

    next_idx = get_next_index(manifest)
    repo_star_cache = {}
    stats = {
        "nvd_queries": 0,
        "cves_seen": 0,
        "cves_skipped_existing": 0,
        "no_github_commit": 0,
        "low_stars_skipped": 0,
        "files_seen": 0,
        "files_excluded": 0,
        "files_no_pattern": 0,
        "files_too_large": 0,
        "files_too_small": 0,
        "saved": 0,
    }

    for cwe_id, cwe_name, target_count in TARGET_CWES:
        if collected >= target:
            break

        # 该 CWE 还需要多少个
        have = existing_cwe_counts.get(cwe_id, 0)
        need = target_count - have
        if need <= 0:
            print(f"\n[{cwe_id} {cwe_name}] 已有 {have} 个，跳过")
            continue

        print(f"\n{'='*50}")
        print(f"[{cwe_id} {cwe_name}] 已有 {have}，目标 {target_count}，需新增 {need}")

        # NVD API 查询（限速 7s）
        time.sleep(7)
        cves = search_nvd_by_cwe(cwe_id, proxy=args.nvd_proxy, max_results=30)
        stats["nvd_queries"] += 1
        print(f"  NVD 返回 {len(cves)} 个 CVE")

        for cve_data in cves:
            if collected >= target or need <= 0:
                break

            cve_id = cve_data["cve_id"]
            nvd_desc = cve_data["description"]
            stats["cves_seen"] += 1

            # 跳过已有 CVE
            if cve_id in existing_cves:
                stats["cves_skipped_existing"] += 1
                continue

            # 提取 GitHub commit URL
            commit_info = extract_github_commit_url(cve_data["references"])
            if not commit_info:
                stats["no_github_commit"] += 1
                continue

            owner, repo, sha = commit_info
            if sha in existing_shas:
                continue

            print(f"  [{cve_id}] {owner}/{repo}@{sha[:8]} ({cwe_id})")

            # star 过滤
            repo_key = f"{owner}/{repo}"
            if repo_key in repo_star_cache:
                stars = repo_star_cache[repo_key]
            else:
                time.sleep(random.uniform(0.5, 1.0))
                stars = get_repo_stars(token, owner, repo)
                repo_star_cache[repo_key] = stars

            if 0 <= stars < args.min_stars:
                stats["low_stars_skipped"] += 1
                print(f"    跳过低 star: ★{stars} < {args.min_stars}")
                continue

            print(f"    ★{stars}，获取 commit detail...")

            # 获取 commit detail
            time.sleep(random.uniform(1.0, 2.0))
            detail = get_commit_detail(token, owner, repo, sha)
            if not detail:
                continue
            parents = detail.get("parents", [])
            if not parents:
                continue
            parent_sha = parents[0].get("sha")
            if not parent_sha:
                continue

            # 过滤目标语言文件（每个 CVE 只取 1 个文件）
            best_file = None
            best_patterns = []
            for f in detail.get("files", []):
                fname = f.get("filename", "")
                stats["files_seen"] += 1
                if not lang_of_file(fname):
                    continue
                if is_excluded_file(fname):
                    stats["files_excluded"] += 1
                    continue
                status = f.get("status", "")
                if status == "removed":
                    continue

                # 下载文件内容
                time.sleep(random.uniform(0.5, 1.0))
                code = get_file_content(token, owner, repo, fname, parent_sha)
                if code is None:
                    continue

                # 大小筛选
                if len(code) < args.min_file_size:
                    stats["files_too_small"] += 1
                    continue
                if len(code) > args.max_file_size:
                    stats["files_too_large"] += 1
                    continue

                # 硬性验证：文件必须含可检测的漏洞模式
                matched = detect_vuln_patterns(code)
                if cwe_id in CWE_REQUIRES_PATTERN_MATCH and not matched:
                    stats["files_no_pattern"] += 1
                    print(f"    跳过（无漏洞模式匹配）: {fname}")
                    continue

                # 优先选择模式匹配数最多的文件
                if len(matched) > len(best_patterns):
                    best_file = (fname, code, matched)
                    best_patterns = matched

            if not best_file:
                print(f"    未找到含漏洞模式的文件，跳过此 CVE")
                continue

            fname, code, matched = best_file
            ext = Path(fname).suffix.lower()
            lang = lang_of_file(fname)

            # 保存
            base_name = f"cve_fix_{next_idx:04d}{ext}"
            file_path = output_dir / base_name
            file_path.write_text(code, encoding="utf-8")

            description_short = (nvd_desc or f"{cve_id} vulnerability")[:200]
            sample = {
                "file": base_name,
                "language": lang,
                "category": "cve_fix",
                "difficulty": "real",
                "expected_present": True,
                "expected_vulnerability": description_short,
                "expected_cwe": cwe_id,
                "expected_risk_level": "High",
                "source": "N/A",
                "sink": "N/A",
                "taint_path": "N/A",
                "fix_idea": f"参考修复 commit {owner}/{repo}@{sha[:8]}",
                "source_sha": sha,
                "source_repo": f"{owner}/{repo}",
                "source_path": fname,
                "cve_id": cve_id,
                "vuln_patterns": matched,
                "pattern_not_matched": len(matched) == 0,
                "_expansion_batch": "2026-07-25",
            }
            manifest.setdefault("samples", []).append(sample)
            existing_shas.add(sha)
            existing_cves.add(cve_id)
            existing_cwe_counts[cwe_id] = existing_cwe_counts.get(cwe_id, 0) + 1
            collected += 1
            need -= 1
            next_idx += 1
            stats["saved"] += 1
            print(f"    ✓ 保存 {base_name} ({lang}, {len(code)} chars, patterns={matched})")

            # 增量保存
            save_manifest(manifest_path, manifest)

    save_manifest(manifest_path, manifest)

    # 统计
    print(f"\n{'='*60}")
    print(f"扩充完成：{collected} 个样本（新增 {stats['saved']}）")
    print(f"{'='*60}")
    print(f"统计：")
    print(f"  NVD 查询: {stats['nvd_queries']}")
    print(f"  CVE 看过: {stats['cves_seen']}")
    print(f"  CVE 已有跳过: {stats['cves_skipped_existing']}")
    print(f"  CVE 无 GitHub commit: {stats['no_github_commit']}")
    print(f"  低 star 跳过: {stats['low_stars_skipped']}")
    print(f"  文件看过: {stats['files_seen']}")
    print(f"  文件排除(测试/配置): {stats['files_excluded']}")
    print(f"  文件无漏洞模式: {stats['files_no_pattern']}")
    print(f"  文件过大: {stats['files_too_large']}")
    print(f"  文件过小: {stats['files_too_small']}")
    print(f"  最终保存: {stats['saved']}")

    # 最终 CWE 分布
    print(f"\n最终 CWE 分布：")
    final_cwe = {}
    for s in manifest.get("samples", []):
        cwe = s.get("expected_cwe", "?")
        final_cwe[cwe] = final_cwe.get(cwe, 0) + 1
    for cwe, cnt in sorted(final_cwe.items(), key=lambda x: -x[1]):
        print(f"  {cwe}: {cnt}")


if __name__ == "__main__":
    main()
