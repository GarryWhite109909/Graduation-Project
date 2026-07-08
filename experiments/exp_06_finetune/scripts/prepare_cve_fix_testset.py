"""
从 GitHub 搜索 CVE 修复 commit，提取漏洞版本代码作为独立测试集（held-out）。

背景：
  - 项目现有测试集 exp_04_hard_samples 与训练集同分布，需要独立测试集评估泛化能力
  - 本脚本通过 GitHub Search API 搜索 commit message 含 "CVE-" + "fix" 的公开 commit，
    对每个修复 commit 取修复前（parent sha）的目标文件代码作为漏洞样本

数据源（均通过 GitHub REST API）：
  1. GET /search/commits?q=cve+fix+is:public+committer-date:>{date}&sort=committer-date
     Header: Authorization: token $GITHUB_TOKEN
             Accept: application/vnd.github.cloak-preview+json  (commit search 必需)
  2. GET /repos/{owner}/{repo}/commits/{sha}           拿 files 列表 + parents
  3. GET /repos/{owner}/{repo}/contents/{path}?ref={parent_sha}  拿修复前文件内容（base64）

输出：
  experiments/exp_06_finetune/testset_cve_fix/
    ├── manifest.json   （schema 与 exp_04_hard_samples/samples/manifest.json 一致）
    └── cve_fix_0001.py 等（每个样本一个代码文件）

  manifest 每个样本标注 expected_present=true（漏洞版本），
  expected_cwe 字段直接记 CVE 编号（如 CVE-2024-12345），无 CWE 库时不映射 CWE-XX。

用法：
  export GITHUB_TOKEN=ghp_xxx
  python prepare_cve_fix_testset.py --max-samples 30 --language python --resume

依赖：仅 Python 标准库（urllib/json/base64/pathlib/argparse），不依赖 graduation_project 模块，
      以便独立运行；manifest 格式与项目一致以便 evaluate.py 复用。
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

GITHUB_API = "https://api.github.com"
# 脚本位于 exp_06_finetune/scripts/，上级即 exp_06_finetune/
EXP06_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = EXP06_DIR / "testset_cve_fix"

# 支持的语言扩展名 -> manifest 中的 language 字段（与 exp_04 风格一致）
LANG_EXT_MAP = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript",
    ".php": "PHP",
    ".go": "Go",
    ".c": "C",
}
# --language 参数值 -> 允许的扩展名集合
LANG_FILTER = {
    "python": {".py"},
    "java": {".java"},
    "javascript": {".js"},
    "php": {".php"},
    "go": {".go"},
    "c": {".c"},
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def check_token() -> str:
    """检查 GITHUB_TOKEN 环境变量，未设置则报错退出。

    严禁硬编码 token —— 必须通过环境变量传入。
    对 token 做 strip 和 ASCII 校验，避免复制时混入空格/中文/不可见字符。
    """
    raw = os.environ.get("GITHUB_TOKEN", "")
    token = raw.strip()
    if not token:
        print("错误：未设置 GITHUB_TOKEN 环境变量。", file=sys.stderr)
        print("请先 export GITHUB_TOKEN=ghp_xxx 再运行本脚本。", file=sys.stderr)
        sys.exit(1)
    # GitHub token 只含 ASCII；若含非 ASCII 通常是复制污染
    try:
        token.encode("ascii")
    except UnicodeEncodeError as e:
        print(f"错误：GITHUB_TOKEN 包含非 ASCII 字符: {e}", file=sys.stderr)
        print("请检查 token 是否混入了空格、换行或中文。", file=sys.stderr)
        sys.exit(1)
    return token


def github_request(url: str, token: str, accept: str = "application/vnd.github+json"):
    """发起 GitHub API 请求，处理 rate limit 与重试。

    遇到 403 时读取 X-RateLimit-Reset 头，sleep 到 reset 后重试一次。
    返回 (status_code, headers_dict, parsed_json_or_None)。
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": accept,
        "User-Agent": "graduation-project-cve-fix-fetcher",
    }
    for attempt in range(2):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    parsed = None
                return resp.status, dict(resp.headers), parsed
        except urllib.error.HTTPError as e:
            if e.code == 403:
                reset = e.headers.get("X-RateLimit-Reset") if e.headers else None
                if attempt == 0 and reset:
                    try:
                        wait = int(reset) - int(time.time()) + 5
                    except ValueError:
                        wait = 0
                    if 0 < wait < 3600:
                        print(f"  [rate limit] 等待 {wait}s 至 reset...", file=sys.stderr)
                        time.sleep(wait)
                        continue
                print(f"  [403] 访问被拒: {url}", file=sys.stderr)
                return 403, dict(e.headers or {}), None
            print(f"  [HTTP {e.code}] {url}: {e.reason}", file=sys.stderr)
            return e.code, dict(e.headers or {}), None
        except urllib.error.URLError as e:
            print(f"  [网络错误] {url}: {e.reason}", file=sys.stderr)
            if attempt == 0:
                time.sleep(3)
                continue
            return 0, {}, None
    return 0, {}, None


def search_fix_commits(token: str, date_since: str, per_page: int = 50) -> list:
    """搜索 CVE 修复 commit，返回 commit item 列表。"""
    q = f"cve fix is:public committer-date:>{date_since}"
    params = {
        "q": q,
        "sort": "committer-date",
        "order": "desc",
        "per_page": str(per_page),
    }
    url = f"{GITHUB_API}/search/commits?" + urllib.parse.urlencode(params)
    print(f"搜索 commit: {url}")
    status, _headers, data = github_request(
        url, token, accept="application/vnd.github.cloak-preview+json"
    )
    if status != 200 or not data:
        print(f"搜索失败 status={status}", file=sys.stderr)
        return []
    items = data.get("items", [])
    print(f"  共找到 {data.get('total_count', 0)} 条，本次返回 {len(items)} 条")
    return items


def get_commit_detail(token: str, owner: str, repo: str, sha: str):
    """获取单个 commit 的 files 列表与 parents。"""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    status, _headers, data = github_request(url, token)
    if status != 200 or not data:
        return None
    return data


def get_file_content(token: str, owner: str, repo: str, path: str, ref: str):
    """获取指定 ref 的文件内容（base64 解码为文本）。"""
    encoded_path = urllib.parse.quote(path, safe="/")
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{encoded_path}?ref={ref}"
    status, _headers, data = github_request(url, token)
    if status != 200 or not data:
        return None
    if data.get("encoding") != "base64":
        return None
    content_b64 = data.get("content", "")
    try:
        raw = base64.b64decode(content_b64)
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [解码失败] {path}: {e}", file=sys.stderr)
        return None


def extract_cve(message: str):
    """从 commit message 提取第一个 CVE 编号（大写）。"""
    m = CVE_RE.search(message or "")
    return m.group(0).upper() if m else None


def lang_of_file(filename: str):
    """根据扩展名返回 manifest 中的 language 名。"""
    ext = Path(filename).suffix.lower()
    return LANG_EXT_MAP.get(ext)


def load_existing_manifest(manifest_path: Path) -> dict:
    """读取已有 manifest（用于 --resume）。"""
    if not manifest_path.exists():
        return {"experiment": "exp_06_cve_fix_testset", "samples": []}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"experiment": "exp_06_cve_fix_testset", "samples": []}


def save_manifest(manifest_path: Path, manifest: dict) -> None:
    """保存 manifest（UTF-8，缩进 2）。"""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def parse_repo_info(item: dict):
    """从 commit search item 解析 (owner, repo, sha, message)。

    commit search 返回结构兼容 repository / repo 两种字段命名。
    """
    sha = item.get("sha")
    message = (item.get("commit", {}) or {}).get("message", "")
    owner = None
    repo = None
    # 优先 repository 字段
    rep = item.get("repository") or {}
    if isinstance(rep, dict):
        owner_info = rep.get("owner") or {}
        if isinstance(owner_info, dict):
            owner = owner_info.get("login")
        repo = rep.get("name")
    # 兼容 repo 字段
    if not owner or not repo:
        rep2 = item.get("repo") or {}
        if isinstance(rep2, dict):
            owner_info = rep2.get("owner") or {}
            if isinstance(owner_info, dict):
                owner = owner_info.get("login") or owner
            repo = rep2.get("name") or repo
    return owner, repo, sha, message


def main():
    parser = argparse.ArgumentParser(
        description="从 GitHub 抓取 CVE 修复 commit 的漏洞版本代码作为独立测试集"
    )
    parser.add_argument("--max-samples", type=int, default=30,
                        help="最多抓取的样本数（默认 30）")
    parser.add_argument("--language", choices=list(LANG_FILTER.keys()), default=None,
                        help="只抓取指定语言的文件（默认全部）")
    parser.add_argument("--resume", action="store_true",
                        help="从上次中断处继续（跳过已下载的样本）")
    parser.add_argument("--since-years", type=int, default=2,
                        help="搜索近 N 年的 commit（默认 2）")
    parser.add_argument("--output-dir", type=str, default=str(OUTPUT_DIR),
                        help="输出目录")
    args = parser.parse_args()

    token = check_token()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"

    # resume：读取已有 manifest，跳过已下载的样本
    if args.resume:
        manifest = load_existing_manifest(manifest_path)
        existing_shas = {s.get("source_sha") for s in manifest.get("samples", [])}
        existing_files = {s.get("file") for s in manifest.get("samples", [])}
        print(f"[resume] 已有 {len(manifest.get('samples', []))} 个样本，将跳过")
    else:
        manifest = {
            "experiment": "exp_06_cve_fix_testset",
            "description": (
                "CVE-fix 独立测试集：从 GitHub 搜索 CVE 修复 commit，"
                "提取修复前版本代码作为漏洞样本（held-out，不与训练集重叠）。"
                "expected_cwe 字段记录 CVE 编号。"
            ),
            "schema_version": "8col_v1",
            "source": "github_search_commits",
            "ground_truth_columns": [
                "file", "language", "category", "difficulty",
                "expected_present", "expected_vulnerability",
                "expected_cwe", "expected_risk_level",
                "source", "sink", "taint_path", "fix_idea",
            ],
            "samples": [],
        }
        existing_shas = set()
        existing_files = set()

    allowed_exts = LANG_FILTER.get(args.language) if args.language else set(LANG_EXT_MAP.keys())

    date_since = (datetime.utcnow() - timedelta(days=365 * args.since_years)).strftime("%Y-%m-%d")
    print(f"搜索 {date_since} 之后的 CVE 修复 commit...")

    commits = search_fix_commits(token, date_since)
    if not commits:
        print("未找到任何 commit，退出。")
        save_manifest(manifest_path, manifest)
        return

    collected = len(manifest.get("samples", []))
    target = args.max_samples

    for ci, c in enumerate(commits):
        if collected >= target:
            break
        owner, repo, sha, message = parse_repo_info(c)
        if not owner or not repo or not sha:
            continue
        if sha in existing_shas:
            print(f"[{ci+1}/{len(commits)}] 跳过已下载 sha={sha[:8]}")
            continue

        cve_id = extract_cve(message)
        if not cve_id:
            # 跳过 commit message 中无 CVE 编号的
            continue

        print(f"[{ci+1}/{len(commits)}] 处理 {owner}/{repo}@{sha[:8]} ({cve_id})")

        # 限速：每两个请求之间 sleep 1-2 秒
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

        # 过滤目标语言文件
        target_files = []
        for f in detail.get("files", []):
            fname = f.get("filename", "")
            if not lang_of_file(fname):
                continue
            if Path(fname).suffix.lower() not in allowed_exts:
                continue
            status = f.get("status", "")
            # 排除纯删除
            if status == "removed":
                continue
            target_files.append(f)

        if not target_files:
            print(f"  无匹配文件（{args.language or 'all'}）")
            continue

        for f in target_files:
            if collected >= target:
                break
            fname = f.get("filename", "")
            lang = lang_of_file(fname)
            ext = Path(fname).suffix.lower()

            # 限速
            time.sleep(random.uniform(1.0, 2.0))
            code = get_file_content(token, owner, repo, fname, parent_sha)
            if code is None:
                continue
            # 过滤过短/过长的文件
            if len(code) < 50:
                continue
            if len(code) > 20000:
                code = code[:20000]

            idx = collected + 1
            base_name = f"cve_fix_{idx:04d}{ext}"
            while base_name in existing_files:
                idx += 1
                base_name = f"cve_fix_{idx:04d}{ext}"
            file_path = output_dir / base_name
            file_path.write_text(code, encoding="utf-8")
            existing_files.add(base_name)

            first_line = message.splitlines()[0][:120] if message else ""
            sample = {
                "file": base_name,
                "language": lang,
                "category": "cve_fix",
                "difficulty": "real",
                "expected_present": True,
                "expected_vulnerability": f"{cve_id}: {first_line}",
                "expected_cwe": cve_id,  # CVE 编号（无 CWE 库时直接记 CVE）
                "expected_risk_level": "High",  # CVE 修复默认 High
                "source": "N/A",  # 源/sink/污点路径待模型分析
                "sink": "N/A",
                "taint_path": "N/A",
                "fix_idea": f"参考修复 commit {owner}/{repo}@{sha[:8]}",
                "source_sha": sha,
                "source_repo": f"{owner}/{repo}",
                "source_path": fname,
                "cve_id": cve_id,
            }
            manifest.setdefault("samples", []).append(sample)
            existing_shas.add(sha)
            collected += 1
            print(f"  保存 {base_name} ({lang}, {len(code)} chars)")

            # 增量保存 manifest（断点续传友好）
            save_manifest(manifest_path, manifest)

    save_manifest(manifest_path, manifest)
    print(f"\n完成：共 {collected} 个样本，输出到 {output_dir}")


if __name__ == "__main__":
    main()
