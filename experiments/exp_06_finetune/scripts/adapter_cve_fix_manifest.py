"""
把 CVE-fix 测试集 manifest 适配为 evaluate.py 可直接读取的格式。

prepare_cve_fix_testset.py 生成的 manifest 中：
  - expected_cwe 是 CVE 编号（如 CVE-2024-12345），不是 CWE-XX
  - expected_vulnerability 可能含 commit message 首行
  - category = "cve_fix"

本脚本输出一份兼容 manifest，把 expected_cwe 从 CVE 编号映射为通用 CWE 占位符，
或保留 CVE 编号但让 evaluate.py 可以正常读取。

用法：
  PYTHONPATH=/home/zane/文档/code/毕业设计 \
  /home/zane/miniconda3/envs/graproj/bin/python3 \
  experiments/exp_06_finetune/scripts/adapter_cve_fix_manifest.py \
      --input experiments/exp_06_finetune/testset_cve_fix/manifest.json \
      --output experiments/exp_06_finetune/testset_cve_fix/manifest_eval.json

转换规则：
  - 保留所有原始字段
  - 若 expected_cwe 以 CVE- 开头，仍保留为 CVE 编号（evaluate.py 不依赖具体 CWE 字符串做判断）
  - 补充缺少的可选字段默认值，避免 evaluate.py 中的 rec.get 返回 None
"""

import argparse
import json
import os
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_INPUT = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix/manifest.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "experiments/exp_06_finetune/testset_cve_fix/manifest_eval.json"


def guess_cwe_from_commit_msg(msg: str) -> str:
    """根据 commit message 粗略映射 CWE（保守策略，无把握时返回 CVE 编号）。"""
    msg_l = msg.lower()
    if any(k in msg_l for k in ["sql", "sqli", "injection", "query"]):
        return "CWE-89 SQL注入"
    if any(k in msg_l for k in ["xss", "cross-site scripting", "cross site scripting"]):
        return "CWE-79 XSS"
    if any(k in msg_l for k in ["command", "shell", "os command", "rce"]):
        return "CWE-78 命令注入"
    if any(k in msg_l for k in ["path", "traversal", "directory"]):
        return "CWE-22 路径穿越"
    if any(k in msg_l for k in ["ssrf", "server-side request"]):
        return "CWE-918 SSRF"
    if any(k in msg_l for k in ["xxe", "xml external entity"]):
        return "CWE-611 XXE"
    if any(k in msg_l for k in ["deserializ", "unserialize", "pickle"]):
        return "CWE-502 反序列化"
    if any(k in msg_l for k in ["csrf", "cross-site request"]):
        return "CWE-352 CSRF"
    if any(k in msg_l for k in ["auth", "authorization", "permission"]):
        return "CWE-862 缺失授权"
    if any(k in msg_l for k in ["authen", "login", "credential"]):
        return "CWE-306 缺失认证"
    if any(k in msg_l for k in ["secret", "key", "token", "password"]):
        return "CWE-798 硬编码凭证"
    if any(k in msg_l for k in ["overflow", "integer"]):
        return "CWE-190 整数溢出"
    if any(k in msg_l for k in ["crypto", "encrypt", "hash", "md5", "sha1"]):
        return "CWE-327 弱加密"
    return "CWE-未知 CVE"


def adapt_sample(s: dict) -> dict:
    """把 CVE-fix sample 转为 evaluate.py 可读格式。"""
    out = dict(s)
    out.setdefault("category", "cve_fix")
    out.setdefault("difficulty", "real")
    out.setdefault("expected_present", True)
    out.setdefault("expected_risk_level", "High")
    out.setdefault("source", "N/A")
    out.setdefault("sink", "N/A")
    out.setdefault("taint_path", "N/A")
    out.setdefault("fix_idea", f"参考修复 commit {s.get('source_repo','')}/{s.get('source_sha','')}")

    expected_vuln = s.get("expected_vulnerability") or s.get("cve_id") or "未知 CVE"
    out.setdefault("expected_vulnerability", expected_vuln)

    cwe = s.get("expected_cwe") or "CVE-未知"
    if cwe.upper().startswith("CVE-"):
        # 尝试从 commit message 推断 CWE，保留 CVE 编号作为 fallback
        inferred = guess_cwe_from_commit_msg(s.get("expected_vulnerability", ""))
        out["expected_cwe"] = inferred if inferred != "CWE-未知 CVE" else cwe
    return out


def main():
    parser = argparse.ArgumentParser(description="适配 CVE-fix manifest 为 evaluate.py 可读格式")
    parser.add_argument("--input", type=str, default=str(DEFAULT_INPUT))
    parser.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"错误：输入文件不存在: {in_path}", file=os.sys.stderr)
        print("请先运行 prepare_cve_fix_testset.py 抓取 CVE-fix 测试集。", file=os.sys.stderr)
        os.sys.exit(1)

    manifest = json.loads(in_path.read_text(encoding="utf-8"))
    samples = manifest.get("samples", [])
    if not samples:
        print("错误：manifest 中没有样本", file=os.sys.stderr)
        os.sys.exit(1)

    adapted = [adapt_sample(s) for s in samples]
    manifest["samples"] = adapted
    manifest["description"] = (
        manifest.get("description", "") + " [已适配为 evaluate.py 可读格式]"
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已适配 {len(adapted)} 个 CVE-fix 样本，输出: {out_path}")
    print("用法：修改 evaluate.py 的 MANIFEST_PATH 指向此文件以评估 CVE-fix 测试集。")


if __name__ == "__main__":
    main()
