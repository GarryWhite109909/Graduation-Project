"""
外部扫描器模块 —— 封装传统 SAST / SCA / Secret / IaC 工具，作为 LLM 扫描的并行预筛层。

设计目标：
- 将 Bandit / Semgrep / Gitleaks / Trivy 等成熟工具的输出统一为 ExternalFinding 结构，
  与 prefilter.py（正则预筛）互补：prefilter 是"规则匹配"，本模块是"调用真实工具"。
- 所有工具可选，通过 shutil.which() 探测安装情况；未安装的工具静默跳过，不影响其他工具。
- 每个工具以子进程方式运行，输出 JSON，超时 60s；解析失败或工具异常均降级为空结果。
- scan() 聚合 SAST + Secret + SCA + IaC 四类扫描结果，供上层与 LLM 结果融合。

与 prefilter.py 的关系：
- prefilter.py 在 LLM 调用"之前"做正则快速预筛（毫秒级）；
- 本模块在 LLM 调用"之前/并行"调用传统工具（秒级），提供更高召回的候选发现；
- 二者结果均可作为 LLM 的辅助输入，构成"传统工具 + LLM"的混合扫描架构。

注意：本模块不负责修复或阻断，仅产出 ExternalFinding 列表供上层决策。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
_TOOL_TIMEOUT: int = 60  # 每个工具子进程超时（秒）

# 全部支持的工具名（与 shutil.which 检测的命令名一致）
_ALL_TOOLS: list[str] = ["bandit", "semgrep", "gitleaks", "trivy"]

# Semgrep 固定规则集（保证 Stage 1 工具层结果可复现；自写 taint 规则文件可追加到此列表）
_SEMGREP_CONFIGS: list[str] = [
    "p/security-audit",
    "p/owasp-top-10",
]


# ---------------------------------------------------------------------------
# 发现数据结构
# ---------------------------------------------------------------------------
@dataclass
class ExternalFinding:
    """单个外部工具发现。

    Attributes:
        tool: 发现该问题的工具名（bandit / semgrep / gitleaks / trivy）
        rule_id: 工具内部的规则 / 漏洞 ID（如 B101、CVE-2021-12345、AVD-terraform-001）
        severity: 严重等级（工具原始值小写化，如 low / medium / high / critical）
        message: 问题描述文本
        filename: 受影响的文件路径（工具输出中的原始路径）
        line: 行号（1-based；工具未提供时为 0）
        category: 发现类别 —— "sast" 静态分析 / "sca" 依赖漏洞 /
                  "secret" 硬编码密钥 / "iac" 基础设施即代码配置
    """
    tool: str
    rule_id: str
    severity: str
    message: str
    filename: str
    line: int
    category: str  # "sast" / "sca" / "secret" / "iac"

    def __repr__(self) -> str:
        return (f"ExternalFinding(tool={self.tool}, category={self.category}, "
                f"severity={self.severity}, rule={self.rule_id}, "
                f"file={self.filename}:{self.line})")


def normalize_severity(value: str) -> str:
    """把各工具的 severity 归一化为 critical/high/medium/low/info。

    Bandit: LOW/MEDIUM/HIGH/UNDEFINED；Semgrep: ERROR/WARNING/INFO；
    Gitleaks: CRITICAL/HIGH/MEDIUM/LOW/INFO；Trivy: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN。
    归一化结果为裁决层（Stage 2）提供统一输入格式。
    """
    s = (value or "").strip().lower()
    if not s or s in ("unknown", "undefined", "unassigned", "none",
                      "informational", "note", "info"):
        return "info"
    if s in ("critical", "严重", "危急"):
        return "critical"
    if s in ("high", "error", "高危"):
        return "high"
    if s in ("medium", "moderate", "warning", "warn", "中危"):
        return "medium"
    if s in ("low", "info", "低危"):
        return "low"
    # 模糊匹配（如 "CRITICAL/HIGH" 组合值）
    if "crit" in s:
        return "critical"
    if "high" in s:
        return "high"
    if "med" in s or "moderate" in s or "warn" in s:
        return "medium"
    if "low" in s or "info" in s:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# 外部扫描器
# ---------------------------------------------------------------------------
class ExternalScanner:
    """传统安全工具聚合扫描器。

    封装 Bandit（Python SAST）、Semgrep（多语言 SAST）、Gitleaks（密钥检测）、
    Trivy（SCA 依赖漏洞 + IaC 配置扫描）四类工具，统一输出 ExternalFinding 列表。

    工具探测：
    - __init__ 时通过 shutil.which() 检测已安装工具；
    - 未安装的工具在对应 scan_* 方法中静默跳过（返回空列表），不抛异常；
    - available_tools() 返回当前已安装且被请求的工具列表。

    降级策略：
    - 工具未安装 → 跳过
    - 子进程超时（60s）→ 跳过
    - JSON 解析失败 → 跳过
    - 工具退出码非零但 stdout 有 JSON → 仍尝试解析（部分工具无发现时退出码非零）
    """

    def __init__(self, tools: list[str] | None = None) -> None:
        """初始化扫描器，探测已安装工具。

        Args:
            tools: 要启用的工具名列表（None 表示全部启用）。
                   支持的名称：bandit / semgrep / gitleaks / trivy。
                   未安装或未知的工具名会被忽略。
        """
        requested = list(tools) if tools is not None else list(_ALL_TOOLS)
        # 探测已安装工具，保存可执行文件路径
        self._installed: dict[str, str] = {}
        for name in requested:
            if name not in _ALL_TOOLS:
                continue  # 未知工具名，忽略
            resolved = shutil.which(name)
            if resolved:
                self._installed[name] = resolved

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    def available_tools(self) -> list[str]:
        """返回已安装且被启用的工具名列表。"""
        return list(self._installed.keys())

    def scan(self, path: str, language: str = "python") -> list[ExternalFinding]:
        """对给定文件 / 目录运行全部已启用工具，聚合发现。

        Args:
            path: 待扫描的文件或目录路径
            language: 主要语言标签（影响 SAST 工具选择，如 bandit 仅扫描 Python）

        Returns:
            所有工具发现的聚合列表（SAST + Secret + SCA + IaC）
        """
        findings: list[ExternalFinding] = []
        findings.extend(self.scan_sast(path, language))
        findings.extend(self.scan_secrets(path))
        findings.extend(self.scan_sca(path))
        findings.extend(self.scan_iac(path))
        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: list[ExternalFinding]) -> list[ExternalFinding]:
        """按 (tool, rule_id, filename, line) 去重，保证裁决层输入稳定。"""
        seen: set[tuple] = set()
        out: list[ExternalFinding] = []
        for item in findings:
            key = (item.tool, item.rule_id, item.filename, item.line)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    def scan_sast(self, path: str, language: str = "python") -> list[ExternalFinding]:
        """运行 SAST 工具（Bandit + Semgrep）。

        - Bandit：仅对 Python 生效，language="python" 时启用
        - Semgrep：多语言，始终启用（若已安装）

        Args:
            path: 待扫描的文件或目录路径
            language: 语言标签

        Returns:
            SAST 发现列表（category="sast"）
        """
        findings: list[ExternalFinding] = []
        if language == "python" and "bandit" in self._installed:
            findings.extend(self._run_bandit(path))
        if "semgrep" in self._installed:
            findings.extend(self._run_semgrep(path))
        return findings

    def scan_secrets(self, path: str) -> list[ExternalFinding]:
        """运行密钥检测工具（Gitleaks）。

        Args:
            path: 待扫描的文件或目录路径（Gitleaks 在 git 仓库中效果最佳，
                  也可扫描普通文件）

        Returns:
            密钥发现列表（category="secret"）
        """
        if "gitleaks" not in self._installed:
            return []
        return self._run_gitleaks(path)

    def scan_sca(self, path: str) -> list[ExternalFinding]:
        """运行 SCA 工具（Trivy fs）扫描依赖漏洞。

        Trivy fs 会自动识别路径中的 requirements.txt / package.json /
        go.sum / Gemfile.lock 等依赖清单文件并检查已知漏洞。

        Args:
            path: 待扫描的文件或目录路径

        Returns:
            依赖漏洞发现列表（category="sca"）
        """
        if "trivy" not in self._installed:
            return []
        return self._run_trivy_fs(path)

    def scan_iac(self, path: str) -> list[ExternalFinding]:
        """运行 IaC 配置扫描工具（Trivy config）。

        Trivy config 会扫描 Terraform / Kubernetes / Dockerfile /
        CloudFormation 等基础设施配置文件中的安全问题。

        Args:
            path: 待扫描的文件或目录路径

        Returns:
            IaC 配置发现列表（category="iac"）
        """
        if "trivy" not in self._installed:
            return []
        return self._run_trivy_config(path)

    # ------------------------------------------------------------------
    # 子进程执行
    # ------------------------------------------------------------------
    def _run_subprocess(self, cmd: list[str]) -> Optional[str]:
        """运行子进程并返回 stdout 文本。

        工具未找到 / 超时 / 其他异常均返回 None，由调用方降级处理。
        不检查退出码 —— 部分工具（如 gitleaks）在"无发现"时退出码非零，
        但 stdout 仍可能包含 JSON。
        """
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8", errors="replace",
                timeout=_TOOL_TIMEOUT,
            )
            return proc.stdout
        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None

    # ------------------------------------------------------------------
    # 各工具运行器
    # ------------------------------------------------------------------
    def _run_bandit(self, path: str) -> list[ExternalFinding]:
        """运行 Bandit（Python SAST）。

        命令：bandit -f json -q <path>
        输出 JSON 含 results 数组，每项含 test_id / issue_severity /
        issue_text / filename / line_number。
        """
        out = self._run_subprocess(["bandit", "-f", "json", "-q", path])
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        findings: list[ExternalFinding] = []
        for r in data.get("results", []):
            findings.append(ExternalFinding(
                tool="bandit",
                rule_id=str(r.get("test_id", "")),
                severity=normalize_severity(str(r.get("issue_severity", "UNKNOWN"))),
                message=str(r.get("issue_text", "")),
                filename=str(r.get("filename", "")),
                line=int(r.get("line_number", 0) or 0),
                category="sast",
            ))
        return findings

    def _run_semgrep(self, path: str) -> list[ExternalFinding]:
        """运行 Semgrep（多语言 SAST）。

        命令：semgrep --json --quiet --config p/security-audit --config p/owasp-top-10 <path>
        输出 JSON 含 results 数组，每项含 check_id / path / start.line /
        extra.severity / extra.message。
        """
        # 固定规则集（可复现）：security-audit + owasp-top-10；
        # 后续自写 taint 规则文件追加进 _SEMGREP_CONFIGS 即可。
        # 离线/规则拉取失败时 semgrep 会在 JSON errors 中报告，
        # 此时视为工具不可用而非"扫描通过"
        out = self._run_subprocess(
            ["semgrep", "--json", "--quiet"]
            + [c for cfg in _SEMGREP_CONFIGS for c in ("--config", cfg)]
            + [path]
        )
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if data.get("errors"):
            print(f"[ExternalScanner] semgrep 报告错误（可能是离线/规则拉取失败）: "
                  f"{str(data['errors'][0])[:200]}")
            return []
        findings: list[ExternalFinding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            start = r.get("start", {}) or {}
            findings.append(ExternalFinding(
                tool="semgrep",
                rule_id=str(r.get("check_id", "")),
                severity=normalize_severity(str(extra.get("severity", "INFO"))),
                message=str(extra.get("message", "")),
                filename=str(r.get("path", "")),
                line=int(start.get("line", 0) or 0),
                category="sast",
            ))
        return findings

    def _run_gitleaks(self, path: str) -> list[ExternalFinding]:
        """运行 Gitleaks（密钥检测）。

        命令：gitleaks detect --source <path> --report-format json --report-path -
        --report-path - 将 JSON 输出到 stdout。输出为 JSON 数组，每项含
        RuleID / Description / File / StartLine / Severity。
        """
        out = self._run_subprocess([
            "gitleaks", "detect",
            "--source", path,
            "--report-format", "json",
            "--report-path", "-",
        ])
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        # gitleaks 输出为数组；个别版本可能包在 {"Results": [...]} 中
        if isinstance(data, dict):
            items = data.get("Results", data.get("findings", []))
        else:
            items = data
        findings: list[ExternalFinding] = []
        for r in items:
            raw_sev = str(r.get("Severity", "")).strip()
            severity = normalize_severity(raw_sev)
            if not raw_sev:
                severity = "high"  # 工具未给等级时密钥泄露默认高危
            findings.append(ExternalFinding(
                tool="gitleaks",
                rule_id=str(r.get("RuleID", "")),
                severity=severity,
                message=str(r.get("Description", "") or r.get("RuleID", "")),
                filename=str(r.get("File", "")),
                line=int(r.get("StartLine", 0) or 0),
                category="secret",
            ))
        return findings

    def _run_trivy_fs(self, path: str) -> list[ExternalFinding]:
        """运行 Trivy fs（SCA 依赖漏洞扫描）。

        命令：trivy fs --format json <path>
        输出 JSON 含 Results 数组，每项含 Target / Vulnerabilities 数组。
        每个 Vulnerability 含 VulnerabilityID / Severity / Title / PkgName。
        """
        out = self._run_subprocess(["trivy", "fs", "--format", "json", path])
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        findings: list[ExternalFinding] = []
        for result in data.get("Results", []):
            target = str(result.get("Target", ""))
            vulns = result.get("Vulnerabilities") or []
            for v in vulns:
                title = v.get("Title") or v.get("Description", "")
                findings.append(ExternalFinding(
                    tool="trivy",
                    rule_id=str(v.get("VulnerabilityID", "")),
                    severity=normalize_severity(str(v.get("Severity", "UNKNOWN"))),
                    message=str(title),
                    filename=target,
                    line=0,  # 依赖漏洞无行号
                    category="sca",
                ))
        return findings

    def _run_trivy_config(self, path: str) -> list[ExternalFinding]:
        """运行 Trivy config（IaC 配置扫描）。

        命令：trivy config --format json <path>
        输出 JSON 含 Results 数组，每项含 Target / Misconfigurations 数组 /
        CauseMetadata.StartLine。每个 Misconfiguration 含 ID / Severity / Message。
        """
        out = self._run_subprocess(["trivy", "config", "--format", "json", path])
        if not out or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        findings: list[ExternalFinding] = []
        for result in data.get("Results", []):
            target = str(result.get("Target", ""))
            cause_meta = result.get("CauseMetadata", {}) or {}
            default_line = int(cause_meta.get("StartLine", 0) or 0)
            misconfs = result.get("Misconfigurations") or []
            for m in misconfs:
                findings.append(ExternalFinding(
                    tool="trivy",
                    rule_id=str(m.get("ID", "") or m.get("AVDID", "")),
                    severity=str(m.get("Severity", "UNKNOWN")).lower(),
                    message=str(m.get("Message", "")),
                    filename=target,
                    line=default_line,
                    category="iac",
                ))
        return findings


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os

    print("=== 外部扫描器自检 ===\n")

    scanner = ExternalScanner()
    available = scanner.available_tools()

    print(f"支持的工具: {_ALL_TOOLS}")
    print(f"已安装的工具: {available if available else '（无，所有 scan 方法将返回空列表）'}")
    print()

    for tool in _ALL_TOOLS:
        status = "已安装" if tool in available else "未安装"
        print(f"  [{status}] {tool}")

    print()
    if available:
        # 对脚本所在目录做一次演示扫描
        demo_path = os.path.dirname(os.path.abspath(__file__))
        print(f"对目录做演示扫描: {demo_path}")
        print("（每工具超时 60s，请耐心等待）\n")
        results = scanner.scan(demo_path)
        if results:
            print(f"共发现 {len(results)} 项:")
            for f in results:
                print(f"  {f}")
        else:
            print("未发现安全问题（或工具无输出）。")
    else:
        print("未检测到任何外部工具，模块以降级模式运行（所有 scan 返回空列表）。")
        print("安装示例: pip install bandit semgrep  |  choco install gitleaks trivy")
