"""
修复建议验证模块 —— 对 LLM 生成的 fix_suggestion 做基础自动化校验。

设计目标：
- LLM 扫描器在 SingleResult.fix_suggestion 中给出修复建议文本（通常含 markdown
  代码围栏）。本模块从中抽取修复后的代码，做两件事：
  1. 语法校验：Python 用 ast.parse / py_compile，JavaScript 用 node --check，
     Java 用 javac（如可用），其他语言跳过（返回 True）。
  2. 漏洞模式移除检查：复用 schema.py 中精挑细选的 _VULN_SIGNATURE_PATTERNS，
     若原始代码命中危险模式而修复后代码不再命中，则视为修复有效。
- 故意保持简单：不做语义等价性证明、不跑真实测试用例，仅做"能解析 + 危险
  特征消失"的轻量检查，作为人工复核前的快速过滤层。

判定逻辑：
- syntax_valid：修复后代码能否通过语法解析
- tests_passed：None=无法判定；True=危险模式已移除；False=危险模式仍在
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Optional

# 复用 schema.py 中精挑细选的漏洞特征正则，避免重复维护
from graduation_project.schema import _VULN_SIGNATURE_PATTERNS


# ---------------------------------------------------------------------------
# 验证结果
# ---------------------------------------------------------------------------
@dataclass
class VerificationResult:
    """单次修复验证结果。

    Attributes:
        original_code: 原始漏洞代码
        fixed_code: 从 fix_suggestion 中抽取的修复代码；抽取失败为 None
        language: 代码语言标签
        syntax_valid: 修复后代码是否通过语法校验
        tests_passed: 漏洞模式移除检查结果。None=无法判定，True=危险模式已移除，
                      False=危险模式仍存在
        error_message: 语法校验或抽取过程中的错误信息
        duration: 验证耗时（秒）
    """
    original_code: str
    fixed_code: Optional[str]
    language: str
    syntax_valid: bool
    tests_passed: Optional[bool]
    error_message: Optional[str]
    duration: float

    def __repr__(self) -> str:
        status = "通过" if self.syntax_valid else "失败"
        test_str = {True: "模式已移除", False: "模式仍存在", None: "无法判定"}[self.tests_passed]
        return (f"VerificationResult(syntax={status}, test={test_str}, "
                f"lang={self.language}, duration={self.duration:.2f}s)")


# ---------------------------------------------------------------------------
# 修复验证器
# ---------------------------------------------------------------------------
class FixVerifier:
    """修复建议自动验证器。

    Args:
        timeout: 子进程语法校验超时时间（秒），用于 node --check / javac
    """

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # 代码块抽取
    # ------------------------------------------------------------------
    def extract_code(self, fix_suggestion: str) -> Optional[str]:
        """从 fix_suggestion 文本中抽取 markdown 代码围栏内的代码。

        匹配 ```lang ... ``` 或 ``` ... ``` 形式。返回最后一个代码块的内容
        （修复建议通常在最后给出完整修复代码）；无代码围栏时返回 None。
        """
        if not fix_suggestion:
            return None
        # 匹配 ```可选语言标签 换行 代码内容 换行```
        matches = re.findall(r"```[a-zA-Z0-9_+-]*\n(.*?)```", fix_suggestion, re.DOTALL)
        if not matches:
            return None
        # 取最后一个代码块（修复建议末尾通常是完整修复代码）
        return matches[-1].strip()

    # ------------------------------------------------------------------
    # 语法校验
    # ------------------------------------------------------------------
    def verify_syntax(self, code: str, language: str) -> tuple[bool, Optional[str]]:
        """校验代码语法是否正确。

        Args:
            code: 待校验代码
            language: 语言标签（python/javascript/java/...）

        Returns:
            (是否合法, 错误信息)。不支持的语言返回 (True, None) 跳过。
        """
        lang = (language or "").lower()
        if lang in ("python", "py", "python3"):
            return self._verify_python(code)
        if lang in ("javascript", "js", "node"):
            return self._verify_javascript(code)
        if lang in ("java",):
            return self._verify_java(code)
        # 其他语言不做校验
        return (True, None)

    def _verify_python(self, code: str) -> tuple[bool, Optional[str]]:
        """Python 语法校验：优先 ast.parse（不执行代码，最安全）。"""
        try:
            ast.parse(code)
            return (True, None)
        except SyntaxError as e:
            return (False, f"SyntaxError: {e.msg} (line {e.lineno})")

    def _verify_javascript(self, code: str) -> tuple[bool, Optional[str]]:
        """JavaScript 语法校验：node --check 子进程。"""
        try:
            result = subprocess.run(
                ["node", "--check", "-"],
                input=code, text=True, encoding="utf-8", errors="replace",
                capture_output=True, timeout=self.timeout,
            )
            if result.returncode == 0:
                return (True, None)
            return (False, result.stderr.strip() or "node --check 失败")
        except FileNotFoundError:
            return (True, None)  # node 未安装，跳过
        except subprocess.TimeoutExpired:
            return (False, f"node --check 超时（{self.timeout}s）")

    def _verify_java(self, code: str) -> tuple[bool, Optional[str]]:
        """Java 语法校验：javac 编译临时文件（需提取 public 类名）。"""
        # 提取 public class 名作为文件名
        m = re.search(r"public\s+(?:final\s+)?class\s+(\w+)", code)
        class_name = m.group(1) if m else "Main"
        try:
            # 文件名必须与 public class 名完全一致（含 .java 后缀），
            # 否则 javac 报 "类 X 是公共的，应在名为 X.java 的文件中声明"
            with tempfile.TemporaryDirectory(prefix="vuln_verify_java_") as tmpdir:
                tmp_path = os.path.join(tmpdir, f"{class_name}.java")
                with open(tmp_path, "w", encoding="utf-8") as tmp:
                    tmp.write(code)
                result = subprocess.run(
                    ["javac", "-Xlint:none", tmp_path],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    timeout=self.timeout,
                )
                if result.returncode == 0:
                    return (True, None)
                return (False, result.stderr.strip() or "javac 编译失败")
        except FileNotFoundError:
            return (True, None)  # javac 未安装，跳过
        except subprocess.TimeoutExpired:
            return (False, f"javac 编译超时（{self.timeout}s）")

    # ------------------------------------------------------------------
    # 漏洞模式移除检查
    # ------------------------------------------------------------------
    def run_test(
        self, original_code: str, fixed_code: str, language: str
    ) -> Optional[bool]:
        """基础测试：修复后代码能否解析 + 危险模式是否移除。

        判定逻辑：
        1. 修复后代码若无法通过语法解析 → False
        2. 原始代码命中危险模式 + 修复后代码不再命中 → True
        3. 原始代码命中危险模式 + 修复后代码仍命中 → False
        4. 原始代码未命中危险模式 → None（无法判定）
        5. 修复后代码无法解析（非已知语言）→ 仅做模式移除检查

        Returns:
            True=修复有效，False=修复无效，None=无法判定
        """
        # 修复后代码语法校验（已知语言）
        syntax_ok, _ = self.verify_syntax(fixed_code, language)
        if not syntax_ok:
            return False

        # 危险模式移除检查
        orig_has_vuln = self._has_vuln_pattern(original_code)
        fixed_has_vuln = self._has_vuln_pattern(fixed_code)

        if not orig_has_vuln:
            # 原始代码未命中已知危险模式，无法判定修复是否有效
            return None
        # 原始有危险模式：修复后不再有则通过，否则失败
        return not fixed_has_vuln

    def _has_vuln_pattern(self, code: str) -> bool:
        """检查代码是否命中任一已知危险模式（复用 schema.py 的正则）。"""
        return any(pat.search(code) for pat in _VULN_SIGNATURE_PATTERNS)

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def verify_fix(
        self, original_code: str, fix_suggestion: str, language: str = "python"
    ) -> VerificationResult:
        """验证修复建议：抽取代码 → 语法校验 → 模式移除检查。

        Args:
            original_code: 原始漏洞代码
            fix_suggestion: LLM 生成的修复建议文本（含 markdown 代码围栏）
            language: 代码语言，默认 python

        Returns:
            VerificationResult
        """
        start = time.time()
        fixed_code = self.extract_code(fix_suggestion)

        # 抽取失败
        if fixed_code is None:
            return VerificationResult(
                original_code=original_code,
                fixed_code=None,
                language=language,
                syntax_valid=False,
                tests_passed=None,
                error_message="未能从 fix_suggestion 中抽取代码块",
                duration=time.time() - start,
            )

        # 语法校验
        syntax_ok, err_msg = self.verify_syntax(fixed_code, language)

        # 模式移除检查（仅在语法合法时进行）
        if syntax_ok:
            tests_passed = self.run_test(original_code, fixed_code, language)
        else:
            tests_passed = False  # 语法不合法直接判失败

        return VerificationResult(
            original_code=original_code,
            fixed_code=fixed_code,
            language=language,
            syntax_valid=syntax_ok,
            tests_passed=tests_passed,
            error_message=err_msg,
            duration=time.time() - start,
        )


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # (标签, 原始代码, 修复建议, 语言, 期望 syntax_valid, 期望 tests_passed)
    cases: list[tuple[str, str, str, str, bool, Optional[bool]]] = [
        # --- SQL 注入：字符串拼接 → 参数化查询 ---
        # 注：危险模式匹配要求拼接发生在 execute() 内（schema.py 正则设计），
        # 故原始代码用 cursor.execute("..." + uid) 内联拼接形式
        ("SQL注入修复(有效)",
         'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
         '修复建议：使用参数化查询\n```python\n'
         'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n```',
         "python", True, True),

        # --- 命令注入：shell=True + 拼接 → 列表参数 ---
        ("命令注入修复(有效)",
         'subprocess.run("cat " + filename, shell=True)',
         '使用列表参数形式避免 shell 注入\n```python\n'
         'subprocess.run(["cat", filename])\n```',
         "python", True, True),

        # --- 修复后仍有语法错误 ---
        ("语法错误修复(无效)",
         'os.system("ping " + host)',
         '```python\n'
         'subprocess.run(["ping", host]  # 缺少右括号\n```',
         "python", False, False),

        # --- 修复后仍含危险模式 ---
        ("未真正修复(无效)",
         'os.system("ls " + user_input)',
         '```python\n'
         'os.system("ls " + user_input)  # 仍然拼接\n```',
         "python", True, False),

        # --- 原始代码未命中已知模式（无法判定）---
        ("无已知模式(无法判定)",
         "x = 1 + 2\nprint(x)",
         '```python\n'
         'y = 3\nprint(y)\n```',
         "python", True, None),

        # --- 抽取失败（无代码围栏）---
        ("无代码块(抽取失败)",
         'eval(request.args.get("x"))',
         "建议使用 ast.literal_eval 替代 eval。",
         "python", False, None),
    ]

    verifier = FixVerifier(timeout=10)
    all_pass = True
    for label, orig, suggestion, lang, exp_syntax, exp_test in cases:
        r = verifier.verify_fix(orig, suggestion, language=lang)
        ok = (r.syntax_valid == exp_syntax and r.tests_passed == exp_test)
        all_pass = all_pass and ok
        flag = "PASS" if ok else "FAIL"
        print(f"[{flag}] {label}: syntax={r.syntax_valid}(期望{exp_syntax}), "
              f"test={r.tests_passed}(期望{exp_test}), "
              f"duration={r.duration:.3f}s"
              + (f", err={r.error_message}" if r.error_message else ""))

    # extract_code 边界用例
    print("\n=== extract_code 边界用例 ===")
    extract_cases: list[tuple[str, Optional[str]]] = [
        ("```python\nprint(1)\n```", "print(1)"),
        ("无围栏的纯文本", None),
        ("```java\nSystem.out.println(1);\n```", "System.out.println(1);"),
        ("说明\n```python\ncode1\n```\n更多说明\n```python\ncode2\n```", "code2"),
    ]
    for text, expected in extract_cases:
        got = verifier.extract_code(text)
        ok = got == expected
        all_pass = all_pass and ok
        print(f"[{'PASS' if ok else 'FAIL'}] extract_code: got={got!r}, expected={expected!r}")

    print("\n=== 全部通过 ===" if all_pass else "\n=== 存在失败用例 ===")
