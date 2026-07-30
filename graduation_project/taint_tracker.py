"""轻量级 CPG 启发式污点分析模块 —— 用 tree-sitter 检测同函数作用域内的 source→sink 数据流。

本模块为 LLM 漏洞扫描器提供数据流路径提示（而非完整的代码属性图 CPG）。
策略：
- 用 tree-sitter 解析 AST，按函数/方法作用域切分
- 在每个作用域内识别 user-controlled source 与危险 sink
- 同作用域内的 (source, sink) 两两配对生成 TaintPath，作为 LLM 上下文提示

局限性（轻量静态分析，非定论）：
- 不做过程间 / 路径敏感分析，不做别名与污点传播
- 仅做"同函数内 source 与 sink 共现"的启发式匹配
- 字符串字面量内的偶然匹配可能产生少量误报（已通过跳过 string 节点 + 仅匹配调用头部缓解）

支持语言：python / javascript / js / typescript / ts / java / php。
其他语言或不传 language → 返回空列表（不报错）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_java as tsjava
import tree_sitter_php as tsphp
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser


# ---------------------------------------------------------------------------
# tree-sitter 语言对象注册表（与 code_slicer.py 保持一致，tree-sitter 0.25+ API）
# ---------------------------------------------------------------------------
_TS_LANGUAGE_OBJECTS = {
    "python": Language(tspython.language()),
    "javascript": Language(tsjs.language()),
    "java": Language(tsjava.language()),
    "php": Language(tsphp.language_php()),
    "typescript": Language(tsts.language_typescript()),
}

_LANGUAGE_MAP = {
    "python": "python", "py": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "java": "java",
    "php": "php",
}

# 函数/方法定义节点 type（与 code_slicer 一致）
_FUNCTION_NODE_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "function_expression", "arrow_function"},
    "java": {"method_declaration", "constructor_declaration"},
    "php": {"function_definition", "method_declaration", "creation_expression"},
}

_CLASS_NODE_TYPES = {"class_declaration", "class_definition"}

# 候选节点 type：调用 / 属性访问 / 下标
_CALL_NODE_TYPES = {
    "call", "call_expression", "method_invocation",
    "function_call_expression", "method_call_expression",
}
_MEMBER_NODE_TYPES = {
    "attribute", "member_expression", "field_access", "member_access_expression",
}
_SUBSCRIPT_NODE_TYPES = {
    "subscript", "subscript_expression", "array_access_expression", "index_access_expression",
}

# 调用参数列表节点的 type（用于截取被调用部分）
_ARGUMENT_LIST_TYPES = {"argument_list", "arguments"}

# 单个作用域内最多输出的路径数，防止病态爆炸
_MAX_PATHS_PER_SCOPE = 50


# ---------------------------------------------------------------------------
# Source 模式（按语言）—— 用户可控输入点
# ---------------------------------------------------------------------------
_SOURCE_PATTERNS: dict[str, list[str]] = {
    "python": [
        "request.args.get(", "request.form", "request.json", "request.data",
        "input(", "sys.argv", "os.environ",
    ],
    "javascript": [
        "req.query", "req.body", "req.params", "process.argv",
    ],
    "typescript": [
        "req.query", "req.body", "req.params", "process.argv",
    ],
    "java": [
        "request.getParameter", "request.getAttribute", "args[",
    ],
    "php": [],
}


# ---------------------------------------------------------------------------
# Sink 模式（危险函数/方法）—— (pattern, taint_type)
# ---------------------------------------------------------------------------
_SINK_DEFINITIONS: list[tuple[str, str]] = [
    # SQL 注入
    (".execute(", "SQL Injection"),
    (".exec(", "SQL Injection"),
    ("cursor.execute", "SQL Injection"),
    # 命令注入
    ("os.system(", "Command Injection"),
    ("subprocess.run(", "Command Injection"),
    ("subprocess.Popen(", "Command Injection"),
    # 代码注入
    ("exec(", "Code Injection"),
    ("eval(", "Code Injection"),
    # 路径穿越
    ("open(", "Path Traversal"),
    # 反序列化
    ("pickle.loads(", "Insecure Deserialization"),
    ("yaml.load(", "Insecure Deserialization"),
    # XSS
    ("innerHTML", "XSS"),
    ("document.write(", "XSS"),
    # 模板注入
    ("render(", "Server-Side Template Injection"),
    ("render_template(", "Server-Side Template Injection"),
]

_SINK_TAINT_TYPE: dict[str, str] = {pat: ttype for pat, ttype in _SINK_DEFINITIONS}
_SINK_PATTERNS: list[str] = [pat for pat, _ in _SINK_DEFINITIONS]


def _core(pattern: str) -> str:
    """去掉 pattern 末尾的 '(' 或 '['，得到用于匹配的核心串。"""
    p = pattern
    while p and p[-1] in "([":
        p = p[:-1]
    return p


def _compile(patterns: list[str]) -> list[tuple[str, str, "re.Pattern[str]"]]:
    """编译模式列表，返回 (原 pattern, core, regex) 三元组，按 core 长度降序。"""
    out: list[tuple[str, str, "re.Pattern[str]"]] = []
    for p in patterns:
        c = _core(p)
        # 点开头的模式（如 ".execute("）不要求前置边界，点本身就是分隔
        if c.startswith("."):
            regex = re.compile(re.escape(c))
        else:
            regex = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(c))
        out.append((p, c, regex))
    out.sort(key=lambda x: -len(x[1]))
    return out


@dataclass
class TaintPath:
    """单条 source→sink 污点路径（同函数作用域内）。"""
    source: str
    sink: str
    taint_type: str
    source_line: int  # 1-indexed
    sink_line: int    # 1-indexed


class TaintTracker:
    """轻量级污点追踪器。

    用 tree-sitter 解析 AST，在每个函数作用域内识别 source 与 sink，
    两两配对生成 TaintPath，作为 LLM 漏洞扫描的数据流提示。
    """

    def __init__(self) -> None:
        self._source_cache: dict[str, list[tuple[str, str, "re.Pattern[str]"]]] = {}
        self._sink_compiled: list[tuple[str, str, "re.Pattern[str]"]] = _compile(_SINK_PATTERNS)

    def _sources_for(self, ts_lang: str) -> list[tuple[str, str, "re.Pattern[str]"]]:
        if ts_lang not in self._source_cache:
            self._source_cache[ts_lang] = _compile(_SOURCE_PATTERNS.get(ts_lang, []))
        return self._source_cache[ts_lang]

    # ------------------------------------------------------------------
    # 公共 API
    # ------------------------------------------------------------------
    def trace(self, code: str, language: str = "python", filename: str = "") -> list[TaintPath]:
        """分析代码，返回同函数作用域内的 source→sink 污点路径列表。

        Args:
            code: 源代码文本
            language: 项目内语言标签（python/js/ts/java/php 等）
            filename: 文件名（仅用于上下文，不参与分析）

        Returns:
            TaintPath 列表；解析失败或不支持的语言返回空列表
        """
        ts_lang = _LANGUAGE_MAP.get((language or "").lower())
        if not ts_lang or not code:
            return []

        try:
            parser = Parser(_TS_LANGUAGE_OBJECTS[ts_lang])
            tree = parser.parse(code.encode("utf-8"))
        except Exception:
            return []

        source_compiled = self._sources_for(ts_lang)
        root = tree.root_node

        # 收集函数作用域（顶层函数 + 类方法，不深入嵌套函数）
        scopes: list[tuple[Node, str]] = self._collect_function_scopes(root, ts_lang)
        if not scopes:
            # 无函数定义 → 把整个文件作为一个作用域
            scopes = [(root, "<module>")]

        paths: list[TaintPath] = []
        for func_node, qualname in scopes:
            paths.extend(self._analyze_scope(func_node, code, source_compiled, ts_lang))
        return paths

    # ------------------------------------------------------------------
    # 作用域收集
    # ------------------------------------------------------------------
    def _collect_function_scopes(self, root: Node, ts_lang: str) -> list[tuple[Node, str]]:
        """递归收集顶层函数 + 类方法节点（不深入函数体内部的嵌套函数）。

        嵌套函数不单独成作用域，其内部代码归入外层函数扫描，避免重复配对。
        """
        func_types = _FUNCTION_NODE_TYPES.get(ts_lang, set())
        class_types = _CLASS_NODE_TYPES
        result: list[tuple[Node, str]] = []

        def walk(node: Node, class_name: Optional[str] = None) -> None:
            for child in node.children:
                if child.type in class_types:
                    cls_name = self._node_name(child) or "AnonymousClass"
                    walk(child, cls_name)
                elif child.type in func_types:
                    fn_name = self._node_name(child) or "anonymous"
                    qual = f"{class_name}.{fn_name}" if class_name else fn_name
                    result.append((child, qual))
                    # 不深入函数体
                else:
                    walk(child, class_name)

        walk(root)
        return result

    def _node_name(self, node: Node) -> Optional[str]:
        """从函数/类定义节点提取名字（第一个 identifier 子节点）。"""
        for child in node.children:
            if child.type in ("identifier", "property_identifier", "type_identifier"):
                return child.text.decode("utf-8")
        return None

    # ------------------------------------------------------------------
    # 作用域分析
    # ------------------------------------------------------------------
    def _analyze_scope(
        self,
        func_node: Node,
        code: str,
        source_compiled: list[tuple[str, str, "re.Pattern[str]"]],
        ts_lang: str,
    ) -> list[TaintPath]:
        """分析单个函数作用域，返回其中的 source→sink 路径。"""
        code_bytes = code.encode("utf-8")
        sources: dict[tuple[int, str], None] = {}
        sinks: dict[tuple[int, str], None] = {}

        # Python web 上下文：路由装饰器的函数参数视为 source
        if ts_lang == "python":
            for src_line, label in self._web_params(func_node):
                sources[(src_line, label)] = None

        for desc in self._iter_descendants(func_node):
            if desc.type not in _CALL_NODE_TYPES and desc.type not in _MEMBER_NODE_TYPES \
                    and desc.type not in _SUBSCRIPT_NODE_TYPES:
                continue
            head = self._head_text(desc, code_bytes)
            if not head:
                continue
            line = desc.start_point[0] + 1
            src = self._match(head, source_compiled)
            if src:
                sources[(line, src)] = None
            snk = self._match(head, self._sink_compiled)
            if snk:
                sinks[(line, snk)] = None

        # 同作用域内 source × sink 两两配对
        paths: list[TaintPath] = []
        for (s_line, s_label) in sources:
            for (k_line, k_label) in sinks:
                paths.append(TaintPath(
                    source=s_label,
                    sink=k_label,
                    taint_type=_SINK_TAINT_TYPE.get(k_label, "Unknown"),
                    source_line=s_line,
                    sink_line=k_line,
                ))
                if len(paths) >= _MAX_PATHS_PER_SCOPE:
                    return paths
        return paths

    def _iter_descendants(self, node: Node):
        """遍历所有后代节点，跳过字符串/注释节点（避免字面量误匹配）。"""
        for child in node.children:
            t = child.type
            if "string" in t or "comment" in t:
                continue
            yield child
            yield from self._iter_descendants(child)

    def _head_text(self, node: Node, code_bytes: bytes) -> str:
        """提取候选节点的"头部文本"用于模式匹配。

        - 调用节点 → 被调用部分（参数列表之前的文本，正确处理嵌套调用）
        - 下标节点 → 对象部分（第一个 '[' 之前）
        - 属性/成员节点 → 完整文本
        """
        if node.type in _CALL_NODE_TYPES:
            for c in node.children:
                if c.type in _ARGUMENT_LIST_TYPES:
                    return code_bytes[node.start_byte:c.start_byte].decode("utf-8", errors="replace").strip()
            return code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()

        text = code_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        if node.type in _SUBSCRIPT_NODE_TYPES:
            idx = text.find("[")
            if idx != -1:
                return text[:idx].rstrip()
        return text

    def _match(
        self,
        text: str,
        compiled: list[tuple[str, str, "re.Pattern[str]"]],
    ) -> Optional[str]:
        """在 text 中查找匹配的模式，返回 core 最长的原 pattern（无匹配返回 None）。"""
        for pat, _c, regex in compiled:  # 已按 core 长度降序
            if regex.search(text):
                return pat
        return None

    # ------------------------------------------------------------------
    # Python web 上下文：路由装饰器函数的参数视为 source
    # ------------------------------------------------------------------
    def _web_params(self, func_node: Node) -> list[tuple[int, str]]:
        """若 Python 函数被路由装饰器（Flask/FastAPI 风格）装饰，把其参数视为 source。

        判定装饰器：文本含 "route" 或形如 @xxx.(get|post|put|delete|patch|route)( 。
        返回 [(函数起始行, "param:<name>"), ...]，排除 self/cls。
        """
        decorators = self._get_decorators(func_node)
        if not decorators:
            return []
        is_web = False
        for dec_text in decorators:
            low = dec_text.lower()
            if "route" in low:
                is_web = True
                break
            if re.search(r"@\s*[\w.]+\s*\.\s*(get|post|put|delete|patch|route)\s*\(", dec_text):
                is_web = True
                break
        if not is_web:
            return []

        params = self._function_param_names(func_node)
        if not params:
            return []
        start_line = func_node.start_point[0] + 1
        return [(start_line, f"param:{name}") for name in params if name not in ("self", "cls")]

    def _get_decorators(self, func_node: Node) -> list[str]:
        """获取函数的装饰器文本。

        兼容两种情况：函数节点自身含 decorator 子节点，或被 decorated_definition 包裹。
        """
        decs: list[Node] = [c for c in func_node.children if c.type == "decorator"]
        parent = func_node.parent
        if parent is not None and parent.type == "decorated_definition":
            for c in parent.children:
                if c.type == "decorator":
                    decs.append(c)
        out: list[str] = []
        for d in decs:
            try:
                out.append(d.text.decode("utf-8", errors="replace"))
            except Exception:
                continue
        return out

    def _function_param_names(self, func_node: Node) -> list[str]:
        """从函数定义节点提取参数名（仅形参名，不含默认值表达式中的标识符）。"""
        params_node: Optional[Node] = None
        for c in func_node.children:
            if c.type in ("parameters", "parameter_list", "formal_parameters"):
                params_node = c
                break
        if params_node is None:
            return []
        names: list[str] = []
        for c in params_node.children:
            if c.type == "identifier":
                names.append(c.text.decode("utf-8", errors="replace"))
            elif c.type in (
                "typed_parameter", "default_parameter", "typed_default_parameter",
                "list_splat_pattern", "dictionary_splat_pattern",
                "required_parameter", "rest_pattern",
            ):
                # 取第一个 identifier 子节点作为参数名
                for cc in c.children:
                    if cc.type == "identifier":
                        names.append(cc.text.decode("utf-8", errors="replace"))
                        break
        return names


# ---------------------------------------------------------------------------
# 模块级便捷函数
# ---------------------------------------------------------------------------
_DEFAULT_TRACKER = TaintTracker()


def trace_taint(code: str, language: str = "python", filename: str = "") -> list[TaintPath]:
    """便捷函数：用默认 TaintTracker 追踪污点路径。"""
    return _DEFAULT_TRACKER.trace(code, language=language, filename=filename)


if __name__ == "__main__":
    # 自检：含 SQL 注入、命令注入、SSTI 的 Python / JS / Java 示例
    sample_python = """\
import os
import subprocess
import pickle
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.form.get("password")
    query = "SELECT * FROM users WHERE name='" + username + "'"
    cursor.execute(query)
    os.system("echo " + username)
    return render_template("result.html", name=username)

def dangerous(data):
    obj = pickle.loads(data)
    f = open(data, "r")
    return obj

def safe_lookup(key):
    items = {"a": 1}
    return items.get(key)
"""
    sample_js = """\
app.get("/search", function(req, res) {
    var q = req.query.q;
    db.execute(q);
    document.write("<div>" + q + "</div>");
    eval(q);
});
"""
    sample_java = """\
public class Vuln {
    public void handle(HttpServletRequest request) {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE name='" + name + "'");
        Runtime.getRuntime().exec("echo " + name);
    }
}
"""
    tracker = TaintTracker()

    for lang, name, src in [
        ("python", "sample.py", sample_python),
        ("javascript", "sample.js", sample_js),
        ("java", "Vuln.java", sample_java),
    ]:
        results = tracker.trace(src, language=lang, filename=name)
        print(f"\n=== {name} ({lang})：检出 {len(results)} 条污点路径 ===")
        for i, p in enumerate(results, 1):
            print(f"  [{i}] L{p.source_line} {p.source}  ->  L{p.sink_line} {p.sink}  ({p.taint_type})")



