"""
扫描编排服务 —— 复用 graduation_project 核心包，统一调度
LLM 推理 + 代码切片 + RAG 检索 + 传统规则预筛。

关键设计：
- SFT v5 用 SYSTEM_PROMPT_LITE 训练，推理也必须用 LITE（训练/推理一致）
- OllamaClient.analyze_vulnerability 硬编码了完整版 SYSTEM_PROMPT，
  本服务绕过它，直接调 client.generate 传入 LITE 版
- RAG 可开关（Web 端默认开，插件端默认关）
- 预筛层（prefilter）可开关：开启后对明显漏洞/安全样本直接短路，跳过 LLM
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from graduation_project.llm_client import OllamaClient
from graduation_project.prompts import SYSTEM_PROMPT, SYSTEM_PROMPT_LITE, BASE_PROMPT, build_user_prompt
from graduation_project.schema import parse_verdict, normalize_has_vulnerability
from graduation_project.code_slicer import CodeSlicer, SliceResult
from graduation_project.prefilter import Prefilter, PrefilterResult
from app.backend.services.model_registry import get_default_model, get_prompt_for_model

# 默认模型：从环境变量读取，缺省为注册表中的默认模型（当前 v9max）
DEFAULT_MODEL = os.environ.get("VULN_SCANNER_MODEL", get_default_model())
# 回退模型：官方 Qwen3-8B（未微调，用户首次未 pull 自定义模型时可用）
FALLBACK_MODEL = os.environ.get("VULN_SCANNER_FALLBACK_MODEL", "qwen3:8b")
# Chroma 知识库集合名
KNOWLEDGE_COLLECTION = "vuln_knowledge"


@dataclass
class SingleResult:
    """单段代码扫描结果。"""
    filename: str
    language: str
    has_vulnerability: Optional[bool]
    vulnerability_type: str = "none"
    risk_level: str = "None"
    source: str = "N/A"
    sink: str = "N/A"
    explanation: str = ""
    fix_suggestion: str = "no fix needed"
    raw_output: str = ""  # 模型原始输出（含 CoT 分析过程）
    duration: float = 0.0
    error: Optional[str] = None
    sliced: bool = False
    chunk_count: int = 1
    prefilter_verdict: Optional[bool] = None  # 预筛层判定（None=未预筛/交LLM）
    prefilter_rules: list[str] = field(default_factory=list)  # 预筛命中规则

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "language": self.language,
            "has_vulnerability": self.has_vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "risk_level": self.risk_level,
            "source": self.source,
            "sink": self.sink,
            "explanation": self.explanation,
            "fix_suggestion": self.fix_suggestion,
            "raw_output": self.raw_output,
            "duration": round(self.duration, 2),
            "error": self.error,
            "sliced": self.sliced,
            "chunk_count": self.chunk_count,
            "prefilter_verdict": self.prefilter_verdict,
            "prefilter_rules": self.prefilter_rules,
        }


@dataclass
class BatchResult:
    """批量扫描汇总结果。"""
    total_files: int = 0
    scanned: int = 0
    vulnerable: int = 0
    safe: int = 0
    errors: int = 0
    results: list[SingleResult] = field(default_factory=list)
    total_duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_files": self.total_files,
            "scanned": self.scanned,
            "vulnerable": self.vulnerable,
            "safe": self.safe,
            "errors": self.errors,
            "results": [r.to_dict() for r in self.results],
            "total_duration": round(self.total_duration, 2),
        }


class Scanner:
    """漏洞扫描编排器。

    Args:
        model: Ollama 模型名（默认注册表中的默认模型，当前 v9max）
        base_url: Ollama 服务地址
        use_rag: 是否启用 RAG 知识库增强
        use_lite_prompt: 已废弃（保留参数兼容旧调用），prompt 现由 model_registry 自动选择
        use_prefilter: 是否启用传统规则预筛层（True 时对明显样本短路跳过 LLM）
        use_structured_fallback: 是否在 CoT+JSON 解析失败时用 Ollama format=json 约束解码兜底
        use_taint_tracking: 是否启用轻量污点分析（source→sink 路径注入 LLM 上下文）
        keep_alive: 模型卸载策略（0=用完即卸，-1=常驻）
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = "http://localhost:11434",
        use_rag: bool = False,
        use_lite_prompt: bool = True,
        use_prefilter: bool = False,
        use_structured_fallback: bool = True,
        use_taint_tracking: bool = False,
        keep_alive=0,
    ):
        self.client = OllamaClient(base_url=base_url, model=model)
        self.model = model
        self.use_rag = use_rag
        self.use_prefilter = use_prefilter
        self.use_structured_fallback = use_structured_fallback
        self.use_taint_tracking = use_taint_tracking
        self.keep_alive = keep_alive
        # 从环境变量读取硬件适配配置（bootstrap.py 设置）
        self._num_ctx = int(os.environ.get("VULN_SCANNER_NUM_CTX", "8192"))
        self._num_gpu = int(os.environ.get("VULN_SCANNER_NUM_GPU", "-1"))
        self._num_thread = int(os.environ.get("VULN_SCANNER_NUM_THREAD", "0"))
        # system prompt 由 model_registry 自动选择（v9max→BASE_PROMPT, v5→LITE）
        self.system_prompt = get_prompt_for_model(model)
        self.slicer = CodeSlicer(min_lines=150)
        self.prefilter = Prefilter() if use_prefilter else None
        self._taint_tracker = None
        self._chroma = None  # 延迟初始化（首次用 RAG 时才连 Chroma）

    def switch_model(self, model: str) -> None:
        """运行时切换活动模型。队列中的待执行任务也会用新模型。

        根据模型注册表自动选择对应的 system prompt：
        - v9max → BASE_PROMPT（训练/推理一致）
        - v5    → SYSTEM_PROMPT_LITE（训练/推理一致）
        """
        self.model = model
        self.client.model = model
        self.system_prompt = get_prompt_for_model(model)

    @property
    def chroma(self):
        """延迟加载 ChromaManager，避免未安装 chromadb 时报错。"""
        if self._chroma is None and self.use_rag:
            try:
                from graduation_project.chroma_manager import ChromaManager
                self._chroma = ChromaManager()
            except Exception as e:
                print(f"[Scanner] RAG 初始化失败，回退纯 LLM: {e}")
                self.use_rag = False
        return self._chroma

    @property
    def taint_tracker(self):
        """延迟加载 TaintTracker，避免未安装依赖时报错。"""
        if self._taint_tracker is None and self.use_taint_tracking:
            try:
                from graduation_project.taint_tracker import TaintTracker
                self._taint_tracker = TaintTracker()
            except Exception as e:
                print(f"[Scanner] 污点分析初始化失败，跳过: {e}")
                self.use_taint_tracking = False
        return self._taint_tracker

    def check_health(self) -> dict:
        """健康检查：Ollama 连接 + 模型可用性 + 各层开关状态。"""
        connected = self.client.check_connection()
        models = self.client.list_models() if connected else []
        model_available = self.model in models
        return {
            "ollama_connected": connected,
            "model": self.model,
            "model_available": model_available,
            "available_models": models,
            "rag_enabled": self.use_rag,
            "prefilter_enabled": self.use_prefilter,
            "structured_fallback_enabled": self.use_structured_fallback,
            "taint_tracking_enabled": self.use_taint_tracking,
        }

    def _retrieve_rag_context(self, code: str) -> Optional[str]:
        """从知识库检索相关漏洞知识。"""
        if not self.use_rag or not self.chroma:
            return None
        try:
            results = self.chroma.query(
                collection_name=KNOWLEDGE_COLLECTION,
                query_text=code[:2000],  # 限制查询长度
                n_results=3,
            )
            docs = results.get("documents", [])
            if not docs:
                return None
            return "\n---\n".join(docs)
        except Exception as e:
            print(f"[Scanner] RAG 检索失败: {e}")
            return None

    def _retrieve_taint_context(self, code: str, filename: str) -> Optional[str]:
        """轻量污点分析：提取 source→sink 数据流路径，作为 LLM 上下文。

        与 RAG 上下文互补：RAG 提供领域知识，污点分析提供代码内真实调用链。
        """
        if not self.use_taint_tracking or not self.taint_tracker:
            return None
        try:
            paths = self.taint_tracker.trace(code, filename=filename)
            if not paths:
                return None
            lines = ["[污点分析] 检测到以下 source→sink 数据流路径："]
            for p in paths:
                lines.append(f"  {p.source} → {p.sink} ({p.taint_type})")
            return "\n".join(lines)
        except Exception as e:
            print(f"[Scanner] 污点分析失败: {e}")
            return None

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "",
        use_rag: Optional[bool] = None,
    ) -> SingleResult:
        """扫描单段代码。

        长文件（>150 行）自动切片，逐 chunk 分析，
        若任一 chunk 发现漏洞则整文件判漏洞。

        Args:
            code: 代码文本
            language: 代码语言
            filename: 文件名（给模型作上下文）
            use_rag: 是否启用 RAG（None 表示用 Scanner 默认值）
        """
        if not code or not code.strip():
            return SingleResult(
                filename=filename, language=language,
                has_vulnerability=None, error="empty code",
            )

        rag_enabled = self.use_rag if use_rag is None else use_rag
        rag_context = self._retrieve_rag_context(code) if rag_enabled else None

        # 污点分析：提取 source→sink 数据流路径，作为 LLM 上下文
        taint_context = self._retrieve_taint_context(code, filename) if self.use_taint_tracking else None

        # 预筛层：对明显漏洞/安全样本直接短路，跳过 LLM 调用
        prefilter_result: Optional[PrefilterResult] = None
        if self.prefilter:
            prefilter_result = self.prefilter.scan(code, language)
            if prefilter_result.preliminary_verdict is not None:
                # 预筛给出高置信判定，直接返回，不调 LLM
                has_vuln = prefilter_result.preliminary_verdict
                if has_vuln:
                    vuln_type = prefilter_result.matched_rules[0] if prefilter_result.matched_rules else "detected"
                    return SingleResult(
                        filename=filename, language=language,
                        has_vulnerability=True,
                        vulnerability_type=vuln_type,
                        risk_level="High",
                        explanation=f"预筛层检测到明显漏洞特征：{', '.join(prefilter_result.matched_rules)}",
                        fix_suggestion="请参考 LLM 详细分析或相关 CWE 修复指南",
                        duration=0.0,
                        prefilter_verdict=True,
                        prefilter_rules=prefilter_result.matched_rules,
                    )
                else:
                    return SingleResult(
                        filename=filename, language=language,
                        has_vulnerability=False,
                        vulnerability_type="none",
                        risk_level="None",
                        explanation=f"预筛层检测到安全模式：{', '.join(prefilter_result.matched_rules)}",
                        prefilter_verdict=False,
                        prefilter_rules=prefilter_result.matched_rules,
                    )

        # 切片
        slice_result: SliceResult = self.slicer.slice(
            code, language=language, filename=filename,
        )

        # 逐 chunk 分析
        chunk_results: list[SingleResult] = []
        for chunk in slice_result.chunks:
            r = self._analyze_chunk(
                chunk.code, language, filename, rag_context,
                chunk_name=chunk.name,
                taint_context=taint_context,
            )
            r.sliced = slice_result.sliced
            r.chunk_count = slice_result.chunk_count
            chunk_results.append(r)

        # 合并：任一 chunk 有漏洞 → 整文件有漏洞；任一 chunk 报错且无漏洞 → 整文件报错
        if len(chunk_results) == 1:
            return chunk_results[0]

        # 多 chunk：取风险最高的；但若有 error 且无漏洞，整文件判 error（避免部分失败被误判为安全）
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        merged = chunk_results[0]
        merged.filename = filename
        for cr in chunk_results[1:]:
            cr_risk = risk_order.get((cr.risk_level or "none").lower(), 0)
            merged_risk = risk_order.get((merged.risk_level or "none").lower(), 0)
            if cr.has_vulnerability and (
                not merged.has_vulnerability or cr_risk > merged_risk
            ):
                merged = cr
                merged.filename = filename

        # 合并后修正：若整体无漏洞但存在报错 chunk，标记为 error（None）而非安全（False）
        if not merged.has_vulnerability:
            has_error_chunk = any(
                cr.has_vulnerability is None or cr.error
                for cr in chunk_results
            )
            if has_error_chunk:
                err_msgs = [
                    (cr.error or cr.chunk_name or "unknown")
                    for cr in chunk_results
                    if (cr.has_vulnerability is None or cr.error)
                ]
                merged.has_vulnerability = None
                merged.error = "部分 chunk 分析失败: " + "; ".join(err_msgs)
        return merged

    def _analyze_chunk(
        self,
        code: str,
        language: str,
        filename: str,
        rag_context: Optional[str],
        chunk_name: str = "",
        taint_context: Optional[str] = None,
    ) -> SingleResult:
        """分析单个代码 chunk。

        流程：
        1. 第一轮：正常 CoT + JSON 输出（保留分析过程）
        2. 若 parse 失败且 use_structured_fallback=True：
           用 Ollama format=json 约束解码重试，数学上保证输出可解析
        3. 污点分析上下文（如有）与 RAG 上下文一并注入 prompt
        """
        display_name = f"{filename}::{chunk_name}" if chunk_name else filename
        # 合并 RAG + 污点上下文
        combined_context = None
        if rag_context and taint_context:
            combined_context = rag_context + "\n\n" + taint_context
        elif rag_context:
            combined_context = rag_context
        elif taint_context:
            combined_context = taint_context

        prompt = build_user_prompt(
            code=code, language=language,
            filename=display_name, rag_context=combined_context,
        )

        start = time.time()
        result = self.client.generate(
            prompt=prompt,
            system_prompt=self.system_prompt,
            keep_alive=self.keep_alive,
            num_ctx=self._num_ctx,
            num_gpu=self._num_gpu,
            num_thread=self._num_thread,
        )
        duration = time.time() - start

        if result["error"]:
            return SingleResult(
                filename=filename, language=language,
                has_vulnerability=None, error=result["error"],
                duration=duration,
            )

        verdict = parse_verdict(result["text"])
        has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))

        # 约束解码兜底：CoT+JSON 解析失败时，用 Ollama format=json 重试
        if has_vuln is None and self.use_structured_fallback:
            structured_result = self.client.generate_structured(
                prompt=prompt,
                system_prompt=self.system_prompt,
                keep_alive=self.keep_alive,
                num_ctx=self._num_ctx,
                num_gpu=self._num_gpu,
                num_thread=self._num_thread,
            )
            if not structured_result["error"]:
                verdict = parse_verdict(structured_result["text"])
                has_vuln = normalize_has_vulnerability(verdict.get("has_vulnerability"))
                if has_vuln is not None:
                    # 约束解码成功，用结构化输出替换
                    result = structured_result
                    duration += structured_result["duration"]

        return SingleResult(
            filename=filename,
            language=language,
            has_vulnerability=has_vuln,
            vulnerability_type=verdict.get("vulnerability_type", "none"),
            risk_level=verdict.get("risk_level", "None"),
            source=verdict.get("source", "N/A"),
            sink=verdict.get("sink", "N/A"),
            explanation=verdict.get("explanation", ""),
            fix_suggestion=verdict.get("fix_suggestion", "no fix needed"),
            raw_output=result["text"],
            duration=duration,
        )

    def unload(self):
        """卸载模型释放显存。"""
        self.client.unload_model()
