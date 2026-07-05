"""
Ollama LLM 客户端
封装本地模型调用，支持 RAG 增强的漏洞检测
"""

import sys
import requests
import time
from typing import Dict, List, Optional

# schema 与 prompt 统一从 graduation_project.schema / graduation_project.prompts 导入（全项目唯一来源）。
# 此处 re-export 仅为向后兼容历史代码 `from graduation_project.llm_client import parse_verdict`。
from graduation_project.schema import VERDICT_SCHEMA, parse_verdict, normalize_has_vulnerability
from graduation_project.prompts import SYSTEM_PROMPT, build_user_prompt

__all__ = [
    "OllamaClient",
    "VERDICT_SCHEMA",
    "parse_verdict",
    "normalize_has_vulnerability",
]


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5-coder:7b"):
        self.base_url = base_url
        self.model = model
        self.api_generate = f"{base_url}/api/generate"
        self.api_chat = f"{base_url}/api/chat"
        
    def check_connection(self) -> bool:
        """检查 Ollama 服务是否运行"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
    
    def list_models(self) -> List[str]:
        """列出可用模型"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=10)
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            print(f"[OllamaClient] 获取模型列表失败: {e}")
            return []
    
    @staticmethod
    def _normalize_keep_alive(keep_alive) -> object:
        """规范化 keep_alive 参数。

        Ollama 0.x 旧版本接受字符串 "-1" / "0"；新版本（2024+）要求
        字符串必须带单位（如 "30m"），但整数 -1 / 0 仍可用。

        为兼容历史调用方（脚本中传字符串），此处把无单位的字符串 "-1" / "0"
        自动转为整数。带单位的字符串（如 "5m"）原样透传。
        """
        if isinstance(keep_alive, str):
            if keep_alive == "-1":
                return -1
            if keep_alive == "0":
                return 0
        return keep_alive

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048,
        keep_alive=0,
        timeout: int = 300,
        num_ctx: int = 16384,
        num_gpu: Optional[int] = None,
        num_thread: Optional[int] = None,
    ) -> Dict:
        """
        生成文本

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度（越低越确定）
            max_tokens: 最大生成长度；None 表示不设上限（用 Ollama 默认）
            keep_alive: 模型保留时间；0 表示用完卸载，-1 表示常驻，
                        也可传带单位的字符串如 "5m"（兼容旧版字符串 "-1"/"0"）
            timeout: 请求超时秒数
            num_ctx: 上下文窗口 token 数（默认 16384）。
                     Ollama 默认仅 4096，对长文件/RAG 场景不足，
                     exp_04 中 4 个难样本因 4096 截断导致输出为空。
                     gemma4:12b 原生支持 256K，16384 足够覆盖长文件+RAG。
            num_gpu: GPU offload 层数。None 表示 Ollama 自动判断（默认）；
                     0 表示纯 CPU；-1 表示全部 GPU；正数 N 表示前 N 层在 GPU，
                     其余在 CPU。大模型（20b+）在 16k 上下文时，显存可能不足以
                     放全部层，Ollama 自动混合模式下 GPU 利用率可能偏低，
                     可手动调整此参数优化 CPU+GPU 协同（配合高带宽 DDR5）。
            num_thread: CPU 推理线程数。None 表示 Ollama 默认（通常=物理核数）。
                        大模型 CPU offload 部分受 CPU 线程数影响，DDR5 高带宽
                        场景可适当增大以充分利用内存带宽。

        Returns:
            {"text": str, "duration": float, "tokens": dict, "meta": dict, "error": str|None}
            error 为 None 表示成功；非 None 时 text 为空字符串。
        """
        options = {"temperature": temperature, "num_ctx": num_ctx}
        if max_tokens is not None:
            options["num_predict"] = max_tokens
        if num_gpu is not None:
            options["num_gpu"] = num_gpu
        if num_thread is not None:
            options["num_thread"] = num_thread

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": options,
            "keep_alive": self._normalize_keep_alive(keep_alive),
        }

        if system_prompt:
            payload["system"] = system_prompt

        start_time = time.time()

        try:
            resp = requests.post(self.api_generate, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()

            duration = time.time() - start_time

            return {
                "text": data.get("response", ""),
                "duration": duration,
                "tokens": {
                    "prompt": data.get("prompt_eval_count", 0),
                    "completion": data.get("eval_count", 0),
                    "total": data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
                },
                "meta": {
                    "eval_count": data.get("eval_count"),
                    "eval_duration_ns": data.get("eval_duration"),
                    "load_duration_ns": data.get("load_duration"),
                    "total_duration_ns": data.get("total_duration"),
                    "prompt_eval_count": data.get("prompt_eval_count"),
                },
                "error": None,
            }
        except Exception as e:
            return {
                "text": "",
                "duration": time.time() - start_time,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "meta": {},
                "error": f"{type(e).__name__}: {e}",
            }

    def unload_model(self, timeout: int = 60) -> bool:
        """主动从显存卸载模型（keep_alive=0）。多模型场景下避免爆显存。

        返回 True 表示卸载请求成功发出。
        """
        payload = {"model": self.model, "keep_alive": 0}
        try:
            resp = requests.post(self.api_generate, json=payload, timeout=timeout)
            resp.raise_for_status()
            return True
        except Exception as e:
            print(f"[OllamaClient] 卸载模型失败: {e}", file=sys.stderr)
            return False
    
    def analyze_vulnerability(
        self,
        code: str,
        language: str = "python",
        rag_context: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Dict:
        """
        分析代码漏洞（RAG 增强版）

        Args:
            code: 待分析代码
            language: 代码语言
            rag_context: RAG 检索到的相关知识（可选）
            filename: 代码文件名（可选，提供给模型作为上下文）

        Returns:
            generate() 的返回值，text 字段为模型输出（含 JSON 结论块）。
            统一输出 schema 见 VERDICT_SCHEMA（定义在 graduation_project.schema）。
        """
        prompt = build_user_prompt(
            code=code,
            language=language,
            filename=filename,
            rag_context=rag_context,
        )
        return self.generate(prompt, system_prompt=SYSTEM_PROMPT)


if __name__ == "__main__":
    client = OllamaClient(model="qwen2.5-coder:7b")
    
    # 检查连接
    if not client.check_connection():
        print("[OllamaClient] 无法连接到 Ollama，请确保服务已启动")
        exit(1)
    
    print(f"[OllamaClient] 已连接，可用模型: {client.list_models()}")
    
    # 简单测试
    test_code = '''
import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()
'''
    
    result = client.analyze_vulnerability(test_code, "python")
    if result["error"]:
        print(f"\n[错误] {result['error']}")
    else:
        print(f"\n分析耗时: {result['duration']:.2f}s")
        print(f"Token 数: {result['tokens']}")
        print(f"\n分析结果:\n{result['text']}")
