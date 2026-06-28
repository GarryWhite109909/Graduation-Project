"""
Ollama LLM 客户端
封装本地模型调用，支持 RAG 增强的漏洞检测
"""

import re
import sys
import requests
import json
import time
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# 统一输出 schema —— 全项目所有实验脚本必须使用此 schema 解析模型结论
# ---------------------------------------------------------------------------
VERDICT_SCHEMA = {
    "has_vulnerability": "bool, true 表示存在漏洞",
    "vulnerability_type": "str, CWE 编号 + 中文名；无漏洞填 'none'",
    "risk_level": "str, Critical/High/Medium/Low；无漏洞填 'None'",
    "source": "str, 污染来源（用户可控输入点）；无漏洞填 'N/A'",
    "sink": "str, 危险函数或触发点；无漏洞填 'N/A'",
    "explanation": "str, 漏洞或安全现状说明",
    "fix_suggestion": "str, 修复建议；无漏洞填 'no fix needed'",
}


def parse_verdict(raw_output: str) -> dict:
    """从模型输出中抽取最后的 JSON 结论（统一 schema）。

    优先匹配 ```json ... ``` 代码块；兜底匹配含 has_vulnerability 字段的 JSON 片段。
    解析失败返回空 dict。
    """
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", raw_output, re.DOTALL)
    candidates = blocks if blocks else re.findall(
        r"\{[^{}]*\"has_vulnerability\"[^{}]*\}", raw_output, re.DOTALL
    )
    for cand in candidates[-1:] if candidates else []:
        try:
            parsed = json.loads(cand)
            if "has_vulnerability" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    # 兜底：尝试找最后一个完整的 { ... } 片段
    for match in re.finditer(r"\{[^{}]*\}", raw_output, re.DOTALL):
        try:
            parsed = json.loads(match.group(0))
            if "has_vulnerability" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue
    return {}


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "gemma4:26b"):
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
    
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048,
        keep_alive: str = "0",
        timeout: int = 300,
    ) -> Dict:
        """
        生成文本

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度（越低越确定）
            max_tokens: 最大生成长度；None 表示不设上限（用 Ollama 默认）
            keep_alive: 模型保留时间，"0" 表示用完卸载，"-1" 表示常驻
            timeout: 请求超时秒数

        Returns:
            {"text": str, "duration": float, "tokens": dict, "meta": dict, "error": str|None}
            error 为 None 表示成功；非 None 时 text 为空字符串。
        """
        options = {"temperature": temperature}
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": options,
            "keep_alive": keep_alive,
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
        rag_context: Optional[str] = None
    ) -> Dict:
        """
        分析代码漏洞（RAG 增强版）

        Args:
            code: 待分析代码
            language: 代码语言
            rag_context: RAG 检索到的相关知识（可选）

        Returns:
            generate() 的返回值，text 字段为模型输出（含 JSON 结论块）。
            统一输出 schema 见 VERDICT_SCHEMA。
        """
        system_prompt = (
            "你是代码安全审计专家。请先给出分析过程，然后在回答末尾严格输出一个 "
            "```json``` 包裹的 JSON 对象作为最终结论，字段如下：\n"
            "- has_vulnerability: 布尔值，true 表示存在漏洞，false 表示未发现漏洞\n"
            "- vulnerability_type: 字符串，漏洞类型（优先用 CWE 编号 + 中文名）；"
            "若未发现漏洞，填 \"none\"\n"
            "- risk_level: 字符串，风险等级 Critical/High/Medium/Low；"
            "若未发现漏洞，填 \"None\"\n"
            "- source: 字符串，污染来源（用户可控输入点）；若未发现漏洞，填 \"N/A\"\n"
            "- sink: 字符串，危险函数或触发点；若未发现漏洞，填 \"N/A\"\n"
            "- explanation: 字符串，对漏洞或安全现状的简短说明\n"
            "- fix_suggestion: 字符串，修复建议；若未发现漏洞，填 \"no fix needed\"\n"
        )

        # 构建 Prompt
        prompt_parts = [
            f"请分析以下 {language} 代码的安全漏洞：\n",
            "```" + language + "\n" + code + "\n```\n"
        ]

        if rag_context:
            prompt_parts.append(
                f"\n【相关知识参考】\n{rag_context}\n"
                f"请结合以上知识，更准确地分析代码漏洞。\n"
            )

        prompt_parts.append("请先给出分析过程，然后在最后给出 JSON 结论。")

        prompt = "\n".join(prompt_parts)

        return self.generate(prompt, system_prompt=system_prompt)


if __name__ == "__main__":
    client = OllamaClient(model="gemma4:26b")
    
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
