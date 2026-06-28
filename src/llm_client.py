"""
Ollama LLM 客户端
封装本地模型调用，支持 RAG 增强的漏洞检测
"""

import requests
import json
import time
from typing import Dict, List, Optional


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
        except:
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
        max_tokens: int = 2048,
        keep_alive: str = "0"
    ) -> Dict:
        """
        生成文本
        
        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度（越低越确定）
            max_tokens: 最大生成长度
            keep_alive: 模型保留时间，"0"表示用完卸载
            
        Returns:
            {"text": "生成的文本", "duration": 耗时秒数, "tokens": token数}
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            },
            "keep_alive": keep_alive
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        start_time = time.time()
        
        try:
            resp = requests.post(self.api_generate, json=payload, timeout=300)
            resp.raise_for_status()
            data = resp.json()
            
            duration = time.time() - start_time
            
            return {
                "text": data.get("response", ""),
                "duration": duration,
                "tokens": {
                    "prompt": data.get("prompt_eval_count", 0),
                    "completion": data.get("eval_count", 0),
                    "total": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                }
            }
        except Exception as e:
            return {
                "text": f"错误: {str(e)}",
                "duration": time.time() - start_time,
                "tokens": {"prompt": 0, "completion": 0, "total": 0}
            }
    
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
        """
        system_prompt = """你是代码安全审计专家。请严格按以下格式输出分析结果：

1. 漏洞判定：存在/不存在
2. 漏洞类型：CWE编号 + 中文名称
3. 风险等级：Critical / High / Medium / Low
4. 漏洞说明：简要描述漏洞原理
5. 触发路径：具体哪行代码、什么条件下触发
6. 修复建议：提供修复后的代码片段
7. 仅返回结构化内容，不要多余解释"""

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
        
        prompt_parts.append("请按指定格式输出分析结果。")
        
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
    print(f"\n分析耗时: {result['duration']:.2f}s")
    print(f"Token 数: {result['tokens']}")
    print(f"\n分析结果:\n{result['text']}")
