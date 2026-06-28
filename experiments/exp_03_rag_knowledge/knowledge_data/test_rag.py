"""
测试 RAG 增强的漏洞检测
对比：纯 LLM vs RAG + LLM
"""

from src.chroma_manager import ChromaManager
from src.llm_client import OllamaClient


def test_rag_vs_pure_llm():
    """对比 RAG 增强 vs 纯 LLM 的检测效果"""
    
    # 待测代码（一个稍微复杂的例子，需要上下文理解）
    test_code = '''
import os
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/load', methods=['POST'])
def load_data():
    # 从请求中获取序列化数据
    serialized = request.form.get('data')
    
    # 直接反序列化用户输入
    obj = pickle.loads(serialized.encode())
    
    # 使用反序列化后的对象
    filename = obj.get('file')
    
    # 直接拼接路径
    full_path = "/app/data/" + filename
    
    # 读取文件
    with open(full_path, 'r') as f:
        content = f.read()
    
    return {"content": content}

if __name__ == '__main__':
    app.run(debug=True)
'''
    
    print("=" * 60)
    print("待测代码：")
    print(test_code)
    print("=" * 60)
    
    # 初始化
    cm = ChromaManager()
    client = OllamaClient(model="gemma4:26b")
    
    if not client.check_connection():
        print("[错误] Ollama 未启动，请先运行 ollama serve")
        return
    
    # ========== 测试 1：纯 LLM（无 RAG）==========
    print("\n" + "=" * 60)
    print("【测试 1】纯 LLM 分析（无 RAG 增强）")
    print("=" * 60)
    
    result_pure = client.analyze_vulnerability(test_code, "python")
    if result_pure["text"].startswith("错误:"):
        print(f"[错误] 纯 LLM 分析失败: {result_pure['text']}")
        return
    print(f"耗时: {result_pure['duration']:.2f}s")
    print(f"结果:\n{result_pure['text']}")
    
    # ========== 测试 2：RAG + LLM ==========
    print("\n" + "=" * 60)
    print("【测试 2】RAG 增强分析")
    print("=" * 60)
    
    # 检索相关知识
    query_text = "pickle反序列化用户输入导致的安全漏洞"
    rag_results = cm.query("vulnerability_knowledge", query_text, n_results=3)
    
    # 构建 RAG 上下文
    rag_context = "\n\n".join([
        f"【知识 {i+1}】{doc}"
        for i, doc in enumerate(rag_results["documents"])
    ])
    
    print(f"检索到的相关知识（Top-3）:")
    for i, (doc, dist, meta) in enumerate(zip(
        rag_results["documents"],
        rag_results["distances"],
        rag_results["metadatas"]
    )):
        print(f"  {i+1}. [{meta.get('type', '未知')}] 相似度: {dist:.4f}")
    
    # RAG 增强分析
    result_rag = client.analyze_vulnerability(
        code=test_code,
        language="python",
        rag_context=rag_context
    )

    if result_rag["text"].startswith("错误:"):
        print(f"\n[错误] RAG 增强分析失败: {result_rag['text']}")
        return

    print(f"\n耗时: {result_rag['duration']:.2f}s")
    print(f"结果:\n{result_rag['text']}")
    
    # ========== 对比总结 ==========
    print("\n" + "=" * 60)
    print("【对比总结】")
    print("=" * 60)
    print(f"纯 LLM 耗时: {result_pure['duration']:.2f}s")
    print(f"RAG+LLM 耗时: {result_rag['duration']:.2f}s")
    print(f"\n纯 LLM 输出长度: {len(result_pure['text'])} 字符")
    print(f"RAG+LLM 输出长度: {len(result_rag['text'])} 字符")


if __name__ == "__main__":
    # 先确保知识库已构建
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from build_knowledge import build_vulnerability_knowledge
    build_vulnerability_knowledge()
    
    # 运行对比测试
    test_rag_vs_pure_llm()