"""
构建漏洞知识库
将 OWASP/CWE 等知识导入 Chroma，供 RAG 检索使用

知识条目存放在同目录 knowledge.json，扩充时直接编辑该文件即可，
无需改动本脚本。
"""

import json
from pathlib import Path

from src.chroma_manager import ChromaManager

KNOWLEDGE_FILE = Path(__file__).parent / "knowledge.json"


def build_vulnerability_knowledge():
    """构建漏洞知识库"""
    cm = ChromaManager()

    # 从 knowledge.json 加载知识条目
    entries = json.loads(KNOWLEDGE_FILE.read_text(encoding="utf-8"))
    documents = [e["document"] for e in entries]
    ids = [e["id"] for e in entries]
    metadatas = [e["metadata"] for e in entries]

    # 添加到知识库
    cm.add_documents(
        collection_name="vulnerability_knowledge",
        documents=documents,
        ids=ids,
        metadatas=metadatas
    )

    print(f"\n[build_knowledge] 知识库构建完成，共 {len(documents)} 条知识")
    print(f"[build_knowledge] 集合: vulnerability_knowledge")
    print(f"[build_knowledge] 文档数: {cm.count('vulnerability_knowledge')}")


if __name__ == "__main__":
    build_vulnerability_knowledge()
