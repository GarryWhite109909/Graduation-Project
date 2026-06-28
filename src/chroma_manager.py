"""
Chroma 向量数据库管理器
封装增删改查操作，供 RAG 知识库使用
"""

import os
import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional


class ChromaManager:
    def __init__(self, persist_dir: str = None):
        """
        初始化 Chroma 客户端
        
        Args:
            persist_dir: 持久化目录，默认使用项目 data/chroma_db
        """
        if persist_dir is None:
            # 自动定位到项目根目录下的 data/chroma_db
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            persist_dir = os.path.join(base_dir, "data", "chroma_db")
        
        self.persist_dir = persist_dir
        self.client = chromadb.PersistentClient(path=persist_dir)
        
        # 使用 sentence-transformers 的本地 embedding 模型
        # 模型会自动下载到本地缓存，无需联网
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"  # 轻量级，384维，适合本地运行
        )
        
        print(f"[ChromaManager] 数据库路径: {persist_dir}")
        print(f"[ChromaManager] Embedding 模型: all-MiniLM-L6-v2")
    
    def create_collection(self, name: str, description: str = "") -> chromadb.Collection:
        """创建集合（如果不存在则获取）"""
        try:
            collection = self.client.get_collection(name=name)
            print(f"[ChromaManager] 获取已有集合: {name}")
        except Exception:
            collection = self.client.create_collection(
                name=name,
                metadata={"description": description},
                embedding_function=self.embedding_fn
            )
            print(f"[ChromaManager] 创建新集合: {name}")
        return collection
    
    def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        ids: List[str],
        metadatas: Optional[List[Dict]] = None
    ):
        """向集合中添加文档"""
        collection = self.create_collection(collection_name)
        collection.add(
            documents=documents,
            ids=ids,
            metadatas=metadatas
        )
        print(f"[ChromaManager] 添加 {len(documents)} 条文档到 {collection_name}")
    
    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
        filter_dict: Optional[Dict] = None
    ) -> Dict:
        """
        查询相似文档
        
        Returns:
            {
                "documents": [...],
                "ids": [...],
                "distances": [...],
                "metadatas": [...]
            }
        """
        collection = self.client.get_collection(
            name=collection_name,
            embedding_function=self.embedding_fn
        )
        
        kwargs = {
            "query_texts": [query_text],
            "n_results": n_results
        }
        if filter_dict:
            kwargs["where"] = filter_dict
            
        results = collection.query(**kwargs)
        
        return {
            "documents": results["documents"][0],
            "ids": results["ids"][0],
            "distances": results["distances"][0],
            "metadatas": results["metadatas"][0] if results.get("metadatas") else []
        }
    
    def list_collections(self) -> List[str]:
        """列出所有集合"""
        return [c.name for c in self.client.list_collections()]
    
    def delete_collection(self, name: str):
        """删除集合"""
        self.client.delete_collection(name=name)
        print(f"[ChromaManager] 删除集合: {name}")
    
    def count(self, collection_name: str) -> int:
        """获取集合中文档数量"""
        collection = self.client.get_collection(
            name=collection_name,
            embedding_function=self.embedding_fn
        )
        return collection.count()


if __name__ == "__main__":
    # 简单测试
    cm = ChromaManager()
    
    # 创建测试集合
    cm.create_collection("test", "测试集合")
    
    # 添加文档
    cm.add_documents(
        collection_name="test",
        documents=[
            "SQL注入发生在用户输入直接拼接到SQL语句中",
            "XSS攻击通过在网页注入恶意脚本窃取用户数据",
            "命令注入是用户输入被当作系统命令执行"
        ],
        ids=["sqli_001", "xss_001", "cmdi_001"],
        metadatas=[
            {"type": "SQL注入", "language": "通用"},
            {"type": "XSS", "language": "通用"},
            {"type": "命令注入", "language": "通用"}
        ]
    )
    
    # 查询
    results = cm.query("test", "用户输入导致数据库被攻击", n_results=2)
    print("\n查询结果:")
    for i, (doc, dist, meta) in enumerate(zip(
        results["documents"], 
        results["distances"],
        results["metadatas"]
    )):
        print(f"{i+1}. [{meta.get('type', '未知')}] {doc}")
        print(f"   相似度距离: {dist:.4f}")
    
    # 查看集合列表
    print(f"\n所有集合: {cm.list_collections()}")