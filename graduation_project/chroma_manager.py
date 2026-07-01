"""
Chroma 向量数据库管理器
封装增删改查操作，供 RAG 知识库使用
"""

import os
import glob
import chromadb
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional


# 默认 embedding 模型（sentence-transformers 格式）
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"


def _set_offline_mode() -> None:
    """强制 sentence-transformers / transformers 离线，避免运行时访问 HuggingFace。

    这是防御性设置：即使代码其它路径触发模型加载，也不会因为网络问题挂掉。
    """
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


def _find_cached_sentence_transformer(model_name: str) -> Optional[str]:
    """在 HuggingFace 本地缓存中查找 sentence-transformers 模型的 snapshot 目录。

    支持通过 HF_HOME 环境变量自定义缓存根目录，默认 ~/.cache/huggingface。
    返回可直接传给 SentenceTransformer(model_name=...) 的本地路径；未找到返回 None。
    """
    hf_home = os.environ.get("HF_HOME", os.path.expanduser("~/.cache/huggingface"))
    hub_dir = os.path.join(hf_home, "hub")
    if not os.path.isdir(hub_dir):
        return None

    # HF 缓存目录命名规则：models--<org>--<model>/snapshots/<commit>/
    repo_name = model_name.replace("/", "--")
    repo_dir = os.path.join(hub_dir, f"models--{repo_name}")
    if not os.path.isdir(repo_dir):
        return None

    snapshots = glob.glob(os.path.join(repo_dir, "snapshots", "*"))
    for snapshot_dir in snapshots:
        config_path = os.path.join(snapshot_dir, "config.json")
        if os.path.isfile(config_path):
            return snapshot_dir
    return None


def _resolve_embedding_model_path(model_name: str) -> str:
    """解析 embedding 模型路径，优先使用本地缓存，绝不在运行时联网下载。

    解析顺序：
    1. CHROMA_EMBEDDING_MODEL_PATH 环境变量（用户显式指定本地路径）
    2. HuggingFace 本地缓存 (~/.cache/huggingface/hub/...)
    3. 若都没有，抛出明确错误并告诉用户如何准备模型
    """
    explicit_path = os.environ.get("CHROMA_EMBEDDING_MODEL_PATH")
    if explicit_path:
        if not os.path.isdir(explicit_path):
            raise FileNotFoundError(
                f"[ChromaManager] 环境变量 CHROMA_EMBEDDING_MODEL_PATH 指向的目录不存在: {explicit_path}\n"
                f"请检查路径，或取消该环境变量以使用默认缓存。"
            )
        return explicit_path

    cached = _find_cached_sentence_transformer(model_name)
    if cached:
        return cached

    raise RuntimeError(
        f"[ChromaManager] 未找到本地 embedding 模型: {model_name}\n"
        f"ChromaManager 已强制离线模式（HF_HUB_OFFLINE=1），不会从 HuggingFace 下载。\n"
        f"请按以下方式之一准备模型:\n"
        f"  1. 在有网络的环境执行: python -c \"from sentence_transformers import SentenceTransformer; SentenceTransformer('{model_name}')\"\n"
        f"     模型将缓存到 ~/.cache/huggingface/hub/\n"
        f"  2. 手动下载模型文件夹后，设置环境变量: export CHROMA_EMBEDDING_MODEL_PATH=/path/to/local/model\n"
    )


class ChromaManager:
    def __init__(self, persist_dir: str = None):
        """
        初始化 Chroma 客户端

        Args:
            persist_dir: 持久化目录，默认使用项目 data/chroma_db
        """
        # 强制离线，避免 sentence-transformers 联网下载
        _set_offline_mode()

        if persist_dir is None:
            # 优先从环境变量读取，便于打包部署；否则回退到项目根目录下的 data/chroma_db
            persist_dir = os.environ.get("CHROMA_PERSIST_DIR")
            if not persist_dir:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                persist_dir = os.path.join(base_dir, "data", "chroma_db")

        self.persist_dir = persist_dir
        self.client = chromadb.PersistentClient(path=persist_dir)

        # 使用本地缓存的 sentence-transformers embedding 模型，运行时绝不联网
        self._model_path = _resolve_embedding_model_path(DEFAULT_EMBEDDING_MODEL)
        self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=self._model_path
        )

        print(f"[ChromaManager] 数据库路径: {persist_dir}")
        print(f"[ChromaManager] Embedding 模型: {DEFAULT_EMBEDDING_MODEL_NAME} (本地: {self._model_path})")
    
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
        """向集合中添加文档（id 已存在时会报错，如需覆盖请用 upsert_documents）"""
        collection = self.create_collection(collection_name)
        collection.add(
            documents=documents,
            ids=ids,
            metadatas=metadatas
        )
        print(f"[ChromaManager] 添加 {len(documents)} 条文档到 {collection_name}")

    def upsert_documents(
        self,
        collection_name: str,
        documents: List[str],
        ids: List[str],
        metadatas: Optional[List[Dict]] = None
    ):
        """向集合中写入文档（id 已存在则覆盖，支持幂等重复运行）。

        适合知识库构建脚本反复运行而不报错。
        """
        collection = self.create_collection(collection_name)
        collection.upsert(
            documents=documents,
            ids=ids,
            metadatas=metadatas
        )
        print(f"[ChromaManager] 写入/覆盖 {len(documents)} 条文档到 {collection_name}")
    
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