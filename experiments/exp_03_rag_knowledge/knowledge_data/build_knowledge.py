"""
构建漏洞知识库
将 OWASP/CWE 等知识导入 Chroma，供 RAG 检索使用
"""

import sys
import os

# 添加 src 到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from chroma_manager import ChromaManager


def build_vulnerability_knowledge():
    """构建漏洞知识库"""
    
    cm = ChromaManager()
    
    # 漏洞知识数据（后续可以从文件读取）
    documents = [
        # SQL 注入
        "SQL注入（CWE-89）：攻击者通过在输入中注入恶意SQL语句，操纵数据库查询。典型场景包括：字符串拼接SQL、动态查询构造、未参数化的用户输入。修复方案：使用参数化查询（Prepared Statements），如 Python 的 sqlite3.execute('SELECT * FROM users WHERE id = ?', (user_id,))。",
        
        # XSS
        "跨站脚本攻击 XSS（CWE-79）：攻击者在网页中注入恶意脚本，当其他用户浏览时执行。分为存储型、反射型、DOM型。典型场景：直接输出用户输入到HTML、未转义的动态内容。修复方案：对所有用户输入进行HTML转义（如使用 html.escape()），实施内容安全策略（CSP）。",
        
        # 命令注入
        "命令注入（CWE-78）：攻击者通过操纵程序执行的系统命令，在目标系统上执行任意命令。典型场景：使用 os.system()、subprocess.call() 拼接用户输入、eval() 执行动态代码。修复方案：避免直接拼接命令，使用参数列表传递（subprocess.run(['ls', filename])），或使用沙箱环境。",
        
        # 路径遍历
        "路径遍历（CWE-22）：攻击者通过构造包含 ../ 等序列的文件路径，访问受限目录之外的文件。典型场景：直接使用用户输入作为文件路径、未验证路径合法性。修复方案：使用 os.path.abspath() 规范化路径，检查路径是否在允许目录内，使用白名单机制。",
        
        # 硬编码密钥
        "硬编码凭证（CWE-798）：将密码、API密钥、令牌等敏感信息直接写入源代码。风险：代码泄露即凭证泄露，难以轮换。修复方案：使用环境变量（os.environ）、密钥管理服务（KMS）、.env 文件（不提交到版本控制）。",
        
        # 不安全的反序列化
        "不安全的反序列化（CWE-502）：反序列化不可信数据时，攻击者可构造恶意对象执行任意代码。典型场景：Python pickle.loads()、Java ObjectInputStream.readObject() 处理用户输入。修复方案：避免反序列化不可信数据，使用 JSON 等安全格式，实施签名验证。",
        
        # 敏感数据泄露
        "敏感数据泄露（CWE-200）：系统无意中向未授权用户暴露敏感信息。典型场景：错误信息包含堆栈跟踪、日志记录敏感字段、API 返回完整对象。修复方案：自定义错误页面、日志脱敏、API 响应字段白名单。",
        
        # CSRF
        "跨站请求伪造 CSRF（CWE-352）：攻击者诱导已认证用户执行非预期操作。典型场景：无状态表单提交、无验证的敏感操作。修复方案：使用 CSRF Token、SameSite Cookie 属性、验证 Referer 头。",
        
        # 不安全的直接对象引用
        "不安全的直接对象引用（CWE-639）：通过修改参数值直接访问其他用户的数据。典型场景：/api/user/123 中的 123 可被修改为其他用户ID。修复方案：实施访问控制检查、使用间接引用映射（如 UUID）。",
        
        # 安全配置错误
        "安全配置错误（CWE-16）：系统、框架或应用的安全配置不当。典型场景：默认密码未修改、不必要的功能未关闭、错误的安全头配置。修复方案：使用安全配置基线、定期审计配置、自动化配置检查。"
    ]
    
    ids = [
        "sqli_knowledge",
        "xss_knowledge", 
        "cmdi_knowledge",
        "pathtraversal_knowledge",
        "hardcoded_knowledge",
        "deserialization_knowledge",
        "sensitivedata_knowledge",
        "csrf_knowledge",
        "idor_knowledge",
        "misconfig_knowledge"
    ]
    
    metadatas = [
        {"type": "SQL注入", "cwe": "CWE-89", "category": "注入类"},
        {"type": "XSS", "cwe": "CWE-79", "category": "注入类"},
        {"type": "命令注入", "cwe": "CWE-78", "category": "注入类"},
        {"type": "路径遍历", "cwe": "CWE-22", "category": "访问控制"},
        {"type": "硬编码凭证", "cwe": "CWE-798", "category": "敏感数据"},
        {"type": "不安全的反序列化", "cwe": "CWE-502", "category": "反序列化"},
        {"type": "敏感数据泄露", "cwe": "CWE-200", "category": "敏感数据"},
        {"type": "CSRF", "cwe": "CWE-352", "category": "会话管理"},
        {"type": "不安全的直接对象引用", "cwe": "CWE-639", "category": "访问控制"},
        {"type": "安全配置错误", "cwe": "CWE-16", "category": "配置管理"}
    ]
    
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