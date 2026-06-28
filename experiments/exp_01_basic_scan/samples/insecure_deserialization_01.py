# 样本: 不安全的反序列化 - Python pickle
# 期望: 检测到不安全的反序列化（pickle.loads 处理用户可控数据）
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/session/restore")
def restore_session():
    token = request.args.get("token", "")
    # 漏洞：直接反序列化用户提供的 pickle 数据
    raw = base64.b64decode(token)
    session_data = pickle.loads(raw)
    return str(session_data)
