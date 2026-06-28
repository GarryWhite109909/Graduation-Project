# 样本: 路径穿越 - Python Flask 读取文件
# 期望: 检测到路径穿越（用户输入拼接到文件路径，未过滤 ../）
import os
from flask import Flask, request, abort

app = Flask(__name__)

BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # 漏洞：直接拼接用户输入，未限制 ../
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.isfile(filepath):
        abort(404)
    with open(filepath, "rb") as f:
        return f.read()
