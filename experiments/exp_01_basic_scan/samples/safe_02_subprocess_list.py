# 样本: 安全对照 - Python 安全命令执行
# 期望: 不应报告漏洞（使用参数列表，不使用 shell）
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # 安全：使用参数列表传参，shell=False，且校验输入
    if not host.replace(".", "").replace("-", "").isalnum():
        return "invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        timeout=5,
    )
    return result.stdout.decode()
