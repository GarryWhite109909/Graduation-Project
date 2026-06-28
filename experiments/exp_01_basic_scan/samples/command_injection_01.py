# 样本: 命令注入 - Python subprocess shell=True
# 期望: 检测到命令注入（用户输入拼接到 shell 命令中且 shell=True）
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # 漏洞：shell=True 且直接拼接用户输入
    result = subprocess.Popen(
        "ping -c 1 " + host,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = result.communicate()
    return out.decode()
