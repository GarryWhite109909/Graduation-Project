# 样本: 安全对照 - Python 参数化查询
# 期望: 不应报告漏洞（使用参数化查询）
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 安全：使用占位符参数化查询
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    if user:
        return "login success"
    return "login failed", 401
