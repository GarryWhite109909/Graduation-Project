# 样本: SQL注入 - Python Flask 拼接字符串
# 期望: 检测到 SQL 注入（用户输入直接拼接到 SQL 语句中）
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 漏洞：直接拼接用户输入
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return "login success"
    return "login failed", 401
