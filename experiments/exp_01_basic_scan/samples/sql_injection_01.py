from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return "login success"
    return "login failed", 401
