import bcrypt
from flask import Flask, request

app = Flask(__name__)


@app.route("/register_safe", methods=["POST"])
def register_safe():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    return f"User {username} registered"
