import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/session/restore")
def restore_session():
    token = request.args.get("token", "")
    raw = base64.b64decode(token)
    session_data = pickle.loads(raw)
    return str(session_data)
