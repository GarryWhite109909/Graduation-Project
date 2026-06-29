import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        return "invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        timeout=5,
    )
    return result.stdout.decode()
