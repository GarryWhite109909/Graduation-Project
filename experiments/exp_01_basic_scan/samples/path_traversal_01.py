import os
from flask import Flask, request, abort

app = Flask(__name__)

BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    filepath = os.path.join(BASE_DIR, filename)
    if not os.path.isfile(filepath):
        abort(404)
    with open(filepath, "rb") as f:
        return f.read()
