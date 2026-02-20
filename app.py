from flask import Flask, request, Response, jsonify
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

PROXY_SECRET = os.environ.get("PROXY_SECRET", "dev-secret")


def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.hostname in ("localhost", "127.0.0.1"):
            return False
        return True
    except Exception:
        return False


@app.route("/api/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    # 🔐 basic protection
    if request.headers.get("x-proxy-secret") != PROXY_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "Missing url"}), 400

    if not is_safe_url(target_url):
        return jsonify({"error": "Unsafe url"}), 400

    try:
        # Forward headers safely
        forward_headers = {}
        for k, v in request.headers.items():
            if k.lower() not in ["host", "x-proxy-secret", "content-length"]:
                forward_headers[k] = v

        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=request.get_data(),
            params={k: v for k, v in request.args.items() if k != "url"},
            timeout=25,
        )

        excluded = ["content-encoding", "content-length", "transfer-encoding", "connection"]
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

        return Response(resp.content, resp.status_code, headers)

    except requests.exceptions.Timeout:
        return jsonify({"error": "Upstream timeout"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def home():
    return {"status": "proxy running"}
