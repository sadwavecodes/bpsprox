from flask import Flask, request, Response, jsonify
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# 🔐 REQUIRED: set this in Render env vars
PROXY_SECRET = os.getenv("PROXY_SECRET", "changeme")

# 🔒 Optional safety: block localhost & private networks
BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0"
}


def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.hostname in BLOCKED_HOSTS:
            return False
        return True
    except:
        return False


@app.route("/api/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy():
    # 🔐 secret check (prevents public abuse)
    client_secret = request.headers.get("x-proxy-secret")
    if client_secret != PROXY_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "Missing url"}), 400

    if not is_safe_url(target_url):
        return jsonify({"error": "Unsafe url"}), 400

    try:
        # Forward almost all headers
        headers = {
            key: value
            for key, value in request.headers
            if key.lower() not in ["host", "x-proxy-secret", "content-length"]
        }

        # Forward request based on method
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            params={k: v for k, v in request.args.items() if k != "url"},
            timeout=20,
        )

        # Clean response headers
        excluded = ["content-encoding", "content-length", "transfer-encoding"]
        response_headers = [
            (k, v) for k, v in resp.headers.items()
            if k.lower() not in excluded
        ]

        return Response(resp.content, resp.status_code, response_headers)

    except requests.exceptions.Timeout:
        return jsonify({"error": "Upstream timeout"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def health():
    return {"status": "universal proxy alive"}
