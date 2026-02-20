from flask import Flask, request, Response, jsonify
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# 🔒 Only allow specific APIs
ALLOWED_DOMAINS = {
    "api.twitch.tv",
    "www.googleapis.com",
    "youtube.googleapis.com"
}

# Optional secret to prevent abuse
PROXY_SECRET = os.getenv("PROXY_SECRET", "changeme")


def is_allowed(url):
    try:
        domain = urlparse(url).netloc
        return domain in ALLOWED_DOMAINS
    except:
        return False


@app.route("/api/proxy", methods=["GET", "POST"])
def proxy():
    # 🔐 optional auth
    client_secret = request.headers.get("x-proxy-secret")
    if client_secret != PROXY_SECRET:
        return jsonify({"error": "Unauthorized"}), 401

    target_url = request.args.get("url")
    if not target_url:
        return jsonify({"error": "Missing url"}), 400

    if not is_allowed(target_url):
        return jsonify({"error": "Domain not allowed"}), 403

    try:
        # Forward headers (important for Twitch)
        headers = {
            key: value
            for key, value in request.headers
            if key.lower() not in ["host", "x-proxy-secret"]
        }

        if request.method == "POST":
            resp = requests.post(
                target_url,
                headers=headers,
                json=request.get_json(silent=True),
                timeout=15,
            )
        else:
            resp = requests.get(
                target_url,
                headers=headers,
                params=request.args,
                timeout=15,
            )

        excluded = ["content-encoding", "content-length", "transfer-encoding"]
        response_headers = [
            (k, v) for k, v in resp.headers.items()
            if k.lower() not in excluded
        ]

        return Response(resp.content, resp.status_code, response_headers)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def health():
    return {"status": "proxy alive"}
