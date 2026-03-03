from flask import Flask
import socket
import time
from urllib.parse import urlparse

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update", "free",
    "secure", "bank", "ebay", "paypal", "password",
    "signin", "confirm", "reset", "http://127.0.0.1:5000"
]

@app.route("/")
def home():
    return "Flask running on Vercel 🚀"

@app.route("/scan", methods=["POST"])
def scan():
    url = request.json.get("url", "").strip()

    if not url:
        return jsonify({"error": "TARGET URL REQUIRED"}), 400

    logs = []
    logs.append("[*] Initializing modules...")
    time.sleep(0.8)

    logs.append("[*] Analyzing target URL...")
    time.sleep(0.8)

    logs.append("[*] Resolving DNS records...")
    time.sleep(0.8)

    try:
        domain = urlparse(url).netloc
        if "@" in domain:
            domain = domain.split("@")[-1]
        ip = socket.gethostbyname(domain)
        logs.append(f"[+] IP Address → {ip}")
    except Exception as e:
        logs.append(f"[-] IP Resolution Failed → {e}")

    found = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]

    logs.append("")
    if found:
        logs.append("[!] ⚠ WARNING: SUSPICIOUS URL DETECTED")
    else:
        logs.append("[✓] URL STATUS → SAFE")

    return jsonify({"logs": logs})




