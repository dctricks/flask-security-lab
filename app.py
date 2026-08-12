from flask import Flask, request, jsonify
import subprocess
import ipaddress
import re


app = Flask(__name__)


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()

    if not host:
        return jsonify({"error": "Missing host"}), 400

    if len(host) > 253:
        return jsonify({"error": "Host is too long"}), 400

    try:
        ipaddress.ip_address(host)
        valid_host = True
    except ValueError:
        valid_host = False

    hostname_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    if not valid_host and not hostname_pattern.fullmatch(host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10
        )

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 504

    return jsonify({
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )
