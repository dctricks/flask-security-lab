from flask import Flask, request, jsonify
import subprocess
import ipaddress
import re


app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>Flask Security Lab</h1>
    <p>Secure command execution practice.</p>
    """


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()

    # Reject missing input
    if not host:
        return jsonify({"error": "Missing host"}), 400

    # Prevent excessively long input
    if len(host) > 253:
        return jsonify({"error": "Host is too long"}), 400

    # Check whether the input is an IP address
    try:
        ipaddress.ip_address(host)
        valid_host = True
    except ValueError:
        valid_host = False

    # Check normal DNS hostname syntax
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
