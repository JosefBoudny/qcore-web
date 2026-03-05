"""
Q-CORE SYSTEMS: Web Q-SCANNER
Flask application for qcore.systems
"""

import os
import json
import time
import threading
from datetime import datetime, timezone
from dataclasses import asdict
from flask import Flask, render_template, request, jsonify

from q_scanner import QScanner, ScanResult

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "qcore-dev-key-change-in-prod")
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "15"))

# Simple in-memory rate limiter (per IP, max 5 scans per minute)
_rate_limit: dict[str, list[float]] = {}
_rate_lock = threading.Lock()

RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is allowed."""
    now = time.time()
    with _rate_lock:
        timestamps = _rate_limit.get(ip, [])
        timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(timestamps) >= RATE_LIMIT_MAX:
            _rate_limit[ip] = timestamps
            return False
        timestamps.append(now)
        _rate_limit[ip] = timestamps
        return True


def _clean_domain(raw: str) -> str:
    """Normalize user input to a bare hostname."""
    domain = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def _result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult dataclass to a JSON-serializable dict."""
    data = {
        "hostname": result.hostname,
        "ip_address": result.ip_address,
        "port": result.port,
        "scan_timestamp": result.scan_timestamp,
        "tls_version": result.tls_version,
        "cipher": asdict(result.active_cipher),
        "certificate": asdict(result.certificate),
        "chain_length": result.chain_length,
        "chain_issues": result.chain_issues,
        "supported_protocols": result.supported_protocols,
        "quantum_risks": result.quantum_risks,
        "overall_pqc_status": result.overall_pqc_status,
        "overall_risk_score": result.overall_risk_score,
        "recommendations": result.recommendations,
        "errors": result.errors,
    }
    if result.http_headers:
        data["http_headers"] = asdict(result.http_headers)
    else:
        data["http_headers"] = None
    return data


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Run a scan and return JSON results."""
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(ip):
        return jsonify({"error": "Rate limit exceeded. Please wait a minute and try again."}), 429

    body = request.get_json(silent=True) or {}
    raw_domain = body.get("domain", "").strip()

    if not raw_domain:
        return jsonify({"error": "Please enter a domain name."}), 400

    domain = _clean_domain(raw_domain)

    if not domain or len(domain) > 253:
        return jsonify({"error": "Invalid domain name."}), 400

    # Basic validation
    if not all(c.isalnum() or c in ".-" for c in domain):
        return jsonify({"error": "Invalid domain name — only letters, numbers, dots and hyphens are allowed."}), 400

    if "." not in domain:
        return jsonify({"error": "Please enter a full domain (e.g. example.com)."}), 400

    try:
        scanner = QScanner()
        result = scanner.scan(
            hostname=domain,
            port=443,
            timeout=SCAN_TIMEOUT,
            check_protocols=True,
            check_headers=True,
        )
        return jsonify(_result_to_dict(result))
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
