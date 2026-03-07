"""
Q-CORE SYSTEMS: Web App Hub
Flask application for qcore.systems
Integrated with Q-SCANNER, CRA Dashboard, and Q-Academy
"""

import os
import json
import time
import threading
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify

# Importy tvojich modulov (uisti sa, že sú v rovnakej zložke)
from q_scanner import QScanner

app = Flask(__name__)

# --- Konfigurácia ---
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "qcore-enterprise-secret-2026")
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "15"))
MAX_CONCURRENT_SCANS = 3

# Jednoduchý rate limiter (max 5 skenov za minútu na IP)
_rate_limit = {}
_rate_lock = threading.Lock()

def _check_rate_limit(ip):
    now = time.time()
    with _rate_lock:
        timestamps = _rate_limit.get(ip, [])
        timestamps = [t for t in timestamps if now - t < 60]
        if len(timestamps) >= 5:
            return False
        timestamps.append(now)
        _rate_limit[ip] = timestamps
        return True

# --- Zobrazenie stránok (Frontend Routes) ---

@app.route("/")
def index():
    """Hlavná stránka so skenerom."""
    return render_template("index.html")

@app.route("/cra-dashboard")
def cra_dashboard():
    """Nový modul pre audit podľa EU Cyber Resilience Act."""
    return render_template("cra_dashboard.html")

@app.route("/academy")
def academy():
    """Vzdelávacia platforma pre firmy (SMEs)."""
    return render_template("academy.html")

# --- API Koncové body ---

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Logika pre online skenovanie domény."""
    if not _check_rate_limit(request.remote_addr):
        return jsonify({"error": "Príliš veľa požiadaviek. Skúste to o minútu."}), 429

    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()

    if not domain or "." not in domain:
        return jsonify({"error": "Zadajte platnú doménu (napr. firma.cz)."}), 400

    try:
        scanner = QScanner()
        # Vykonanie neintruzívneho auditu
        result = scanner.scan(
            hostname=domain,
            port=443,
            timeout=SCAN_TIMEOUT,
            check_protocols=True,
            check_headers=True
        )
        
        # Prevod výsledku na slovník pre frontend
        return jsonify({
            "hostname": result.hostname,
            "tls_version": result.tls_version,
            "cipher": result.active_cipher.name,
            "key_type": result.certificate.key_type,
            "overall_pqc_status": result.overall_pqc_status,
            "recommendations": result.recommendations
        })
    except Exception as e:
        return jsonify({"error": f"Audit zlyhal: {str(e)}"}), 500

@app.route("/api/health")
def health():
    return jsonify({"status": "active", "version": "2.1.0-enterprise"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)