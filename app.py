"""
Q-CORE SYSTEMS: Web Q-SCANNER + CRA Dashboard (Multilingual)
Flask application for qcore.systems
"""

import os
import json
import time
import threading
import tempfile
from datetime import datetime, timezone
from dataclasses import asdict
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory

from q_scanner import QScanner, ScanResult
from q_cra_engine import map_scan_to_cra, CRAReportPDF, detect_language

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "qcore-dev-key-change-in-prod")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "ZakladatelJB.186cm_100kg.")
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "15"))

# Simple in-memory rate limiter (per IP, max 5 scans per minute)
_rate_limit: dict[str, list[float]] = {}
_rate_lock = threading.Lock()

RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60  # seconds


def _check_rate_limit(ip: str) -> bool:
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


def _is_admin(req) -> bool:
    key = req.args.get("key", "") or req.headers.get("X-Admin-Key", "")
    return key == ADMIN_KEY


def _clean_domain(raw: str) -> str:
    domain = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def _result_to_dict(result: ScanResult) -> dict:
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


@app.after_request
def add_security_headers(response):
    """Q-CORE SYSTEMS — minimal headers, scanner friendly."""
    response.headers['X-PQC-Shield'] = 'Q-CORE/hybrid-ready'
    response.headers['X-Powered-By'] = 'Q-CORE SYSTEMS'
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/cra-dashboard")
def cra_dashboard():
    admin = _is_admin(request)
    return render_template("cra_dashboard.html", is_admin=admin)


@app.route("/academy")
def academy():
    return render_template("academy.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
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

    if not all(c.isalnum() or c in ".-" for c in domain):
        return jsonify({"error": "Invalid domain name — only letters, numbers, dots and hyphens are allowed."}), 400

    if "." not in domain:
        return jsonify({"error": "Please enter a full domain (e.g. example.com)."}), 400

    try:
        scanner = QScanner()
        result = scanner.scan(
            hostname=domain, port=443, timeout=SCAN_TIMEOUT,
            check_protocols=True, check_headers=True,
        )
        return jsonify(_result_to_dict(result))
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@app.route("/api/cra-report", methods=["POST"])
def api_cra_report():
    """Generate CRA PDF. Admin only. Supports lang parameter."""
    admin_key = request.headers.get("X-Admin-Key", "")
    if admin_key != ADMIN_KEY:
        return jsonify({"error": "CRA report generation requires Pro subscription. Contact info@qcore.systems"}), 403

    body = request.get_json(silent=True) or {}
    if not body or "hostname" not in body:
        return jsonify({"error": "No scan data provided."}), 400

    # Language: from request header, or auto-detect from domain TLD
    lang = request.headers.get("X-Report-Lang", "").lower()
    if lang not in ("en", "cs", "de"):
        lang = detect_language(body.get("hostname", ""))

    try:
        cra_results = map_scan_to_cra(body, lang=lang)
        pdf_gen = CRAReportPDF(lang=lang)
        tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, prefix="cra_report_")
        pdf_gen.generate(body, cra_results, tmp.name)

        return send_file(
            tmp.name, mimetype="application/pdf", as_attachment=True,
            download_name=f"CRA_Report_{body.get('hostname', 'unknown')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        )
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500


@app.route("/api/cra-map", methods=["POST"])
def api_cra_map():
    """Return CRA mapping JSON. Available to all. Supports lang parameter."""
    body = request.get_json(silent=True) or {}
    if not body:
        return jsonify({"error": "No scan data provided."}), 400

    lang = request.headers.get("X-Report-Lang", "").lower()
    if lang not in ("en", "cs", "de"):
        lang = detect_language(body.get("hostname", ""))

    try:
        cra_results = map_scan_to_cra(body, lang=lang)
        return jsonify({"cra_results": cra_results, "language": lang})
    except Exception as e:
        return jsonify({"error": f"CRA mapping failed: {str(e)}"}), 500



@app.route("/api/font-debug")
def font_debug():
    """Debug endpoint to check font loading on Railway."""
    import os as _os
    from q_cra_engine import _UNICODE_FONT, _UNICODE_FONT_BOLD, t
    
    fonts_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "fonts")
    bundled = _os.listdir(fonts_dir) if _os.path.exists(fonts_dir) else []
    
    cs_test = t("key_exchange_security", "cs")
    info = {
        "font": _UNICODE_FONT,
        "font_bold": _UNICODE_FONT_BOLD,
        "fonts_dir_exists": _os.path.exists(fonts_dir),
        "bundled_fonts": bundled,
        "system_dejavu": _os.path.exists("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        "czech_test_str": cs_test,
        "czech_hex": cs_test.encode("utf-8").hex(),
        "has_real_chars": all(c in cs_test for c in "čěůíý"),
    }
    return jsonify(info)



@app.route("/api/font-test-pdf")
def font_test_pdf():
    """Generate a test PDF to verify Czech characters on Railway."""
    import tempfile
    from reportlab.pdfbase import pdfmetrics as _pm
    from reportlab.pdfbase.ttfonts import TTFont as _TT
    from reportlab.pdfbase.pdfmetrics import registerFontFamily as _rff
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle as _PS
    from reportlab.platypus import SimpleDocTemplate as _SD, Paragraph as _P, Spacer as _Sp, Table as _T, TableStyle as _TS
    from reportlab.lib.colors import HexColor
    import os as _os

    # Register bundled font fresh
    fdir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "fonts")
    try:
        _pm.registerFont(_TT("TestDV", _os.path.join(fdir, "DejaVuSans.ttf")))
        _pm.registerFont(_TT("TestDV-B", _os.path.join(fdir, "DejaVuSans-Bold.ttf")))
        _pm.registerFont(_TT("TestDV-I", _os.path.join(fdir, "DejaVuSans-Oblique.ttf")))
        _pm.registerFont(_TT("TestDV-BI", _os.path.join(fdir, "DejaVuSans-BoldOblique.ttf")))
        _rff("TestDV", normal="TestDV", bold="TestDV-B", italic="TestDV-I", boldItalic="TestDV-BI")
        font_name = "TestDV"
        font_bold = "TestDV-B"
    except Exception as e:
        return jsonify({"error": f"Font registration failed: {e}"}), 500

    sn = _PS("N", fontName=font_name, fontSize=10, leading=14)
    sb = _PS("B", fontName=font_bold, fontSize=10, leading=14)
    sh = _PS("H", fontName=font_bold, fontSize=8, textColor=HexColor("#FFFFFF"))
    sc = _PS("C", fontName=font_name, fontSize=8)

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    doc = _SD(tmp.name, pagesize=A4)
    el = []

    el.append(_P("Test: Czech Characters in PDF on Railway", sb))
    el.append(_Sp(1, 20))
    el.append(_P("Plain Paragraph tests:", sb))
    el.append(_P("Bezpečnost výměny klíčů", sn))
    el.append(_P("Připravenost na post-kvantovou kryptografii", sn))
    el.append(_P("Zpráva o shodě s CRA", sn))
    el.append(_P("ZPRÁVA O SHODĚ S CRA", sb))
    el.append(_P("Článek Doporučení Šifrování Náprava", sn))
    el.append(_P("Čas skenu Přidat hlavičku Žádné", sn))
    el.append(_P("Bezpečné výchozí nastavení", sn))
    el.append(_P("Správa zranitelností", sn))
    el.append(_Sp(1, 20))

    el.append(_P("Bold tag test:", sb))
    el.append(_P("<b>Bezpečnost</b> výměny <b>klíčů</b>", sn))
    el.append(_P("<b>Připravenost</b> na post-kvantovou <i>kryptografii</i>", sn))
    el.append(_Sp(1, 20))

    el.append(_P("Table with Paragraph cells:", sb))
    data = [
        [_P("Článek CRA", sh), _P("Kontrola", sh), _P("Kategorie", sh)],
        [_P("Art.10(1)", sc), _P("Bezpečnost výměny klíčů", sc), _P("Bezpečnost produktu", sc)],
        [_P("Art.10(5)", sc), _P("Připravenost na PQC", sc), _P("Ochrana dat", sc)],
        [_P("Art.10(4)", sc), _P("HTTP bezpečnostní hlavičky", sc), _P("Bezpečné výchozí nastavení", sc)],
        [_P("Art.10(6)", sc), _P("HSTS — vnucení zabezpečeného transportu", sc), _P("Plocha útoku", sc)],
        [_P("Art.10(6)", sc), _P("Podpora zastaralých protokolů", sc), _P("Plocha útoku", sc)],
    ]
    t = _T(data, colWidths=[60, 200, 140])
    t.setStyle(_TS([
        ("BACKGROUND", (0,0), (-1,0), HexColor("#0A1628")),
        ("GRID", (0,0), (-1,-1), 0.4, HexColor("#B0BEC5")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
    ]))
    el.append(t)

    doc.build(el)
    return send_file(tmp.name, mimetype="application/pdf", as_attachment=True,
                     download_name="czech_font_test_railway.pdf")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)