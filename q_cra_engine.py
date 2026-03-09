"""
Q-CRA Engine — CRA Report Generator for Web
=============================================
Q-CORE Systems | qcore.systems

Takes Q-SCANNER web output and generates CRA compliance PDF.
Used by Flask app, not standalone.
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)

VERSION = "2.1.0"
COMPANY = "Q-CORE Systems"
WEBSITE = "qcore.systems"

# Colors
C_PRIMARY = HexColor("#0A1628")
C_ACCENT = HexColor("#00E5FF")
C_SUCCESS = HexColor("#00C853")
C_WARNING = HexColor("#FFB300")
C_DANGER = HexColor("#FF3B5C")
C_NEUTRAL = HexColor("#B0BEC5")
C_BG = HexColor("#F0F4F8")
C_TEXT = HexColor("#1A1A2E")
C_DIM = HexColor("#6B7280")

# ============================================================================
# CRA + NIS2 MAPPING
# ============================================================================
CRA_MAP = {
    "key_exchange": {
        "checks": ["key_exchange"],
        "article": "Art.10(1)",
        "title": "Cybersecurity requirements — Key Exchange",
        "description": "Products shall use state-of-the-art key exchange mechanisms.",
        "severity": "CRITICAL",
        "category": "Product Security",
        "nis2": "Art.21(2)(e)",
    },
    "pqc_readiness": {
        "checks": ["pqc_kem"],
        "article": "Art.10(5)",
        "title": "Data protection — PQC Readiness",
        "description": "Products shall protect data against future quantum decryption threats.",
        "severity": "CRITICAL",
        "category": "Data Protection",
        "nis2": "Art.21(2)(e), Art.21(2)(h)",
    },
    "tls_version": {
        "checks": ["tls_version"],
        "article": "Art.10(1)",
        "title": "Cybersecurity requirements — TLS Protocol",
        "description": "Products shall use current, non-deprecated transport security protocols.",
        "severity": "HIGH",
        "category": "Product Security",
        "nis2": "Art.21(2)(e)",
    },
    "cipher_strength": {
        "checks": ["encryption"],
        "article": "Art.10(1)",
        "title": "Cybersecurity requirements — Cipher Strength",
        "description": "Encryption must provide adequate security level (AES-256 recommended).",
        "severity": "HIGH",
        "category": "Product Security",
        "nis2": "Art.21(2)(e)",
    },
    "certificate": {
        "checks": ["certificate"],
        "article": "Art.10(3)",
        "title": "Security update delivery — Certificate Management",
        "description": "Security mechanisms including certificates must be maintained.",
        "severity": "HIGH",
        "category": "Update Management",
        "nis2": "Art.21(2)(e)",
    },
    "cert_key_quantum": {
        "checks": ["cert_key"],
        "article": "Annex I.1",
        "title": "Essential requirements — Certificate Key Quantum Safety",
        "description": "Certificate keys must be assessed for quantum vulnerability.",
        "severity": "HIGH",
        "category": "Security Design",
        "nis2": "Art.21(2)(e)",
    },
    "signature_algorithm": {
        "checks": ["signature"],
        "article": "Annex I.1",
        "title": "Essential requirements — Signature Algorithm",
        "description": "Digital signatures must use quantum-resistant algorithms where possible.",
        "severity": "MEDIUM",
        "category": "Security Design",
        "nis2": "Art.21(2)(e)",
    },
    "security_headers": {
        "checks": ["http_headers"],
        "article": "Art.10(4)",
        "title": "Secure by default — HTTP Security Headers",
        "description": "Products shall be delivered with secure default HTTP configurations.",
        "severity": "HIGH",
        "category": "Secure Defaults",
        "nis2": "Art.21(2)(d)",
    },
    "hsts": {
        "checks": ["hsts"],
        "article": "Art.10(6)",
        "title": "Attack surface minimization — HSTS",
        "description": "HTTPS must be enforced via Strict-Transport-Security header.",
        "severity": "HIGH",
        "category": "Attack Surface",
        "nis2": "Art.21(2)(e)",
    },
    "deprecated_protocols": {
        "checks": ["deprecated_tls"],
        "article": "Art.10(6)",
        "title": "Attack surface minimization — Deprecated Protocols",
        "description": "Deprecated TLS versions must be disabled to minimize attack surface.",
        "severity": "CRITICAL",
        "category": "Attack Surface",
        "nis2": "Art.21(2)(d)",
    },
}


def map_scan_to_cra(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map web scanner results to CRA articles."""
    results = []

    cipher = scan_data.get("cipher", {})
    certificate = scan_data.get("certificate", {})
    quantum_risks = scan_data.get("quantum_risks", [])
    headers = scan_data.get("http_headers", {})
    protocols = scan_data.get("supported_protocols", [])
    tls_version = scan_data.get("tls_version", "Unknown")

    # Helper: find risk by component keyword
    def find_risk(keyword):
        for r in quantum_risks:
            if keyword.lower() in r.get("component", "").lower():
                return r
        return None

    # 1. Key Exchange
    kex_risk = find_risk("key exchange")
    kex_level = kex_risk.get("level", "UNKNOWN") if kex_risk else "UNKNOWN"
    kex_status = "PASS" if kex_level == "SAFE" else "WARNING" if kex_level in ("LOW", "MEDIUM") else "FAIL"
    results.append({
        "article": "Art.10(1)",
        "title": "Key Exchange Security",
        "category": "Product Security",
        "severity": "CRITICAL",
        "check": f"Key Exchange: {cipher.get('key_exchange', 'N/A')}",
        "status": kex_status,
        "detail": kex_risk.get("detail", "") if kex_risk else "",
        "remediation": kex_risk.get("recommendation", "") if kex_risk else "",
        "nis2": "Art.21(2)(e)",
    })

    # 2. PQC Readiness
    is_pqc = cipher.get("is_pqc", False)
    results.append({
        "article": "Art.10(5)",
        "title": "Post-Quantum Cryptography Readiness",
        "category": "Data Protection",
        "severity": "CRITICAL",
        "check": f"PQC Key Exchange: {'Detected' if is_pqc else 'Not Detected'}",
        "status": "PASS" if is_pqc else "FAIL",
        "detail": "ML-KEM/Kyber detected in TLS handshake" if is_pqc
                  else "No PQC algorithms in TLS — vulnerable to harvest-now-decrypt-later",
        "remediation": "No action required" if is_pqc
                       else "Deploy hybrid PQC key exchange (X25519+ML-KEM-768)",
        "nis2": "Art.21(2)(e), Art.21(2)(h)",
    })

    # 3. TLS Version
    tls_status = "PASS" if "1.3" in tls_version else "WARNING" if "1.2" in tls_version else "FAIL"
    results.append({
        "article": "Art.10(1)",
        "title": "TLS Protocol Version",
        "category": "Product Security",
        "severity": "HIGH",
        "check": f"TLS Version: {tls_version}",
        "status": tls_status,
        "detail": f"Server negotiated {tls_version}",
        "remediation": "No action" if tls_status == "PASS" else "Upgrade to TLS 1.3",
        "nis2": "Art.21(2)(e)",
    })

    # 4. Cipher Strength
    enc = cipher.get("encryption", "")
    enc_bits = cipher.get("encryption_bits", 0)
    enc_status = "PASS" if enc_bits >= 256 else "WARNING" if enc_bits >= 128 else "FAIL"
    results.append({
        "article": "Art.10(1)",
        "title": "Cipher Strength",
        "category": "Product Security",
        "severity": "HIGH",
        "check": f"Encryption: {enc} ({enc_bits}-bit)",
        "status": enc_status,
        "detail": f"Cipher suite: {cipher.get('name', 'N/A')}",
        "remediation": "No action" if enc_status == "PASS" else "Use AES-256-GCM",
        "nis2": "Art.21(2)(e)",
    })

    # 5. Certificate
    cert_expired = certificate.get("is_expired", False)
    days_left = certificate.get("days_until_expiry", -1)
    if cert_expired:
        cert_status = "FAIL"
    elif days_left < 30:
        cert_status = "WARNING"
    else:
        cert_status = "PASS"
    results.append({
        "article": "Art.10(3)",
        "title": "Certificate Validity",
        "category": "Update Management",
        "severity": "HIGH",
        "check": f"Expires: {certificate.get('not_after', 'N/A')} ({days_left} days)",
        "status": cert_status,
        "detail": f"Subject: {certificate.get('subject', 'N/A')}, Issuer: {certificate.get('issuer', 'N/A')}",
        "remediation": "Renew certificate" if cert_status != "PASS" else "No action",
        "nis2": "Art.21(2)(e)",
    })

    # 6. Certificate Key Quantum Risk
    cert_risk = find_risk("certificate key")
    cert_q_level = cert_risk.get("level", "UNKNOWN") if cert_risk else "UNKNOWN"
    cert_q_status = "PASS" if cert_q_level == "SAFE" else "WARNING" if cert_q_level in ("LOW", "MEDIUM") else "FAIL"
    results.append({
        "article": "Annex I.1",
        "title": "Certificate Key — Quantum Resistance",
        "category": "Security Design",
        "severity": "HIGH",
        "check": f"Key: {certificate.get('key_type', 'N/A')} ({certificate.get('key_size', 0)}-bit)",
        "status": cert_q_status,
        "detail": cert_risk.get("detail", "") if cert_risk else "Unknown key type",
        "remediation": cert_risk.get("recommendation", "") if cert_risk else "Verify manually",
        "nis2": "Art.21(2)(e)",
    })

    # 7. Signature Algorithm
    sig_risk = find_risk("signature")
    sig_level = sig_risk.get("level", "UNKNOWN") if sig_risk else "UNKNOWN"
    sig_status = "PASS" if sig_level == "SAFE" else "WARNING" if sig_level in ("LOW", "MEDIUM") else "FAIL"
    results.append({
        "article": "Annex I.2",
        "title": "Signature Algorithm — Quantum Resistance",
        "category": "Vulnerability Handling",
        "severity": "MEDIUM",
        "check": f"Signature: {certificate.get('signature_algorithm', 'N/A')}",
        "status": sig_status,
        "detail": sig_risk.get("detail", "") if sig_risk else "",
        "remediation": sig_risk.get("recommendation", "") if sig_risk else "",
        "nis2": "Art.21(2)(e)",
    })

    # 8. Security Headers
    if headers:
        h_score = headers.get("score", 0)
        h_status = "PASS" if h_score >= 80 else "WARNING" if h_score >= 50 else "FAIL"
        missing = headers.get("missing_headers", [])
        results.append({
            "article": "Art.10(4)",
            "title": "HTTP Security Headers",
            "category": "Secure Defaults",
            "severity": "HIGH",
            "check": f"Header Score: {h_score}/100",
            "status": h_status,
            "detail": f"Missing: {', '.join(missing)}" if missing else "All headers present",
            "remediation": f"Add: {', '.join(missing)}" if missing else "No action",
            "nis2": "Art.21(2)(d)",
        })

        # 9. HSTS specifically
        hsts = headers.get("hsts")
        results.append({
            "article": "Art.10(6)",
            "title": "HSTS — Transport Security Enforcement",
            "category": "Attack Surface",
            "severity": "HIGH",
            "check": f"HSTS: {'Present' if hsts else 'Missing'}",
            "status": "PASS" if hsts else "FAIL",
            "detail": f"HSTS: {hsts}" if hsts else "No HSTS header — HTTP downgrade possible",
            "remediation": "No action" if hsts else "Add Strict-Transport-Security header",
            "nis2": "Art.21(2)(e)",
        })

    # 10. Deprecated protocols
    deprecated_found = []
    for p in protocols:
        if p.get("supported") and p.get("status") == "CRITICAL":
            deprecated_found.append(p.get("protocol", ""))
    if protocols:
        results.append({
            "article": "Art.10(6)",
            "title": "Deprecated Protocol Support",
            "category": "Attack Surface",
            "severity": "CRITICAL",
            "check": f"Deprecated: {', '.join(deprecated_found) if deprecated_found else 'None'}",
            "status": "FAIL" if deprecated_found else "PASS",
            "detail": f"Server supports: {', '.join(deprecated_found)}" if deprecated_found
                      else "No deprecated protocols enabled",
            "remediation": f"Disable: {', '.join(deprecated_found)}" if deprecated_found else "No action",
            "nis2": "Art.21(2)(d)",
        })

    return results


# ============================================================================
# PDF GENERATOR
# ============================================================================
class CRAReportPDF:
    """Generate CRA compliance PDF from mapped results."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._add_styles()

    def _add_styles(self):
        self.styles.add(ParagraphStyle("QTitle", parent=self.styles["Title"],
            fontSize=24, leading=30, textColor=C_PRIMARY, spaceAfter=4*mm))
        self.styles.add(ParagraphStyle("QH1", parent=self.styles["Heading1"],
            fontSize=16, leading=20, textColor=C_PRIMARY, spaceBefore=8*mm, spaceAfter=3*mm))
        self.styles.add(ParagraphStyle("QH2", parent=self.styles["Heading2"],
            fontSize=12, leading=16, textColor=C_PRIMARY, spaceBefore=5*mm, spaceAfter=2*mm))
        self.styles.add(ParagraphStyle("QBody", parent=self.styles["Normal"],
            fontSize=9, leading=13, textColor=C_TEXT, alignment=TA_JUSTIFY, spaceAfter=2*mm))
        self.styles.add(ParagraphStyle("QSmall", parent=self.styles["Normal"],
            fontSize=7, leading=9, textColor=C_DIM))

    def _header_footer(self, c, doc):
        c.saveState()
        w, h = A4
        c.setStrokeColor(C_ACCENT)
        c.setLineWidth(2)
        c.line(20*mm, h-18*mm, w-20*mm, h-18*mm)
        c.setFont("Helvetica-Bold", 7)
        c.setFillColor(C_PRIMARY)
        c.drawString(20*mm, h-15*mm, f"{COMPANY} | Q-CRA Dashboard v{VERSION}")
        c.setFont("Helvetica", 7)
        c.setFillColor(C_DIM)
        c.drawRightString(w-20*mm, h-15*mm, "CRA COMPLIANCE REPORT")
        c.setStrokeColor(C_NEUTRAL)
        c.setLineWidth(0.5)
        c.line(20*mm, 15*mm, w-20*mm, 15*mm)
        c.drawString(20*mm, 10*mm,
            f"{WEBSITE} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        c.drawRightString(w-20*mm, 10*mm, f"Page {doc.page}")
        c.restoreState()

    def _status_color(self, status):
        return {"PASS": C_SUCCESS, "WARNING": C_WARNING, "FAIL": C_DANGER}.get(status, C_NEUTRAL)

    def generate(self, scan_data: Dict, cra_results: List[Dict], output_path: str) -> str:
        doc = SimpleDocTemplate(output_path, pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm, topMargin=22*mm, bottomMargin=20*mm,
            title=f"CRA Report — {scan_data.get('hostname', 'Unknown')}",
            author=COMPANY)

        elements = []

        # Cover
        elements.append(Spacer(1, 25*mm))
        elements.append(Paragraph("EU Cyber Resilience Act<br/>Compliance Report", self.styles["QTitle"]))
        elements.append(Paragraph(
            f"Generated by Q-CRA Dashboard v{VERSION} | {COMPANY}", self.styles["QSmall"]))
        elements.append(Spacer(1, 10*mm))

        # Summary table
        total = len(cra_results)
        passes = sum(1 for r in cra_results if r["status"] == "PASS")
        warnings = sum(1 for r in cra_results if r["status"] == "WARNING")
        fails = sum(1 for r in cra_results if r["status"] == "FAIL")
        score = round((passes / total) * 100) if total else 0

        info = [
            ["Target:", scan_data.get("hostname", "N/A")],
            ["IP:", scan_data.get("ip_address", "N/A")],
            ["TLS:", scan_data.get("tls_version", "N/A")],
            ["Scan Time:", scan_data.get("scan_timestamp", "N/A")],
            ["Report Time:", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
            ["", ""],
            ["Overall Score:", f"{score}%"],
            ["Checks:", str(total)],
            ["PASS:", str(passes)],
            ["WARNING:", str(warnings)],
            ["FAIL:", str(fails)],
            ["PQC Ready:", "YES" if scan_data.get("cipher", {}).get("is_pqc") else "NO"],
        ]
        t = Table(info, colWidths=[35*mm, 115*mm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("TEXTCOLOR", (0,0), (0,-1), C_PRIMARY),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LINEBELOW", (0,5), (-1,5), 0.5, C_NEUTRAL),
            ("BACKGROUND", (0,6), (-1,6), C_BG),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8*mm))
        elements.append(Paragraph(
            "<b>Disclaimer:</b> This report is auto-generated and provides indicative CRA mapping. "
            "It does not constitute legal advice. Consult a qualified notified body for formal assessment.",
            self.styles["QSmall"]))
        elements.append(PageBreak())

        # Executive Summary Table
        elements.append(Paragraph("1. Executive Summary", self.styles["QH1"]))
        headers = ["CRA Article", "Check", "Category", "Status"]
        table_data = [headers]
        for r in cra_results:
            table_data.append([r["article"], r["title"], r["category"], r["status"]])

        et = Table(table_data, colWidths=[25*mm, 55*mm, 35*mm, 25*mm])
        style_cmds = [
            ("BACKGROUND", (0,0), (-1,0), C_PRIMARY),
            ("TEXTCOLOR", (0,0), (-1,0), white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("ALIGN", (3,0), (3,-1), "CENTER"),
            ("GRID", (0,0), (-1,-1), 0.4, C_NEUTRAL),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, C_BG]),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("TOPPADDING", (0,0), (-1,-1), 4),
        ]
        for i, r in enumerate(cra_results, 1):
            color = self._status_color(r["status"])
            style_cmds.append(("TEXTCOLOR", (3,i), (3,i), color))
            style_cmds.append(("FONTNAME", (3,i), (3,i), "Helvetica-Bold"))
        et.setStyle(TableStyle(style_cmds))
        elements.append(et)
        elements.append(PageBreak())

        # Detailed Findings
        elements.append(Paragraph("2. Detailed Findings", self.styles["QH1"]))
        for r in cra_results:
            color = self._status_color(r["status"])
            block = []
            block.append(Paragraph(
                f'<font color="{color.hexval()}">[{r["status"]}]</font> '
                f'{r["article"]} — {r["title"]}',
                ParagraphStyle("FindTitle", parent=self.styles["Normal"],
                    fontSize=10, fontName="Helvetica-Bold", textColor=C_PRIMARY,
                    spaceAfter=1*mm)))
            block.append(Paragraph(f'<b>Check:</b> {r["check"]}', self.styles["QBody"]))
            if r.get("detail"):
                block.append(Paragraph(f'<i>{r["detail"]}</i>', self.styles["QBody"]))
            if r.get("remediation") and r["remediation"] != "No action":
                block.append(Paragraph(
                    f'<b>Remediation:</b> {r["remediation"]}', self.styles["QBody"]))
            block.append(Paragraph(
                f'<b>CRA:</b> {r["article"]} | <b>NIS2:</b> {r.get("nis2", "N/A")}',
                self.styles["QBody"]))
            block.append(Spacer(1, 4*mm))
            elements.append(KeepTogether(block))

        # Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("3. Recommendations", self.styles["QH1"]))

        fails_list = [r for r in cra_results if r["status"] == "FAIL"]
        warns_list = [r for r in cra_results if r["status"] == "WARNING"]

        if fails_list:
            elements.append(Paragraph("Priority 1 — Immediate Action", self.styles["QH2"]))
            for r in fails_list:
                elements.append(Paragraph(
                    f'<b>{r["article"]}</b> — {r["title"]}: {r.get("remediation", "")}',
                    self.styles["QBody"]))

        if warns_list:
            elements.append(Paragraph("Priority 2 — Recommended Improvements", self.styles["QH2"]))
            for r in warns_list:
                elements.append(Paragraph(
                    f'<b>{r["article"]}</b> — {r["title"]}: {r.get("remediation", "")}',
                    self.styles["QBody"]))

        # PQC note
        pqc_ready = scan_data.get("cipher", {}).get("is_pqc", False)
        if not pqc_ready:
            elements.append(Paragraph("Post-Quantum Migration", self.styles["QH2"]))
            elements.append(Paragraph(
                "This infrastructure does not implement post-quantum cryptography. "
                "NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) are finalized. "
                "Begin PQC migration planning immediately to protect against "
                "harvest-now-decrypt-later attacks. Q-CORE Systems provides "
                "migration tooling through Q-HYBRID and Q-MIGRATOR modules.",
                self.styles["QBody"]))

        # Footer
        elements.append(Spacer(1, 15*mm))
        elements.append(Paragraph(
            f"Report by Q-CRA Dashboard v{VERSION} | {COMPANY} | {WEBSITE}",
            self.styles["QSmall"]))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return output_path
