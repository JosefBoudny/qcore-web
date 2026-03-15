"""
Q-CORE SYSTEMS: Q-SCANNER v2.0 — PQC Vulnerability Audit & Detection
=====================================================================
Author: Josef Boudny
Version: 2.0.0

Q-SCANNER analyzes TLS/SSL configuration of a target server and evaluates
its readiness for the post-quantum era (Y2Q — Years to Quantum).

Scanned areas:
    1. TLS version (1.0/1.1 = CRITICAL, 1.2 = WARNING, 1.3 = OK)
    2. Cipher suite analysis (key exchange, encryption, MAC)
    3. Certificate: key type, size, signature algorithm
    4. Certificate chain: intermediate + root CA analysis
    5. Certificate expiration
    6. Post-quantum KEM detection (Kyber/ML-KEM in key exchange)
    7. HTTP security headers (HSTS, CSP, X-Frame-Options, ...)
    8. Supported cipher suites (multi-probe)
    9. Quantum risk classification (Shor, Grover)

Quantum threats:
    - Shor's algorithm: breaks RSA, ECDSA, DH, ECDH
      -> Public keys and key exchange are VULNERABLE
    - Grover's algorithm: reduces symmetric security by half
      -> AES-128 effectively -> 64-bit (VULNERABLE)
      -> AES-256 effectively -> 128-bit (SAFE)

Harvest Now, Decrypt Later (HNDL):
    An attacker captures encrypted traffic TODAY and waits until they have
    a quantum computer capable of breaking the key exchange.

Dependencies:
    pip install cryptography requests
"""

import ssl
import socket
import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, ec, ed25519, ed448, dsa,
    )
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("Q-SCANNER")


# ===========================================================================
# DATA CLASSES — Structured Output
# ===========================================================================

@dataclass
class QuantumRisk:
    """
    Quantum risk of a single component.

    level:
        SAFE       — Resistant to known quantum algorithms
        LOW        — Theoretically weakened but practically safe (Grover)
        MEDIUM     — Will be vulnerable with a sufficiently large QC
        HIGH       — Breakable by Shor's algorithm
        CRITICAL   — Actively vulnerable / deprecated

    threat:
        "shor"   — Shor's algorithm (factoring, discrete log)
        "grover" — Grover's algorithm (brute-force search)
        "none"   — No known quantum threat
    """
    component: str
    level: str
    threat: str
    detail: str
    recommendation: str


@dataclass
class CertificateInfo:
    """Certificate information."""
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_expired: bool
    key_type: str
    key_size: int
    signature_algorithm: str
    san_domains: list = field(default_factory=list)
    is_self_signed: bool = False
    is_wildcard: bool = False


@dataclass
class CipherSuiteAnalysis:
    """Analysis of a single cipher suite."""
    name: str
    protocol: str
    key_exchange: str
    authentication: str
    encryption: str
    encryption_bits: int
    mac: str
    is_pqc: bool
    quantum_risks: list = field(default_factory=list)


@dataclass
class HTTPSecurityHeaders:
    """HTTP security headers analysis."""
    hsts: Optional[str] = None
    hsts_max_age: Optional[int] = None
    csp: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    missing_headers: list = field(default_factory=list)
    score: int = 0


@dataclass
class ScanResult:
    """Complete scan result."""
    hostname: str
    ip_address: str
    port: int
    scan_timestamp: str
    tls_version: str
    active_cipher: CipherSuiteAnalysis
    certificate: CertificateInfo
    chain_length: int = 0
    chain_issues: list = field(default_factory=list)
    http_headers: Optional[HTTPSecurityHeaders] = None
    supported_protocols: list = field(default_factory=list)
    quantum_risks: list = field(default_factory=list)
    overall_pqc_status: str = "UNKNOWN"
    overall_risk_score: int = 0
    recommendations: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ===========================================================================
# QUANTUM RISK ANALYZER
# ===========================================================================

class QuantumRiskAnalyzer:
    """
    Evaluates quantum risk of cryptographic components.

    Classification based on:
        - NIST Post-Quantum Cryptography standardization
        - ETSI QSC (Quantum Safe Cryptography) guidelines
        - BSI technical recommendations for PQC migration
    """

    KEY_EXCHANGE_RISK = {
        "X25519KYBER768": ("SAFE", "none",
            "Hybrid PQC key exchange (X25519 + ML-KEM-768)"),
        "KYBER768": ("SAFE", "none", "ML-KEM-768 (NIST FIPS 203)"),
        "KYBER1024": ("SAFE", "none", "ML-KEM-1024 (NIST Level 5)"),
        "MLKEM768": ("SAFE", "none", "ML-KEM-768 (NIST FIPS 203)"),
        "ECDHE": ("HIGH", "shor",
            "Elliptic Curve Diffie-Hellman is vulnerable to Shor's algorithm"),
        "ECDH": ("HIGH", "shor",
            "ECDH (no forward secrecy!)"),
        "DHE": ("HIGH", "shor",
            "Diffie-Hellman is vulnerable to Shor's algorithm"),
        "DH": ("CRITICAL", "shor",
            "Static DH — vulnerable + no forward secrecy"),
        "RSA": ("CRITICAL", "shor",
            "RSA key exchange — vulnerable to Shor + no forward secrecy"),
        "UNKNOWN": ("MEDIUM", "unknown", "Unknown key exchange algorithm"),
    }

    SIGNATURE_RISK = {
        "RSA": ("HIGH", "shor", "RSA signatures are vulnerable to Shor"),
        "ECDSA": ("HIGH", "shor", "ECDSA signatures are vulnerable to Shor"),
        "DSA": ("CRITICAL", "shor", "DSA is deprecated + vulnerable to Shor"),
        "ED25519": ("HIGH", "shor", "Ed25519 is vulnerable (ECDLP -> Shor)"),
        "ED448": ("HIGH", "shor", "Ed448 is vulnerable (ECDLP -> Shor)"),
        "DILITHIUM": ("SAFE", "none", "ML-DSA (NIST FIPS 204)"),
        "ML-DSA": ("SAFE", "none", "ML-DSA (NIST FIPS 204)"),
        "SPHINCS": ("SAFE", "none", "SLH-DSA (NIST FIPS 205)"),
        "FALCON": ("SAFE", "none", "FN-DSA (NIST)"),
    }

    SYMMETRIC_RISK = {
        "AES-256": ("SAFE", "grover",
            "AES-256 -> effectively 128-bit after Grover (safe)"),
        "AES-128": ("MEDIUM", "grover",
            "AES-128 -> effectively 64-bit after Grover (insufficient)"),
        "AES-192": ("LOW", "grover",
            "AES-192 -> effectively 96-bit after Grover (acceptable)"),
        "CHACHA20": ("SAFE", "grover",
            "ChaCha20 (256-bit) -> effectively 128-bit (safe)"),
        "3DES": ("CRITICAL", "grover",
            "3DES (112-bit) -> effectively 56-bit (CRITICALLY VULNERABLE)"),
        "RC4": ("CRITICAL", "deprecated", "RC4 is deprecated — classically broken"),
        "DES": ("CRITICAL", "deprecated", "DES is deprecated — trivially broken"),
    }

    @classmethod
    def analyze_cipher_suite(cls, cipher_name: str, bits: int) -> list[QuantumRisk]:
        risks: list[QuantumRisk] = []
        upper = cipher_name.upper()

        kex = cls._extract_key_exchange(upper)
        kex_info = cls.KEY_EXCHANGE_RISK.get(kex, cls.KEY_EXCHANGE_RISK["UNKNOWN"])
        risks.append(QuantumRisk(
            component=f"Key Exchange ({kex})",
            level=kex_info[0], threat=kex_info[1], detail=kex_info[2],
            recommendation=cls._kex_recommendation(kex_info[0]),
        ))

        sym = cls._extract_symmetric(upper, bits)
        sym_info = cls.SYMMETRIC_RISK.get(sym, ("MEDIUM", "unknown", f"Unknown cipher: {sym}"))
        risks.append(QuantumRisk(
            component=f"Encryption ({sym})",
            level=sym_info[0], threat=sym_info[1], detail=sym_info[2],
            recommendation=cls._sym_recommendation(sym_info[0]),
        ))

        return risks

    @classmethod
    def analyze_certificate_key(cls, key_type: str, key_size: int) -> QuantumRisk:
        upper = key_type.upper()
        if "RSA" in upper:
            return QuantumRisk(
                component=f"Certificate Key (RSA-{key_size})",
                level="HIGH", threat="shor",
                detail=f"RSA-{key_size} is breakable by Shor's algorithm "
                       f"(estimated: ~{key_size * 2} logical qubits).",
                recommendation="Migrate to ML-DSA (FIPS 204) or hybrid certificates.",
            )
        elif "EC" in upper or "ECDSA" in upper:
            return QuantumRisk(
                component=f"Certificate Key (ECDSA-{key_size})",
                level="HIGH", threat="shor",
                detail=f"ECDSA-{key_size} is vulnerable (ECDLP -> Shor, "
                       f"~{key_size * 3} logical qubits).",
                recommendation="Migrate to ML-DSA or SLH-DSA.",
            )
        elif "ED25519" in upper:
            return QuantumRisk(
                component="Certificate Key (Ed25519)",
                level="HIGH", threat="shor",
                detail="Ed25519 is vulnerable via ECDLP -> Shor's algorithm.",
                recommendation="Migrate to ML-DSA (FIPS 204).",
            )
        elif "DILITHIUM" in upper or "ML-DSA" in upper:
            return QuantumRisk(
                component=f"Certificate Key ({key_type})",
                level="SAFE", threat="none",
                detail="Post-quantum signature algorithm (NIST FIPS 204).",
                recommendation="No action required.",
            )
        else:
            return QuantumRisk(
                component=f"Certificate Key ({key_type}-{key_size})",
                level="MEDIUM", threat="unknown",
                detail=f"Unknown key type: {key_type}.",
                recommendation="Manually verify quantum resistance.",
            )

    @classmethod
    def analyze_signature_algorithm(cls, sig_alg: str) -> QuantumRisk:
        upper = sig_alg.upper().replace("-", "").replace("_", "")
        for key, (level, threat, detail) in cls.SIGNATURE_RISK.items():
            if key in upper:
                return QuantumRisk(
                    component=f"Signature Algorithm ({sig_alg})",
                    level=level, threat=threat, detail=detail,
                    recommendation=(
                        "No action required." if level == "SAFE"
                        else "Migrate to ML-DSA (FIPS 204) signatures."
                    ),
                )
        return QuantumRisk(
            component=f"Signature Algorithm ({sig_alg})",
            level="MEDIUM", threat="unknown",
            detail=f"Unknown signature algorithm: {sig_alg}.",
            recommendation="Verify manually.",
        )

    @classmethod
    def calculate_risk_score(cls, risks: list[QuantumRisk]) -> int:
        if not risks:
            return 50
        level_scores = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "SAFE": 0}
        weights = {"Key Exchange": 3.0, "Certificate Key": 2.0,
                   "Signature Algorithm": 1.5, "Encryption": 1.0}
        total_score = 0.0
        total_weight = 0.0
        for risk in risks:
            weight = 1.0
            for key, w in weights.items():
                if key.lower() in risk.component.lower():
                    weight = w
                    break
            total_score += level_scores.get(risk.level, 50) * weight
            total_weight += weight
        return round(total_score / total_weight) if total_weight > 0 else 50

    @staticmethod
    def _extract_key_exchange(cipher_upper: str) -> str:
        for pqc in ("X25519KYBER768", "KYBER1024", "KYBER768", "MLKEM768", "MLKEM1024"):
            if pqc in cipher_upper.replace("-", "").replace("_", ""):
                return pqc
        if "ECDHE" in cipher_upper: return "ECDHE"
        if "ECDH" in cipher_upper: return "ECDH"
        if "DHE" in cipher_upper: return "DHE"
        if "DH" in cipher_upper: return "DH"
        if "TLS_AES" in cipher_upper or "TLS_CHACHA" in cipher_upper: return "ECDHE"
        if "RSA" in cipher_upper and "ECDHE" not in cipher_upper: return "RSA"
        return "UNKNOWN"

    @staticmethod
    def _extract_symmetric(cipher_upper: str, bits: int) -> str:
        if "CHACHA20" in cipher_upper: return "CHACHA20"
        if "AES" in cipher_upper:
            # Look for AES_XXX or AES-XXX pattern specifically
            # to avoid matching "256" in "SHA256"
            if "AES_256" in cipher_upper or "AES-256" in cipher_upper: return "AES-256"
            elif "AES_192" in cipher_upper or "AES-192" in cipher_upper: return "AES-192"
            elif "AES_128" in cipher_upper or "AES-128" in cipher_upper: return "AES-128"
            # Fallback to bits if no explicit AES_XXX pattern
            elif bits >= 256: return "AES-256"
            elif bits >= 192: return "AES-192"
            else: return "AES-128"
        if "3DES" in cipher_upper or "DES-CBC3" in cipher_upper: return "3DES"
        if "RC4" in cipher_upper: return "RC4"
        return f"UNKNOWN-{bits}bit"

    @staticmethod
    def _kex_recommendation(level: str) -> str:
        if level == "SAFE": return "No action required — PQC key exchange detected."
        if level in ("HIGH", "CRITICAL"):
            return "Migrate to hybrid PQC key exchange (X25519Kyber768) — NIST FIPS 203."
        return "Consider PQC migration."

    @staticmethod
    def _sym_recommendation(level: str) -> str:
        if level == "SAFE": return "No action required."
        if level == "CRITICAL": return "Immediate migration to AES-256-GCM or ChaCha20-Poly1305."
        return "Consider upgrading to AES-256."


# ===========================================================================
# CERTIFICATE ANALYZER
# ===========================================================================

class CertificateAnalyzer:
    """Detailed X.509 certificate analysis."""

    @staticmethod
    def analyze_from_der(der_bytes: bytes) -> CertificateInfo:
        if not HAS_CRYPTOGRAPHY:
            return CertificateAnalyzer._fallback_analyze()

        cert = x509.load_der_x509_certificate(der_bytes)
        pub_key = cert.public_key()
        key_type, key_size = CertificateAnalyzer._get_key_info(pub_key)

        sig_alg = cert.signature_algorithm_oid._name
        if hasattr(cert, 'signature_hash_algorithm') and cert.signature_hash_algorithm:
            sig_alg = f"{cert.signature_hash_algorithm.name}-{key_type}"

        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_domains = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') \
            else cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') \
            else cert.not_valid_before.replace(tzinfo=timezone.utc)

        days_until_expiry = (not_after - now).days
        is_self_signed = cert.issuer == cert.subject
        is_wildcard = any(d.startswith("*.") for d in san_domains)

        return CertificateInfo(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, 'X'),
            not_before=not_before.isoformat(),
            not_after=not_after.isoformat(),
            days_until_expiry=days_until_expiry,
            is_expired=days_until_expiry < 0,
            key_type=key_type, key_size=key_size,
            signature_algorithm=sig_alg,
            san_domains=san_domains,
            is_self_signed=is_self_signed,
            is_wildcard=is_wildcard,
        )

    @staticmethod
    def _get_key_info(pub_key) -> tuple[str, int]:
        if isinstance(pub_key, rsa.RSAPublicKey): return "RSA", pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey): return "ECDSA", pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey): return "Ed25519", 256
        elif isinstance(pub_key, ed448.Ed448PublicKey): return "Ed448", 448
        elif isinstance(pub_key, dsa.DSAPublicKey): return "DSA", pub_key.key_size
        else: return "UNKNOWN", 0

    @staticmethod
    def _fallback_analyze() -> CertificateInfo:
        return CertificateInfo(
            subject="N/A (install cryptography)", issuer="N/A",
            serial_number="N/A", not_before="N/A", not_after="N/A",
            days_until_expiry=-1, is_expired=False,
            key_type="UNKNOWN", key_size=0, signature_algorithm="UNKNOWN",
        )

    @staticmethod
    def analyze_from_ssl_dict(cert_dict: dict) -> CertificateInfo:
        subject_parts = dict(x[0] for x in cert_dict.get("subject", ()))
        issuer_parts = dict(x[0] for x in cert_dict.get("issuer", ()))

        not_after_str = cert_dict.get("notAfter", "")
        days_until_expiry = -1
        is_expired = False
        try:
            not_after = datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
            days_until_expiry = (not_after - datetime.now(timezone.utc)).days
            is_expired = days_until_expiry < 0
        except (ValueError, TypeError):
            pass

        san_domains = [v for t, v in cert_dict.get("subjectAltName", ()) if t == "DNS"]
        is_self_signed = subject_parts == issuer_parts

        return CertificateInfo(
            subject=subject_parts.get("commonName", "N/A"),
            issuer=issuer_parts.get("commonName", "N/A"),
            serial_number=cert_dict.get("serialNumber", "N/A"),
            not_before=cert_dict.get("notBefore", "N/A"),
            not_after=not_after_str,
            days_until_expiry=days_until_expiry, is_expired=is_expired,
            key_type="UNKNOWN (install cryptography for details)", key_size=0,
            signature_algorithm="UNKNOWN",
            san_domains=san_domains, is_self_signed=is_self_signed,
            is_wildcard=any(d.startswith("*.") for d in san_domains),
        )


# ===========================================================================
# TLS PROTOCOL SCANNER
# ===========================================================================

class TLSScanner:
    """Scans TLS configuration of a server."""

    TLS_VERSIONS = {
        "TLSv1.0": getattr(ssl.TLSVersion, 'TLSv1', None),
        "TLSv1.1": getattr(ssl.TLSVersion, 'TLSv1_1', None),
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    TLS_VERSION_RISK = {
        "TLSv1": "CRITICAL", "TLSv1.0": "CRITICAL",
        "TLSv1.1": "CRITICAL", "TLSv1.2": "WARNING", "TLSv1.3": "OK",
    }

    @staticmethod
    def probe_supported_protocols(hostname: str, port: int = 443, timeout: int = 5) -> list[dict]:
        results: list[dict] = []
        for name, version in TLSScanner.TLS_VERSIONS.items():
            if version is None:
                results.append({"protocol": name, "supported": False,
                                "status": "NOT_TESTED",
                                "note": "Version not available in this Python build"})
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results.append({"protocol": name, "supported": True,
                                        "status": TLSScanner.TLS_VERSION_RISK.get(name, "UNKNOWN"),
                                        "actual_version": ssock.version()})
            except (ssl.SSLError, socket.error, OSError):
                results.append({"protocol": name, "supported": False, "status": "OK"})
        return results


# ===========================================================================
# HTTP SECURITY HEADERS
# ===========================================================================

class HTTPHeaderAnalyzer:
    IMPORTANT_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    @staticmethod
    def analyze(hostname: str, port: int = 443) -> Optional[HTTPSecurityHeaders]:
        if not HAS_REQUESTS:
            log.info("requests library not available — skipping HTTP header analysis.")
            return None
        try:
            url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
            resp = requests.head(url, timeout=10, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            missing = [name for header, name in HTTPHeaderAnalyzer.IMPORTANT_HEADERS.items()
                       if header not in headers]

            hsts = headers.get("strict-transport-security")
            hsts_max_age = None
            if hsts:
                for part in hsts.split(";"):
                    part = part.strip()
                    if part.lower().startswith("max-age="):
                        try: hsts_max_age = int(part.split("=")[1])
                        except (ValueError, IndexError): pass

            total = len(HTTPHeaderAnalyzer.IMPORTANT_HEADERS)
            present = total - len(missing)

            return HTTPSecurityHeaders(
                hsts=hsts, hsts_max_age=hsts_max_age,
                csp=headers.get("content-security-policy"),
                x_frame_options=headers.get("x-frame-options"),
                x_content_type_options=headers.get("x-content-type-options"),
                referrer_policy=headers.get("referrer-policy"),
                permissions_policy=headers.get("permissions-policy"),
                missing_headers=missing,
                score=round(present / total * 100),
            )
        except Exception as e:
            log.warning("HTTP header analysis failed: %s", e)
            return None


# ===========================================================================
# MAIN SCANNER
# ===========================================================================

class QScanner:
    """Main scanner — orchestrates all analyses."""

    def scan(self, hostname: str, port: int = 443, timeout: int = 10,
             check_protocols: bool = True, check_headers: bool = True) -> ScanResult:
        log.info("Scanning: %s:%d", hostname, port)

        errors: list[str] = []
        ip_address = "N/A"

        try:
            ip_address = socket.getaddrinfo(hostname, port, socket.AF_INET)[0][4][0]
            log.info("IP: %s", ip_address)
        except socket.gaierror as e:
            errors.append(f"DNS resolution failed: {e}")

        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher_info = ssock.cipher()
                    cipher_name, tls_version, key_bits = cipher_info

                    log.info("TLS: %s | Cipher: %s | %d-bit", tls_version, cipher_name, key_bits)

                    cipher_risks = QuantumRiskAnalyzer.analyze_cipher_suite(cipher_name, key_bits)
                    kex = QuantumRiskAnalyzer._extract_key_exchange(cipher_name.upper())
                    sym = QuantumRiskAnalyzer._extract_symmetric(cipher_name.upper(), key_bits)
                    is_pqc = any(r.level == "SAFE" and "Key Exchange" in r.component
                                 for r in cipher_risks)

                    active_cipher = CipherSuiteAnalysis(
                        name=cipher_name, protocol=tls_version, key_exchange=kex,
                        authentication="N/A", encryption=sym, encryption_bits=key_bits,
                        mac="AEAD" if "GCM" in cipher_name.upper() or "CHACHA" in cipher_name.upper() else "HMAC",
                        is_pqc=is_pqc,
                        quantum_risks=[asdict(r) for r in cipher_risks],
                    )

                    cert_dict = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)

                    if cert_der and HAS_CRYPTOGRAPHY:
                        cert_info = CertificateAnalyzer.analyze_from_der(cert_der)
                    elif cert_dict:
                        cert_info = CertificateAnalyzer.analyze_from_ssl_dict(cert_dict)
                    else:
                        cert_info = CertificateInfo(
                            subject="N/A", issuer="N/A", serial_number="N/A",
                            not_before="N/A", not_after="N/A",
                            days_until_expiry=-1, is_expired=True,
                            key_type="UNKNOWN", key_size=0, signature_algorithm="UNKNOWN",
                        )
                        errors.append("Could not extract certificate.")

                    all_risks = list(cipher_risks)
                    all_risks.append(QuantumRiskAnalyzer.analyze_certificate_key(
                        cert_info.key_type, cert_info.key_size))
                    all_risks.append(QuantumRiskAnalyzer.analyze_signature_algorithm(
                        cert_info.signature_algorithm))

                    chain_issues: list[str] = []
                    if cert_info.is_self_signed:
                        chain_issues.append("Self-signed certificate!")
                    if cert_info.is_expired:
                        chain_issues.append(f"Certificate EXPIRED {abs(cert_info.days_until_expiry)} days ago!")
                    elif cert_info.days_until_expiry < 30:
                        chain_issues.append(f"Certificate expires in {cert_info.days_until_expiry} days!")

        except ssl.SSLCertVerificationError as e:
            errors.append(f"Certificate verification failed: {e}")
            return self._error_result(hostname, ip_address, port, errors)
        except ssl.SSLError as e:
            errors.append(f"TLS error: {e}")
            return self._error_result(hostname, ip_address, port, errors)
        except socket.timeout:
            errors.append(f"Connection timed out after {timeout}s")
            return self._error_result(hostname, ip_address, port, errors)
        except ConnectionRefusedError:
            errors.append(f"Connection refused on port {port}")
            return self._error_result(hostname, ip_address, port, errors)
        except OSError as e:
            errors.append(f"Network error: {e}")
            return self._error_result(hostname, ip_address, port, errors)

        supported_protocols: list[dict] = []
        if check_protocols:
            log.info("Testing supported TLS versions...")
            supported_protocols = TLSScanner.probe_supported_protocols(hostname, port, timeout=5)
            for proto in supported_protocols:
                if proto["supported"] and proto["status"] == "CRITICAL":
                    chain_issues.append(f"Server supports deprecated {proto['protocol']}!")

        http_headers = None
        if check_headers:
            log.info("Analyzing HTTP security headers...")
            http_headers = HTTPHeaderAnalyzer.analyze(hostname, port)


        # --- Cloudflare PQC proxy detection ---
        cloudflare_pqc = False
        if http_headers and HAS_REQUESTS:
            try:
                url = f"https://{hostname}:{port}" if port != 443 else f"https://{hostname}"
                resp = requests.head(url, timeout=10, allow_redirects=True)
                cf_ray = resp.headers.get("cf-ray", "")
                cf_server = resp.headers.get("server", "").lower()
                if cf_ray or "cloudflare" in cf_server:
                    cloudflare_pqc = True
                    log.info("Cloudflare proxy detected - browsers get X25519+ML-KEM-768 PQC")
                    active_cipher = CipherSuiteAnalysis(
                        name=active_cipher.name,
                        protocol=active_cipher.protocol,
                        key_exchange="X25519+ML-KEM-768 (via Cloudflare)",
                        authentication=active_cipher.authentication,
                        encryption=active_cipher.encryption,
                        encryption_bits=active_cipher.encryption_bits,
                        mac=active_cipher.mac,
                        is_pqc=True,
                        quantum_risks=[],
                    )
                    all_risks = [r for r in all_risks if "key exchange" not in r.component.lower()]
                    all_risks.append(QuantumRisk(
                        component="Key Exchange (browser-facing)",
                        level="SAFE",
                        threat="none",
                        detail="Cloudflare provides X25519+ML-KEM-768 hybrid PQC to all browser visitors",
                        recommendation="PQC key exchange active via Cloudflare proxy"
                    ))
            except Exception as e:
                log.debug(f"Cloudflare detection failed: {e}")

        risk_score = QuantumRiskAnalyzer.calculate_risk_score(all_risks)
        if risk_score <= 10: overall_status = "SAFE"
        elif risk_score <= 40: overall_status = "LOW_RISK"
        elif risk_score <= 60: overall_status = "MEDIUM_RISK"
        elif risk_score <= 80: overall_status = "VULNERABLE"
        else: overall_status = "CRITICAL"

        recommendations = self._generate_recommendations(
            all_risks, cert_info, chain_issues, supported_protocols, http_headers)

        return ScanResult(
            hostname=hostname, ip_address=ip_address, port=port,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            tls_version=tls_version, active_cipher=active_cipher,
            certificate=cert_info, chain_issues=chain_issues,
            http_headers=http_headers,
            supported_protocols=supported_protocols,
            quantum_risks=[asdict(r) for r in all_risks],
            overall_pqc_status=overall_status,
            overall_risk_score=risk_score,
            recommendations=recommendations, errors=errors,
        )

    def _generate_recommendations(self, risks, cert, chain_issues, protocols, headers):
        recs: list[str] = []
        has_pqc_risk = any(r.level in ("HIGH", "CRITICAL") and r.threat == "shor" for r in risks)
        if has_pqc_risk:
            recs.append("PRIORITY 1: Migrate key exchange to hybrid PQC (X25519Kyber768). "
                        "Implement Q-SHIELD module (NIST FIPS 203, ML-KEM-768).")
            recs.append("PRIORITY 2: Migrate certificate signatures to ML-DSA "
                        "(NIST FIPS 204) — requires PQC-ready CA.")
        for proto in protocols:
            if proto.get("supported") and proto.get("status") == "CRITICAL":
                recs.append(f"Disable support for {proto['protocol']} — deprecated and vulnerable.")
        if cert.is_expired:
            recs.append("URGENT: Renew expired certificate!")
        elif cert.days_until_expiry < 30:
            recs.append(f"Certificate expires in {cert.days_until_expiry} days — schedule renewal.")
        if cert.is_self_signed:
            recs.append("Replace self-signed certificate with one from a trusted CA.")
        if headers and headers.missing_headers:
            recs.append(f"Add missing HTTP security headers: {', '.join(headers.missing_headers)}")
        if headers and headers.hsts is None:
            recs.append("Enable HSTS (Strict-Transport-Security) with min max-age=31536000.")
        weak_sym = any(r.level in ("CRITICAL", "MEDIUM") and "Encryption" in r.component for r in risks)
        if weak_sym:
            recs.append("Upgrade symmetric cipher to AES-256-GCM or ChaCha20-Poly1305.")
        if not recs:
            recs.append("No critical recommendations — configuration is solid.")
        return recs

    @staticmethod
    def _error_result(hostname, ip, port, errors):
        empty_cipher = CipherSuiteAnalysis(
            name="N/A", protocol="N/A", key_exchange="N/A",
            authentication="N/A", encryption="N/A",
            encryption_bits=0, mac="N/A", is_pqc=False)
        empty_cert = CertificateInfo(
            subject="N/A", issuer="N/A", serial_number="N/A",
            not_before="N/A", not_after="N/A",
            days_until_expiry=-1, is_expired=True,
            key_type="UNKNOWN", key_size=0, signature_algorithm="UNKNOWN")
        return ScanResult(
            hostname=hostname, ip_address=ip, port=port,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            tls_version="N/A", active_cipher=empty_cipher,
            certificate=empty_cert, overall_pqc_status="ERROR",
            overall_risk_score=100, errors=errors,
            recommendations=["Fix connection errors and try again."])


# ===========================================================================
# REPORT PRINTER
# ===========================================================================

def print_report(result: ScanResult) -> None:
    STATUS_ICONS = {
        "SAFE": "[OK SAFE]", "LOW_RISK": "[~ LOW]", "MEDIUM_RISK": "[! MEDIUM]",
        "VULNERABLE": "[!! HIGH]", "CRITICAL": "[!!! CRITICAL]", "ERROR": "[X ERROR]",
    }

    print("\n" + "=" * 70)
    print("  Q-SCANNER AUDIT REPORT")
    print("=" * 70)
    print(f"\n  Target:     {result.hostname} ({result.ip_address}:{result.port})")
    print(f"  Timestamp:  {result.scan_timestamp}")

    if result.errors:
        print(f"\n  Errors:")
        for err in result.errors:
            print(f"    [!] {err}")
        if result.overall_pqc_status == "ERROR":
            print("\n" + "=" * 70)
            return

    c = result.active_cipher
    print(f"\n  TLS Configuration:")
    print(f"    Protocol:       {result.tls_version}")
    print(f"    Cipher Suite:   {c.name}")
    print(f"    Key Exchange:   {c.key_exchange}")
    print(f"    Encryption:     {c.encryption} ({c.encryption_bits}-bit)")
    print(f"    MAC:            {c.mac}")
    print(f"    PQC KEM:        {'YES' if c.is_pqc else 'NO'}")

    cert = result.certificate
    print(f"\n  Certificate:")
    print(f"    Subject:        {cert.subject}")
    print(f"    Issuer:         {cert.issuer}")
    print(f"    Key:            {cert.key_type} ({cert.key_size}-bit)")
    print(f"    Signature:      {cert.signature_algorithm}")
    print(f"    Expiry:         {cert.not_after} ({cert.days_until_expiry} days)")
    if cert.is_expired: print(f"    [!!!] CERTIFICATE IS EXPIRED!")
    if cert.is_self_signed: print(f"    [!] Self-signed certificate")

    if result.supported_protocols:
        print(f"\n  Supported Protocols:")
        for proto in result.supported_protocols:
            status = "SUPPORTED" if proto["supported"] else "disabled"
            flag = "  [!]" if proto.get("status") == "CRITICAL" and proto["supported"] else "     "
            print(f"   {flag} {proto['protocol']:<10} {status}")

    if result.http_headers:
        h = result.http_headers
        print(f"\n  HTTP Security Headers (score: {h.score}/100):")
        if h.hsts: print(f"    HSTS:           max-age={h.hsts_max_age}")
        if h.missing_headers: print(f"    Missing:        {', '.join(h.missing_headers)}")

    print(f"\n  " + "-" * 60)
    print(f"  QUANTUM RISK ASSESSMENT")
    print(f"  " + "-" * 60)
    for risk_dict in result.quantum_risks:
        level = risk_dict["level"]
        icon = {"SAFE": "[OK]", "LOW": "[~]", "MEDIUM": "[!]",
                "HIGH": "[!!]", "CRITICAL": "[!!!]"}.get(level, "[?]")
        print(f"    {icon} {risk_dict['component']:<40} {level}")
        print(f"        {risk_dict['detail']}")

    status_icon = STATUS_ICONS.get(result.overall_pqc_status, "[?]")
    print(f"\n  OVERALL PQC STATUS: {status_icon}")
    print(f"  Risk Score: {result.overall_risk_score}/100")

    if result.recommendations:
        print(f"\n  Recommendations:")
        for i, rec in enumerate(result.recommendations, 1):
            print(f"    {i}. {rec}")

    if result.chain_issues:
        print(f"\n  Warnings:")
        for issue in result.chain_issues:
            print(f"    [!] {issue}")

    print("\n" + "=" * 70)


def save_json_report(result: ScanResult, path: str) -> None:
    data = {
        "hostname": result.hostname, "ip_address": result.ip_address,
        "port": result.port, "scan_timestamp": result.scan_timestamp,
        "tls_version": result.tls_version,
        "cipher": asdict(result.active_cipher),
        "certificate": asdict(result.certificate),
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
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False))
    log.info("JSON report saved: %s", path)


# ===========================================================================
# CLI
# ===========================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="Q-SCANNER: PQC Vulnerability Audit Tool")
    parser.add_argument("domains", nargs="*", help="Domains to scan (e.g. google.com github.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")
    parser.add_argument("--no-protocols", action="store_true", help="Skip TLS version testing")
    parser.add_argument("--no-headers", action="store_true", help="Skip HTTP header analysis")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output JSON file")
    parser.add_argument("--batch", type=str, default=None, help="File with list of domains (one per line)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("=" * 70)
    print("  Q-CORE SYSTEMS: Q-SCANNER v2.0")
    print("  PQC Vulnerability Audit & Detection")
    print("  Architect: Josef Boudny")
    print("=" * 70)

    domains: list[str] = list(args.domains) if args.domains else []

    if args.batch:
        batch_path = Path(args.batch)
        if batch_path.is_file():
            for line in batch_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)

    if not domains:
        print("\n  Enter domain to scan (e.g. google.com):")
        domain = input("\n  Target > ").strip()
        if domain:
            domains.append(domain)
        else:
            print("  No domain entered. Exiting.")
            sys.exit(0)

    scanner = QScanner()
    all_results: list[ScanResult] = []

    for domain in domains:
        domain = domain.strip().lower()
        if domain.startswith("https://"): domain = domain[8:]
        if domain.startswith("http://"): domain = domain[7:]
        domain = domain.rstrip("/")

        result = scanner.scan(hostname=domain, port=args.port, timeout=args.timeout,
                              check_protocols=not args.no_protocols,
                              check_headers=not args.no_headers)
        all_results.append(result)
        print_report(result)

    if args.output and all_results:
        if len(all_results) == 1:
            save_json_report(all_results[0], args.output)
        else:
            all_data = [{"hostname": r.hostname, "overall_pqc_status": r.overall_pqc_status,
                         "risk_score": r.overall_risk_score, "tls_version": r.tls_version,
                         "cipher": r.active_cipher.name, "key_type": r.certificate.key_type,
                         "recommendations": r.recommendations} for r in all_results]
            Path(args.output).write_text(json.dumps(all_data, indent=2, ensure_ascii=False))

    if len(all_results) > 1:
        print("\n" + "=" * 70)
        print("  BATCH SCAN SUMMARY")
        print("=" * 70)
        print(f"  {'Domain':<30} {'Status':<15} {'Risk':>5} {'TLS':<8} {'PQC KEM':<8}")
        print("  " + "-" * 66)
        for r in all_results:
            pqc = "YES" if r.active_cipher.is_pqc else "NO"
            print(f"  {r.hostname:<30} {r.overall_pqc_status:<15} "
                  f"{r.overall_risk_score:>5} {r.tls_version:<8} {pqc:<8}")


if __name__ == "__main__":
    main()
