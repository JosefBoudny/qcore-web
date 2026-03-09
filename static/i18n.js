// Q-CORE Systems — Internationalization (EN/CS/DE)
// Loaded by all pages. Flag switcher included.

const TRANSLATIONS = {
  // ============ NAVIGATION ============
  "nav.scanner": { en: "Scanner", cs: "Skener", de: "Scanner" },
  "nav.cra": { en: "CRA Dashboard", cs: "CRA Dashboard", de: "CRA Dashboard" },
  "nav.academy": { en: "Academy", cs: "Akademie", de: "Akademie" },
  "nav.platform": { en: "Platform", cs: "Platforma", de: "Plattform" },
  "nav.pricing": { en: "Pricing", cs: "Cen\u00edk", de: "Preise" },
  "nav.about": { en: "About", cs: "O n\u00e1s", de: "\u00dcber uns" },
  "nav.contact": { en: "Contact", cs: "Kontakt", de: "Kontakt" },

  // ============ HOMEPAGE HERO ============
  "hero.badge": { en: "Q-SCANNER v2.1 \u2014 Free PQC Audit", cs: "Q-SCANNER v2.1 \u2014 Bezplatn\u00fd PQC audit", de: "Q-SCANNER v2.1 \u2014 Kostenloser PQC-Audit" },
  "hero.title1": { en: "Is your server ready for", cs: "Je v\u00e1\u0161 server p\u0159ipraven\u00fd na", de: "Ist Ihr Server bereit f\u00fcr" },
  "hero.title2": { en: "quantum threats?", cs: "kvantov\u00e9 hrozby?", de: "Quantenbedrohungen?" },
  "hero.desc": {
    en: "Scan any domain to analyze TLS configuration, cipher suites, certificates, and post-quantum cryptography readiness. Free, open-source, instant results.",
    cs: "Naskenujte libovolnou dom\u00e9nu a analyzujte konfiguraci TLS, \u0161ifrovac\u00ed sady, certifik\u00e1ty a p\u0159ipravenost na post-kvantovou kryptografii. Zdarma, open-source, okam\u017eit\u00e9 v\u00fdsledky.",
    de: "Scannen Sie jede Dom\u00e4ne, um TLS-Konfiguration, Cipher-Suites, Zertifikate und Post-Quanten-Kryptographie-Bereitschaft zu analysieren. Kostenlos, Open-Source, sofortige Ergebnisse."
  },
  "hero.scan_btn": { en: "Scan", cs: "Skenovat", de: "Scannen" },
  "hero.hint": { en: "Try: google.com \u00b7 github.com \u00b7 cloudflare.com", cs: "Zkuste: google.com \u00b7 github.com \u00b7 seznam.cz", de: "Testen: google.com \u00b7 github.com \u00b7 cloudflare.com" },

  // ============ FEATURES ============
  "feat.quantum.title": { en: "Quantum Risk Analysis", cs: "Anal\u00fdza kvantov\u00e9ho rizika", de: "Quantenrisikoanalyse" },
  "feat.quantum.desc": { en: "Evaluates Shor\u2019s & Grover\u2019s algorithm impact on your key exchange, encryption and certificates.", cs: "Vyhodnocuje dopad Shorova a Groverova algoritmu na v\u00fdm\u011bnu kl\u00ed\u010d\u016f, \u0161ifrov\u00e1n\u00ed a certifik\u00e1ty.", de: "Bewertet die Auswirkungen von Shors und Grovers Algorithmus auf Schl\u00fcsselaustausch, Verschl\u00fcsselung und Zertifikate." },
  "feat.tls.title": { en: "TLS Deep Scan", cs: "Hloubkov\u00fd TLS sken", de: "TLS-Tiefenscan" },
  "feat.tls.desc": { en: "Probes all TLS versions, cipher suites, certificate chain, and HTTP security headers.", cs: "Testuje v\u0161echny verze TLS, \u0161ifrovac\u00ed sady, \u0159et\u011bzec certifik\u00e1t\u016f a HTTP bezpe\u010dnostn\u00ed hlavi\u010dky.", de: "Pr\u00fcft alle TLS-Versionen, Cipher-Suites, Zertifikatsketten und HTTP-Sicherheitsheader." },
  "feat.pqc.title": { en: "PQC Readiness", cs: "PQC p\u0159ipravenost", de: "PQC-Bereitschaft" },
  "feat.pqc.desc": { en: "Detects ML-KEM (Kyber), ML-DSA (Dilithium) and other NIST post-quantum standards.", cs: "Detekuje ML-KEM (Kyber), ML-DSA (Dilithium) a dal\u0161\u00ed NIST post-kvantov\u00e9 standardy.", de: "Erkennt ML-KEM (Kyber), ML-DSA (Dilithium) und andere NIST Post-Quanten-Standards." },

  // ============ PLATFORM SECTION ============
  "stack.title1": { en: "The", cs: "", de: "Die" },
  "stack.title2": { en: "Platform", cs: "Platforma", de: "Plattform" },
  "stack.desc": { en: "A complete post-quantum security stack. From scanning to key management \u2014 everything you need to protect your infrastructure.", cs: "Kompletn\u00ed post-kvantov\u00fd bezpe\u010dnostn\u00ed stack. Od skenov\u00e1n\u00ed po spr\u00e1vu kl\u00ed\u010d\u016f \u2014 v\u0161e co pot\u0159ebujete k ochran\u011b va\u0161\u00ed infrastruktury.", de: "Ein vollst\u00e4ndiger Post-Quanten-Sicherheitsstack. Vom Scannen bis zum Schl\u00fcsselmanagement \u2014 alles was Sie zum Schutz Ihrer Infrastruktur ben\u00f6tigen." },

  // Module descriptions
  "mod.scanner.title": { en: "Vulnerability Scanning", cs: "Skenov\u00e1n\u00ed zranitelnost\u00ed", de: "Schwachstellen-Scanning" },
  "mod.scanner.desc": { en: "TLS/PQC vulnerability detection with quantum risk scoring. 9 scan areas, 117 tests, detailed reports with actionable recommendations.", cs: "Detekce TLS/PQC zranitelnost\u00ed s hodnocen\u00edm kvantov\u00e9ho rizika. 9 oblast\u00ed skenu, 117 test\u016f, podrobn\u00e9 reporty s doporu\u010den\u00edmi.", de: "TLS/PQC-Schwachstellenerkennung mit Quantenrisikobewertung. 9 Scanbereiche, 117 Tests, detaillierte Berichte mit Empfehlungen." },
  "mod.shield.title": { en: "Post-Quantum Encryption", cs: "Post-kvantov\u00e9 \u0161ifrov\u00e1n\u00ed", de: "Post-Quanten-Verschl\u00fcsselung" },
  "mod.shield.desc": { en: "ML-KEM (Kyber-768) key encapsulation for quantum-safe key exchange. NIST FIPS 203 compliant.", cs: "ML-KEM (Kyber-768) zapouzd\u0159en\u00ed kl\u00ed\u010d\u016f pro kvantov\u011b bezpe\u010dnou v\u00fdm\u011bnu. Kompatibiln\u00ed s NIST FIPS 203.", de: "ML-KEM (Kyber-768) Schl\u00fcsselkapselung f\u00fcr quantensicheren Schl\u00fcsselaustausch. NIST FIPS 203 konform." },
  "mod.vault.title": { en: "Encrypted Storage", cs: "\u0160ifrovan\u00e9 \u00falo\u017ei\u0161t\u011b", de: "Verschl\u00fcsselter Speicher" },
  "mod.vault.desc": { en: "AES-256-GCM authenticated file encryption with secure key derivation (HKDF). Tamper-evident storage.", cs: "AES-256-GCM autentizovan\u00e9 \u0161ifrov\u00e1n\u00ed soubor\u016f s bezpe\u010dnou derivac\u00ed kl\u00ed\u010d\u016f (HKDF). \u00dalo\u017ei\u0161t\u011b odolav\u0161\u00ed manipulaci.", de: "AES-256-GCM-authentifizierte Dateiverschl\u00fcsselung mit sicherer Schl\u00fcsselableitung (HKDF). Manipulationssicherer Speicher." },
  "mod.gate.title": { en: "Zero Trust Authentication", cs: "Zero Trust autentizace", de: "Zero-Trust-Authentifizierung" },
  "mod.gate.desc": { en: "FIDO2/WebAuthn hardware token authentication with PBKDF2 password fallback. Phishing-resistant, replay-proof MFA.", cs: "FIDO2/WebAuthn autentizace hardwarov\u00fdm tokenem s PBKDF2 z\u00e1lo\u017en\u00edm heslem. Odolnost proti phishingu, MFA.", de: "FIDO2/WebAuthn Hardware-Token-Authentifizierung mit PBKDF2-Passwort-Fallback. Phishing-resistente MFA." },
  "mod.audit.title": { en: "Compliance Logging", cs: "Logov\u00e1n\u00ed shody", de: "Compliance-Protokollierung" },
  "mod.audit.desc": { en: "Hash-chained, tamper-evident audit trail for all cryptographic operations. FIPS-ready compliance reporting.", cs: "Hash-\u0159et\u011bzen\u00fd, manipulaci odoln\u00fd auditn\u00ed z\u00e1znam v\u0161ech kryptografick\u00fdch operac\u00ed.", de: "Hash-verketteter, manipulationssicherer Audit-Trail f\u00fcr alle kryptographischen Operationen." },
  "mod.hsm.title": { en: "Hardware Security Module", cs: "Hardwarov\u00fd bezpe\u010dnostn\u00ed modul", de: "Hardware-Sicherheitsmodul" },
  "mod.hsm.desc": { en: "Unified interface to TPM 2.0, PKCS#11 tokens, and OS keyring. Hardware-bound key storage and signing operations.", cs: "Jednotn\u00e9 rozhran\u00ed pro TPM 2.0, PKCS#11 tokeny a OS keyring. Hardwarov\u011b v\u00e1zan\u00e9 \u00falo\u017ei\u0161t\u011b kl\u00ed\u010d\u016f.", de: "Einheitliche Schnittstelle zu TPM 2.0, PKCS#11-Token und OS-Keyring. Hardwaregebundene Schl\u00fcsselspeicherung." },
  "mod.cycle.title": { en: "Key Lifecycle Manager", cs: "Spr\u00e1vce \u017eivotn\u00edho cyklu kl\u00ed\u010d\u016f", de: "Schl\u00fcssel-Lifecycle-Manager" },
  "mod.cycle.desc": { en: "Automated key rotation with in-memory re-encryption. Plaintext never touches disk. Atomic rollback, compliance audit trail.", cs: "Automatick\u00e1 rotace kl\u00ed\u010d\u016f s re-\u0161ifrov\u00e1n\u00edm v pam\u011bti. Plaintex se nikdy nedotkne disku. Atomick\u00fd rollback.", de: "Automatisierte Schl\u00fcsselrotation mit In-Memory-Neuverschl\u00fcsselung. Klartext ber\u00fchrt nie die Festplatte." },
  "mod.license.title": { en: "License Management", cs: "Spr\u00e1va licenc\u00ed", de: "Lizenzverwaltung" },
  "mod.license.desc": { en: "Ed25519-signed enterprise licensing with feature toggling, expiration, anti-tampering HMAC proofs, and CLI tooling.", cs: "Ed25519 podepsan\u00e9 enterprise licence s p\u0159ep\u00edn\u00e1n\u00edm funkc\u00ed, expirac\u00ed a HMAC ochranou.", de: "Ed25519-signierte Enterprise-Lizenzierung mit Feature-Toggling, Ablauf und HMAC-Schutz." },

  // ============ PRICING ============
  "price.title": { en: "Simple Pricing", cs: "Jednoduch\u00fd cen\u00edk", de: "Einfache Preise" },
  "price.desc": { en: "Start free. Scale when you need enterprise-grade protection.", cs: "Za\u010dn\u011bte zdarma. \u0160k\u00e1lujte a\u017e budete pot\u0159ebovat enterprise ochranu.", de: "Starten Sie kostenlos. Skalieren Sie bei Bedarf auf Enterprise-Schutz." },
  "price.community": { en: "Community", cs: "Komunita", de: "Community" },
  "price.free": { en: "Free", cs: "Zdarma", de: "Kostenlos" },
  "price.free.price": { en: "$0 / forever", cs: "$0 / nav\u017edy", de: "$0 / f\u00fcr immer" },
  "price.pro": { en: "Professional", cs: "Profesion\u00e1l", de: "Professionell" },
  "price.pro.name": { en: "Pro", cs: "Pro", de: "Pro" },
  "price.pro.price": { en: "Contact us", cs: "Kontaktujte n\u00e1s", de: "Kontaktieren Sie uns" },
  "price.ent": { en: "Enterprise", cs: "Enterprise", de: "Enterprise" },
  "price.ent.price": { en: "Contact us", cs: "Kontaktujte n\u00e1s", de: "Kontaktieren Sie uns" },
  "price.start": { en: "Start Scanning", cs: "Za\u010d\u00edt skenovat", de: "Jetzt scannen" },
  "price.touch": { en: "Get in Touch", cs: "Kontaktujte n\u00e1s", de: "Kontakt aufnehmen" },
  "price.sales": { en: "Contact Sales", cs: "Kontaktovat obchod", de: "Vertrieb kontaktieren" },
  "price.popular": { en: "Most Popular", cs: "Nejpopul\u00e1rn\u011bj\u0161\u00ed", de: "Am beliebtesten" },

  // Pricing features
  "pf.scanner_web": { en: "Q-SCANNER web interface", cs: "Q-SCANNER webov\u00e9 rozhran\u00ed", de: "Q-SCANNER Weboberfl\u00e4che" },
  "pf.unlimited": { en: "Unlimited domain scans", cs: "Neomezen\u00e9 skenov\u00e1n\u00ed dom\u00e9n", de: "Unbegrenzte Dom\u00e4nen-Scans" },
  "pf.quantum_risk": { en: "Quantum risk scoring", cs: "Hodnocen\u00ed kvantov\u00e9ho rizika", de: "Quantenrisikobewertung" },
  "pf.basic_rec": { en: "Basic recommendations", cs: "Z\u00e1kladn\u00ed doporu\u010den\u00ed", de: "Grundlegende Empfehlungen" },
  "pf.cli_batch": { en: "CLI & batch scanning", cs: "CLI a d\u00e1vkov\u00e9 skenov\u00e1n\u00ed", de: "CLI & Batch-Scanning" },
  "pf.pdf_reports": { en: "PDF security reports", cs: "PDF bezpe\u010dnostn\u00ed reporty", de: "PDF-Sicherheitsberichte" },
  "pf.shield_vault_gate": { en: "Q-SHIELD, Q-VAULT, Q-GATE", cs: "Q-SHIELD, Q-VAULT, Q-GATE", de: "Q-SHIELD, Q-VAULT, Q-GATE" },
  "pf.compliance_logs": { en: "Compliance audit logs", cs: "Auditn\u00ed z\u00e1znamy shody", de: "Compliance-Audit-Protokolle" },
  "pf.support": { en: "Support", cs: "Podpora", de: "Support" },
  "pf.everything_free": { en: "Everything in Free", cs: "V\u0161e ze Zdarma", de: "Alles aus Kostenlos" },
  "pf.email_support": { en: "Email support", cs: "E-mailov\u00e1 podpora", de: "E-Mail-Support" },
  "pf.consultation": { en: "Security consultation", cs: "Bezpe\u010dnostn\u00ed konzultace", de: "Sicherheitsberatung" },
  "pf.everything_pro": { en: "Everything in Pro", cs: "V\u0161e z Pro", de: "Alles aus Pro" },
  "pf.onprem": { en: "On-premise deployment", cs: "On-premise nasazen\u00ed", de: "On-Premise-Bereitstellung" },
  "pf.custom": { en: "Custom integrations", cs: "Vlastn\u00ed integrace", de: "Individuelle Integrationen" },
  "pf.sla": { en: "SLA & priority support", cs: "SLA a prioritn\u00ed podpora", de: "SLA & Priorit\u00e4ts-Support" },
  "pf.roadmap": { en: "PQC migration roadmap", cs: "Pl\u00e1n migrace na PQC", de: "PQC-Migrationsfahrplan" },
  "pf.engineer": { en: "Dedicated engineer", cs: "Dedikovan\u00fd in\u017een\u00fdr", de: "Dedizierter Ingenieur" },

  // ============ ABOUT ============
  "about.title": { en: "About Q-CORE Systems", cs: "O Q-CORE Systems", de: "\u00dcber Q-CORE Systems" },
  "about.desc1": { en: "Q-CORE Systems is a cybersecurity company focused on post-quantum cryptography. We build tools that help organizations understand and prepare for the quantum computing era.", cs: "Q-CORE Systems je kyberbezpe\u010dnostn\u00ed spole\u010dnost zam\u011b\u0159en\u00e1 na post-kvantovou kryptografii. Stav\u00edme n\u00e1stroje, kter\u00e9 pom\u00e1haj\u00ed organizac\u00edm porozum\u011bt kvantov\u00e9 \u00e9\u0159e a p\u0159ipravit se na ni.", de: "Q-CORE Systems ist ein Cybersecurity-Unternehmen mit Fokus auf Post-Quanten-Kryptographie. Wir entwickeln Tools, die Organisationen helfen, sich auf die Quanten\u00e4ra vorzubereiten." },
  "about.desc2": { en: "Our mission: make post-quantum security accessible \u2014 before it\u2019s too late.", cs: "Na\u0161e mise: zp\u0159\u00edstupnit post-kvantovou bezpe\u010dnost \u2014 d\u0159\u00edv ne\u017e bude pozd\u011b.", de: "Unsere Mission: Post-Quanten-Sicherheit zug\u00e4nglich machen \u2014 bevor es zu sp\u00e4t ist." },
  "about.modules": { en: "Modules", cs: "Modul\u016f", de: "Module" },
  "about.tests": { en: "Tests", cs: "Test\u016f", de: "Tests" },
  "about.areas": { en: "Scan Areas", cs: "Oblast\u00ed skenu", de: "Scanbereiche" },
  "about.compliant": { en: "Compliant", cs: "Kompatibiln\u00ed", de: "Konform" },

  // ============ CTA ============
  "cta.title": { en: "Ready to go quantum-safe?", cs: "P\u0159ipraveni na kvantovou bezpe\u010dnost?", de: "Bereit f\u00fcr Quantensicherheit?" },
  "cta.desc": { en: "Whether you need a free scan or a full enterprise migration \u2014 we\u2019re here to help. Let\u2019s talk.", cs: "A\u0165 pot\u0159ebujete bezplatn\u00fd sken nebo plnou enterprise migraci \u2014 jsme tu pro v\u00e1s.", de: "Ob Sie einen kostenlosen Scan oder eine vollst\u00e4ndige Enterprise-Migration ben\u00f6tigen \u2014 wir sind f\u00fcr Sie da." },

  // ============ CRA DASHBOARD ============
  "cra.badge_demo": { en: "Q-CRA DASHBOARD v2.1 \u2014 DEMO MODE", cs: "Q-CRA DASHBOARD v2.1 \u2014 DEMO RE\u017dIM", de: "Q-CRA DASHBOARD v2.1 \u2014 DEMO-MODUS" },
  "cra.badge_admin": { en: "Q-CRA DASHBOARD v2.1 \u2014 ADMIN / FULL ACCESS", cs: "Q-CRA DASHBOARD v2.1 \u2014 ADMIN / PLN\u00dd P\u0158\u00cdSTUP", de: "Q-CRA DASHBOARD v2.1 \u2014 ADMIN / VOLLZUGRIFF" },
  "cra.title1": { en: "EU Cyber Resilience Act", cs: "EU Cyber Resilience Act", de: "EU Cyber Resilience Act" },
  "cra.title2": { en: "Compliance Scanner", cs: "Skener shody", de: "Konformit\u00e4tsscanner" },
  "cra.desc": { en: "Scan any domain. Automatically map results to CRA & NIS2 articles. Generate signed PDF compliance reports.", cs: "Naskenujte libovolnou dom\u00e9nu. Automaticky namapujte v\u00fdsledky na \u010dl\u00e1nky CRA a NIS2. Generujte podepsan\u00e9 PDF reporty shody.", de: "Scannen Sie jede Dom\u00e4ne. Automatische Zuordnung zu CRA- & NIS2-Artikeln. Signierte PDF-Konformit\u00e4tsberichte." },
  "cra.scan_btn": { en: "Scan & Map CRA", cs: "Skenovat a mapovat CRA", de: "Scannen & CRA zuordnen" },
  "cra.scan_hint": { en: "Scan domain and map findings to EU CRA articles", cs: "Skenujte dom\u00e9nu a mapujte n\u00e1lezy na \u010dl\u00e1nky EU CRA", de: "Dom\u00e4ne scannen und Ergebnisse EU-CRA-Artikeln zuordnen" },
  "cra.lang_label": { en: "Report language:", cs: "Jazyk reportu:", de: "Berichtssprache:" },
  "cra.results_title": { en: "CRA Compliance Results", cs: "V\u00fdsledky shody s CRA", de: "CRA-Konformit\u00e4tsergebnisse" },
  "cra.score": { en: "CRA Score", cs: "CRA sk\u00f3re", de: "CRA-Bewertung" },
  "cra.articles": { en: "Articles", cs: "\u010cl\u00e1nk\u016f", de: "Artikel" },
  "cra.pass": { en: "Pass", cs: "OK", de: "Bestanden" },
  "cra.warning": { en: "Warning", cs: "Varov\u00e1n\u00ed", de: "Warnung" },
  "cra.fail": { en: "Fail", cs: "Selh\u00e1n\u00ed", de: "Fehlgeschlagen" },
  "cra.pqc_ready": { en: "PQC Ready", cs: "PQC p\u0159ipravenost", de: "PQC-bereit" },
  "cra.gen_pdf": { en: "Generate CRA Compliance PDF", cs: "Generovat PDF report shody s CRA", de: "CRA-Konformit\u00e4ts-PDF erstellen" },
  "cra.dl_pdf": { en: "Download CRA Report (PDF)", cs: "St\u00e1hnout CRA report (PDF)", de: "CRA-Bericht herunterladen (PDF)" },
  "cra.pro_title": { en: "PDF Reports \u2014 Pro Feature", cs: "PDF reporty \u2014 Pro funkce", de: "PDF-Berichte \u2014 Pro-Funktion" },
  "cra.pro_desc": { en: "PDF report generation requires Pro subscription. Contact info@qcore.systems to upgrade.", cs: "Generov\u00e1n\u00ed PDF report\u016f vy\u017eaduje Pro p\u0159edplatn\u00e9. Kontaktujte info@qcore.systems.", de: "PDF-Berichterstellung erfordert Pro-Abonnement. Kontaktieren Sie info@qcore.systems." },
  "cra.pro_btn": { en: "Contact for Pro Access", cs: "Kontaktovat pro Pro p\u0159\u00edstup", de: "Kontakt f\u00fcr Pro-Zugang" },
  "cra.demo_pdf": { en: "Download Demo PDF", cs: "St\u00e1hnout demo PDF", de: "Demo-PDF herunterladen" },
  "cra.what_title": { en: "What Q-CRA Dashboard Does", cs: "Co Q-CRA Dashboard um\u00ed", de: "Was Q-CRA Dashboard kann" },
  "cra.what_desc": { en: "Automated compliance assessment from scan to signed PDF", cs: "Automatick\u00e9 hodnocen\u00ed shody od skenu po podepsan\u00e9 PDF", de: "Automatisierte Konformit\u00e4tsbewertung vom Scan bis zum signierten PDF" },
  "cra.ready_title": { en: "Ready for CRA compliance?", cs: "P\u0159ipraveni na shodu s CRA?", de: "Bereit f\u00fcr CRA-Konformit\u00e4t?" },
  "cra.ready_desc": { en: "Scan your domain above or contact us for enterprise integration.", cs: "Naskenujte svou dom\u00e9nu v\u00fd\u0161e nebo n\u00e1s kontaktujte pro enterprise integraci.", de: "Scannen Sie Ihre Dom\u00e4ne oben oder kontaktieren Sie uns f\u00fcr Enterprise-Integration." },

  // Feature cards on CRA page
  "cra.f1.title": { en: "10+ CRA Articles", cs: "10+ \u010dl\u00e1nk\u016f CRA", de: "10+ CRA-Artikel" },
  "cra.f1.desc": { en: "Art.10, Art.10(3-6), Annex I.1, Annex I.2 \u2014 mapped with specific scanner checks and NIS2 cross-references.", cs: "Art.10, Art.10(3-6), Annex I.1, Annex I.2 \u2014 mapov\u00e1no s konkr\u00e9tn\u00edmi kontrolami skeneru a k\u0159\u00ed\u017eov\u00fdmi odkazy na NIS2.", de: "Art.10, Art.10(3-6), Annex I.1, Annex I.2 \u2014 zugeordnet mit spezifischen Scanner-Pr\u00fcfungen und NIS2-Querverweisen." },
  "cra.f2.title": { en: "PQC Readiness", cs: "PQC p\u0159ipravenost", de: "PQC-Bereitschaft" },
  "cra.f2.desc": { en: "Detects ML-KEM (Kyber), ML-DSA (Dilithium) and flags harvest-now-decrypt-later quantum risk.", cs: "Detekuje ML-KEM (Kyber), ML-DSA (Dilithium) a ozna\u010duje riziko harvest-now-decrypt-later.", de: "Erkennt ML-KEM (Kyber), ML-DSA (Dilithium) und markiert Harvest-Now-Decrypt-Later-Risiken." },
  "cra.f3.title": { en: "AI Resilience", cs: "Odolnost AI", de: "KI-Resilienz" },
  "cra.f3.desc": { en: "Detects exposed AI endpoints susceptible to prompt injection, model inversion, and data extraction attacks.", cs: "Detekuje exponovan\u00e9 AI endpointy n\u00e1chyln\u00e9 k prompt injection, model inversion a extrakci dat.", de: "Erkennt exponierte KI-Endpunkte, die anf\u00e4llig f\u00fcr Prompt-Injection und Datenextraktion sind." },
  "cra.f4.title": { en: "NIS2 Cross-Reference", cs: "K\u0159\u00ed\u017eov\u00fd odkaz NIS2", de: "NIS2-Querverweis" },
  "cra.f4.desc": { en: "Every CRA finding is cross-referenced with corresponding NIS2 Directive articles for dual compliance.", cs: "Ka\u017ed\u00fd n\u00e1lez CRA je k\u0159\u00ed\u017eov\u011b odkazov\u00e1n na odpov\u00eddaj\u00edc\u00ed \u010dl\u00e1nky sm\u011brnice NIS2.", de: "Jeder CRA-Befund wird mit entsprechenden NIS2-Richtlinienartikeln querverwiesen." },
  "cra.f5.title": { en: "Signed PDF Reports", cs: "Podepsan\u00e9 PDF reporty", de: "Signierte PDF-Berichte" },
  "cra.f5.desc": { en: "Professional compliance reports with ECDSA P-384 digital signatures for tamper evidence.", cs: "Profesion\u00e1ln\u00ed reporty shody s ECDSA P-384 digit\u00e1ln\u00edmi podpisy pro d\u016fkaz integrity.", de: "Professionelle Konformit\u00e4tsberichte mit ECDSA P-384 digitalen Signaturen." },
  "cra.f6.title": { en: "Scan-Learn-Fix Loop", cs: "Cyklus Skenuj-U\u010d se-Oprav", de: "Scan-Lernen-Beheben-Zyklus" },
  "cra.f6.desc": { en: "Each finding links to Q-Academy lessons via Q-Academy Bridge for guided remediation.", cs: "Ka\u017ed\u00fd n\u00e1lez odkazuje na lekce Q-Academy pro \u0159\u00edzenou n\u00e1pravu.", de: "Jeder Befund verweist auf Q-Academy-Lektionen zur gef\u00fchrten Behebung." },

  // ============ ACADEMY ============
  "acad.badge": { en: "Q-ACADEMY \u2014 Interactive PQC Education", cs: "Q-ACADEMY \u2014 Interaktivn\u00ed PQC vzd\u011bl\u00e1v\u00e1n\u00ed", de: "Q-ACADEMY \u2014 Interaktive PQC-Ausbildung" },
  "acad.title1": { en: "Q-Academy", cs: "Q-Academy", de: "Q-Academy" },
  "acad.title2": { en: "Learn Post-Quantum", cs: "Nau\u010dte se post-kvantovou", de: "Lernen Sie Post-Quanten-" },
  "acad.title3": { en: "Cryptography", cs: "kryptografii", de: "Kryptographie" },
  "acad.desc": { en: "6 interactive modules covering Y2Q threats, EU CRA compliance, NIST FIPS standards, and hands-on PQC implementation. Quizzes, progress tracking, and certification.", cs: "6 interaktivn\u00edch modul\u016f pokr\u00fdvaj\u00edc\u00edch Y2Q hrozby, shodu s EU CRA, standardy NIST FIPS a praktickou implementaci PQC. Kv\u00edzy, sledov\u00e1n\u00ed pokroku a certifikace.", de: "6 interaktive Module zu Y2Q-Bedrohungen, EU-CRA-Konformit\u00e4t, NIST-FIPS-Standards und praktischer PQC-Implementierung. Quiz, Fortschrittsverfolgung und Zertifizierung." },
  "acad.start": { en: "Get Started \u2014 Free", cs: "Za\u010d\u00edt \u2014 Zdarma", de: "Jetzt starten \u2014 Kostenlos" },
  "acad.curriculum": { en: "View Curriculum", cs: "Zobrazit osnovy", de: "Lehrplan anzeigen" },
  "acad.modules": { en: "Modules", cs: "Modul\u016f", de: "Module" },
  "acad.lessons": { en: "Lessons", cs: "Lekc\u00ed", de: "Lektionen" },
  "acad.questions": { en: "Quiz Questions", cs: "Kv\u00edzov\u00fdch ot\u00e1zek", de: "Quizfragen" },
  "acad.certs": { en: "Signed Certs", cs: "Podepsan\u00e9 cert.", de: "Signierte Zert." },
  "acad.curriculum_title": { en: "Curriculum", cs: "Osnovy", de: "Lehrplan" },
  "acad.curriculum_desc": { en: "From quantum threats to production PQC deployment \u2014 structured learning path", cs: "Od kvantov\u00fdch hrozeb po nasazen\u00ed PQC v produkci \u2014 strukturovan\u00e1 vzd\u011bl\u00e1vac\u00ed cesta", de: "Von Quantenbedrohungen bis zur PQC-Produktionsbereitstellung \u2014 strukturierter Lernpfad" },
  "acad.try_quiz": { en: "Try a Quiz", cs: "Zkuste kv\u00edz", de: "Quiz ausprobieren" },
  "acad.quiz_desc": { en: "Sample question from Module 1: Y2Q Threats", cs: "Uk\u00e1zkov\u00e1 ot\u00e1zka z Modulu 1: Y2Q hrozby", de: "Beispielfrage aus Modul 1: Y2Q-Bedrohungen" },
  "acad.full_curriculum": { en: "Full Curriculum", cs: "Kompletn\u00ed osnovy", de: "Vollst\u00e4ndiger Lehrplan" },
  "acad.full_desc": { en: "Detailed lesson breakdown for each module", cs: "Podrobn\u00fd rozpis lekc\u00ed pro ka\u017ed\u00fd modul", de: "Detaillierte Lektions\u00fcbersicht f\u00fcr jedes Modul" },
  "acad.get_started": { en: "Get Started", cs: "Za\u010d\u00edt", de: "Loslegen" },
  "acad.install_desc": { en: "Install and launch in 30 seconds", cs: "Nainstalujte a spu\u0161\u0165te za 30 sekund", de: "In 30 Sekunden installieren und starten" },
  "acad.cta_title": { en: "Start learning PQC today", cs: "Za\u010dn\u011bte se u\u010dit PQC dnes", de: "Beginnen Sie heute mit PQC" },
  "acad.cta_desc": { en: "Modules 1-2 are free. Upgrade to Pro for the full curriculum and certification.", cs: "Moduly 1-2 jsou zdarma. Upgradujte na Pro pro kompletn\u00ed osnovy a certifikaci.", de: "Module 1-2 sind kostenlos. Upgraden Sie auf Pro f\u00fcr den vollst\u00e4ndigen Lehrplan." },
  "acad.download": { en: "Download Q-Workshop", cs: "St\u00e1hnout Q-Workshop", de: "Q-Workshop herunterladen" },

  // Quiz
  "quiz.question": { en: "Which algorithm poses a direct threat to RSA and ECC?", cs: "Kter\u00fd algoritmus p\u0159\u00edmo ohro\u017euje RSA a ECC?", de: "Welcher Algorithmus bedroht RSA und ECC direkt?" },
  "quiz.correct": { en: "Correct! Shor\u2019s algorithm (1994) efficiently solves integer factorization and discrete log \u2014 breaking RSA, ECDSA, and ECDH.", cs: "Spr\u00e1vn\u011b! Shor\u016fv algoritmus (1994) efektivn\u011b \u0159e\u0161\u00ed faktorizaci cel\u00fdch \u010d\u00edsel a diskr\u00e9tn\u00ed logaritmus \u2014 prolomuje RSA, ECDSA a ECDH.", de: "Richtig! Shors Algorithmus (1994) l\u00f6st effizient die Faktorisierung und den diskreten Logarithmus \u2014 bricht RSA, ECDSA und ECDH." },
  "quiz.wrong": { en: "Incorrect. The correct answer is C) Shor\u2019s Algorithm.", cs: "Nespr\u00e1vn\u011b. Spr\u00e1vn\u00e1 odpov\u011b\u010f je C) Shor\u016fv algoritmus.", de: "Falsch. Die richtige Antwort ist C) Shors Algorithmus." },

  // ============ FOOTER ============
  "footer.copy": { en: "Q-CORE SYSTEMS", cs: "Q-CORE SYSTEMS", de: "Q-CORE SYSTEMS" },
};

// ============ LANGUAGE SWITCHER ENGINE ============
function getCurrentLang() {
  return localStorage.getItem("qcore_lang") || "en";
}

function setLang(lang) {
  localStorage.setItem("qcore_lang", lang);
  applyTranslations(lang);
  updateFlags(lang);
}

function applyTranslations(lang) {
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    const tr = TRANSLATIONS[key];
    if (tr && tr[lang]) {
      if (el.tagName === "INPUT" && el.hasAttribute("placeholder")) {
        el.placeholder = tr[lang];
      } else {
        el.innerHTML = tr[lang];
      }
    }
  });
}

function updateFlags(lang) {
  document.querySelectorAll(".flag-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.lang === lang);
  });
}

// Flag HTML component (call this to insert flags into navbar)
function createFlagSwitcher() {
  const container = document.createElement("div");
  container.className = "flag-switcher";
  container.innerHTML = `
    <button class="flag-btn" data-lang="en" onclick="setLang('en')" title="English">&#x1F1EC;&#x1F1E7;</button>
    <button class="flag-btn" data-lang="cs" onclick="setLang('cs')" title="\u010ce\u0161tina">&#x1F1E8;&#x1F1FF;</button>
    <button class="flag-btn" data-lang="de" onclick="setLang('de')" title="Deutsch">&#x1F1E9;&#x1F1EA;</button>
  `;
  return container;
}

// Auto-init on page load
document.addEventListener("DOMContentLoaded", () => {
  // Insert flags into navbar
  const nav = document.querySelector(".nav-links");
  if (nav) {
    const flags = createFlagSwitcher();
    nav.insertBefore(flags, nav.firstChild);
  }
  
  // Apply saved language
  const lang = getCurrentLang();
  applyTranslations(lang);
  updateFlags(lang);
});


// ============ TEXT-MATCHING TRANSLATOR ============
// For pages without data-i18n attributes (like index.html),
// find elements by their English text and translate them.

const TEXT_TRANSLATIONS = {
  // Nav
  "Scanner": { cs: "Skener", de: "Scanner" },
  "Platform": { cs: "Platforma", de: "Plattform" },
  "Pricing": { cs: "Cen\u00edk", de: "Preise" },
  "About": { cs: "O n\u00e1s", de: "\u00dcber uns" },
  "Contact": { cs: "Kontakt", de: "Kontakt" },
  
  // Hero
  "Q-SCANNER v2.0 \u2014 Free PQC Audit": { cs: "Q-SCANNER v2.0 \u2014 Bezplatn\u00fd PQC audit", de: "Q-SCANNER v2.0 \u2014 Kostenloser PQC-Audit" },
  "Scan": { cs: "Skenovat", de: "Scannen" },
  
  // Features
  "Quantum Risk Analysis": { cs: "Anal\u00fdza kvantov\u00e9ho rizika", de: "Quantenrisikoanalyse" },
  "TLS Deep Scan": { cs: "Hloubkov\u00fd TLS sken", de: "TLS-Tiefenscan" },
  "PQC Readiness": { cs: "PQC p\u0159ipravenost", de: "PQC-Bereitschaft" },
  
  // Stack
  "Vulnerability Scanning": { cs: "Skenov\u00e1n\u00ed zranitelnost\u00ed", de: "Schwachstellen-Scanning" },
  "Post-Quantum Encryption": { cs: "Post-kvantov\u00e9 \u0161ifrov\u00e1n\u00ed", de: "Post-Quanten-Verschl\u00fcsselung" },
  "Encrypted Storage": { cs: "\u0160ifrovan\u00e9 \u00falo\u017ei\u0161t\u011b", de: "Verschl\u00fcsselter Speicher" },
  "Zero Trust Authentication": { cs: "Zero Trust autentizace", de: "Zero-Trust-Authentifizierung" },
  "Compliance Logging": { cs: "Logov\u00e1n\u00ed shody", de: "Compliance-Protokollierung" },
  "Hardware Security Module": { cs: "Hardwarov\u00fd bezpe\u010dnostn\u00ed modul", de: "Hardware-Sicherheitsmodul" },
  "Key Lifecycle Manager": { cs: "Spr\u00e1vce \u017eivotn\u00edho cyklu kl\u00ed\u010d\u016f", de: "Schl\u00fcssel-Lifecycle-Manager" },
  "License Management": { cs: "Spr\u00e1va licenc\u00ed", de: "Lizenzverwaltung" },
  
  // Pricing
  "Simple": { cs: "Jednoduch\u00fd", de: "Einfache" },
  "Start free. Scale when you need enterprise-grade protection.": { cs: "Za\u010dn\u011bte zdarma. \u0160k\u00e1lujte a\u017e budete pot\u0159ebovat enterprise ochranu.", de: "Starten Sie kostenlos. Skalieren Sie bei Bedarf auf Enterprise-Schutz." },
  "Community": { cs: "Komunita", de: "Community" },
  "Free": { cs: "Zdarma", de: "Kostenlos" },
  "$0 / forever": { cs: "$0 / nav\u017edy", de: "$0 / f\u00fcr immer" },
  "Contact us": { cs: "Kontaktujte n\u00e1s", de: "Kontaktieren Sie uns" },
  "Most Popular": { cs: "Nejpopul\u00e1rn\u011bj\u0161\u00ed", de: "Am beliebtesten" },
  "Start Scanning": { cs: "Za\u010d\u00edt skenovat", de: "Jetzt scannen" },
  "Get in Touch": { cs: "Kontaktujte n\u00e1s", de: "Kontakt aufnehmen" },
  "Contact Sales": { cs: "Kontaktovat obchod", de: "Vertrieb kontaktieren" },
  
  // Pricing features
  "Q-SCANNER web interface": { cs: "Q-SCANNER webov\u00e9 rozhran\u00ed", de: "Q-SCANNER Weboberfl\u00e4che" },
  "Unlimited domain scans": { cs: "Neomezen\u00e9 skenov\u00e1n\u00ed dom\u00e9n", de: "Unbegrenzte Dom\u00e4nen-Scans" },
  "Quantum risk scoring": { cs: "Hodnocen\u00ed kvantov\u00e9ho rizika", de: "Quantenrisikobewertung" },
  "Basic recommendations": { cs: "Z\u00e1kladn\u00ed doporu\u010den\u00ed", de: "Grundlegende Empfehlungen" },
  "CLI & batch scanning": { cs: "CLI a d\u00e1vkov\u00e9 skenov\u00e1n\u00ed", de: "CLI & Batch-Scanning" },
  "PDF security reports": { cs: "PDF bezpe\u010dnostn\u00ed reporty", de: "PDF-Sicherheitsberichte" },
  "Compliance audit logs": { cs: "Auditn\u00ed z\u00e1znamy shody", de: "Compliance-Audit-Protokolle" },
  "Everything in Free": { cs: "V\u0161e ze Zdarma", de: "Alles aus Kostenlos" },
  "Q-SHIELD (PQC encryption)": { cs: "Q-SHIELD (PQC \u0161ifrov\u00e1n\u00ed)", de: "Q-SHIELD (PQC-Verschl\u00fcsselung)" },
  "Q-VAULT (encrypted storage)": { cs: "Q-VAULT (\u0161ifrovan\u00e9 \u00falo\u017ei\u0161t\u011b)", de: "Q-VAULT (verschl\u00fcsselter Speicher)" },
  "Q-GATE (FIDO2 auth)": { cs: "Q-GATE (FIDO2 autentizace)", de: "Q-GATE (FIDO2-Auth)" },
  "Q-AUDIT (compliance logs)": { cs: "Q-AUDIT (auditn\u00ed z\u00e1znamy)", de: "Q-AUDIT (Compliance-Protokolle)" },
  "Email support": { cs: "E-mailov\u00e1 podpora", de: "E-Mail-Support" },
  "Security consultation": { cs: "Bezpe\u010dnostn\u00ed konzultace", de: "Sicherheitsberatung" },
  "Everything in Pro": { cs: "V\u0161e z Pro", de: "Alles aus Pro" },
  "Q-HSM (TPM / PKCS#11)": { cs: "Q-HSM (TPM / PKCS#11)", de: "Q-HSM (TPM / PKCS#11)" },
  "Q-CYCLE (key rotation)": { cs: "Q-CYCLE (rotace kl\u00ed\u010d\u016f)", de: "Q-CYCLE (Schl\u00fcsselrotation)" },
  "Q-LICENSE management": { cs: "Q-LICENSE spr\u00e1va", de: "Q-LICENSE Verwaltung" },
  "On-premise deployment": { cs: "On-premise nasazen\u00ed", de: "On-Premise-Bereitstellung" },
  "Custom integrations": { cs: "Vlastn\u00ed integrace", de: "Individuelle Integrationen" },
  "SLA & priority support": { cs: "SLA a prioritn\u00ed podpora", de: "SLA & Priorit\u00e4ts-Support" },
  "PQC migration roadmap": { cs: "Pl\u00e1n migrace na PQC", de: "PQC-Migrationsfahrplan" },
  "Dedicated engineer": { cs: "Dedikovan\u00fd in\u017een\u00fdr", de: "Dedizierter Ingenieur" },
  "Support": { cs: "Podpora", de: "Support" },
  
  // About
  "Modules": { cs: "Modul\u016f", de: "Module" },
  "Tests": { cs: "Test\u016f", de: "Tests" },
  "Scan Areas": { cs: "Oblast\u00ed skenu", de: "Scanbereiche" },
  "Compliant": { cs: "Kompatibiln\u00ed", de: "Konform" },
  
  // CTA
  "Ready to go quantum-safe?": { cs: "P\u0159ipraveni na kvantovou bezpe\u010dnost?", de: "Bereit f\u00fcr Quantensicherheit?" },
  "View on GitHub \u2192": { cs: "Zobrazit na GitHub \u2192", de: "Auf GitHub ansehen \u2192" },
};

// Store original English text for reverting
const _originals = new Map();

function applyTextTranslations(lang) {
  if (lang === "en") {
    // Revert to originals
    _originals.forEach((orig, el) => {
      el.textContent = orig;
    });
    return;
  }
  
  // Walk all text nodes and translate
  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
  while (walk.nextNode()) {
    const el = walk.currentNode;
    // Only translate leaf text elements (h1,h2,h3,p,a,span,button,li,div with direct text)
    if (["SCRIPT","STYLE","SVG","PATH","CIRCLE","ELLIPSE","DEFS","STOP","LINEARGRADIENT","RADIALGRADIENT","INPUT"].includes(el.tagName)) continue;
    if (el.children.length > 0 && el.tagName !== "LI" && el.tagName !== "A" && el.tagName !== "BUTTON") continue;
    
    const text = el.textContent.trim();
    if (text && TEXT_TRANSLATIONS[text] && TEXT_TRANSLATIONS[text][lang]) {
      if (!_originals.has(el)) {
        _originals.set(el, el.textContent);
      }
      el.textContent = TEXT_TRANSLATIONS[text][lang];
    }
  }
}

// Override the main setLang to also apply text translations
const _originalSetLang = setLang;
setLang = function(lang) {
  localStorage.setItem("qcore_lang", lang);
  applyTranslations(lang);      // data-i18n attributes
  applyTextTranslations(lang);   // text matching
  updateFlags(lang);
};

// Update DOMContentLoaded to also apply text translations
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    const lang = getCurrentLang();
    if (lang !== "en") {
      applyTextTranslations(lang);
    }
  }, 100);
});
