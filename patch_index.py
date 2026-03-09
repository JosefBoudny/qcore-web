"""
Patch index.html: adds data-i18n attributes for full translation support.
Run from qcore-web folder: python patch_index.py
"""
import os, sys

path = os.path.join("templates", "index.html")
if not os.path.exists(path):
    print("ERROR: templates/index.html not found!")
    sys.exit(1)

with open(path, "r", encoding="utf-8") as f:
    html = f.read()

# Remove old patch if present
if "i18n.js" in html and "flag-switcher" in html:
    print("Already patched. Re-patching...")

# Ensure flag CSS is present
if ".flag-switcher" not in html:
    flag_css = """
        .flag-switcher{display:flex;gap:2px;align-items:center;margin-right:10px}
        .flag-btn{background:none;border:1px solid rgba(0,229,255,0.2);border-radius:4px;cursor:pointer;font-size:0.7rem;font-weight:600;padding:4px 8px;color:#5a6178;transition:all 0.2s;line-height:1}
        .flag-btn:hover{color:#00e5ff;border-color:#00e5ff44}
        .flag-btn.active{color:#00e5ff;border-color:#00e5ff;background:rgba(0,229,255,0.1)}
"""
    html = html.replace("</style>", flag_css + "    </style>")
    print("  + Flag CSS added")

# Add data-i18n to hero section
replacements = [
    # Hero badge
    ('>Q-SCANNER v2.0', ' data-i18n="hero.badge">Q-SCANNER v2.0'),
    # Hero title - wrap parts
    ('<h1>Is your server ready for<br><span class="accent">quantum threats?</span></h1>',
     '<h1><span data-i18n="hero.title1">Is your server ready for</span><br><span class="accent" data-i18n="hero.title2">quantum threats?</span></h1>'),
    # Hero description
    ('<p>Scan any domain to analyze TLS configuration, cipher suites, certificates,\n               and post-quantum cryptography readiness. Free, open-source, instant results.</p>',
     '<p data-i18n="hero.desc">Scan any domain to analyze TLS configuration, cipher suites, certificates, and post-quantum cryptography readiness. Free, open-source, instant results.</p>'),
    # Scan button
    ('>Scan</button>', ' data-i18n="hero.scan_btn">Scan</button>'),
    # Hint
    ('Try: google.com', 'Try: google.com'),  # handled by text matcher
    
    # Features
    ('>Quantum Risk Analysis</h3>', ' data-i18n="feat.quantum.title">Quantum Risk Analysis</h3>'),
    ('>TLS Deep Scan</h3>', ' data-i18n="feat.tls.title">TLS Deep Scan</h3>'),
    ('>PQC Readiness</h3>', ' data-i18n="feat.pqc.title">PQC Readiness</h3>'),
    
    # Platform section
    ('The <span class="accent">Q-CORE</span> Platform',
     '<span data-i18n="stack.title1">The</span> <span class="accent">Q-CORE</span> <span data-i18n="stack.title2">Platform</span>'),
    
    # Module titles
    ('>Vulnerability Scanning</h3>', ' data-i18n="mod.scanner.title">Vulnerability Scanning</h3>'),
    ('>Post-Quantum Encryption</h3>', ' data-i18n="mod.shield.title">Post-Quantum Encryption</h3>'),
    ('>Encrypted Storage</h3>', ' data-i18n="mod.vault.title">Encrypted Storage</h3>'),
    ('>Zero Trust Authentication</h3>', ' data-i18n="mod.gate.title">Zero Trust Authentication</h3>'),
    ('>Compliance Logging</h3>', ' data-i18n="mod.audit.title">Compliance Logging</h3>'),
    ('>Hardware Security Module</h3>', ' data-i18n="mod.hsm.title">Hardware Security Module</h3>'),
    ('>Key Lifecycle Manager</h3>', ' data-i18n="mod.cycle.title">Key Lifecycle Manager</h3>'),
    ('>License Management</h3>', ' data-i18n="mod.license.title">License Management</h3>'),
    
    # Pricing
    ('Simple <span class="accent">Pricing</span>',
     '<span data-i18n="price.title">Simple <span class="accent">Pricing</span></span>'),
    ('>Start free. Scale when you need enterprise-grade protection.</p>',
     ' data-i18n="price.desc">Start free. Scale when you need enterprise-grade protection.</p>'),
    
    # Pricing tiers
    ('class="pricing-tier tier-free">Community', 'class="pricing-tier tier-free" data-i18n="price.community">Community'),
    ('class="pricing-name">Free', 'class="pricing-name" data-i18n="price.free">Free'),
    ('class="pricing-price">$0 / forever', 'class="pricing-price" data-i18n="price.free.price">$0 / forever'),
    ('class="pricing-tier tier-pro">Professional', 'class="pricing-tier tier-pro" data-i18n="price.pro">Professional'),
    ('class="pricing-name">Pro', 'class="pricing-name" data-i18n="price.pro.name">Pro'),
    ('class="popular-badge">Most Popular', 'class="popular-badge" data-i18n="price.popular">Most Popular'),
    ('class="pricing-tier tier-ent">Enterprise', 'class="pricing-tier tier-ent" data-i18n="price.ent">Enterprise'),
    
    # Pricing buttons
    ('>Start Scanning</a>', ' data-i18n="price.start">Start Scanning</a>'),
    ('>Get in Touch</a>', ' data-i18n="price.touch">Get in Touch</a>'),
    ('>Contact Sales</a>', ' data-i18n="price.sales">Contact Sales</a>'),
    
    # About
    ('About <span class="accent">Q-CORE Systems</span>',
     '<span data-i18n="about.title">About <span class="accent">Q-CORE Systems</span></span>'),
    
    # About stats
    ('class="about-stat-label">Modules', 'class="about-stat-label" data-i18n="about.modules">Modules'),
    ('class="about-stat-label">Tests', 'class="about-stat-label" data-i18n="about.tests">Tests'),
    ('class="about-stat-label">Scan Areas', 'class="about-stat-label" data-i18n="about.areas">Scan Areas'),
    ('class="about-stat-label">Compliant', 'class="about-stat-label" data-i18n="about.compliant">Compliant'),
    
    # CTA
    ('>Ready to go quantum-safe?</h2>', ' data-i18n="cta.title">Ready to go quantum-safe?</h2>'),
    
    # Nav links
    ('>Scanner</a>', ' data-i18n="nav.scanner">Scanner</a>'),
    ('>CRA Dashboard</a>', ' data-i18n="nav.cra">CRA Dashboard</a>'),
    ('>Q-Academy</a>', ' data-i18n="nav.academy">Q-Academy</a>'),
    ('>Platform</a>', ' data-i18n="nav.platform">Platform</a>'),
    ('>Pricing</a>', ' data-i18n="nav.pricing">Pricing</a>'),
]

count = 0
for old, new in replacements:
    if old in html and old != new:
        html = html.replace(old, new, 1)
        count += 1

# Fix the multi-line description (may have newline)
if 'data-i18n="hero.desc"' not in html:
    html = html.replace(
        '<p>Scan any domain to analyze TLS configuration, cipher suites, certificates,',
        '<p data-i18n="hero.desc">Scan any domain to analyze TLS configuration, cipher suites, certificates,'
    )
    count += 1

# Add i18n.js script before </body> if not present
if 'i18n.js' not in html:
    html = html.replace('</body>', '    <script src="/static/i18n.js"></script>\n</body>')
    count += 1

print(f"  + {count} replacements made")

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print("SUCCESS: index.html fully patched!")
