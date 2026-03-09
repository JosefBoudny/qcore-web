"""
Patch index.html: v2.1 update + new modules + fix translations
Run from qcore-web folder: python patch_index.py
"""
import os, sys

path = os.path.join("templates", "index.html")
if not os.path.exists(path):
    print("ERROR: templates/index.html not found!")
    sys.exit(1)

with open(path, "r", encoding="utf-8") as f:
    html = f.read()

changes = 0

# 1. Version v2.0 -> v2.1
if "v2.0" in html:
    html = html.replace("v2.0", "v2.1")
    changes += 1
    print("  + Version updated to v2.1")

# 2. Module count 11 -> 13
html = html.replace(
    '<div class="about-stat-num">11</div>',
    '<div class="about-stat-num">13</div>'
)
changes += 1
print("  + Module count updated to 13")

# 3. Add 4 new modules to stack-grid (before closing </div> of stack-grid)
new_modules = '''
                <div class="stack-card">
                    <div class="stack-card-header"><span class="stack-card-name">Q-CRA</span></div>
                    <h3>CRA Compliance Dashboard</h3>
                    <p>Automated EU Cyber Resilience Act compliance reports. Maps scan results to CRA &amp; NIS2 articles. Multilingual PDF generation (EN/CS/DE).</p>
                    <span class="stack-tag tag-pro">Professional</span>
                </div>
                <div class="stack-card">
                    <div class="stack-card-header"><span class="stack-card-name">Q-SIGN</span></div>
                    <h3>Digital Signatures (ML-DSA)</h3>
                    <p>ECDSA P-384 digital signatures with ML-DSA (FIPS 204) migration path. Tamper-evident report signing and verification.</p>
                    <span class="stack-tag tag-pro">Professional</span>
                </div>
                <div class="stack-card">
                    <div class="stack-card-header"><span class="stack-card-name">Q-ACADEMY</span></div>
                    <h3>PQC Education Platform</h3>
                    <p>6 interactive modules: Y2Q threats, CRA legislation, NIST FIPS 203/204, PQC implementation. Quizzes, certification, Scan-Learn-Fix loop.</p>
                    <span class="stack-tag tag-free">Free / Pro</span>
                </div>
                <div class="stack-card">
                    <div class="stack-card-header"><span class="stack-card-name">Q-BRIDGE</span></div>
                    <h3>Academy Bridge</h3>
                    <p>Maps scanner findings to Q-Academy lessons. Creates personalized learning paths based on actual security gaps. Scan &rarr; Learn &rarr; Fix cycle.</p>
                    <span class="stack-tag tag-pro">Professional</span>
                </div>
'''

# Find the last stack-card and add after it
last_license = html.find("Q-LICENSE")
if last_license > 0:
    # Find the closing </div> of Q-LICENSE stack-card
    close_pos = html.find("</div>", last_license)  # stack-card-header close
    close_pos = html.find("</div>", close_pos + 1)  # after h3
    close_pos = html.find("</div>", close_pos + 1)  # after p  
    # Actually find the next </div>\n after the stack-tag
    tag_pos = html.find("tag-ent", last_license)
    if tag_pos > 0:
        end_card = html.find("</div>", tag_pos)
        if end_card > 0:
            insert_pos = end_card + len("</div>")
            html = html[:insert_pos] + new_modules + html[insert_pos:]
            changes += 1
            print("  + 4 new modules added (Q-CRA, Q-SIGN, Q-ACADEMY, Q-BRIDGE)")

# 4. Add Q-CRA and Q-ACADEMY to Pro pricing
pro_features_marker = "Security consultation"
if pro_features_marker in html:
    html = html.replace(
        "<li>Security consultation</li>",
        "<li>Security consultation</li>\n                        <li>Q-CRA Dashboard (CRA reports)</li>\n                        <li>Q-SIGN (digital signatures)</li>"
    )
    changes += 1
    print("  + Pro pricing updated with Q-CRA, Q-SIGN")

# 5. Add Q-BRIDGE to Enterprise pricing  
ent_features_marker = "Dedicated engineer"
if ent_features_marker in html:
    html = html.replace(
        "<li>Dedicated engineer</li>",
        "<li>Dedicated engineer</li>\n                        <li>Q-ACADEMY Bridge</li>"
    )
    changes += 1
    print("  + Enterprise pricing updated with Q-BRIDGE")

# 6. Update scan button text after scan completes (in JS)
# Change scanBtn.textContent='Scan' to use i18n
if "scanBtn.textContent='Scanning...'" in html:
    html = html.replace(
        "scanBtn.textContent='Scanning...'",
        "scanBtn.textContent=(localStorage.getItem('qcore_lang')=='cs'?'Skenuji...':localStorage.getItem('qcore_lang')=='de'?'Scanne....':'Scanning...')"
    )
    changes += 1

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print(f"\nSUCCESS: {changes} changes applied to index.html")
