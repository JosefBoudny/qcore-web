"""
Patch script: adds i18n support to index.html
Run from qcore-web folder: python patch_index.py
"""
import os

path = os.path.join("templates", "index.html")
if not os.path.exists(path):
    print("ERROR: templates/index.html not found. Run from qcore-web folder.")
    exit(1)

with open(path, "r", encoding="utf-8") as f:
    html = f.read()

# Check if already patched
if "i18n.js" in html:
    print("Already patched! Skipping.")
    exit(0)

# 1. Add flag CSS before </style>
flag_css = """
        /* FLAG SWITCHER */
        .flag-switcher{display:flex;gap:4px;align-items:center;margin-right:8px}
        .flag-btn{background:none;border:1px solid transparent;border-radius:4px;cursor:pointer;font-size:1.1rem;padding:2px 4px;opacity:.5;transition:opacity .2s,border-color .2s;line-height:1}
        .flag-btn:hover{opacity:.8}
        .flag-btn.active{opacity:1;border-color:var(--cyan)}
"""
html = html.replace("</style>", flag_css + "    </style>")

# 2. Add i18n.js script before </body>
html = html.replace("</body>", '    <script src="/static/i18n.js"></script>\n</body>')

with open(path, "w", encoding="utf-8") as f:
    f.write(html)

print("SUCCESS: index.html patched with i18n support!")
print("  - Flag CSS added")
print("  - i18n.js script added")
