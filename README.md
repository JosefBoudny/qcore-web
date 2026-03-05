# Q-CORE SYSTEMS: Q-SCANNER Web App

Web interface for [Q-SCANNER](https://github.com/JosefBoudny/q-core-systems) — Post-Quantum Vulnerability Audit & Detection tool.

## Local Development

```bash
# 1. Clone or copy files
cd qcore-web

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
# venv\Scripts\activate    # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py

# Open http://localhost:5000
```

## Deploy to Railway.app

### Step-by-step guide

**1. Create a Railway account**
- Go to [railway.app](https://railway.app) and sign up (free tier includes $5/month credit)

**2. Push code to GitHub**
```bash
cd qcore-web
git init
git add .
git commit -m "Q-SCANNER web app"
git remote add origin https://github.com/JosefBoudny/q-core-systems.git
git push origin main
```

**3. Deploy on Railway**
- Click **"New Project"** → **"Deploy from GitHub Repo"**
- Select your `q-core-systems` repository
- Railway auto-detects Python + `requirements.txt` + `Procfile`
- Click **Deploy** — it builds and starts automatically

**4. Set environment variables** (Settings → Variables):
```
SECRET_KEY=your-random-secret-key-here
SCAN_TIMEOUT=15
MAX_CONCURRENT_SCANS=3
```

**5. Add custom domain**
- In Railway: Settings → Networking → Custom Domain
- Enter: `qcore.systems`
- Railway gives you a CNAME record (e.g. `abc123.up.railway.app`)
- In your DNS provider, add:
  - **Type:** CNAME
  - **Name:** `@` (or empty for root domain)
  - **Value:** the Railway CNAME value
- For root domain, some DNS providers need an ALIAS or ANAME record instead of CNAME. Railway's docs explain this.
- SSL is automatic via Railway.

**6. Verify**
- Visit `https://qcore.systems` — should show Q-SCANNER
- Try scanning `google.com` to test

## Project Structure

```
qcore-web/
├── app.py              # Flask server + API
├── q_scanner.py        # Scanner engine (your existing code)
├── templates/
│   └── index.html      # Frontend (single-file, no build step)
├── requirements.txt    # Python dependencies
├── Procfile            # Railway/Heroku start command
├── railway.toml        # Railway configuration
└── .gitignore
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main page |
| `/api/scan` | POST | Run scan (JSON body: `{"domain": "example.com"}`) |
| `/api/health` | GET | Health check |

## Author

**Josef Boudny** — [Q-CORE SYSTEMS](https://qcore.systems)
