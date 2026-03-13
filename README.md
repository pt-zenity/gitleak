# 🔍 GitLeakHunter

> **Git Secret Scanner** — Scan GitHub repositories and files for leaked API keys, passwords, private keys, certificates, and database credentials before attackers find them.

[![Cloudflare Pages](https://img.shields.io/badge/Deployed%20on-Cloudflare%20Pages-F38020?logo=cloudflare&logoColor=white)](https://pages.cloudflare.com/)
[![Hono](https://img.shields.io/badge/Framework-Hono-E36002?logo=hono&logoColor=white)](https://hono.dev/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

---

## ⚡ One-Line Auto Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pt-zenity/gitleak/main/install.sh)
```

> Installs Node.js, PM2, clones the repo, builds, and starts GitLeakHunter automatically.  
> Supports: **Ubuntu/Debian · CentOS/RHEL · Arch Linux · macOS**

---

## ✨ Features

- 🔭 **Deep GitHub Scan** — parallel fetch of files + commit history (no file limit, up to 100 commits)
- 📦 **ZIP Upload Scanner** — drag & drop `.zip`, `.jar`, `.war`, `.apk` — extract & scan entirely in-browser (up to 1000 MB)
- 📋 **Paste / File Scanner** — paste any code, `.env`, YAML, JSON, PEM files directly
- 🧠 **33 Detection Patterns** across 10+ secret categories
- ⚡ **50 concurrent requests** — parallel file scanning with controlled concurrency
- ⏱️ **Per-request timeout** — stalled requests auto-skip (no more hanging scans)
- ⛔ **Cancel button** — stop any scan instantly with AbortController
- 🎯 **Entropy filter** — reduces false positives on generic patterns
- 🔢 **Context lines** — shows surrounding code for each finding
- 📊 **Severity levels** — Critical / High / Medium / Low with color-coded UI
- 📋 **Copy buttons** — copy secret value, snippet, full finding, or all findings
- 🔔 **Telegram notifications** — auto-send scan results to a Telegram bot
- 🌃 **Matrix rain** cyberpunk UI

---

## 🚀 Install Methods

### Method 1 — Auto Install Script (Recommended)

```bash
# Download and run
bash <(curl -fsSL https://raw.githubusercontent.com/pt-zenity/gitleak/main/install.sh)
```

**Options:**

```bash
# Custom port
bash install.sh --port=8080

# Custom install directory
bash install.sh --dir=/opt/gitleakhunter

# Deploy to Cloudflare Pages
export CLOUDFLARE_API_TOKEN=your_cf_token
bash install.sh --deploy

# Uninstall
bash install.sh --uninstall

# Show help
bash install.sh --help
```

After install, open: **http://localhost:3000**

---

### Method 2 — Manual Install

#### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | ≥ 18.x | https://nodejs.org |
| npm | ≥ 9.x | bundled with Node.js |
| Git | any | https://git-scm.com |
| PM2 | latest | `npm install -g pm2` |

#### Steps

```bash
# 1. Clone
git clone https://github.com/pt-zenity/gitleak.git
cd gitleak

# 2. Install dependencies
npm install

# 3. Build
npm run build

# 4. Start with PM2
pm2 start ecosystem.config.cjs

# 5. Open browser
open http://localhost:3000
```

#### PM2 Management

```bash
pm2 status                      # Show running processes
pm2 logs gitleakhunter          # View live logs
pm2 restart gitleakhunter       # Restart
pm2 stop gitleakhunter          # Stop
pm2 startup && pm2 save         # Auto-start on system reboot
```

---

### Method 3 — Development Mode (Hot Reload)

```bash
git clone https://github.com/pt-zenity/gitleak.git
cd gitleak
npm install
npm run dev
```

Open: **http://localhost:5173**

> Uses Vite dev server with instant hot-reload on `src/index.tsx` changes.

---

### Method 4 — Docker

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npx", "wrangler", "pages", "dev", "dist", "--ip", "0.0.0.0", "--port", "3000"]
```

```bash
docker build -t gitleakhunter .
docker run -p 3000:3000 gitleakhunter
```

---

## ☁️ Deploy to Cloudflare Pages (Free)

### Step 1 — Create Cloudflare account

https://dash.cloudflare.com/sign-up (free, no credit card needed)

### Step 2 — Get API Token

1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Click **Create Token** → Use template **Edit Cloudflare Workers**
3. Copy the token

### Step 3 — Deploy

```bash
export CLOUDFLARE_API_TOKEN=your_token_here
npm run deploy
```

**Or use the auto install script:**

```bash
export CLOUDFLARE_API_TOKEN=your_token_here
bash install.sh --deploy
```

You'll receive:
```
✅ Deployment complete!
   Production:  https://gitleakhunter.pages.dev
   Branch:      https://main.gitleakhunter.pages.dev
```

---

## ♻️ Update to Latest Version

```bash
cd ~/gitleakhunter
git pull
npm install
npm run build
pm2 restart gitleakhunter
```

**Or re-run the install script** (it auto-pulls latest):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pt-zenity/gitleak/main/install.sh)
```

---

## 🛠️ Project Structure

```
gitleak/
├── src/
│   └── index.tsx          # All backend routes + frontend HTML (Hono app)
├── public/                # Static assets
├── dist/                  # Built output (auto-generated, gitignored)
├── install.sh             # ← Auto install script
├── ecosystem.config.cjs   # PM2 config
├── wrangler.jsonc         # Cloudflare Workers/Pages config
├── vite.config.ts         # Vite + Hono build config
├── tsconfig.json          # TypeScript config
└── package.json           # Scripts & dependencies
```

### Available scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Vite dev server (hot-reload, port 5173) |
| `npm run build` | Build production bundle → `dist/` |
| `npm run preview` | Preview production build with Wrangler (port 8787) |
| `npm run deploy` | Build + deploy to Cloudflare Pages |

---

## 🔌 API Reference

### `POST /api/scan/github`

```json
{ "url": "https://github.com/owner/repository" }
```

Response:
```json
{
  "success": true,
  "meta": {
    "repo": "owner/repo", "branch": "main",
    "scannedFiles": 47, "totalFiles": 120,
    "totalFindings": 3, "commits": 100, "elapsed": "4.2"
  },
  "findings": [
    {
      "patternId": "aws_access_key", "label": "AWS Access Key ID",
      "category": "Cloud Credentials", "severity": "critical",
      "file": ".env", "line": 3,
      "snippet": "AWS_ACCESS_KEY_ID=AKIA...",
      "context": "2│ # AWS\n3│ AWS_ACCESS_KEY_ID=AKIA...\n4│ REGION=us-east-1",
      "match": "AKIAIOSFODNN7EXAMPLE", "entropy": 3.58
    }
  ]
}
```

### `POST /api/scan/text`

```json
{ "content": "DB_PASSWORD=hunter2", "filename": "config.env" }
```

### `POST /api/scan/zip`

```json
{ "files": [{ "name": ".env", "content": "AWS_KEY=AKIA..." }] }
```

### `GET /api/patterns`

Returns all 33 detection pattern definitions.

---

## 🧩 Detection Patterns (33 total)

| # | Pattern | Category | Severity |
|---|---------|----------|----------|
| 1 | AWS Access Key ID | Cloud Credentials | 🔴 Critical |
| 2 | AWS Secret Access Key | Cloud Credentials | 🔴 Critical |
| 3 | OpenAI API Key | AI Service Keys | 🔴 Critical |
| 4 | Google API Key | Cloud Credentials | 🟠 High |
| 5 | Google OAuth Token | OAuth Tokens | 🟠 High |
| 6 | GitHub Token (fine-grained) | VCS Tokens | 🔴 Critical |
| 7 | GitHub Classic Token | VCS Tokens | 🔴 Critical |
| 8 | Stripe Secret Key | Payment Keys | 🔴 Critical |
| 9 | Stripe Restricted Key | Payment Keys | 🟠 High |
| 10 | Slack Token | Messaging Tokens | 🟠 High |
| 11 | Slack Webhook URL | Messaging Tokens | 🟡 Medium |
| 12 | RSA Private Key | Cryptographic Keys | 🔴 Critical |
| 13 | SSH Private Key (OpenSSH) | Cryptographic Keys | 🔴 Critical |
| 14 | EC Private Key | Cryptographic Keys | 🔴 Critical |
| 15 | DSA Private Key | Cryptographic Keys | 🔴 Critical |
| 16 | TLS/SSL Certificate | Certificates | 🟡 Medium |
| 17 | Certificate Signing Request | Certificates | 🟢 Low |
| 18 | PKCS#12 / PFX Certificate | Certificates | 🔴 Critical |
| 19 | Database Password | Database Credentials | 🟠 High |
| 20 | Database Connection String | Database Credentials | 🔴 Critical |
| 21 | Generic Password | Passwords | 🟡 Medium |
| 22 | Generic Secret / Token | Passwords | 🟡 Medium |
| 23 | JWT Token | Auth Tokens | 🟠 High |
| 24 | Twilio Account SID | Messaging Tokens | 🟠 High |
| 25 | Twilio Auth Token | Messaging Tokens | 🔴 Critical |
| 26 | SendGrid API Key | Email Service Keys | 🟠 High |
| 27 | Azure Storage Account Key | Cloud Credentials | 🔴 Critical |
| 28 | Heroku API Key | Cloud Credentials | 🟠 High |
| 29 | NPM Access Token | Package Registry Tokens | 🟠 High |
| 30 | Discord Bot Token | Messaging Tokens | 🟠 High |
| 31 | Telegram Bot Token | Messaging Tokens | 🟠 High |
| 32 | Firebase API Key | Cloud Credentials | 🟠 High |
| 33 | Private Key Passphrase | Cryptographic Keys | 🟠 High |

---

## 🔒 Security Notes

- **No credentials stored** — nothing is saved server-side
- **Public repos only** — uses unauthenticated GitHub API (60 req/hour per IP)
- **ZIP processing in browser** — extraction is 100% client-side with JSZip
- **For authorized use only** — only scan repos you own or have permission to audit

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 🙏 Acknowledgements

- [Hono](https://hono.dev/) — ultra-fast web framework
- [Cloudflare Pages](https://pages.cloudflare.com/) — edge deployment platform
- [JSZip](https://stuk.github.io/jszip/) — client-side ZIP processing
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — inspiration for pattern design
- [TailwindCSS](https://tailwindcss.com/) — utility-first CSS
