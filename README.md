# 🔍 GitLeakHunter

> **Git Secret Scanner** — Scan GitHub repositories and files for leaked API keys, passwords, private keys, certificates, and database credentials before attackers find them.

[![Cloudflare Pages](https://img.shields.io/badge/Deployed%20on-Cloudflare%20Pages-F38020?logo=cloudflare&logoColor=white)](https://pages.cloudflare.com/)
[![Hono](https://img.shields.io/badge/Framework-Hono-E36002?logo=hono&logoColor=white)](https://hono.dev/)
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

---

## ✨ Features

- 🔭 **Deep GitHub Scan** — traverses full commit history (up to 100 commits, 250 files)
- 📦 **ZIP Upload Scanner** — drag & drop `.zip`, `.jar`, `.war`, `.apk` — extract & scan entirely in-browser
- 📋 **Paste / File Scanner** — paste any code, `.env`, YAML, JSON, PEM files directly
- 🧠 **33 Detection Patterns** across 10 secret categories:
  - ☁️ Cloud: AWS, Azure, Google, Firebase, Heroku
  - 💳 Payment: Stripe (live & restricted)
  - 🤖 AI: OpenAI
  - 🐙 VCS: GitHub tokens (classic & fine-grained)
  - 🔑 Crypto: RSA, SSH, EC, DSA private keys
  - 📜 TLS/SSL certificates & CSRs
  - 🗃️ Database connection strings & passwords
  - 💬 Messaging: Slack, Discord, Telegram, Twilio
  - 📧 Email: SendGrid
  - 📦 Package: NPM tokens
  - 🔒 Generic: passwords, secret keys, JWT tokens
- ⚡ **High-value files prioritised** — `.env`, `.pem`, `.key`, `credentials` scanned first
- 🎯 **Entropy filter** — reduces false positives on generic patterns
- 🔢 **Context lines** — shows surrounding code for each finding
- 📊 **Severity levels** — Critical / High / Medium / Low with color-coded UI
- 🔍 **Filter & search** — filter by severity, file, category, or keyword
- 💾 **Export JSON** — download full scan report
- 🌃 **Matrix rain** cyberpunk background

---

## 🚀 Quick Start (Cloudflare Pages — Recommended)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | ≥ 18.x | https://nodejs.org |
| npm | ≥ 9.x | bundled with Node.js |
| Git | any | https://git-scm.com |

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/pt-zenity/gitleak.git
cd gitleak
```

---

### Step 2 — Install dependencies

```bash
npm install
```

> This installs: `hono`, `vite`, `wrangler`, `@hono/vite-build`, and TypeScript.

---

### Step 3 — Run locally (development mode)

```bash
npm run dev
```

Open your browser at **http://localhost:5173**

> Uses Vite dev server with hot-reload. Changes to `src/index.tsx` are reflected instantly.

---

### Step 4 — Build for production

```bash
npm run build
```

Output: `dist/_worker.js` (~94 KB) — a single Cloudflare Worker bundle.

---

### Step 5 — Preview production build locally

```bash
npm run preview
```

Opens a local Cloudflare Workers simulation at **http://localhost:8787**

---

## ☁️ Deploy to Cloudflare Pages (Free)

### 5.1 — Create a free Cloudflare account

Go to https://dash.cloudflare.com/sign-up and create a free account.

---

### 5.2 — Install Wrangler CLI (already included)

```bash
npx wrangler --version   # should show 4.x
```

---

### 5.3 — Authenticate with Cloudflare

```bash
npx wrangler login
```

Your browser will open and ask you to log in to Cloudflare and authorize Wrangler. After approval, return to the terminal.

Verify it worked:

```bash
npx wrangler whoami
```

---

### 5.4 — Deploy

```bash
npm run deploy
```

This runs `npm run build && wrangler pages deploy dist` automatically.

You will receive two URLs:

```
✅ Deployment complete!
   Production:  https://gitleak.pages.dev
   Branch:      https://main.gitleak.pages.dev
```

---

### 5.5 — (Optional) Custom project name

Edit `package.json` and change the deploy script:

```json
"deploy": "npm run build && wrangler pages deploy dist --project-name YOUR-PROJECT-NAME"
```

Then run:

```bash
npm run deploy
```

---

## 🐳 Run with Docker (Alternative)

> Note: Docker runs the Wrangler dev server, not a native Node.js server.

### Dockerfile

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 8787
CMD ["npx", "wrangler", "pages", "dev", "dist", "--ip", "0.0.0.0", "--port", "8787"]
```

### Build & run

```bash
docker build -t gitleakhunter .
docker run -p 8787:8787 gitleakhunter
```

Open: **http://localhost:8787**

---

## 🛠️ Development Workflow

### Project structure

```
gitleak/
├── src/
│   └── index.tsx          # All backend routes + frontend HTML (Hono app)
├── public/                # Static assets
├── dist/                  # Built output (auto-generated, gitignored)
├── ecosystem.config.cjs   # PM2 config (for sandbox/server deployment)
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

All endpoints are part of the same Cloudflare Worker.

### `POST /api/scan/github`

Scan a GitHub repository for secrets.

**Request:**
```json
{
  "url": "https://github.com/owner/repository"
}
```

**Response:**
```json
{
  "success": true,
  "meta": {
    "repo": "owner/repository",
    "branch": "main",
    "scannedFiles": 47,
    "totalFiles": 120,
    "totalFindings": 3,
    "commits": 50,
    "elapsed": "4.2",
    "platform": "github"
  },
  "findings": [
    {
      "patternId": "aws_access_key",
      "label": "AWS Access Key ID",
      "category": "Cloud Credentials",
      "severity": "critical",
      "icon": "☁️",
      "description": "Amazon Web Services Access Key ID",
      "file": ".env",
      "line": 3,
      "snippet": "AWS_ACCESS_KEY_ID=AKIA...",
      "context": "2│ # AWS config\n3│ AWS_ACCESS_KEY_ID=AKIA...\n4│ AWS_DEFAULT_REGION=us-east-1",
      "match": "AKIA****EXAMPLE",
      "entropy": 3.58
    }
  ]
}
```

---

### `POST /api/scan/text`

Scan pasted text or file content.

**Request:**
```json
{
  "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2",
  "filename": "config.env"
}
```

**Response:** same shape as `/api/scan/github` with `meta.scannedFiles = 1`.

---

### `POST /api/scan/zip`

Scan files extracted from a ZIP archive (called from frontend after browser-side extraction with JSZip).

**Request:**
```json
{
  "files": [
    { "name": ".env", "content": "AWS_ACCESS_KEY_ID=AKIA..." },
    { "name": "config/database.yml", "content": "password: hunter2" }
  ]
}
```

**Response:** same shape, with additional `scannedList` and `skippedList` arrays.

---

### `GET /api/patterns`

Returns the full list of 33 detection pattern definitions.

**Response:**
```json
[
  {
    "id": "aws_access_key",
    "label": "AWS Access Key ID",
    "category": "Cloud Credentials",
    "severity": "critical",
    "icon": "☁️",
    "description": "Amazon Web Services Access Key ID"
  },
  ...
]
```

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

## ⚙️ Configuration

### Scan limits (editable in `src/index.tsx`)

```typescript
const MAX_FILES   = 250    // max files scanned per GitHub repo
const MAX_COMMITS = 100    // max commits analyzed per repo
const MAX_FILE_SIZE = 150_000  // skip files > 150 KB
```

### Scan concurrency

```typescript
const BATCH = 20  // parallel file fetches (GitHub)
```

---

## 🔒 Security Notes

- **No credentials stored** — this tool never saves API keys, tokens, or scan results server-side
- **Public repos only** — GitHub API is called without authentication (60 req/hour rate limit per IP)
- **ZIP processing in browser** — ZIP extraction happens client-side with JSZip; file contents are sent to the Worker only for pattern matching
- **For authorized use only** — only scan repositories you own or have explicit permission to audit
- **Demo data** — the built-in demo content uses clearly-labeled fake/placeholder values for testing

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
