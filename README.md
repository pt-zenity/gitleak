# GitLeakHunter 🔍

**Scanner rahasia (secrets) di repositori Git, file ZIP, dan teks langsung.**  
Deteksi API key, password, token, dan credential yang ter-expose sebelum terjadi kebocoran data.

```
  ██████╗ ██╗████████╗██╗     ███████╗ █████╗ ██╗  ██╗
 ██╔════╝ ██║╚══██╔══╝██║     ██╔════╝██╔══██╗██║ ██╔╝
 ██║  ███╗██║   ██║   ██║     █████╗  ███████║█████╔╝
 ██║   ██║██║   ██║   ██║     ██╔══╝  ██╔══██║██╔═██╗
 ╚██████╔╝██║   ██║   ███████╗███████╗██║  ██║██║  ██╗
  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## ✨ Fitur Utama

| Fitur | Keterangan |
|-------|-----------|
| 🐙 **GitHub Scan** | Scan seluruh repo GitHub publik (source + commit history) |
| 📦 **ZIP Scan** | Upload file `.zip` untuk scan offline |
| 📝 **Text Scan** | Paste teks/config langsung untuk dianalisis |
| 📊 **33 Pattern** | AWS, GCP, Azure, OpenAI, GitHub, JWT, SSH, database URL, dll |
| ⚡ **Fast** | 80 concurrent workers, pre-filter QUICK_FILTER_RE, streaming results |
| 📋 **Copy Buttons** | Copy secret / snippet / full detail finding (Secret · Line · Full) |
| 🔔 **Notifikasi** | Browser notification + Telegram alert setelah scan selesai |
| 📜 **History** | Riwayat scan tersimpan di localStorage |
| 🌐 **HTTPS Ready** | Auto-detect SSL: Cloudflare Origin Cert / Let's Encrypt / custom cert |

---

## 🚀 Cara Install

### Metode 1 — One-Line Installer (Direkomendasikan)

```bash
curl -fsSL https://raw.githubusercontent.com/pt-zenity/gitleak/main/install.sh | bash
```

Script ini otomatis:
- Install Node.js 18+ (jika belum ada)
- Install PM2 secara global
- Clone repo ke `~/gitleakhunter`
- Install dependencies (`npm install`)
- Build project (`npm run build`)
- Start server via PM2 (port 3000)

---

### Metode 2 — Manual Step-by-Step

#### Prasyarat
- **Node.js** v18 atau lebih baru → [nodejs.org](https://nodejs.org)
- **npm** v8+ (biasanya sudah bundled bersama Node.js)
- **Git** → [git-scm.com](https://git-scm.com)

#### Langkah Instalasi

```bash
# 1. Clone repositori
git clone https://github.com/pt-zenity/gitleak.git
cd gitleak

# 2. Install dependencies
npm install

# 3. Build project (kompilasi TypeScript → JavaScript)
npm run build

# 4. Jalankan server
npm start
```

Server berjalan di **http://localhost:3000**

---

### Metode 3 — Dengan PM2 (Production / Auto-restart)

PM2 menjaga server tetap berjalan bahkan setelah reboot atau crash.

```bash
# Install PM2 secara global (sekali saja)
npm install -g pm2

# Clone dan build
git clone https://github.com/pt-zenity/gitleak.git
cd gitleak
npm install
npm run build

# Start dengan PM2
pm2 start ecosystem.config.cjs

# (Opsional) Aktifkan auto-start saat sistem reboot
pm2 save
pm2 startup
# Jalankan perintah yang muncul dari output 'pm2 startup'
```

#### Perintah PM2 yang Berguna

```bash
pm2 status               # Cek status semua proses
pm2 logs gitleakhunter   # Lihat log real-time
pm2 logs --nostream      # Lihat log tanpa blocking
pm2 restart gitleakhunter # Restart server
pm2 stop gitleakhunter   # Stop server
pm2 delete gitleakhunter # Hapus dari PM2
```

---

### Metode 4 — Docker (Opsional)

```bash
# Build image
docker build -t gitleakhunter .

# Run container
docker run -d \
  --name gitleakhunter \
  -p 3000:3000 \
  --restart unless-stopped \
  gitleakhunter

# Akses di http://localhost:3000
```

---

## ⚙️ Konfigurasi

### Port

Edit file `ecosystem.config.cjs`, ubah nilai `HTTP_PORT`:

```js
env: {
  HTTP_PORT: 3000,   // ← ganti sesuai kebutuhan
  ...
}
```

Atau gunakan environment variable saat menjalankan langsung:

```bash
HTTP_PORT=8080 npm start
```

### HTTPS / SSL

GitLeakHunter mendukung 4 mode SSL, dikonfigurasi via `SSL_MODE`:

| Mode | Keterangan |
|------|-----------|
| `auto` | Auto-detect: Cloudflare Cert → Custom → Let's Encrypt → HTTP only |
| `cloudflare` | Cloudflare Origin Certificate (Full/Full Strict) |
| `letsencrypt` | Let's Encrypt (butuh domain publik) |
| `custom` | Sertifikat SSL kustom milik sendiri |
| `flexible` | HTTP only — Cloudflare handle HTTPS (Flexible SSL) |

#### Contoh: Cloudflare Origin Certificate

```js
// ecosystem.config.cjs
env: {
  SSL_MODE: 'cloudflare',
  CF_ORIGIN_KEY:  '/etc/ssl/cloudflare/origin.key',
  CF_ORIGIN_CERT: '/etc/ssl/cloudflare/origin.pem',
  HTTP_PORT:  80,
  HTTPS_PORT: 443,
}
```

> Download certificate dari: Cloudflare Dashboard → SSL/TLS → Origin Server → Create Certificate

#### Contoh: Let's Encrypt

```js
env: {
  SSL_MODE: 'letsencrypt',
  DOMAIN: 'scanner.yourdomain.com',
  HTTP_PORT:  80,
  HTTPS_PORT: 443,
}
```

#### Contoh: Custom Certificate

```js
env: {
  SSL_MODE: 'custom',
  SSL_KEY:  '/path/to/privkey.pem',
  SSL_CERT: '/path/to/fullchain.pem',
  HTTP_PORT:  80,
  HTTPS_PORT: 443,
}
```

---

## 📖 Cara Penggunaan

### 1. GitHub Scan
1. Buka browser ke `http://localhost:3000`
2. Tab **GitHub** sudah aktif secara default
3. Masukkan URL repositori GitHub, contoh:
   ```
   https://github.com/username/repo-name
   ```
4. Klik tombol **Scan Repository**
5. Tunggu proses scan — ada progress bar dengan estimasi tahap
6. Hasil muncul otomatis dengan severity: Critical / High / Medium / Low

### 2. ZIP Scan
1. Klik tab **ZIP**
2. Drag & drop file `.zip` atau klik untuk memilih file
3. Klik **Scan for Secrets**
4. Mendukung ZIP dari project apapun (Node.js, Python, Java, dll)

### 3. Text Scan
1. Klik tab **Text**
2. Paste konten file (`.env`, config, source code, dll)
3. Klik **Scan Content**
4. Hasil instan dalam < 1 detik

### 4. Tombol Copy di Hasil Scan
Setiap finding memiliki 3 tombol copy:
- **Secret** — copy nilai secret/token mentah
- **Line** — copy baris kode yang mengandung secret
- **Full** — copy detail lengkap (severity, file, line, category, matched, snippet)

### 5. Notifikasi Telegram (Opsional)
1. Buat bot via [@BotFather](https://t.me/BotFather) di Telegram
2. Dapatkan **Bot Token** dan **Chat ID**
3. Klik ikon ⚙️ (Settings) di pojok kanan atas
4. Masukkan Bot Token dan Chat ID
5. Klik **Test** untuk verifikasi
6. Aktifkan toggle **Auto-notify**

---

## 🔍 Pattern yang Dideteksi (33 total)

| Kategori | Pattern |
|----------|---------|
| ☁️ Cloud Credentials | AWS Access Key ID, AWS Secret Key, GCP API Key, Azure Storage Key |
| 🤖 AI Services | OpenAI API Key, Anthropic API Key |
| 🐙 Version Control | GitHub Personal Token, GitHub OAuth, GitLab Token |
| 💳 Payment | Stripe Secret Key, Stripe Publishable Key |
| 💬 Communication | Slack Bot Token, Slack Webhook, Twilio Credentials, SendGrid Key |
| 🔑 Generic | Generic API Key, Generic Secret, Generic Password, Generic Token |
| 📜 Crypto | RSA Private Key, DSA Private Key, EC Private Key, PGP Key |
| 🗃️ Database | Database Connection URL (PostgreSQL, MySQL, MongoDB, Redis) |
| 🔒 Auth | JWT Token, Basic Auth Credentials |
| 🎫 Other | Heroku API Key, NPM Token, Firebase Key, Mailgun Key, Twilio Token |

---

## 🏗️ Struktur Proyek

```
gitleakhunter/
├── src/
│   ├── index.tsx      # Backend API (Hono) + Frontend HTML/JS (semua dalam 1 file)
│   └── server.ts      # Node.js HTTP/HTTPS server dengan SSL support
├── dist/              # Output build TypeScript (di-generate oleh npm run build)
│   ├── index.js       # Compiled backend + frontend
│   └── server.js      # Compiled server
├── public/            # Static assets
├── ecosystem.config.cjs  # Konfigurasi PM2
├── install.sh         # One-line installer script
├── package.json       # Dependencies
├── tsconfig.json      # TypeScript config
└── README.md          # Dokumentasi ini
```

---

## 🛠️ Development

```bash
# Mode development dengan hot-reload
npm run dev

# Build ulang setelah perubahan
npm run build

# Jalankan hasil build
npm start
```

---

## 📋 Requirements

| Dependency | Versi Minimum | Keterangan |
|-----------|---------------|-----------|
| Node.js | v18.0.0 | Runtime JavaScript |
| npm | v8.0.0 | Package manager |
| Hono | v4.12.7 | Web framework |
| @hono/node-server | v1.13.7 | Node.js adapter |

---

## 🔗 Links

- **Repository**: https://github.com/pt-zenity/gitleak
- **Issues**: https://github.com/pt-zenity/gitleak/issues

---

## 📄 License

MIT License — bebas digunakan, dimodifikasi, dan didistribusikan.
