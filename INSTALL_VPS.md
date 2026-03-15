# 🚀 Panduan Install GitLeakHunter di VPS Ubuntu — Dari Awal Hingga Selesai

Repository: https://github.com/pt-zenity/gitleak

---

## 📋 Daftar Isi
1. [Persiapan VPS](#1-persiapan-vps)
2. [Masuk ke VPS via SSH](#2-masuk-ke-vps-via-ssh)
3. [Setup Awal Server](#3-setup-awal-server)
4. [Install Node.js v24 via nvm](#4-install-nodejs-v24-via-nvm)
5. [Install PM2](#5-install-pm2)
6. [Clone & Build Aplikasi](#6-clone--build-aplikasi)
7. [Jalankan Aplikasi](#7-jalankan-aplikasi)
8. [Buka Firewall](#8-buka-firewall)
9. [Test Akses](#9-test-akses)
10. [Setup Domain + HTTPS dengan Nginx](#10-setup-domain--https-dengan-nginx)
11. [Auto-start saat Reboot](#11-auto-start-saat-reboot)
12. [Perintah Sehari-hari](#12-perintah-sehari-hari)
13. [Update Aplikasi](#13-update-aplikasi)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Persiapan VPS

### Spesifikasi Minimum
| Komponen | Minimum | Rekomendasi |
|----------|---------|-------------|
| OS       | Ubuntu 20.04 LTS | Ubuntu 22.04 / 24.04 LTS |
| RAM      | 512 MB | 1 GB |
| CPU      | 1 vCPU | 1-2 vCPU |
| Storage  | 5 GB | 10 GB |
| Port     | 22, 3000 | 22, 80, 443 |

### Provider VPS yang Bisa Digunakan
- **DigitalOcean** → Droplet $6/bulan (1GB RAM)
- **Vultr** → Cloud Compute $6/bulan
- **Hetzner** → CX11 €4/bulan (2GB RAM, paling murah)
- **Contabo** → €5/bulan (4GB RAM)
- **Linode/Akamai** → Nanode $5/bulan
- **AWS EC2** → t2.micro (free tier 1 tahun)
- **Google Cloud** → e2-micro (free tier)

### Saat Order VPS, pilih:
- OS: **Ubuntu 22.04 LTS** atau **Ubuntu 24.04 LTS**
- Authentication: **SSH Key** (lebih aman) atau password

---

## 2. Masuk ke VPS via SSH

### Dari Linux / macOS:
```bash
ssh root@IP_VPS_ANDA
# Contoh:
ssh root@103.23.45.67
```

### Dari Windows:
Gunakan **PuTTY** atau **Windows Terminal**:
```
Host: IP_VPS_ANDA
Port: 22
Username: root
```

### Jika menggunakan SSH Key:
```bash
ssh -i ~/.ssh/id_rsa root@IP_VPS_ANDA
```

---

## 3. Setup Awal Server

### 3.1 Update sistem
```bash
apt update && apt upgrade -y
```

### 3.2 Install paket dasar
```bash
apt install -y curl git wget unzip ufw nano htop
```

### 3.3 Buat user baru (opsional tapi direkomendasikan — jangan pakai root)
```bash
# Buat user baru
adduser deploy
# Masukkan password saat diminta

# Beri akses sudo
usermod -aG sudo deploy

# Login sebagai user baru
su - deploy
```

> Jika memilih buat user baru, semua perintah selanjutnya dijalankan sebagai user **deploy** (bukan root).

---

## 4. Install Node.js v24 via nvm

### 4.1 Install nvm (Node Version Manager)
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
```

### 4.2 Aktifkan nvm di sesi saat ini
```bash
source ~/.bashrc
```

### 4.3 Verifikasi nvm
```bash
nvm --version
# Output: 0.40.3
```

### 4.4 Install Node.js v24 LTS
```bash
nvm install --lts
```

Output yang diharapkan:
```
Installing latest LTS version.
Downloading and installing node v24.14.0...
Now using node v24.14.0 (npm v11.9.0)
```

### 4.5 Set v24 sebagai default
```bash
nvm alias default lts/*
nvm use default
```

### 4.6 Verifikasi
```bash
node --version
# v24.14.0

npm --version
# 11.9.0
```

---

## 5. Install PM2

PM2 adalah process manager yang menjaga aplikasi tetap berjalan.

```bash
npm install -g pm2
```

Verifikasi:
```bash
pm2 --version
# 6.x.x
```

---

## 6. Clone & Build Aplikasi

### 6.1 Clone repository
```bash
git clone https://github.com/pt-zenity/gitleak.git ~/gitleakhunter
```

### 6.2 Masuk ke direktori
```bash
cd ~/gitleakhunter
```

### 6.3 Install dependencies
```bash
npm install
```

### 6.4 Build project (kompilasi TypeScript)
```bash
npm run build
```

Output yang diharapkan:
```
> build
> tsc -p tsconfig.build.json
```
(tidak ada error = berhasil)

### 6.5 Verifikasi hasil build
```bash
ls dist/
# index.js  renderer.js  server.js
```

---

## 7. Jalankan Aplikasi

### 7.1 Jalankan dengan PM2
```bash
pm2 start ecosystem.config.cjs
```

### 7.2 Cek status
```bash
pm2 status
```

Output yang diharapkan:
```
┌────┬──────────────────┬─────────┬──────────┬────────┬───────────┐
│ id │ name             │ mode    │ pid      │ uptime │ status    │
├────┼──────────────────┼─────────┼──────────┼────────┼───────────┤
│ 0  │ gitleakhunter    │ fork    │ 12345    │ 5s     │ online    │
└────┴──────────────────┴─────────┴──────────┴────────┴───────────┘
```

### 7.3 Lihat log untuk memastikan berjalan
```bash
pm2 logs gitleakhunter --nostream --lines 20
```

Output yang diharapkan:
```
GitLeakHunter running at http://0.0.0.0:3000
```

### 7.4 Test dari dalam VPS
```bash
curl http://localhost:3000/api/patterns | python3 -c "import sys,json; print('Patterns:', len(json.load(sys.stdin)))"
# Patterns: 33
```

---

## 8. Buka Firewall

### 8.1 Aktifkan UFW
```bash
sudo ufw enable
```

### 8.2 Izinkan SSH (PENTING — jangan sampai terkunci!)
```bash
sudo ufw allow OpenSSH
# atau
sudo ufw allow 22/tcp
```

### 8.3 Izinkan port aplikasi

**Jika akses langsung via port 3000:**
```bash
sudo ufw allow 3000/tcp
```

**Jika menggunakan Nginx (port 80/443):**
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

### 8.4 Cek status firewall
```bash
sudo ufw status
```

---

## 9. Test Akses

### Dari browser:
```
http://IP_VPS_ANDA:3000
```

### Dari terminal (di komputer lokal):
```bash
curl http://IP_VPS_ANDA:3000/api/patterns
```

Jika berhasil, browser menampilkan tampilan GitLeakHunter. ✅

---

## 10. Setup Domain + HTTPS dengan Nginx

> Lakukan ini jika punya domain. Jika tidak, lewati bagian ini.

### 10.1 Arahkan DNS domain ke IP VPS

Di panel DNS domain kamu, buat record:
```
Type : A
Name : @ (atau subdomain, misal: scanner)
Value: IP_VPS_ANDA
TTL  : 300
```

Tunggu propagasi DNS (biasanya 1-5 menit jika menggunakan Cloudflare, hingga 24 jam untuk DNS biasa).

### 10.2 Install Nginx
```bash
sudo apt install -y nginx
```

### 10.3 Buat konfigurasi Nginx
```bash
sudo nano /etc/nginx/sites-available/gitleakhunter
```

Isi dengan (ganti `domain.anda.com`):
```nginx
server {
    listen 80;
    server_name domain.anda.com;

    # Redirect ke HTTPS (akan diisi certbot otomatis)
    location / {
        proxy_pass         http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection 'upgrade';
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

Simpan: `Ctrl+X` → `Y` → `Enter`

### 10.4 Aktifkan konfigurasi
```bash
sudo ln -s /etc/nginx/sites-available/gitleakhunter /etc/nginx/sites-enabled/
sudo nginx -t
# nginx: configuration file /etc/nginx/nginx.conf test is successful
sudo systemctl reload nginx
```

### 10.5 Install SSL Certificate (Let's Encrypt — gratis)
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d domain.anda.com
```

Ikuti instruksi:
- Masukkan email
- Setuju Terms of Service: `Y`
- Pilih redirect HTTP → HTTPS: `2`

### 10.6 Verifikasi HTTPS
```bash
curl https://domain.anda.com/api/patterns
```

Atau buka browser: `https://domain.anda.com` ✅

### 10.7 Auto-renew SSL Certificate
Certbot otomatis mengatur cron job, tapi bisa verifikasi:
```bash
sudo certbot renew --dry-run
```

---

## 11. Auto-start saat Reboot

Agar aplikasi otomatis berjalan kembali setelah VPS restart:

```bash
pm2 save
pm2 startup
```

Output `pm2 startup` akan memberikan perintah seperti:
```
sudo env PATH=$PATH:/home/deploy/.nvm/versions/node/v24.14.0/bin \
  /home/deploy/.nvm/versions/node/v24.14.0/lib/node_modules/pm2/bin/pm2 \
  startup systemd -u deploy --hp /home/deploy
```

**Copy dan jalankan perintah tersebut** (sesuai output di terminal kamu):
```bash
# Jalankan perintah yang muncul dari pm2 startup
sudo env PATH=... pm2 startup systemd ...
```

Simpan konfigurasi:
```bash
pm2 save
```

### Test auto-start
```bash
sudo reboot
```

Setelah VPS hidup kembali (tunggu ~30 detik), SSH lagi dan cek:
```bash
pm2 status
```

---

## 12. Perintah Sehari-hari

```bash
# Cek status aplikasi
pm2 status

# Lihat log live (Ctrl+C untuk keluar)
pm2 logs gitleakhunter

# Lihat log tanpa blocking
pm2 logs gitleakhunter --nostream --lines 50

# Restart aplikasi
pm2 restart gitleakhunter

# Stop aplikasi
pm2 stop gitleakhunter

# Start aplikasi
pm2 start gitleakhunter

# Monitor resource (CPU/RAM)
pm2 monit

# Reload Nginx setelah edit config
sudo systemctl reload nginx

# Cek status Nginx
sudo systemctl status nginx

# Cek port yang dipakai
sudo ss -tlnp | grep -E '3000|80|443'
```

---

## 13. Update Aplikasi

Setiap ada update di GitHub, jalankan ini di VPS:

```bash
cd ~/gitleakhunter

# Pull kode terbaru
git pull origin main

# Install dependencies baru (jika ada)
npm install

# Build ulang
npm run build

# Restart aplikasi
pm2 restart gitleakhunter

# Cek status
pm2 status
```

Atau buat alias biar mudah:
```bash
echo 'alias update-gitleak="cd ~/gitleakhunter && git pull && npm install && npm run build && pm2 restart gitleakhunter"' >> ~/.bashrc
source ~/.bashrc

# Gunakan dengan:
update-gitleak
```

---

## 14. Troubleshooting

### ❌ "Connection refused" saat akses dari browser

```bash
# Cek apakah server berjalan
pm2 status

# Cek apakah port 3000 listening
sudo ss -tlnp | grep 3000

# Cek firewall
sudo ufw status

# Cek log error
pm2 logs gitleakhunter --nostream --lines 30
```

### ❌ PM2 status "errored" atau "stopped"

```bash
# Lihat log error
pm2 logs gitleakhunter --err --nostream --lines 30

# Cek apakah dist/ ada
ls ~/gitleakhunter/dist/

# Build ulang jika dist/ kosong
cd ~/gitleakhunter && npm run build

# Restart
pm2 restart gitleakhunter
```

### ❌ "nvm: command not found" setelah login ulang

```bash
# Load nvm manual
source ~/.bashrc
# atau
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
```

Jika masalah berlanjut, tambahkan ke `~/.bashrc`:
```bash
echo 'export NVM_DIR="$HOME/.nvm"' >> ~/.bashrc
echo '[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"' >> ~/.bashrc
source ~/.bashrc
```

### ❌ Port 80/443 "Permission denied"

Port di bawah 1024 butuh akses root. Gunakan Nginx sebagai reverse proxy (lihat bagian 10), atau:
```bash
# Beri izin node untuk bind port rendah
sudo setcap 'cap_net_bind_service=+ep' $(which node)
```

### ❌ Nginx "502 Bad Gateway"

```bash
# Pastikan aplikasi berjalan di port 3000
pm2 status
curl http://localhost:3000

# Cek config Nginx
sudo nginx -t

# Cek log Nginx
sudo tail -f /var/log/nginx/error.log
```

### ❌ SSL Certificate gagal (Let's Encrypt)

```bash
# Pastikan DNS sudah pointing ke IP VPS
dig +short domain.anda.com

# Pastikan port 80 terbuka
sudo ufw allow 80/tcp

# Coba lagi
sudo certbot --nginx -d domain.anda.com
```

### ❌ Scan GitHub lambat / timeout

Tambahkan GitHub Personal Access Token (opsional, meningkatkan rate limit dari 60 → 5000 req/jam):
```bash
# Edit ecosystem config
nano ~/gitleakhunter/ecosystem.config.cjs
```

Tambahkan di bagian `env`:
```js
GITHUB_TOKEN: 'ghp_xxxxxxxxxxxxxxxxxxxxx',
```

Restart:
```bash
pm2 restart gitleakhunter
```

---

## ✅ Checklist Instalasi

- [ ] VPS Ubuntu 22.04/24.04 aktif
- [ ] SSH berhasil masuk
- [ ] `apt update && apt upgrade` selesai
- [ ] nvm terinstall (`nvm --version`)
- [ ] Node.js v24 aktif (`node -v`)
- [ ] PM2 terinstall (`pm2 --version`)
- [ ] Repository ter-clone (`ls ~/gitleakhunter`)
- [ ] Build berhasil (`ls ~/gitleakhunter/dist/`)
- [ ] PM2 status **online** (`pm2 status`)
- [ ] Bisa akses `http://IP:3000` dari browser
- [ ] Firewall dikonfigurasi (`ufw status`)
- [ ] (Opsional) Domain pointing ke VPS
- [ ] (Opsional) Nginx reverse proxy aktif
- [ ] (Opsional) SSL certificate terpasang
- [ ] (Opsional) Auto-start dikonfigurasi (`pm2 startup`)
