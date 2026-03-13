#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║             GitLeakHunter — Local Auto Install Script                  ║
# ║         Jalankan di server / VPS / localhost tanpa Cloudflare          ║
# ║   Supports: Ubuntu/Debian · CentOS/RHEL · Arch Linux · Alpine · macOS ║
# ╚══════════════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Warna terminal ──────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m';    NC='\033[0m'

ok()   { echo -e "${GREEN}  ✅  $*${NC}"; }
info() { echo -e "${CYAN}  ℹ   $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠   $*${NC}"; }
err()  { echo -e "${RED}  ❌  $*${NC}"; }
step() { echo -e "\n${BOLD}${BLUE}┌─── $* ───────────────────────────────────────┐${NC}"; }
done_step() { echo -e "${BOLD}${BLUE}└──────────────────────────────────────────────┘${NC}"; }

# ─── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}${RED}"
cat << 'BANNER'
  ██████╗ ██╗████████╗██╗     ███████╗ █████╗ ██╗  ██╗
 ██╔════╝ ██║╚══██╔══╝██║     ██╔════╝██╔══██╗██║ ██╔╝
 ██║  ███╗██║   ██║   ██║     █████╗  ███████║█████╔╝
 ██║   ██║██║   ██║   ██║     ██╔══╝  ██╔══██║██╔═██╗
 ╚██████╔╝██║   ██║   ███████╗███████╗██║  ██║██║  ██╗
  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
     H U N T E R  —  G i t  S e c r e t  S c a n n e r
BANNER
echo -e "${NC}${BOLD}         Local Install (Node.js + PM2) — v2.0${NC}"
echo -e "${CYAN}   https://github.com/pt-zenity/gitleak${NC}\n"

# ─── Konfigurasi default (bisa di-override lewat env / argumen) ──────────────
REPO_URL="https://github.com/pt-zenity/gitleak.git"
APP_DIR="${INSTALL_DIR:-$HOME/gitleakhunter}"
APP_PORT="${PORT:-3000}"
APP_NAME="gitleakhunter"
APP_DOMAIN=""
SSL_EMAIL=""
NODE_MIN=18

# ─── Parse argumen ───────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --port=*)    APP_PORT="${arg#*=}" ;;
    --dir=*)     APP_DIR="${arg#*=}" ;;
    --domain=*)  APP_DOMAIN="${arg#*=}" ;;
    --email=*)   SSL_EMAIL="${arg#*=}" ;;
    --uninstall|-u)
      echo -e "\n${BOLD}${RED}Uninstall GitLeakHunter...${NC}"
      pm2 delete "$APP_NAME" 2>/dev/null && ok "PM2 process dihapus" || true
      pm2 save --force 2>/dev/null || true
      if [ -d "$APP_DIR" ]; then
        rm -rf "$APP_DIR"
        ok "Direktori $APP_DIR dihapus"
      fi
      # Hapus konfigurasi Nginx jika ada
      if [ -f "/etc/nginx/sites-enabled/${APP_NAME}" ]; then
        run_sudo rm -f "/etc/nginx/sites-enabled/${APP_NAME}" 2>/dev/null || true
        run_sudo rm -f "/etc/nginx/sites-available/${APP_NAME}" 2>/dev/null || true
        run_sudo systemctl reload nginx 2>/dev/null || true
        ok "Konfigurasi Nginx dihapus"
      fi
      if [ -f "/etc/nginx/conf.d/${APP_NAME}.conf" ]; then
        run_sudo rm -f "/etc/nginx/conf.d/${APP_NAME}.conf" 2>/dev/null || true
        run_sudo systemctl reload nginx 2>/dev/null || true
        ok "Konfigurasi Nginx dihapus"
      fi
      ok "GitLeakHunter berhasil diuninstall"
      exit 0
      ;;
    --update|-U)
      echo -e "\n${BOLD}${CYAN}Update GitLeakHunter ke versi terbaru...${NC}"
      if [ ! -d "$APP_DIR/.git" ]; then
        err "Direktori $APP_DIR tidak ditemukan. Jalankan install terlebih dahulu."
        exit 1
      fi
      git -C "$APP_DIR" pull --quiet origin main
      cd "$APP_DIR" && npm install --quiet --no-audit --no-fund
      npm run build --quiet
      pm2 restart "$APP_NAME" --update-env 2>/dev/null || pm2 start ecosystem.config.cjs
      pm2 save --force --quiet
      ok "Update selesai! Versi terbaru sudah berjalan."
      exit 0
      ;;
    --help|-h)
      echo -e "${BOLD}Penggunaan:${NC} bash install-local.sh [opsi]\n"
      echo -e "  ${CYAN}(tanpa opsi)${NC}              Install & jalankan di port 3000"
      echo -e "  ${CYAN}--port=NNNN${NC}               Ganti port (default: 3000)"
      echo -e "  ${CYAN}--dir=/path${NC}               Ganti direktori install (default: ~/gitleakhunter)"
      echo -e "  ${CYAN}--domain=example.com${NC}      Setup domain + Nginx reverse proxy"
      echo -e "  ${CYAN}--email=user@example.com${NC}  Email untuk SSL certificate (Let's Encrypt)"
      echo -e "  ${CYAN}--update${NC}                  Update ke versi terbaru dari GitHub"
      echo -e "  ${CYAN}--uninstall${NC}               Hapus GitLeakHunter & stop PM2 process"
      echo -e "  ${CYAN}--help${NC}                    Tampilkan bantuan ini\n"
      echo -e "${BOLD}Contoh:${NC}"
      echo -e "  ${CYAN}bash install-local.sh${NC}"
      echo -e "  ${CYAN}bash install-local.sh --port=8080${NC}"
      echo -e "  ${CYAN}bash install-local.sh --dir=/opt/gitleakhunter${NC}"
      echo -e "  ${CYAN}bash install-local.sh --domain=scan.example.com${NC}"
      echo -e "  ${CYAN}bash install-local.sh --domain=scan.example.com --email=admin@example.com${NC}"
      echo -e "  ${CYAN}bash install-local.sh --update${NC}"
      exit 0
      ;;
  esac
done

# ─── Deteksi OS ──────────────────────────────────────────────────────────────
step "Deteksi sistem operasi"
OS="unknown"
if [[ "${OSTYPE:-}" == "darwin"* ]]; then
  OS="macos"
elif [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian|linuxmint|pop|kali|raspbian) OS="debian" ;;
    centos|rhel|fedora|rocky|almalinux|ol)     OS="rhel"   ;;
    arch|manjaro|endeavouros|garuda)            OS="arch"   ;;
    alpine)                                     OS="alpine" ;;
    opensuse*|sles)                             OS="suse"   ;;
  esac
fi
info "OS terdeteksi: ${BOLD}${OS}${NC}"
done_step

# ─── Cek apakah bisa sudo ─────────────────────────────────────────────────────
CAN_SUDO=false
if sudo -n true 2>/dev/null; then
  CAN_SUDO=true
elif [ "$(id -u)" -eq 0 ]; then
  CAN_SUDO=true   # running as root
fi

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif $CAN_SUDO; then
    sudo "$@"
  else
    warn "Perlu sudo untuk: $*"
    warn "Jalankan ulang sebagai root atau dengan sudo"
    return 1
  fi
}

# ─── Install Git ─────────────────────────────────────────────────────────────
step "Memeriksa Git"
if command -v git &>/dev/null; then
  ok "Git $(git --version | awk '{print $3}') sudah terinstall"
else
  info "Menginstall Git..."
  case "$OS" in
    debian) run_sudo apt-get update -qq && run_sudo apt-get install -y -qq git ;;
    rhel)   run_sudo yum install -y -q git 2>/dev/null || run_sudo dnf install -y -q git ;;
    arch)   run_sudo pacman -Sy --noconfirm --quiet git ;;
    alpine) run_sudo apk add --no-cache -q git ;;
    suse)   run_sudo zypper install -y -q git ;;
    macos)
      if command -v brew &>/dev/null; then brew install -q git
      else err "Install Homebrew dulu: https://brew.sh"; exit 1; fi
      ;;
    *) err "OS tidak dikenali. Install Git manual: https://git-scm.com"; exit 1 ;;
  esac
  ok "Git $(git --version | awk '{print $3}') berhasil diinstall"
fi
done_step

# ─── Install Node.js ─────────────────────────────────────────────────────────
step "Memeriksa Node.js (diperlukan v${NODE_MIN}+)"
NEED_NODE=false
if command -v node &>/dev/null; then
  CURRENT_NODE=$(node -v | sed 's/v//' | cut -d. -f1)
  if [ "$CURRENT_NODE" -ge "$NODE_MIN" ] 2>/dev/null; then
    ok "Node.js $(node -v) sudah terinstall"
  else
    warn "Node.js $(node -v) terlalu lama — perlu upgrade ke v${NODE_MIN}+"
    NEED_NODE=true
  fi
else
  info "Node.js belum terinstall"
  NEED_NODE=true
fi

if $NEED_NODE; then
  info "Menginstall Node.js v22 (LTS)..."
  case "$OS" in
    debian)
      run_sudo apt-get install -y -qq curl ca-certificates gnupg
      curl -fsSL https://deb.nodesource.com/setup_22.x | run_sudo -E bash - 2>/dev/null
      run_sudo apt-get install -y -qq nodejs
      ;;
    rhel)
      curl -fsSL https://rpm.nodesource.com/setup_22.x | run_sudo bash - 2>/dev/null
      run_sudo yum install -y -q nodejs npm 2>/dev/null || \
        run_sudo dnf install -y -q nodejs npm
      ;;
    arch)
      run_sudo pacman -Sy --noconfirm --quiet nodejs npm
      ;;
    alpine)
      run_sudo apk add --no-cache -q nodejs npm
      ;;
    suse)
      run_sudo zypper install -y -q nodejs npm
      ;;
    macos)
      if command -v brew &>/dev/null; then brew install -q node
      else err "Install Homebrew dulu: https://brew.sh"; exit 1; fi
      ;;
    *)
      err "OS tidak dikenali. Install Node.js manual: https://nodejs.org"
      exit 1
      ;;
  esac
  ok "Node.js $(node -v) berhasil diinstall"
fi
done_step

# ─── Install PM2 ─────────────────────────────────────────────────────────────
step "Memeriksa PM2 (process manager)"
if command -v pm2 &>/dev/null; then
  ok "PM2 $(pm2 -v) sudah terinstall"
else
  info "Menginstall PM2 secara global..."
  npm install -g pm2 --quiet --no-audit --no-fund
  ok "PM2 $(pm2 -v) berhasil diinstall"
fi
done_step

# ─── Clone atau Update repo ───────────────────────────────────────────────────
step "Menyiapkan repository"
if [ -d "$APP_DIR/.git" ]; then
  info "Repository sudah ada di ${APP_DIR} — pulling update..."
  git -C "$APP_DIR" fetch --quiet origin
  git -C "$APP_DIR" reset --hard origin/main --quiet
  ok "Repository diperbarui ke versi terbaru"
else
  info "Cloning dari ${REPO_URL}..."
  git clone --depth 1 "$REPO_URL" "$APP_DIR" --quiet
  ok "Repository berhasil di-clone ke ${APP_DIR}"
fi
done_step

# ─── Install dependencies ─────────────────────────────────────────────────────
step "Menginstall dependensi Node.js"
cd "$APP_DIR"
npm install --quiet --no-audit --no-fund
ok "Dependensi berhasil diinstall"
done_step

# ─── Build project ────────────────────────────────────────────────────────────
step "Build project"
cd "$APP_DIR"
npm run build
ok "Build selesai → dist/"
done_step

# ─── Tulis ecosystem PM2 ─────────────────────────────────────────────────────
step "Membuat konfigurasi PM2"
cat > "$APP_DIR/ecosystem.config.cjs" << ECOEOF
module.exports = {
  apps: [
    {
      name: '${APP_NAME}',
      script: 'npx',
      args: 'wrangler pages dev dist --ip 0.0.0.0 --port ${APP_PORT}',
      cwd: '${APP_DIR}',
      env: {
        NODE_ENV: 'production',
        PORT: ${APP_PORT},
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 15,
      restart_delay: 3000,
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
    }
  ]
}
ECOEOF
ok "Konfigurasi PM2 ditulis ke ecosystem.config.cjs"
done_step

# ─── Jalankan dengan PM2 ─────────────────────────────────────────────────────
step "Menjalankan GitLeakHunter"

# Bebaskan port jika sudah terpakai
if command -v fuser &>/dev/null; then
  fuser -k "${APP_PORT}/tcp" 2>/dev/null || true
elif command -v lsof &>/dev/null; then
  lsof -ti:"${APP_PORT}" | xargs kill -9 2>/dev/null || true
fi

# Hapus proses lama jika ada
pm2 delete "$APP_NAME" 2>/dev/null || true
sleep 1

# Start
cd "$APP_DIR"
pm2 start ecosystem.config.cjs
sleep 5

# Health check
if pm2 show "$APP_NAME" 2>/dev/null | grep -q "online"; then
  ok "GitLeakHunter berjalan via PM2 ✨"
else
  warn "Proses mungkin belum online — cek log:"
  pm2 logs "$APP_NAME" --nostream --lines 15 2>/dev/null || true
fi

# Simpan daftar proses PM2
pm2 save --force 2>/dev/null || true
done_step

# ─── Auto-start saat reboot ───────────────────────────────────────────────────
step "Mengatur auto-start saat sistem reboot"
STARTUP_OUT=$(pm2 startup 2>&1 || true)
STARTUP_CMD=$(echo "$STARTUP_OUT" | grep -E "^sudo " | head -1 | xargs 2>/dev/null || true)
if [ -n "$STARTUP_CMD" ]; then
  if eval "$STARTUP_CMD" 2>/dev/null; then
    ok "Auto-start dikonfigurasi — PM2 akan otomatis jalan saat reboot"
  else
    warn "Tidak bisa set auto-start otomatis. Jalankan manual:"
    echo -e "  ${CYAN}${STARTUP_CMD}${NC}"
  fi
else
  warn "Auto-start sudah dikonfigurasi sebelumnya atau perlu konfigurasi manual"
fi
pm2 save --force 2>/dev/null || true
done_step

# ─── Setup Domain + Nginx + SSL (opsional) ───────────────────────────────────
setup_nginx() {
  local domain="$1"
  local port="$2"
  local email="${3:-}"

  step "Setup Nginx untuk domain: ${domain}"

  # Cek apakah OS mendukung Nginx (bukan macOS tanpa brew)
  if [ "$OS" = "macos" ]; then
    if ! command -v brew &>/dev/null; then
      warn "macOS tanpa Homebrew — skip Nginx setup"
      return
    fi
  fi

  # Install Nginx
  if ! command -v nginx &>/dev/null; then
    info "Menginstall Nginx..."
    case "$OS" in
      debian) run_sudo apt-get install -y -qq nginx ;;
      rhel)   run_sudo yum install -y -q nginx 2>/dev/null || run_sudo dnf install -y -q nginx ;;
      arch)   run_sudo pacman -Sy --noconfirm --quiet nginx ;;
      alpine) run_sudo apk add --no-cache -q nginx ;;
      suse)   run_sudo zypper install -y -q nginx ;;
      macos)  brew install -q nginx ;;
      *)      warn "OS tidak mendukung Nginx auto-install. Install manual." ; return ;;
    esac
    ok "Nginx berhasil diinstall"
  else
    ok "Nginx $(nginx -v 2>&1 | awk -F/ '{print $2}') sudah terinstall"
  fi

  # Deteksi direktori konfigurasi Nginx
  NGINX_CONF_DIR=""
  NGINX_ENABLED_DIR=""
  if [ -d "/etc/nginx/sites-available" ]; then
    # Debian/Ubuntu style
    NGINX_CONF_DIR="/etc/nginx/sites-available"
    NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
  elif [ -d "/etc/nginx/conf.d" ]; then
    # RHEL/CentOS/Arch style
    NGINX_CONF_DIR="/etc/nginx/conf.d"
    NGINX_ENABLED_DIR=""
  else
    warn "Direktori konfigurasi Nginx tidak ditemukan. Skip setup Nginx."
    return
  fi

  # Tulis konfigurasi Nginx (HTTP dulu, SSL nanti via Certbot)
  NGINX_SITE_FILE="${NGINX_CONF_DIR}/${APP_NAME}"
  [ -n "$NGINX_ENABLED_DIR" ] || NGINX_SITE_FILE="${NGINX_CONF_DIR}/${APP_NAME}.conf"

  info "Menulis konfigurasi Nginx ke ${NGINX_SITE_FILE}..."
  run_sudo tee "$NGINX_SITE_FILE" > /dev/null << NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain} www.${domain};

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Proxy ke GitLeakHunter
    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        client_max_body_size 1100m;
    }

    # Log
    access_log /var/log/nginx/${APP_NAME}_access.log;
    error_log  /var/log/nginx/${APP_NAME}_error.log;
}
NGINXEOF

  ok "Konfigurasi Nginx ditulis"

  # Aktifkan site (Debian/Ubuntu style)
  if [ -n "$NGINX_ENABLED_DIR" ]; then
    run_sudo ln -sf "$NGINX_SITE_FILE" "${NGINX_ENABLED_DIR}/${APP_NAME}" 2>/dev/null || true
    # Hapus default site yang mungkin bentrok
    run_sudo rm -f "${NGINX_ENABLED_DIR}/default" 2>/dev/null || true
    ok "Site diaktifkan di sites-enabled"
  fi

  # Test & reload Nginx
  if run_sudo nginx -t 2>/dev/null; then
    run_sudo systemctl enable nginx 2>/dev/null || true
    run_sudo systemctl restart nginx 2>/dev/null || run_sudo service nginx restart 2>/dev/null || true
    ok "Nginx di-reload dengan konfigurasi baru"
  else
    err "Konfigurasi Nginx gagal! Cek dengan: sudo nginx -t"
    return
  fi

  done_step

  # ─── Install SSL dengan Certbot ────────────────────────────────────────────
  step "Setup SSL (Let's Encrypt) untuk ${domain}"

  if [ "$OS" = "macos" ]; then
    warn "macOS terdeteksi — SSL via Certbot tidak disetup otomatis."
    info "Untuk SSL di macOS, gunakan mkcert: https://github.com/FiloSottile/mkcert"
    done_step
    return
  fi

  if [ "$OS" = "alpine" ]; then
    warn "Alpine Linux — SSL via Certbot perlu setup manual."
    info "Jalankan: apk add certbot certbot-nginx && certbot --nginx -d ${domain}"
    done_step
    return
  fi

  # Install Certbot
  if ! command -v certbot &>/dev/null; then
    info "Menginstall Certbot..."
    case "$OS" in
      debian)
        run_sudo apt-get install -y -qq certbot python3-certbot-nginx
        ;;
      rhel)
        run_sudo yum install -y -q epel-release 2>/dev/null || run_sudo dnf install -y -q epel-release 2>/dev/null || true
        run_sudo yum install -y -q certbot python3-certbot-nginx 2>/dev/null || \
          run_sudo dnf install -y -q certbot python3-certbot-nginx
        ;;
      arch)
        run_sudo pacman -Sy --noconfirm --quiet certbot certbot-nginx
        ;;
      suse)
        run_sudo zypper install -y -q certbot python3-certbot-nginx 2>/dev/null || \
          warn "Certbot tidak tersedia di zypper — install manual: https://certbot.eff.org"
        ;;
    esac
    ok "Certbot berhasil diinstall"
  else
    ok "Certbot $(certbot --version 2>&1 | awk '{print $2}') sudah terinstall"
  fi

  # Jalankan Certbot
  if command -v certbot &>/dev/null; then
    info "Meminta SSL certificate untuk ${domain}..."
    CERTBOT_OPTS="--nginx -d ${domain} -d www.${domain} --redirect --agree-tos --non-interactive"
    if [ -n "$email" ]; then
      CERTBOT_OPTS="$CERTBOT_OPTS --email ${email}"
    else
      CERTBOT_OPTS="$CERTBOT_OPTS --register-unsafely-without-email"
    fi

    if run_sudo certbot $CERTBOT_OPTS 2>/dev/null; then
      ok "SSL certificate berhasil dipasang untuk ${domain}"
      ok "HTTPS aktif! Certbot akan auto-renew setiap 90 hari."
    else
      warn "Certbot gagal mendapatkan certificate."
      warn "Kemungkinan DNS belum mengarah ke server ini."
      warn "Setelah DNS aktif, jalankan manual:"
      if [ -n "$email" ]; then
        echo -e "  ${CYAN}sudo certbot --nginx -d ${domain} -d www.${domain} --email ${email} --agree-tos --non-interactive --redirect${NC}"
      else
        echo -e "  ${CYAN}sudo certbot --nginx -d ${domain} -d www.${domain} --agree-tos --non-interactive --redirect${NC}"
      fi
    fi
  fi

  done_step
}

# Jalankan setup domain jika --domain diberikan
if [ -n "$APP_DOMAIN" ]; then
  setup_nginx "$APP_DOMAIN" "$APP_PORT" "$SSL_EMAIL"
fi

# ─── Verifikasi port tersedia ─────────────────────────────────────────────────
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${APP_PORT}/" 2>/dev/null || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
  ok "HTTP check: 200 OK — aplikasi merespons dengan baik"
else
  warn "HTTP check mengembalikan status ${HTTP_STATUS} (mungkin masih starting up)"
fi

# ─── Ringkasan akhir ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║        GitLeakHunter berhasil diinstall! 🎉              ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}🌐 Akses lokal:${NC}      ${BOLD}${CYAN}http://localhost:${APP_PORT}${NC}"

# Jika domain dikonfigurasi
if [ -n "$APP_DOMAIN" ]; then
  echo -e "  ${BOLD}🔗 Domain HTTP:${NC}     ${BOLD}${CYAN}http://${APP_DOMAIN}${NC}"
  echo -e "  ${BOLD}🔒 Domain HTTPS:${NC}    ${BOLD}${GREEN}https://${APP_DOMAIN}${NC}"
fi

# Jika punya IP publik, tampilkan juga
PUBLIC_IP=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || \
            curl -s --max-time 3 https://checkip.amazonaws.com 2>/dev/null || echo "")
if [ -n "$PUBLIC_IP" ]; then
  echo -e "  ${BOLD}🌍 Akses dari luar:${NC}  ${CYAN}http://${PUBLIC_IP}:${APP_PORT}${NC}  ${YELLOW}(pastikan firewall/port sudah dibuka)${NC}"
fi

echo -e "  ${BOLD}📁 Direktori:${NC}        ${CYAN}${APP_DIR}${NC}"
echo -e "  ${BOLD}🔧 Port:${NC}             ${CYAN}${APP_PORT}${NC}"
echo ""
echo -e "  ${BOLD}${YELLOW}── Perintah PM2 ───────────────────────────────────────${NC}"
echo -e "  ${CYAN}pm2 status${NC}                      — lihat status semua proses"
echo -e "  ${CYAN}pm2 logs ${APP_NAME}${NC}        — lihat log langsung"
echo -e "  ${CYAN}pm2 restart ${APP_NAME}${NC}     — restart aplikasi"
echo -e "  ${CYAN}pm2 stop ${APP_NAME}${NC}         — hentikan aplikasi"
echo -e "  ${CYAN}pm2 delete ${APP_NAME}${NC}       — hapus dari PM2"
echo ""

if [ -n "$APP_DOMAIN" ]; then
  echo -e "  ${BOLD}${YELLOW}── Manajemen SSL (Certbot) ─────────────────────────────${NC}"
  echo -e "  ${CYAN}sudo certbot renew --dry-run${NC}     — test auto-renew SSL"
  echo -e "  ${CYAN}sudo certbot certificates${NC}        — lihat daftar certificate"
  echo -e "  ${CYAN}sudo certbot delete --cert-name ${APP_DOMAIN}${NC}  — hapus certificate"
  echo ""
  echo -e "  ${BOLD}${YELLOW}── Manajemen Nginx ─────────────────────────────────────${NC}"
  echo -e "  ${CYAN}sudo nginx -t${NC}                    — test konfigurasi Nginx"
  echo -e "  ${CYAN}sudo systemctl reload nginx${NC}      — reload Nginx"
  echo -e "  ${CYAN}sudo tail -f /var/log/nginx/${APP_NAME}_access.log${NC}"
  echo ""
fi

echo -e "  ${BOLD}${YELLOW}── Update ke versi terbaru ────────────────────────────${NC}"
echo -e "  ${CYAN}bash ${APP_DIR}/install-local.sh --update${NC}"
echo -e "  ${YELLOW}atau secara manual:${NC}"
echo -e "  ${CYAN}cd ${APP_DIR} && git pull && npm install && npm run build && pm2 restart ${APP_NAME}${NC}"
echo ""
echo -e "  ${BOLD}${YELLOW}── Uninstall ──────────────────────────────────────────${NC}"
echo -e "  ${CYAN}bash ${APP_DIR}/install-local.sh --uninstall${NC}"
echo ""
echo -e "  ${BOLD}${YELLOW}── Buka port di firewall (jika perlu) ─────────────────${NC}"
echo -e "  ${CYAN}# Ubuntu/Debian (ufw):${NC}"
echo -e "  ${CYAN}sudo ufw allow 80/tcp && sudo ufw allow 443/tcp${NC}"
echo -e "  ${CYAN}# CentOS/RHEL (firewalld):${NC}"
echo -e "  ${CYAN}sudo firewall-cmd --permanent --add-service=http --add-service=https && sudo firewall-cmd --reload${NC}"
echo ""

if [ -n "$APP_DOMAIN" ]; then
  echo -e "  ${BOLD}${YELLOW}── DNS yang harus diarahkan ke server ini ──────────────${NC}"
  echo -e "  ${CYAN}Type: A   Name: @           Value: ${PUBLIC_IP:-YOUR_SERVER_IP}${NC}"
  echo -e "  ${CYAN}Type: A   Name: www         Value: ${PUBLIC_IP:-YOUR_SERVER_IP}${NC}"
  echo -e "  ${CYAN}(atau CNAME: www → ${APP_DOMAIN})${NC}"
  echo ""
fi
