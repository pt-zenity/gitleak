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
echo -e "${NC}${BOLD}         Local Install (Node.js + PM2) — v1.0${NC}"
echo -e "${CYAN}   https://github.com/pt-zenity/gitleak${NC}\n"

# ─── Konfigurasi default (bisa di-override lewat env / argumen) ──────────────
REPO_URL="https://github.com/pt-zenity/gitleak.git"
APP_DIR="${INSTALL_DIR:-$HOME/gitleakhunter}"
APP_PORT="${PORT:-3000}"
APP_NAME="gitleakhunter"
NODE_MIN=18

# ─── Parse argumen ───────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --port=*)    APP_PORT="${arg#*=}" ;;
    --dir=*)     APP_DIR="${arg#*=}" ;;
    --uninstall|-u)
      echo -e "\n${BOLD}${RED}Uninstall GitLeakHunter...${NC}"
      pm2 delete "$APP_NAME" 2>/dev/null && ok "PM2 process dihapus" || true
      pm2 save --force 2>/dev/null || true
      if [ -d "$APP_DIR" ]; then
        rm -rf "$APP_DIR"
        ok "Direktori $APP_DIR dihapus"
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
      echo -e "  ${CYAN}(tanpa opsi)${NC}     Install & jalankan di port 3000"
      echo -e "  ${CYAN}--port=NNNN${NC}      Ganti port (default: 3000)"
      echo -e "  ${CYAN}--dir=/path${NC}      Ganti direktori install (default: ~/gitleakhunter)"
      echo -e "  ${CYAN}--update${NC}         Update ke versi terbaru dari GitHub"
      echo -e "  ${CYAN}--uninstall${NC}      Hapus GitLeakHunter & stop PM2 process"
      echo -e "  ${CYAN}--help${NC}           Tampilkan bantuan ini\n"
      echo -e "${BOLD}Contoh:${NC}"
      echo -e "  ${CYAN}bash install-local.sh${NC}"
      echo -e "  ${CYAN}bash install-local.sh --port=8080${NC}"
      echo -e "  ${CYAN}bash install-local.sh --dir=/opt/gitleakhunter${NC}"
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
echo -e "  ${BOLD}🌐 Buka browser:${NC}    ${BOLD}${CYAN}http://localhost:${APP_PORT}${NC}"

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
echo -e "  ${CYAN}sudo ufw allow ${APP_PORT}/tcp${NC}"
echo -e "  ${CYAN}# CentOS/RHEL (firewalld):${NC}"
echo -e "  ${CYAN}sudo firewall-cmd --permanent --add-port=${APP_PORT}/tcp && sudo firewall-cmd --reload${NC}"
echo ""
