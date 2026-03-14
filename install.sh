#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║          GitLeakHunter — Auto Install Script                    ║
# ║  Supports: Ubuntu/Debian · CentOS/RHEL · macOS · Arch · Alpine ║
# ║  Node.js: installed via nvm (v24 LTS)                          ║
# ╚══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✅ $*${NC}"; }
info() { echo -e "${CYAN}ℹ  $*${NC}"; }
warn() { echo -e "${YELLOW}⚠  $*${NC}"; }
err()  { echo -e "${RED}❌ $*${NC}"; }
step() { echo -e "\n${BOLD}${BLUE}── $* ──────────────────────────────────────${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${RED}"
cat << 'BANNER'
  ██████╗ ██╗████████╗██╗     ███████╗ █████╗ ██╗  ██╗
 ██╔════╝ ██║╚══██╔══╝██║     ██╔════╝██╔══██╗██║ ██╔╝
 ██║  ███╗██║   ██║   ██║     █████╗  ███████║█████╔╝ 
 ██║   ██║██║   ██║   ██║     ██╔══╝  ██╔══██║██╔═██╗ 
 ╚██████╔╝██║   ██║   ███████╗███████╗██║  ██║██║  ██╗
  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
echo -e "${NC}${BOLD}         Hunter — Git Secret Scanner v2.0${NC}"
echo -e "${CYAN}    https://github.com/pt-zenity/gitleak${NC}\n"

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/pt-zenity/gitleak.git"
APP_DIR="${INSTALL_DIR:-$HOME/gitleakhunter}"
APP_PORT="${PORT:-3000}"
NODE_TARGET_LTS="lts/*"      # installs latest LTS (currently v24)
NVM_VERSION="v0.40.3"
NVM_DIR="${NVM_DIR:-$HOME/.nvm}"

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
  if [[ "${OSTYPE:-}" == "darwin"* ]]; then
    OS="macos"
  elif [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|debian|linuxmint|pop|raspbian) OS="debian" ;;
      centos|rhel|fedora|rocky|alma)        OS="rhel"   ;;
      arch|manjaro|endeavouros)             OS="arch"   ;;
      alpine)                               OS="alpine" ;;
      *)                                    OS="unknown" ;;
    esac
  else
    OS="unknown"
  fi
  info "Detected OS: ${BOLD}$OS${NC}"
}

# ── Install build tools (needed by nvm on some systems) ──────────────────────
install_build_tools() {
  case "$OS" in
    debian)
      if ! command -v curl &>/dev/null || ! command -v git &>/dev/null; then
        info "Installing curl + git..."
        sudo apt-get update -qq && sudo apt-get install -y -qq curl git
      fi
      ;;
    rhel)
      sudo yum install -y curl git 2>/dev/null || sudo dnf install -y curl git 2>/dev/null || true
      ;;
    arch)
      sudo pacman -Sy --noconfirm --needed curl git 2>/dev/null || true
      ;;
    alpine)
      sudo apk add --no-cache curl git bash 2>/dev/null || true
      ;;
    macos)
      if ! command -v git &>/dev/null; then
        xcode-select --install 2>/dev/null || true
      fi
      ;;
  esac
}

# ── Install Git ───────────────────────────────────────────────────────────────
install_git() {
  step "Checking Git"
  if command -v git &>/dev/null; then
    ok "Git $(git --version | awk '{print $3}') already installed"
    return
  fi
  info "Installing Git..."
  case "$OS" in
    debian)  sudo apt-get install -y git ;;
    rhel)    sudo yum install -y git || sudo dnf install -y git ;;
    arch)    sudo pacman -Sy --noconfirm git ;;
    alpine)  sudo apk add --no-cache git ;;
    macos)   brew install git 2>/dev/null || xcode-select --install ;;
    *)       err "Please install Git manually: https://git-scm.com"; exit 1 ;;
  esac
  ok "Git installed"
}

# ── Install nvm + Node.js v24 LTS ────────────────────────────────────────────
install_node() {
  step "Installing Node.js via nvm"

  # Load nvm if already present
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true

  # Install nvm if not present
  if ! command -v nvm &>/dev/null 2>&1 && [ ! -s "$NVM_DIR/nvm.sh" ]; then
    info "Installing nvm ${NVM_VERSION}..."
    curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" | bash
    export NVM_DIR="$NVM_DIR"
    \. "$NVM_DIR/nvm.sh"
    ok "nvm ${NVM_VERSION} installed"
  else
    ok "nvm already installed ($(nvm --version 2>/dev/null || echo 'loaded'))"
  fi

  # Check current Node.js version
  if command -v node &>/dev/null; then
    NODE_MAJOR=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "${NODE_MAJOR:-0}" -ge 20 ]; then
      ok "Node.js $(node -v) already satisfies requirement (>=20)"
      return
    else
      warn "Node.js $(node -v) too old, upgrading to LTS..."
    fi
  fi

  # Install latest LTS
  info "Installing Node.js LTS (v24)..."
  nvm install "$NODE_TARGET_LTS"
  nvm alias default "$NODE_TARGET_LTS"
  nvm use default

  ok "Node.js $(node -v) installed  |  npm $(npm -v)"
}

# ── Install PM2 ───────────────────────────────────────────────────────────────
install_pm2() {
  step "Checking PM2"

  # Make sure nvm node is in PATH
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true

  if command -v pm2 &>/dev/null; then
    ok "PM2 $(pm2 -v) already installed"
    return
  fi
  info "Installing PM2 globally..."
  npm install -g pm2 --quiet
  ok "PM2 $(pm2 -v) installed"
}

# ── Clone or update repo ──────────────────────────────────────────────────────
clone_repo() {
  step "Setting up repository"

  if [ -d "$APP_DIR/.git" ]; then
    info "Repository already exists at ${APP_DIR}. Pulling latest..."
    git -C "$APP_DIR" fetch --quiet origin
    git -C "$APP_DIR" reset --hard origin/main --quiet
    ok "Repository updated to latest"
  else
    info "Cloning from ${REPO_URL}..."
    git clone --depth 1 "$REPO_URL" "$APP_DIR" --quiet
    ok "Repository cloned to ${APP_DIR}"
  fi
}

# ── Install dependencies ──────────────────────────────────────────────────────
install_deps() {
  step "Installing Node.js dependencies"
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true
  cd "$APP_DIR"
  npm install --quiet --no-audit --no-fund
  ok "Dependencies installed"
}

# ── Build project ─────────────────────────────────────────────────────────────
build_project() {
  step "Building project (TypeScript → JavaScript)"
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true
  cd "$APP_DIR"
  npm run build
  ok "Build complete → dist/"
}

# ── Write PM2 ecosystem config ────────────────────────────────────────────────
write_pm2_config() {
  # Resolve the node binary from nvm so PM2 uses the correct version
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true
  NODE_BIN="$(command -v node)"

  cat > "$APP_DIR/ecosystem.config.cjs" << ECOSYSTEM
module.exports = {
  apps: [
    {
      name: 'gitleakhunter',
      script: '${NODE_BIN}',
      args: 'dist/server.js',
      cwd: '${APP_DIR}',
      env: {
        NODE_ENV: 'production',
        HTTP_PORT: ${APP_PORT},
        HTTPS_PORT: $((APP_PORT + 443)),
        HOST: '0.0.0.0',
        // SSL_MODE: 'auto'  → auto-detect Cloudflare cert → custom → Let's Encrypt → HTTP only
        SSL_MODE: 'auto',
        CF_ORIGIN_KEY:  '/etc/ssl/cloudflare/origin.key',
        CF_ORIGIN_CERT: '/etc/ssl/cloudflare/origin.pem',
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
ECOSYSTEM
  ok "PM2 ecosystem config written"
}

# ── Start with PM2 ────────────────────────────────────────────────────────────
start_pm2() {
  step "Starting GitLeakHunter with PM2"
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true
  cd "$APP_DIR"

  # Kill any existing process on the port
  if command -v fuser &>/dev/null; then
    fuser -k "${APP_PORT}/tcp" 2>/dev/null || true
  elif command -v lsof &>/dev/null; then
    lsof -ti:"${APP_PORT}" | xargs kill -9 2>/dev/null || true
  fi

  write_pm2_config

  # Stop old instance if exists
  pm2 delete gitleakhunter 2>/dev/null || true
  sleep 1

  pm2 start ecosystem.config.cjs --silent
  sleep 3

  # Check health
  if curl -sf "http://localhost:${APP_PORT}/api/patterns" &>/dev/null; then
    ok "GitLeakHunter is running on port ${APP_PORT}"
  elif pm2 show gitleakhunter 2>/dev/null | grep -q "online"; then
    ok "GitLeakHunter process is online (HTTP check pending)"
  else
    warn "PM2 process may not be ready yet. Checking logs..."
    pm2 logs gitleakhunter --nostream --lines 15 2>/dev/null || true
  fi

  # Save PM2 process list to survive reboots
  pm2 save --force --silent 2>/dev/null || true
}

# ── Setup PM2 startup (auto-start on reboot) ─────────────────────────────────
setup_startup() {
  step "Configuring auto-start on reboot"
  local startup_out
  startup_out=$(pm2 startup 2>&1 || true)
  if echo "$startup_out" | grep -q "sudo"; then
    STARTUP_CMD=$(echo "$startup_out" | grep "sudo env" | head -1)
    if [ -n "$STARTUP_CMD" ]; then
      eval "$STARTUP_CMD" 2>/dev/null || warn "Could not set startup automatically. Run manually: pm2 startup"
    fi
  fi
  pm2 save --force --silent 2>/dev/null || true
  ok "Auto-start configured"
}

# ── Print final summary ────────────────────────────────────────────────────────
print_summary() {
  # Get Node.js version
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true

  echo ""
  echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${GREEN}║       GitLeakHunter installed successfully! 🎉         ║${NC}"
  echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${BOLD}🌐 URL:${NC}          ${CYAN}http://localhost:${APP_PORT}${NC}"
  echo -e "  ${BOLD}📁 Install dir:${NC}  ${CYAN}${APP_DIR}${NC}"
  echo -e "  ${BOLD}⚙️  Node.js:${NC}      ${CYAN}$(node -v 2>/dev/null || echo 'N/A') via nvm${NC}"
  echo -e "  ${BOLD}📦 PM2:${NC}          ${CYAN}v$(pm2 -v 2>/dev/null || echo 'N/A')${NC}"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Useful commands:${NC}"
  echo -e "  ${CYAN}pm2 status${NC}                      — show running processes"
  echo -e "  ${CYAN}pm2 logs gitleakhunter${NC}           — view live logs"
  echo -e "  ${CYAN}pm2 restart gitleakhunter${NC}        — restart the app"
  echo -e "  ${CYAN}pm2 stop gitleakhunter${NC}           — stop the app"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Update to latest version:${NC}"
  echo -e "  ${CYAN}cd ${APP_DIR} && git pull && npm install && npm run build && pm2 restart gitleakhunter${NC}"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Enable HTTPS (Cloudflare Origin Cert):${NC}"
  echo -e "  Edit ${CYAN}${APP_DIR}/ecosystem.config.cjs${NC} → set SSL_MODE + cert paths"
  echo -e "  Then run ${CYAN}pm2 restart gitleakhunter${NC}"
  echo ""
  echo -e "  ${BOLD}${YELLOW}nvm — manage Node.js versions:${NC}"
  echo -e "  ${CYAN}nvm ls${NC}                          — list installed versions"
  echo -e "  ${CYAN}nvm install --lts${NC}               — install latest LTS"
  echo -e "  ${CYAN}nvm use --lts${NC}                   — switch to LTS"
  echo ""
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  step "Uninstalling GitLeakHunter"
  export NVM_DIR="$NVM_DIR"
  [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null || true
  pm2 delete gitleakhunter 2>/dev/null || true
  pm2 save --force --silent 2>/dev/null || true
  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    ok "Removed ${APP_DIR}"
  fi
  ok "GitLeakHunter uninstalled"
  exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────
for arg in "$@"; do
  case "$arg" in
    --uninstall|-u) detect_os; uninstall ;;
    --port=*)      APP_PORT="${arg#*=}" ;;
    --dir=*)       APP_DIR="${arg#*=}" ;;
    --help|-h)
      echo -e "${BOLD}Usage:${NC} bash install.sh [options]"
      echo ""
      echo -e "  ${CYAN}(no args)${NC}        Install & run locally with PM2 on port 3000"
      echo -e "  ${CYAN}--port=NNNN${NC}      Set custom port (default: 3000)"
      echo -e "  ${CYAN}--dir=/path${NC}      Set install directory (default: ~/gitleakhunter)"
      echo -e "  ${CYAN}--uninstall${NC}      Remove GitLeakHunter and stop PM2 process"
      echo -e "  ${CYAN}--help${NC}           Show this help"
      echo ""
      echo -e "  ${BOLD}Examples:${NC}"
      echo -e "  ${CYAN}bash install.sh${NC}"
      echo -e "  ${CYAN}bash install.sh --port=8080${NC}"
      echo -e "  ${CYAN}bash install.sh --dir=/opt/gitleakhunter${NC}"
      echo -e "  ${CYAN}PORT=8080 bash install.sh${NC}"
      exit 0
      ;;
  esac
done

# ── Main flow ─────────────────────────────────────────────────────────────────
main() {
  detect_os
  install_build_tools
  install_git
  install_node
  install_pm2
  clone_repo
  install_deps
  build_project
  start_pm2
  setup_startup
  print_summary
}

main "$@"
