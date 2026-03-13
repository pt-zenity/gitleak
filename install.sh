#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║          GitLeakHunter — Auto Install Script                    ║
# ║  Supports: Ubuntu/Debian · CentOS/RHEL · macOS · Arch Linux    ║
# ║  Modes:  local (PM2)  |  Cloudflare Pages (wrangler deploy)    ║
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
echo -e "${NC}${BOLD}         Hunter — Git Secret Scanner v1.0${NC}"
echo -e "${CYAN}    https://github.com/pt-zenity/gitleak${NC}\n"

# ── Config ────────────────────────────────────────────────────────────────────
REPO_URL="https://github.com/pt-zenity/gitleak.git"
APP_DIR="${INSTALL_DIR:-$HOME/gitleakhunter}"
APP_PORT="${PORT:-3000}"
NODE_MIN_VERSION=18

# ── Helper: compare versions ─────────────────────────────────────────────────
version_gte() {
  # Returns 0 (true) if $1 >= $2
  [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
  elif [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      ubuntu|debian|linuxmint|pop)  OS="debian" ;;
      centos|rhel|fedora|rocky|alma) OS="rhel" ;;
      arch|manjaro|endeavouros)      OS="arch" ;;
      alpine)                        OS="alpine" ;;
      *)                             OS="unknown" ;;
    esac
  else
    OS="unknown"
  fi
  info "Detected OS: ${BOLD}$OS${NC}"
}

# ── Install Node.js ───────────────────────────────────────────────────────────
install_node() {
  step "Checking Node.js"

  if command -v node &>/dev/null; then
    NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VER" -ge "$NODE_MIN_VERSION" ] 2>/dev/null; then
      ok "Node.js $(node -v) already installed"
      return
    else
      warn "Node.js $(node -v) is too old (need v${NODE_MIN_VERSION}+). Upgrading..."
    fi
  else
    info "Node.js not found. Installing..."
  fi

  case "$OS" in
    debian)
      curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - 2>/dev/null
      sudo apt-get install -y nodejs 2>/dev/null
      ;;
    rhel)
      curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash - 2>/dev/null
      sudo yum install -y nodejs npm 2>/dev/null || sudo dnf install -y nodejs npm 2>/dev/null
      ;;
    arch)
      sudo pacman -Sy --noconfirm nodejs npm 2>/dev/null
      ;;
    alpine)
      sudo apk add --no-cache nodejs npm 2>/dev/null
      ;;
    macos)
      if command -v brew &>/dev/null; then
        brew install node 2>/dev/null
      else
        err "Homebrew not found. Install from https://nodejs.org/en/download/"
        exit 1
      fi
      ;;
    *)
      err "Unsupported OS. Please install Node.js v${NODE_MIN_VERSION}+ manually: https://nodejs.org"
      exit 1
      ;;
  esac

  ok "Node.js $(node -v) installed"
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
    macos)   brew install git ;;
    *)       err "Please install Git manually: https://git-scm.com"; exit 1 ;;
  esac
  ok "Git installed"
}

# ── Install PM2 ───────────────────────────────────────────────────────────────
install_pm2() {
  step "Checking PM2"
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
    git -C "$APP_DIR" fetch --quiet
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
  cd "$APP_DIR"
  npm install --quiet --no-audit --no-fund 2>/dev/null
  ok "Dependencies installed"
}

# ── Build project ─────────────────────────────────────────────────────────────
build_project() {
  step "Building project"
  cd "$APP_DIR"
  npm run build --quiet 2>/dev/null
  ok "Build complete → dist/"
}

# ── Write PM2 ecosystem config ────────────────────────────────────────────────
write_pm2_config() {
  cat > "$APP_DIR/ecosystem.config.cjs" << ECOSYSTEM
module.exports = {
  apps: [
    {
      name: 'gitleakhunter',
      script: 'npx',
      args: 'wrangler pages dev dist --ip 0.0.0.0 --port ${APP_PORT}',
      cwd: '${APP_DIR}',
      env: {
        NODE_ENV: 'production',
        PORT: ${APP_PORT}
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
    }
  ]
}
ECOSYSTEM
}

# ── Start with PM2 ────────────────────────────────────────────────────────────
start_pm2() {
  step "Starting GitLeakHunter with PM2"
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
  sleep 4

  # Check health
  if pm2 show gitleakhunter 2>/dev/null | grep -q "online"; then
    ok "GitLeakHunter is running via PM2"
  else
    warn "PM2 process may not be online yet. Checking logs..."
    pm2 logs gitleakhunter --nostream --lines 10 2>/dev/null || true
  fi

  # Save PM2 process list to survive reboots
  pm2 save --force --silent 2>/dev/null || true
}

# ── Setup PM2 startup (auto-start on reboot) ─────────────────────────────────
setup_startup() {
  step "Configuring auto-start on reboot"
  if pm2 startup 2>&1 | grep -q "sudo"; then
    STARTUP_CMD=$(pm2 startup 2>&1 | grep "sudo env" | head -1 | xargs)
    if [ -n "$STARTUP_CMD" ]; then
      eval "$STARTUP_CMD" 2>/dev/null || warn "Could not set startup. Run manually: pm2 startup"
    fi
  fi
  pm2 save --force --silent 2>/dev/null || true
  ok "Auto-start configured"
}

# ── Deploy to Cloudflare Pages ────────────────────────────────────────────────
deploy_cloudflare() {
  step "Deploying to Cloudflare Pages"

  if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
    err "CLOUDFLARE_API_TOKEN environment variable is not set."
    echo -e "  ${YELLOW}Set it with:${NC}"
    echo -e "  ${CYAN}export CLOUDFLARE_API_TOKEN=your_token_here${NC}"
    echo -e "  ${CYAN}Then re-run: bash install.sh --deploy${NC}"
    exit 1
  fi

  cd "$APP_DIR"

  # Create project (ignore error if already exists)
  npx wrangler pages project create gitleakhunter \
    --production-branch main 2>/dev/null || true

  # Deploy
  npx wrangler pages deploy dist --project-name gitleakhunter
  ok "Deployed to Cloudflare Pages!"
}

# ── Print final instructions ──────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${GREEN}║       GitLeakHunter installed successfully!    ║${NC}"
  echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${BOLD}🌐 Local URL:${NC}    ${CYAN}http://localhost:${APP_PORT}${NC}"
  echo -e "  ${BOLD}📁 Install dir:${NC}  ${CYAN}${APP_DIR}${NC}"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Useful commands:${NC}"
  echo -e "  ${CYAN}pm2 status${NC}                     — show running processes"
  echo -e "  ${CYAN}pm2 logs gitleakhunter${NC}          — view live logs"
  echo -e "  ${CYAN}pm2 restart gitleakhunter${NC}       — restart the app"
  echo -e "  ${CYAN}pm2 stop gitleakhunter${NC}          — stop the app"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Update to latest version:${NC}"
  echo -e "  ${CYAN}cd ${APP_DIR} && git pull && npm install && npm run build && pm2 restart gitleakhunter${NC}"
  echo ""
  echo -e "  ${BOLD}${YELLOW}Deploy to Cloudflare Pages:${NC}"
  echo -e "  ${CYAN}export CLOUDFLARE_API_TOKEN=your_token${NC}"
  echo -e "  ${CYAN}bash install.sh --deploy${NC}"
  echo ""
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  step "Uninstalling GitLeakHunter"
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
DEPLOY_MODE=false
for arg in "$@"; do
  case "$arg" in
    --deploy|-d)   DEPLOY_MODE=true ;;
    --uninstall|-u) uninstall ;;
    --port=*)      APP_PORT="${arg#*=}" ;;
    --dir=*)       APP_DIR="${arg#*=}" ;;
    --help|-h)
      echo -e "${BOLD}Usage:${NC} bash install.sh [options]"
      echo ""
      echo -e "  ${CYAN}(no args)${NC}        Install & run locally with PM2 on port 3000"
      echo -e "  ${CYAN}--deploy${NC}         Build + deploy to Cloudflare Pages"
      echo -e "  ${CYAN}--port=NNNN${NC}      Set custom port (default: 3000)"
      echo -e "  ${CYAN}--dir=/path${NC}      Set install directory (default: ~/gitleakhunter)"
      echo -e "  ${CYAN}--uninstall${NC}      Remove GitLeakHunter and stop PM2 process"
      echo -e "  ${CYAN}--help${NC}           Show this help"
      echo ""
      echo -e "  ${BOLD}Examples:${NC}"
      echo -e "  ${CYAN}bash install.sh${NC}"
      echo -e "  ${CYAN}bash install.sh --port=8080${NC}"
      echo -e "  ${CYAN}bash install.sh --dir=/opt/gitleakhunter${NC}"
      echo -e "  ${CYAN}CLOUDFLARE_API_TOKEN=xxx bash install.sh --deploy${NC}"
      exit 0
      ;;
  esac
done

# ── Main flow ─────────────────────────────────────────────────────────────────
main() {
  detect_os
  install_git
  install_node
  install_pm2
  clone_repo
  install_deps
  build_project

  if [ "$DEPLOY_MODE" = true ]; then
    deploy_cloudflare
  else
    start_pm2
    setup_startup
    print_summary
  fi
}

main "$@"
