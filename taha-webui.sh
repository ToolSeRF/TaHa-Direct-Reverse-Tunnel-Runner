#!/usr/bin/env bash
set -euo pipefail

banner() {
  cat <<'EOF'
╔═══════════════════════════════════════╗
║   ████████╗ █████╗ ██╗  ██╗ █████╗    ║
║   ╚══██╔══╝██╔══██╗██║  ██║██╔══██╗   ║
║      ██║   ███████║███████║███████║   ║
║      ██║   ██╔══██║██╔══██║██╔══██║   ║
║      ██║   ██║  ██║██║  ██║██║  ██║   ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ║
║         T A H A   H O S H Y A R       ║
╚═══════════════════════════════════════╝
EOF
}

TAHA_DIR="/opt/taha"
PANEL_DIR="/opt/taha/panel"
VENV_DIR="/opt/taha/venv"
SERVICE_FILE="/etc/systemd/system/taha-panel.service"

PANEL_TGZ_PRIMARY="https://github.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/releases/download/V-02/taha-webui-v2.tar.gz"
PANEL_TGZ_FALLBACK="https://h4.linklick.ir/c3cc50ccf337b96057c81fc5f76d58b6/taha-webui-v2.tar.gz"

PANEL_PORT_DEFAULT="8787"
PANEL_PORT_FILE="/opt/taha/panel_port"

PANEL_PORT="$PANEL_PORT_DEFAULT"
[[ -f "$PANEL_PORT_FILE" ]] && PANEL_PORT="$(tr -d '\r\n' < "$PANEL_PORT_FILE")"

need_root() {
  local uid
  uid="$(id -u 2>/dev/null || echo 9999)"
  if [[ "$uid" != "0" ]]; then
    exec sudo -E bash "$0" "$@"
  fi
}


pause() { read -r -p "Press ENTER to continue..." _; }

log()  { echo -e "\e[1;36m[INFO]\e[0m $*"; }
ok()   { echo -e "\e[1;32m[ OK ]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
err()  { echo -e "\e[1;31m[ERR]\e[0m  $*"; }

die() { err "$*"; pause; exit 1; }

trap 'rc=$?; err "FAILED (rc=$rc) at line $LINENO: ${BASH_COMMAND}"; pause; exit $rc' ERR

safe_clear() {
  command -v clear >/dev/null 2>&1 || return 0
  clear >/dev/null 2>&1 || true
}

valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 1 <= 10#${1} && 10#${1} <= 65535 ))
}

get_ipv4_kernel() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
      | sed -n 's/.*src \([0-9.]*\).*/\1/p' \
      | head -n1)

  echo "${ip:-SERVER_IP}"
}



ensure_pkgs() {
  log "Step 1/6: Installing required packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y python3 python3-venv python3-pip jq tar curl wget >/dev/null
  ok "Packages installed."
}

create_dirs() {
  log "Step 2/6: Preparing directories..."
  mkdir -p "$TAHA_DIR" "$PANEL_DIR"
  chmod 700 "$TAHA_DIR" || true
  [[ -f "$TAHA_DIR/servers.json" ]] || echo "[]" >"$TAHA_DIR/servers.json"
  [[ -f "$TAHA_DIR/tunnels.json" ]] || echo "[]" >"$TAHA_DIR/tunnels.json"
  chmod 600 "$TAHA_DIR/"*.json || true
  ok "Directories ready."
}

fetch_panel_bundle() {
  log "Step 3/6: Downloading panel bundle..."
  log "Primary : $PANEL_TGZ_PRIMARY"
  log "Fallback: $PANEL_TGZ_FALLBACK"

  local tmp tgz
  tmp="$(mktemp -d)"
  tgz="$tmp/panel.tar.gz"

  if ! curl -fL --connect-timeout 10 --max-time 180 -o "$tgz" "$PANEL_TGZ_PRIMARY"; then
    warn "Primary failed, using fallback..."
    curl -fL --connect-timeout 10 --max-time 180 -o "$tgz" "$PANEL_TGZ_FALLBACK" || die "Download failed"
  fi

  log "Extracting bundle..."
  tar -xzf "$tgz" -C "$tmp"
  [[ -f "$tmp/panel/app.py" ]] || { rm -rf "$tmp"; die "Invalid bundle structure (expected panel/app.py)"; }

  log "Installing files to $PANEL_DIR (replacing old panel files)..."
  rm -rf "$PANEL_DIR"
  mkdir -p "$PANEL_DIR"
  cp -a "$tmp/panel/." "$PANEL_DIR/"
  rm -rf "$tmp"

  ok "Panel files installed."
}

write_requirements() {
  log "Step 4/6: Writing requirements.txt ..."
  cat >"$PANEL_DIR/requirements.txt" <<'EOF'
fastapi==0.115.6
uvicorn[standard]==0.33.0
jinja2==3.1.5
python-multipart==0.0.20
paramiko==3.5.0
itsdangerous==2.2.0
EOF
  ok "requirements.txt created."
}

create_venv() {
  log "Step 5/6: Creating Python venv & installing dependencies..."
  rm -rf "$VENV_DIR" >/dev/null 2>&1 || true
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
  "$VENV_DIR/bin/pip" install -r "$PANEL_DIR/requirements.txt" >/dev/null
  ok "Python environment ready."
}

write_auth() {
  log "Step 6/6: Creating auth..."
  read -r -p "Panel username (default admin): " u
  read -r -s -p "Panel password (default admin): " p
  echo
  u="${u:-admin}"
  p="${p:-admin}"

  "$VENV_DIR/bin/python" - <<PY
import json, base64, hashlib, secrets
salt = secrets.token_bytes(16)
dk = hashlib.pbkdf2_hmac("sha256", "$p".encode(), salt, 200_000)
json.dump({
  "username":"$u",
  "salt_b64":base64.b64encode(salt).decode(),
  "dk_b64":base64.b64encode(dk).decode(),
  "iters":200000
}, open("/opt/taha/auth.json","w"), indent=2)
PY
  chmod 600 /opt/taha/auth.json
  ok "Auth created."
}

write_systemd() {
  log "Creating systemd service..."
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=TaHa Web Panel
After=network-online.target
Wants=network-online.target


[Service]
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$VENV_DIR/bin/uvicorn app:app --host 0.0.0.0 --port $PANEL_PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable taha-panel.service >/dev/null 2>&1 || true
  systemctl restart taha-panel.service

  ok "Service started on port $PANEL_PORT"
  local ip
  ip="$(get_ipv4_kernel)"
  log "URL: http://${ip}:$PANEL_PORT"

}

install_flow() {
  safe_clear; banner
  log "Starting INSTALL..."

  ensure_pkgs
  create_dirs

  log "Asking for panel port..."
  read -r -p "Panel port (default $PANEL_PORT_DEFAULT): " port
  port="${port:-$PANEL_PORT_DEFAULT}"
  valid_port "$port" || die "Invalid port"
  echo "$port" >"$PANEL_PORT_FILE"
  PANEL_PORT="$port"
  ok "Port set: $PANEL_PORT (saved)"

  fetch_panel_bundle
  write_requirements
  create_venv
  write_auth
  write_systemd

  ok "Installation completed 🎉"
  pause
}

change_auth_flow() {
  safe_clear; banner
  log "Starting CHANGE AUTH..."

  [[ -x "$VENV_DIR/bin/python" ]] || die "venv not found: $VENV_DIR (Install first)"
  write_auth
  systemctl restart taha-panel.service || true
  ok "Auth changed and service restarted."
  pause
}

delete_flow() {
  safe_clear; banner
  warn "This will remove panel + venv + service. Data files in $TAHA_DIR remain."
  read -r -p "Are you sure? (y/N): " yn
  yn="${yn,,}"
  [[ "$yn" != "y" ]] && { warn "Canceled."; pause; return; }

  log "Stopping service..."
  systemctl stop taha-panel.service >/dev/null 2>&1 || true
  systemctl disable taha-panel.service >/dev/null 2>&1 || true

  log "Removing files..."
  rm -rf "$PANEL_DIR" "$VENV_DIR" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE" "$PANEL_PORT_FILE" >/dev/null 2>&1 || true

  systemctl daemon-reload >/dev/null 2>&1 || true

  ok "Deleted. (data kept in $TAHA_DIR)"
  pause
}

menu() {
  while true; do
    safe_clear; banner
    echo
    echo "1) Install panel"
    echo "2) Change auth"
    echo "3) Delete panel"
    echo "0) Exit"
    echo
    read -r -p "Select: " c
    case "$c" in
      1) install_flow ;;
      2) change_auth_flow ;;
      3) delete_flow ;;
      0) exit 0 ;;
      *) err "Invalid انتخاب!"; sleep 1;;
    esac
  done
}

need_root "$@"
menu
