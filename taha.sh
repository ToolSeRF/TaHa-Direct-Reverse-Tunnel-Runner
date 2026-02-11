#!/usr/bin/env bash

set +e
set +u
export LC_ALL=C

GOST_VER="3.2.7-nightly.20251122"
GOST_BIN="/usr/local/bin/gost"
SYS_DIR="/etc/systemd/system"
RESET_SCRIPT="/etc/reset-gost.sh"

LOG_LINES=()
LOG_MIN=3
LOG_MAX=8

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

add_log() {
  local msg="$1"
  local ts
  ts="$(date +"%H:%M:%S")"
  msg="${msg//$'\n'/ }"
  msg="${msg//$'\r'/ }"
  msg="${msg:0:80}"
  LOG_LINES+=("[$ts] $msg")
  if ((${#LOG_LINES[@]} > LOG_MAX)); then
    LOG_LINES=("${LOG_LINES[@]: -$LOG_MAX}")
  fi
}

renderx() {
  clear
  banner
  echo
  local shown_count="${#LOG_LINES[@]}"
  local height=$shown_count
  ((height < LOG_MIN)) && height=$LOG_MIN
  ((height > LOG_MAX)) && height=$LOG_MAX

  echo "+------------------------------ ACTION LOG ------------------------------+"
  local start_index=0
  if ((${#LOG_LINES[@]} > height)); then
    start_index=$((${#LOG_LINES[@]} - height))
  fi

  local i line
  for ((i=start_index; i<${#LOG_LINES[@]}; i++)); do
    line="${LOG_LINES[$i]}"
    printf "| %-70s |\n" "$line"
  done

  local missing=$((height - (${#LOG_LINES[@]} - start_index)))
  for ((i=0; i<missing; i++)); do
    printf "| %-70s |\n" ""
  done

  echo "+------------------------------------------------------------------------+"
  echo

  if [[ -x "$GOST_BIN" ]]; then
    local gv
    gv="$("$GOST_BIN" -V 2>/dev/null | head -n1)"
    [[ -z "$gv" ]] && gv="GOST installed"
    echo "GOST: $gv"
  else
    echo "GOST: not installed"
  fi

  local active
  active="$(systemctl list-units --type=service --state=active 2>/dev/null \
    | awk '{print $1}' | grep -E '^gost-(iran|kharej)-[0-9]+\.service$' || true)"
  echo "Active services:"
  if [[ -z "$active" ]]; then
    echo "  None"
  else
    echo "$active" | sed 's/^/  - /'
  fi
  echo
}

render() {
  clear
  banner
  echo
  local shown_count="${#LOG_LINES[@]}"
  local height=$shown_count
  ((height < LOG_MIN)) && height=$LOG_MIN
  ((height > LOG_MAX)) && height=$LOG_MAX

  echo "+------------------------------ ACTION LOG ------------------------------+"
  local start_index=0
  if ((${#LOG_LINES[@]} > height)); then
    start_index=$((${#LOG_LINES[@]} - height))
  fi

  local i line
  for ((i=start_index; i<${#LOG_LINES[@]}; i++)); do
    line="${LOG_LINES[$i]}"
    printf "| %-70s |\n" "$line"
  done

  local missing=$((height - (${#LOG_LINES[@]} - start_index)))
  for ((i=0; i<missing; i++)); do
    printf "| %-70s |\n" ""
  done

  echo "+------------------------------------------------------------------------+"
}

pause_enter() {
  echo
  read -r -p "Press ENTER to continue..." _
}

ensure_root() {
  if [[ ${EUID:-0} -ne 0 ]]; then
    echo "This script must be run as root. Re-running with sudo..."
    exec sudo -E bash "$0" "$@"
  fi
}

trim() { sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$1"; }

sanitize_input() {
  local s="$1"
  s="${s//$'\r'/}"
  s="$(printf '%s' "$s" | sed -E 's/\x1B\[[0-9;?]*[A-Za-z]//g')"
  s="$(printf '%s' "$s" | tr -cd '[:print:]')"
  s="$(trim "$s")"
  printf "%s" "$s"
}

is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

valid_octet() { [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1>=0 && 10#$1<=255)); }

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}

valid_port() {
  local p="$1"
  is_int "$p" || return 1
  ((10#$p>=1 && 10#$p<=65535))
}

valid_id_1_99() {
  local n="$1"
  is_int "$n" || return 1
  ((10#$n>=1 && 10#$n<=99))
}

ssh_key_dir() {
  if [[ -d "/root/.ssh" ]]; then
    echo "/root/.ssh"
  elif [[ -d "/root/.SSH" ]]; then
    echo "/root/.SSH"
  else
    echo "/root/.ssh"
  fi
}

ssh_keygen_and_copy() {
  local side="$1"
  local remote_ip="$2"
  local id="$3"
  local dir key base pub

  dir="$(ssh_key_dir)"
  mkdir -p "$dir" >/dev/null 2>&1 || true
  chmod 700 "$dir" >/dev/null 2>&1 || true

  base="${side}${id}_ed25519"
  key="${dir}/${base}"
  pub="${key}.pub"

  add_log "Generating key: ${key}"
  render

  rm -f "$key" "$pub" >/dev/null 2>&1 || true

  ssh-keygen -t ed25519 -N "" -f "$key" >/dev/null 2>&1
  local rc=$?
  if ((rc!=0)); then
    add_log "ERROR: ssh-keygen failed (rc=$rc)"
    render
    pause_enter
    return 1
  fi

  add_log "Copying public key to root@${remote_ip} (needs YES + password)"
  render
  ssh-copy-id -i "$pub" "root@${remote_ip}"
  rc=$?

  if ((rc==0)); then
    add_log "SUCCESS: Key copied to root@${remote_ip}"
  else
    add_log "FAILED: ssh-copy-id error (rc=$rc)"
  fi

  render
  pause_enter
  return $rc
}

ssh_key_generator_menu() {
  local c=""
  while true; do
    render
    echo "SSH Key Generator"
    echo
    echo "1) on IRAN side"
    echo "2) on KHAREJ side"
    echo "0) Back"
    echo
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"

    case "$c" in
      1)
        local kh_ip iran_id
        ask_until_valid "input KHAREJ IP :" valid_ipv4 kh_ip
        ask_until_valid "input iran ID (1-99) :" valid_id_1_99 iran_id
        ssh_keygen_and_copy "iran" "$kh_ip" "$iran_id"
        ;;
      2)
        local ir_ip kh_id
        ask_until_valid "input iran IP :" valid_ipv4 ir_ip
        ask_until_valid "input kharej ID (1-99) :" valid_id_1_99 kh_id
        ssh_keygen_and_copy "kharej" "$ir_ip" "$kh_id"
        ;;
      0) return 0 ;;
      *) add_log "Invalid selection" ;;
    esac
  done
}


ask_until_valid() {
  local prompt="$1" validator="$2" __var="$3"
  local ans=""
  while true; do
    render
    read -r -e -p "$prompt " ans
    ans="$(sanitize_input "$ans")"
    if [[ -z "$ans" ]]; then
      add_log "Empty input. Try again."
      continue
    fi
    if "$validator" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      add_log "OK: ${prompt} ${ans}"
      return 0
    else
      add_log "Invalid: ${prompt} ${ans}"
      add_log "Try again."
    fi
  done
}

ask_ports() {
  local prompt="Input Forward Ports (80 | 80,2053 | 2050-2060):"
  local raw=""
  while true; do
    render
    read -r -e -p "$prompt " raw
    raw="$(sanitize_input "$raw")"
    raw="${raw// /}"

    if [[ -z "$raw" ]]; then
      add_log "Empty ports. Try again."
      continue
    fi

    local -a ports=()
    local ok=1

    if [[ "$raw" =~ ^[0-9]+$ ]]; then
      valid_port "$raw" && ports+=("$raw") || ok=0

    elif [[ "$raw" =~ ^[0-9]+-[0-9]+$ ]]; then
      local s="${raw%-*}"
      local e="${raw#*-}"
      if valid_port "$s" && valid_port "$e" && ((10#$s<=10#$e)); then
        local p
        for ((p=10#$s; p<=10#$e; p++)); do ports+=("$p"); done
      else
        ok=0
      fi

    elif [[ "$raw" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
      IFS=',' read -r -a parts <<<"$raw"
      local part
      for part in "${parts[@]}"; do
        valid_port "$part" && ports+=("$part") || { ok=0; break; }
      done
    else
      ok=0
    fi

    if ((ok==0)); then
      add_log "Invalid ports: $raw"
      add_log "Examples: 80 | 80,2053 | 2050-2060"
      continue
    fi

    mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
    PORT_SPEC="$raw"
    add_log "Ports accepted: ${PORT_LIST[*]}"
    return 0
  done
}

write_atomic() {
  local path="$1"
  local tmp="${path}.tmp.$$"
  umask 022
  cat >"$tmp"
  mv -f "$tmp" "$path"
}

systemd_reload() { systemctl daemon-reload >/dev/null 2>&1 || true; }

enable_start() {
  local unit="$1"
  systemd_reload
  systemctl enable "$unit" >/dev/null 2>&1 || true
  systemctl restart "$unit" >/dev/null 2>&1 || true
}

show_status() {
  local unit="$1"
  render
  echo "---- STATUS ($unit) ----"
  systemctl --no-pager --full status "$unit" 2>&1 | sed -n '1,18p'
  echo "------------------------"
  pause_enter
}

ensure_gost_installed() {
  if [[ ! -x "$GOST_BIN" ]]; then
    add_log "GOST not installed. Install Core first."
    render
    pause_enter
    return 1
  fi
  return 0
}

install_core() {
  local arch=""
  while true; do
    render
    echo "Install Core"
    echo "1) AMD64"
    echo "2) ARM64"
    echo "0) Back"
    echo
    read -r -e -p "Select: " arch
    arch="$(sanitize_input "$arch")"
    case "$arch" in
      1) arch="amd64"; break ;;
      2) arch="arm64"; break ;;
      0) return 0 ;;
      *) add_log "Invalid selection";;
    esac
  done

  local url="https://github.com/go-gost/gost/releases/download/v${GOST_VER}/gost_${GOST_VER}_linux_${arch}.tar.gz"
  local tmp="/tmp/gost_${GOST_VER}_${arch}.$$"
  mkdir -p "$tmp" >/dev/null 2>&1

  add_log "Downloading GOST v${GOST_VER} (${arch})"
  render
  wget -q -O "${tmp}/gost.tgz" "$url" || { add_log "Download failed"; rm -rf "$tmp"; pause_enter; return 0; }

  add_log "Extracting"
  tar -xzf "${tmp}/gost.tgz" -C "$tmp" || { add_log "Extract failed"; rm -rf "$tmp"; pause_enter; return 0; }

  if [[ ! -f "${tmp}/gost" ]]; then
    add_log "Binary not found in archive"
    rm -rf "$tmp"; pause_enter; return 0
  fi

  chmod +x "${tmp}/gost" >/dev/null 2>&1
  cp -f "${tmp}/gost" "$GOST_BIN" >/dev/null 2>&1

  local ver
  ver="$("$GOST_BIN" -V 2>/dev/null | head -n1)"
  add_log "Installed: $ver"

  rm -rf "$tmp" >/dev/null 2>&1
  pause_enter
}

build_L_lines_for_forwarder() {
  local scheme="$1" spec="$2"
  if [[ "$spec" =~ ^[0-9]+-[0-9]+$ ]]; then
    echo "-L \"${scheme}://0.0.0.0:${spec}/127.0.0.1:${spec}\""
    return
  fi
  if [[ "$spec" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
    local p
    IFS=',' read -r -a arr <<<"$spec"
    for p in "${arr[@]}"; do
      echo "-L \"${scheme}://0.0.0.0:${p}/127.0.0.1:${p}\""
    done
    return
  fi
  echo "-L \"${scheme}://0.0.0.0:${spec}/127.0.0.1:${spec}\""
}

make_execstart_forwarder_F() {
  local scheme="$1" portspec="$2" forward_uri="$3"
  local exec="${GOST_BIN}"
  while IFS= read -r l; do
    exec+=" ${l}"
  done < <(build_L_lines_for_forwarder "$scheme" "$portspec")
  exec+=" -F \"${forward_uri}\""
  echo "$exec"
}

build_listen_uri_admission() {
  local proto1="$1" proto2="$2" port="$3" ip="$4" bindflag="$5"
  local proto=""
  if [[ "$proto2" == "raw" ]]; then
    proto="$proto1"
  else
    proto="${proto1}+${proto2}"
  fi

  if [[ "$bindflag" == "1" ]]; then
    echo "${proto}://0.0.0.0:${port}?bind=true&admission.allow=${ip}/32"
  else
    echo "${proto}://0.0.0.0:${port}?admission.allow=${ip}/32"
  fi
}

make_direct_iran() {
  ensure_gost_installed || return 0
  local tid kh_ip tun_port
  ask_until_valid "Input IRAN/KHAREJ tunnel id (1-99):" valid_id_1_99 tid
  ask_until_valid "Input KHAREJ IP:" valid_ipv4 kh_ip
  ask_until_valid "Input TUNNEL PORT:" valid_port tun_port
  ask_ports

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local sshid=""
  if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
    ask_until_valid "input ssh id (1-99):" valid_id_1_99 sshid
  fi

  local keydir
  keydir="$(ssh_key_dir)"

  local forward_uri
  if [[ "$PROTO2" == "raw" ]]; then
    if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
      forward_uri="${PROTO1}://root@${kh_ip}:${tun_port}?identity=${keydir}/iran${sshid}_ed25519"
    else
      forward_uri="${PROTO1}://${kh_ip}:${tun_port}"
    fi
  else
    if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
      forward_uri="${PROTO1}+${PROTO2}://root@${kh_ip}:${tun_port}?identity=${keydir}/iran${sshid}_ed25519"
    else
      forward_uri="${PROTO1}+${PROTO2}://${kh_ip}:${tun_port}"
    fi
  fi


  local execstart
  execstart="$(make_execstart_forwarder_F "tcp" "$PORT_SPEC" "$forward_uri")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${execstart}
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_direct_kharej() {
  ensure_gost_installed || return 0
  local tid ir_ip tun_port
  ask_until_valid "Input IRAN/KHAREJ tunnel id (1-99):" valid_id_1_99 tid
  ask_until_valid "Input IRAN IP:" valid_ipv4 ir_ip
  ask_until_valid "Input TUNNEL PORT:" valid_port tun_port

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$ir_ip" "0")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${GOST_BIN} -L "${listen_uri}"
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_reverse_iran() {
  ensure_gost_installed || return 0
  local tid kh_ip tun_port
  ask_until_valid "Input IRAN/KHAREJ tunnel id (1-99):" valid_id_1_99 tid
  ask_until_valid "Input KHAREJ IP:" valid_ipv4 kh_ip
  ask_until_valid "Input TUNNEL PORT:" valid_port tun_port

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$kh_ip" "1")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${GOST_BIN} -L "${listen_uri}"
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_reverse_kharej() {
  ensure_gost_installed || return 0
  local tid ir_ip tun_port
  ask_until_valid "Input IRAN/KHAREJ tunnel id (1-99):" valid_id_1_99 tid
  ask_until_valid "Input IRAN IP:" valid_ipv4 ir_ip
  ask_until_valid "Input TUNNEL PORT:" valid_port tun_port
  ask_ports

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local sshid=""
  if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
    ask_until_valid "input ssh id (1-99):" valid_id_1_99 sshid
  fi

  local keydir
  keydir="$(ssh_key_dir)"

  local forward_uri
  if [[ "$PROTO2" == "raw" ]]; then
    if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
      forward_uri="${PROTO1}://root@${ir_ip}:${tun_port}?identity=${keydir}/kharej${sshid}_ed25519"
    else
      forward_uri="${PROTO1}://${ir_ip}:${tun_port}"
    fi
  else
    if [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]; then
      forward_uri="${PROTO1}+${PROTO2}://root@${ir_ip}:${tun_port}?identity=${keydir}/kharej${sshid}_ed25519"
    else
      forward_uri="${PROTO1}+${PROTO2}://${ir_ip}:${tun_port}"
    fi
  fi


  local execstart
  execstart="$(make_execstart_forwarder_F "rtcp" "$PORT_SPEC" "$forward_uri")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${execstart}
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

select_side_and_build() {
  local side=""
  while true; do
    render
    echo "1) IRAN SIDE"
    echo "2) KHAREJ SIDE"
    echo "0) Back"
    echo
    read -r -e -p "Select: " side
    side="$(sanitize_input "$side")"
    case "$side" in
      1) SIDE="IRAN"; return 0 ;;
      2) SIDE="KHAREJ"; return 0 ;;
      0) return 1 ;;
      *) add_log "Invalid side";;
    esac
  done
}

proto2_menu() {
  local title="$1"
  shift
  local -a options=("$@")
  local c=""
  while true; do
    render
    echo "$title"
    echo
    local i
    for ((i=0; i<${#options[@]}; i++)); do
      printf "%d) %s\n" $((i+1)) "${options[$i]}"
    done
    echo "0) Back"
    echo
    read -r -e -p "Select proto2: " c
    c="$(sanitize_input "$c")"
    if [[ "$c" == "0" ]]; then
      return 1
    fi
    if [[ "$c" =~ ^[0-9]+$ ]] && ((10#$c>=1 && 10#$c<=${#options[@]})); then
      PROTO2="${options[$((c-1))]}"
      return 0
    fi
    add_log "Invalid proto2"
  done
}

direct_proto_menu() {
  local p1=""
  while true; do
    render
    echo "Direct Method"
    echo "1) SOCKS5"
    echo "2) ICMP"
    echo "3) TLS"
    echo "4) OTLS"
    echo "5) RELAY"
    echo "6) SSH"
    echo "7) FTCP"
    echo "0) Back"
    echo
    read -r -e -p "Select proto1: " p1
    p1="$(sanitize_input "$p1")"
    case "$p1" in
      1) PROTO1="socks5" ;;
      2) PROTO1="icmp" ;;
      3) PROTO1="tls" ;;
      4) PROTO1="otls" ;;
      5) PROTO1="relay" ;;
      6) PROTO1="ssh" ;;
      7) PROTO1="ftcp" ;;
      0) return 0 ;;
      *) add_log "Invalid proto1"; continue ;;
    esac
    break
  done

  case "$PROTO1" in
    socks5)
      proto2_menu "Direct Method (proto1=$PROTO1)" raw tcp icmp ssh || return 0
      ;;
    icmp)
      proto2_menu "Direct Method (proto1=$PROTO1)" raw ws tcp otls ftcp relay ssh || return 0
      ;;
    tls|otls)
      proto2_menu "Direct Method (proto1=$PROTO1)" raw ws tcp icmp socks5 relay ssh || return 0
      ;;
    relay)
      proto2_menu "Direct Method (proto1=$PROTO1)" raw ws wss mws mwss tcp icmp socks5 relay ssh || return 0
      ;;
    ssh|ftcp)
      proto2_menu "Direct Method (proto1=$PROTO1)" raw || return 0
      ;;
  esac

  add_log "Selected: ${PROTO1}+${PROTO2}"
  if ! select_side_and_build; then return 0; fi

  if [[ "$SIDE" == "IRAN" ]]; then
    make_direct_iran
  else
    make_direct_kharej
  fi
}

reverse_proto_menu() {
  local p1=""
  while true; do
    render
    echo "Reverse Method"
    echo "1) RELAY"
    echo "2) SOCKS5"
    echo "0) Back"
    echo
    read -r -e -p "Select proto1: " p1
    p1="$(sanitize_input "$p1")"
    case "$p1" in
      1) PROTO1="relay" ;;
      2) PROTO1="socks5" ;;
      0) return 0 ;;
      *) add_log "Invalid proto1"; continue ;;
    esac
    break
  done

  if [[ "$PROTO1" == "relay" ]]; then
    proto2_menu "Reverse Method (proto1=$PROTO1)" raw ws tcp otls icmp || return 0
  else
    proto2_menu "Reverse Method (proto1=$PROTO1)" raw tcp otls icmp relay || return 0
  fi

  add_log "Selected: ${PROTO1}+${PROTO2}"
  if ! select_side_and_build; then return 0; fi

  if [[ "$SIDE" == "IRAN" ]]; then
    make_reverse_iran
  else
    make_reverse_kharej
  fi
}

get_gost_units() {
  find "$SYS_DIR" -maxdepth 1 -type f -name 'gost-*.service' 2>/dev/null \
    -printf '%f\n' \
  | grep -E '^gost-(iran|kharej)-[0-9]+\.service$' \
  | awk 'NF' \
  | sort -V
}

menu_select_unit_strict() {
  local title="$1"
  local choice=""
  mapfile -t UNITS < <(get_gost_units)

  if ((${#UNITS[@]}==0)); then
    add_log "Service not found."
    render
    return 1
  fi

  while true; do
    render
    echo "$title"
    echo
    local i
    for ((i=0; i<${#UNITS[@]}; i++)); do
      printf "%d) %s\n" $((i+1)) "${UNITS[$i]}"
    done
    echo "0) Back"
    echo

    read -r -e -p "Select service: " choice
    choice="$(sanitize_input "$choice")"

    if [[ "$choice" == "0" ]]; then
      return 1
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]] && ((10#$choice>=1 && 10#$choice<=${#UNITS[@]})); then
      SELECTED_UNIT="${UNITS[$((choice-1))]}"
      return 0
    fi
    add_log "Invalid selection"
  done
}

remove_unit_everywhere() {
  local unit="$1"
  local unit_path="${SYS_DIR}/${unit}"

  add_log "Stopping: $unit"
  systemctl stop "$unit" >/dev/null 2>&1 || true
  systemctl kill -s SIGKILL "$unit" >/dev/null 2>&1 || true

  add_log "Disabling: $unit"
  systemctl disable "$unit" >/dev/null 2>&1 || true

  add_log "Removing unit file"
  rm -f "$unit_path" >/dev/null 2>&1 || true
  rm -rf "${unit_path}.d" >/dev/null 2>&1 || true

  add_log "Removing autostart links"
  local d
  for d in /etc/systemd/system/*.wants /etc/systemd/system/*/*.wants; do
    rm -f "$d/$unit" >/dev/null 2>&1 || true
  done

  rm -f /run/systemd/generator/*"$unit"* >/dev/null 2>&1 || true
  rm -f /run/systemd/generator.late/*"$unit"* >/dev/null 2>&1 || true

  add_log "Daemon reload + reset-failed"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  systemctl reset-failed >/dev/null 2>&1 || true

  add_log "Removed: $unit"
}

uninstall_menu() {
  if ! menu_select_unit_strict "Uninstall"; then
    return 0
  fi

  while true; do
    remove_unit_everywhere "$SELECTED_UNIT"
    pause_enter
    if ! menu_select_unit_strict "Uninstall"; then
      return 0
    fi
  done
}

valid_hourly_step() {
  local v="$1"
  is_int "$v" || return 1
  ((10#$v>=1 && 10#$v<=12))
}
valid_minute_step() {
  local v="$1"
  is_int "$v" || return 1
  ((10#$v>=5 && 10#$v<=55))
}

ensure_reset_script_line() {
  local unit="$1"
  local line="sudo systemctl restart ${unit} 2>/dev/null || true"

  if [[ ! -f "$RESET_SCRIPT" ]]; then
    add_log "Creating reset script"
    write_atomic "$RESET_SCRIPT" <<EOF
#!/bin/bash
${line}
sudo journalctl --vacuum-size=1M
EOF
    chmod +x "$RESET_SCRIPT" >/dev/null 2>&1 || true
    return 0
  fi

  if ! head -n1 "$RESET_SCRIPT" 2>/dev/null | grep -q '^#!/bin/bash'; then
    add_log "Fixing reset script header"
    local tmp="${RESET_SCRIPT}.tmp.$$"
    {
      echo '#!/bin/bash'
      cat "$RESET_SCRIPT"
    } > "$tmp"
    mv -f "$tmp" "$RESET_SCRIPT"
  fi

  if grep -Fqx "$line" "$RESET_SCRIPT" 2>/dev/null; then
    add_log "Service already in reset script"
  else
    add_log "Adding service to reset script"
    if grep -q 'journalctl --vacuum-size=1M' "$RESET_SCRIPT" 2>/dev/null; then
      sed -i "/journalctl --vacuum-size=1M/i ${line}" "$RESET_SCRIPT" >/dev/null 2>&1 || true
    else
      echo "$line" >> "$RESET_SCRIPT"
      echo "sudo journalctl --vacuum-size=1M" >> "$RESET_SCRIPT"
    fi
  fi

  chmod +x "$RESET_SCRIPT" >/dev/null 2>&1 || true
  return 0
}

set_reset_cron() {
  local mode="$1" step="$2"
  local cron_line=""
  if [[ "$mode" == "hourly" ]]; then
    cron_line="0 */${step} * * * ${RESET_SCRIPT}"
  else
    cron_line="*/${step} * * * * ${RESET_SCRIPT}"
  fi

  local tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -vF "$RESET_SCRIPT" > "$tmp" || true
  echo "$cron_line" >> "$tmp"
  crontab "$tmp" >/dev/null 2>&1 || true
  rm -f "$tmp" >/dev/null 2>&1 || true

  add_log "Cron set: $cron_line"
}

service_reset_cronjob_menu() {
  if ! menu_select_unit_strict "Service Reset CronJob"; then
    return 0
  fi

  while true; do
    local mode=""
    while true; do
      render
      echo "Selected: $SELECTED_UNIT"
      echo
      echo "1) Hourly"
      echo "2) Minute"
      echo "0) Back"
      echo
      read -r -e -p "Select: " mode
      mode="$(sanitize_input "$mode")"
      case "$mode" in
        1) mode="hourly"; break ;;
        2) mode="minute"; break ;;
        0) mode=""; break ;;
        *) add_log "Invalid selection" ;;
      esac
    done

    if [[ -z "$mode" ]]; then
      if ! menu_select_unit_strict "Service Reset CronJob"; then
        return 0
      fi
      continue
    fi

    local step=""
    if [[ "$mode" == "hourly" ]]; then
      ask_until_valid "Input hourly step (1-12):" valid_hourly_step step
    else
      ask_until_valid "Input minute step (5-55):" valid_minute_step step
    fi

    ensure_reset_script_line "$SELECTED_UNIT"
    set_reset_cron "$mode" "$step"
    pause_enter

    if ! menu_select_unit_strict "Service Reset CronJob"; then
      return 0
    fi
  done
}
optimizer_menu() {
  local c=""
  while true; do
    render
    echo "Optimizer"
    echo
    echo "1) Apply"
    echo "2) Delete"
    echo "0) Back"
    echo
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      1) add_log "Optimizer: Apply"; optimizer_apply; return 0 ;;
      2) add_log "Optimizer: Delete"; optimizer_delete; return 0 ;;
      0) return 0 ;;
      *) add_log "Invalid selection" ;;
    esac
  done
}

optimizer_apply() {
  local sysctl_conf="/etc/sysctl.d/99-gost-20k.conf"
  local logrotate_conf="/etc/logrotate.d/rsyslog"

  add_log "Optimizer: write sysctl config"
  render

  write_atomic "$sysctl_conf" <<'EOF'
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_limit_output_bytes = 1048576
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.core.somaxconn=65535
net.core.netdev_max_backlog=65535
net.ipv4.tcp_max_syn_backlog=65535
fs.file-max=2097152
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6
net.ipv4.tcp_syncookies=1
EOF

  add_log "Applying sysctl"
  render
  sysctl --system >/dev/null 2>&1 || true

  add_log "Optimizer: write logrotate config"
  render

  write_atomic "$logrotate_conf" <<'EOF'
/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
        rotate 0
        daily
        size 5G
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
EOF

  add_log "Running logrotate (dry-run)"
  render
  logrotate -d /etc/logrotate.conf >/dev/null 2>&1 || true

  add_log "Running logrotate (force)"
  render
  logrotate -f /etc/logrotate.conf >/dev/null 2>&1 || true

  add_log "Optimizer applied successfully"
  render
  pause_enter
}


optimizer_delete() {
  local conf="/etc/sysctl.d/99-gost-20k.conf"

  if [[ -f "$conf" ]]; then
    add_log "Removing: $conf"
    rm -f "$conf" >/dev/null 2>&1 || true
  else
    add_log "File not found: $conf"
  fi

  add_log "Applying sysctl"
  render
  sysctl --system >/dev/null 2>&1 || true

  add_log "Optimizer deleted"
  render
  pause_enter
}

service_action_menu() {
  local unit="$1"
  local c=""
  while true; do
    render
    echo "Service Management"
    echo
    echo "Selected: $unit"
    echo
    echo "1) Restart"
    echo "2) Stop"
    echo "3) Start"
    echo "4) Disable"
    echo "5) Enable"
    echo "6) Status"
    echo "0) Back"
    echo
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      1) add_log "Restart: $unit"; systemctl restart "$unit" >/dev/null 2>&1 || add_log "Restart failed";;
      2) add_log "Stop: $unit"; systemctl stop "$unit" >/dev/null 2>&1 || add_log "Stop failed";;
      3) add_log "Start: $unit"; systemctl start "$unit" >/dev/null 2>&1 || add_log "Start failed";;
      4) add_log "Disable: $unit"; systemctl disable "$unit" >/dev/null 2>&1 || add_log "Disable failed";;
      5) add_log "Enable: $unit"; systemctl enable "$unit" >/dev/null 2>&1 || add_log "Enable failed";;
      6) show_status "$unit" ;;
      0) return 0 ;;
      *) add_log "Invalid selection" ;;
    esac
  done
}

service_management_menu() {
  if ! menu_select_unit_strict "Service Management"; then
    return 0
  fi

  while true; do
    service_action_menu "$SELECTED_UNIT"
    if ! menu_select_unit_strict "Service Management"; then
      return 0
    fi
  done
}

usage_cli() {

  term_width() {
    local w
    w="$(tput cols 2>/dev/null)"
    [[ -z "$w" || "$w" -lt 60 ]] && w=100
    echo "$w"
  }

  wrap_line() {
    local width
    width="$(term_width)"
    fold -s -w "$width"
  }

  disp_p2() { [[ "$1" == "raw" ]] && echo "RAW" || echo "$1"; }

  cat <<'EOF'
Quick usage (NEW):

  ./taha <side> <method> <PROTO1+PROTO2> <TID> <PEER_IP> <TUN_PORT> [FORWARD_PORTS] [SSH_ID]

SIDE:
  ir | iran     => IRAN side
  kh | kharej   => KHAREJ side

METHOD:
  1 | d | direct      => Direct
  2 | r | reverse     => Reverse
EOF

  echo
  echo "Direct:"
  echo "  IRAN  : ./taha ir <method> PROTO1+PROTO2  TID KHAREJ_IP TUN_PORT FORWARD_PORTS [SSH_ID]"
  echo "  KHAREJ: ./taha kh <method> PROTO1+PROTO2  TID IRAN_IP   TUN_PORT"

  echo
  echo "Reverse:"
  echo "  IRAN  : ./taha ir <method> PROTO1+PROTO2  TID KHAREJ_IP TUN_PORT"
  echo "  KHAREJ: ./taha kh <method> PROTO1+PROTO2  TID IRAN_IP   TUN_PORT FORWARD_PORTS [SSH_ID]"

  echo
  cat <<'EOF'
Notes:
- PROTO1+PROTO2 can be: NUM+NUM | NAME+NAME | NUM+NAME | NAME+NUM
- SSH_ID only required if proto includes ssh (forwarder side)
- FORWARD_PORTS: 80 | 80,2053 | 2050-2060
EOF

echo
echo "For mappings list:"
echo "  ./taha -m"

}
usage_map() {
  term_width() {
    local w
    w="$(tput cols 2>/dev/null)"
    [[ -z "$w" || "$w" -lt 60 ]] && w=100
    echo "$w"
  }

  wrap_line() {
    local width
    width="$(term_width)"
    fold -s -w "$width"
  }

  disp_p2() { [[ "$1" == "raw" ]] && echo "RAW" || echo "$1"; }

  echo
  echo "DIRECT (method=1|d|direct) mappings:"
  echo "1+1 = socks5+$(disp_p2 raw) | 1+2 = socks5+tcp | 1+3 = socks5+icmp | 1+4 = socks5+ssh |" | wrap_line
  echo "2+1 = icmp+$(disp_p2 raw) | 2+2 = icmp+ws | 2+3 = icmp+tcp | 2+4 = icmp+otls | 2+5 = icmp+ftcp | 2+6 = icmp+relay | 2+7 = icmp+ssh |" | wrap_line
  echo "3+1 = tls+$(disp_p2 raw) | 3+2 = tls+ws | 3+3 = tls+tcp | 3+4 = tls+icmp | 3+5 = tls+socks5 | 3+6 = tls+relay | 3+7 = tls+ssh |" | wrap_line
  echo "4+1 = otls+$(disp_p2 raw) | 4+2 = otls+ws | 4+3 = otls+tcp | 4+4 = otls+icmp | 4+5 = otls+socks5 | 4+6 = otls+relay | 4+7 = otls+ssh |" | wrap_line
  echo "5+1 = relay+$(disp_p2 raw) | 5+2 = relay+ws | 5+3 = relay+wss | 5+4 = relay+mws | 5+5 = relay+mwss | 5+6 = relay+tcp | 5+7 = relay+icmp | 5+8 = relay+socks5 | 5+9 = relay+relay | 5+10 = relay+ssh |" | wrap_line
  echo "6+1 = ssh+$(disp_p2 raw) |" | wrap_line
  echo "7+1 = ftcp+$(disp_p2 raw) |" | wrap_line

  echo
  echo "REVERSE (method=2|r|reverse) mappings:"
  echo "1+1 = relay+$(disp_p2 raw) | 1+2 = relay+ws | 1+3 = relay+tcp | 1+4 = relay+otls | 1+5 = relay+icmp |" | wrap_line
  echo "2+1 = socks5+$(disp_p2 raw) | 2+2 = socks5+tcp | 2+3 = socks5+otls | 2+4 = socks5+icmp | 2+5 = socks5+relay |" | wrap_line

  echo
  echo "Examples:"
  echo "  ./taha ir d tls+ws   9 10.20.30.40 443 2052,2053"
  echo "  ./taha ir 1 3+2      9 10.20.30.40 443 2052,2053"
  echo "  ./taha ir direct ssh+raw 9 10.20.30.40 443 2052,2053 5"
  echo
  echo "  ./taha kh 1 tls+ws   9 10.20.30.41 443"
  echo "  ./taha kh r relay+ws 9 10.20.30.41 443 2052,2053"

  echo
  echo "Mixed proto examples:"
  echo "  3+ws     = tls+ws"
  echo "  tls+2    = tls+ws"
  echo "  5+ssh    = relay+ssh"
  echo "  relay+10 = relay+ssh"
  echo "  socks+1  = socks5+RAW"
}


parse_ports_spec() {
  local raw="$1"
  raw="$(sanitize_input "$raw")"
  raw="${raw// /}"
  [[ -z "$raw" ]] && return 1

  local -a ports=()
  local ok=1

  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    valid_port "$raw" && ports+=("$raw") || ok=0

  elif [[ "$raw" =~ ^[0-9]+-[0-9]+$ ]]; then
    local s="${raw%-*}"
    local e="${raw#*-}"
    if valid_port "$s" && valid_port "$e" && ((10#$s<=10#$e)); then
      local p
      for ((p=10#$s; p<=10#$e; p++)); do ports+=("$p"); done
    else
      ok=0
    fi

  elif [[ "$raw" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
    IFS=',' read -r -a parts <<<"$raw"
    local part
    for part in "${parts[@]}"; do
      valid_port "$part" && ports+=("$part") || { ok=0; break; }
    done
  else
    ok=0
  fi

  ((ok==0)) && return 1

  mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
  PORT_SPEC="$raw"
  return 0
}

proto_direct_p1() {
  case "$1" in
    1) echo "socks5" ;;
    2) echo "icmp" ;;
    3) echo "tls" ;;
    4) echo "otls" ;;
    5) echo "relay" ;;
    6) echo "ssh" ;;
    7) echo "ftcp" ;;
    *) return 1 ;;
  esac
}

proto_reverse_p1() {
  case "$1" in
    1) echo "relay" ;;
    2) echo "socks5" ;;
    *) return 1 ;;
  esac
}

normalize_method() {
  local m
  m="$(sanitize_input "${1:-}")"
  m="$(echo "$m" | tr 'A-Z' 'a-z')"

  case "$m" in
    1|d|dir|direct) echo "1" ;;
    2|r|rev|reverse) echo "2" ;;
    *) return 1 ;;
  esac
}


proto2_from_p1_direct() {
  local p1="$1" p2n="$2"
  case "$p1" in
    socks5)
      case "$p2n" in 1)echo raw;;2)echo tcp;;3)echo icmp;;4)echo ssh;;*)return 1;; esac ;;
    icmp)
      case "$p2n" in 1)echo raw;;2)echo ws;;3)echo tcp;;4)echo otls;;5)echo ftcp;;6)echo relay;;7)echo ssh;;*)return 1;; esac ;;
    tls|otls)
      case "$p2n" in 1)echo raw;;2)echo ws;;3)echo tcp;;4)echo icmp;;5)echo socks5;;6)echo relay;;7)echo ssh;;*)return 1;; esac ;;
    relay)
      case "$p2n" in
        1)echo raw;;2)echo ws;;3)echo wss;;4)echo mws;;5)echo mwss;;
        6)echo tcp;;7)echo icmp;;8)echo socks5;;9)echo relay;;10)echo ssh;;
        *)return 1;;
      esac ;;
    ssh|ftcp)
      case "$p2n" in 1)echo raw;;*)return 1;; esac ;;
    *) return 1 ;;
  esac
}

proto2_from_p1_reverse() {
  local p1="$1" p2n="$2"
  case "$p1" in
    relay)
      case "$p2n" in 1)echo raw;;2)echo ws;;3)echo tcp;;4)echo otls;;5)echo icmp;;*)return 1;; esac ;;
    socks5)
      case "$p2n" in 1)echo raw;;2)echo tcp;;3)echo otls;;4)echo icmp;;5)echo relay;;*)return 1;; esac ;;
    *) return 1 ;;
  esac
}

parse_proto_spec() {
  local spec="$1"
  spec="$(sanitize_input "$spec")"
  spec="${spec// /}"
  [[ "$spec" =~ ^([^+]+)\+([^+]+)$ ]] || return 1
  P1TOK="${BASH_REMATCH[1]}"
  P2TOK="${BASH_REMATCH[2]}"
  return 0
}
norm_tok() {
  local t="$1"
  t="$(sanitize_input "$t")"
  t="${t// /}"
  echo "$t" | tr 'A-Z' 'a-z'
}

tok_kind() { [[ "$1" =~ ^[0-9]+$ ]] && echo "num" || echo "name"; }

proto_direct_p1_name() {
  case "$(norm_tok "$1")" in
    socks5|socks) echo "socks5" ;;
    icmp) echo "icmp" ;;
    tls) echo "tls" ;;
    otls) echo "otls" ;;
    relay) echo "relay" ;;
    ssh) echo "ssh" ;;
    ftcp) echo "ftcp" ;;
    *) return 1 ;;
  esac
}
proto_reverse_p1_name() {
  case "$(norm_tok "$1")" in
    relay) echo "relay" ;;
    socks5|socks) echo "socks5" ;;
    *) return 1 ;;
  esac
}

proto2_direct_name_for_p1() {
  local p1="$1" p2="$(norm_tok "$2")"
  case "$p1" in
    socks5)
      case "$p2" in raw|tcp|icmp|ssh) echo "$p2" ;; *) return 1;; esac ;;
    icmp)
      case "$p2" in raw|ws|tcp|otls|ftcp|relay|ssh) echo "$p2" ;; *) return 1;; esac ;;
    tls|otls)
      case "$p2" in raw|ws|tcp|icmp|socks5|socks|relay|ssh)
        [[ "$p2" == "socks" ]] && p2="socks5"
        echo "$p2"
      ;; *) return 1;; esac ;;
    relay)
      case "$p2" in raw|ws|wss|mws|mwss|tcp|icmp|socks5|socks|relay|ssh)
        [[ "$p2" == "socks" ]] && p2="socks5"
        echo "$p2"
      ;; *) return 1;; esac ;;
    ssh|ftcp)
      [[ "$p2" == "raw" ]] && echo "raw" || return 1 ;;
    *) return 1 ;;
  esac
}

proto2_reverse_name_for_p1() {
  local p1="$1" p2="$(norm_tok "$2")"
  case "$p1" in
    relay)
      case "$p2" in raw|ws|tcp|otls|icmp) echo "$p2" ;; *) return 1;; esac ;;
    socks5)
      case "$p2" in raw|tcp|otls|icmp|relay) echo "$p2" ;; *) return 1;; esac ;;
    *) return 1 ;;
  esac
}

resolve_proto_pair() {
  local method="$1"
  local t1="$2" t2="$3"

  t1="$(norm_tok "$t1")"
  t2="$(norm_tok "$t2")"

  if [[ "$method" == "1" ]]; then
    if [[ "$(tok_kind "$t1")" == "num" ]]; then
      PROTO1="$(proto_direct_p1 "$t1")" || return 1
    else
      PROTO1="$(proto_direct_p1_name "$t1")" || return 1
    fi

    if [[ "$(tok_kind "$t2")" == "num" ]]; then
      PROTO2="$(proto2_from_p1_direct "$PROTO1" "$t2")" || return 1
    else
      PROTO2="$(proto2_direct_name_for_p1 "$PROTO1" "$t2")" || return 1
    fi
    return 0
  fi

  if [[ "$(tok_kind "$t1")" == "num" ]]; then
    PROTO1="$(proto_reverse_p1 "$t1")" || return 1
  else
    PROTO1="$(proto_reverse_p1_name "$t1")" || return 1
  fi

  if [[ "$(tok_kind "$t2")" == "num" ]]; then
    PROTO2="$(proto2_from_p1_reverse "$PROTO1" "$t2")" || return 1
  else
    PROTO2="$(proto2_reverse_name_for_p1 "$PROTO1" "$t2")" || return 1
  fi
  return 0
}


need_ssh_id() {
  [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]
}


make_direct_iran_cli() {
  ensure_gost_installed || return 1
  local tid="$1" kh_ip="$2" tun_port="$3" portspec="$4" sshid="${5:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$kh_ip" || { echo "Invalid KHAREJ IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }
  parse_ports_spec "$portspec" || { echo "Invalid forward ports: $portspec"; return 1; }

  if need_ssh_id; then
    valid_id_1_99 "$sshid" || { echo "SSH_ID required/invalid"; return 1; }
  fi

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"
  local keydir forward_uri execstart

  keydir="$(ssh_key_dir)"

  if [[ "$PROTO2" == "raw" ]]; then
    if need_ssh_id; then
      forward_uri="${PROTO1}://root@${kh_ip}:${tun_port}?identity=${keydir}/iran${sshid}_ed25519"
    else
      forward_uri="${PROTO1}://${kh_ip}:${tun_port}"
    fi
  else
    if need_ssh_id; then
      forward_uri="${PROTO1}+${PROTO2}://root@${kh_ip}:${tun_port}?identity=${keydir}/iran${sshid}_ed25519"
    else
      forward_uri="${PROTO1}+${PROTO2}://${kh_ip}:${tun_port}"
    fi
  fi

  execstart="$(make_execstart_forwarder_F "tcp" "$PORT_SPEC" "$forward_uri")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${execstart}
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_direct_kharej_cli() {
  ensure_gost_installed || return 1
  local tid="$1" ir_ip="$2" tun_port="$3"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$ir_ip" || { echo "Invalid IRAN IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"
  local listen_uri

  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$ir_ip" "0")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${GOST_BIN} -L "${listen_uri}"
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_reverse_iran_cli() {
  ensure_gost_installed || return 1
  local tid="$1" kh_ip="$2" tun_port="$3"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$kh_ip" || { echo "Invalid KHAREJ IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"
  local listen_uri

  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$kh_ip" "1")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${GOST_BIN} -L "${listen_uri}"
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_reverse_kharej_cli() {
  ensure_gost_installed || return 1
  local tid="$1" ir_ip="$2" tun_port="$3" portspec="$4" sshid="${5:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$ir_ip" || { echo "Invalid IRAN IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }
  parse_ports_spec "$portspec" || { echo "Invalid forward ports: $portspec"; return 1; }

  if need_ssh_id; then
    valid_id_1_99 "$sshid" || { echo "SSH_ID required/invalid"; return 1; }
  fi

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"
  local keydir forward_uri execstart

  keydir="$(ssh_key_dir)"

  if [[ "$PROTO2" == "raw" ]]; then
    if need_ssh_id; then
      forward_uri="${PROTO1}://root@${ir_ip}:${tun_port}?identity=${keydir}/kharej${sshid}_ed25519"
    else
      forward_uri="${PROTO1}://${ir_ip}:${tun_port}"
    fi
  else
    if need_ssh_id; then
      forward_uri="${PROTO1}+${PROTO2}://root@${ir_ip}:${tun_port}?identity=${keydir}/kharej${sshid}_ed25519"
    else
      forward_uri="${PROTO1}+${PROTO2}://${ir_ip}:${tun_port}"
    fi
  fi

  execstart="$(make_execstart_forwarder_F "rtcp" "$PORT_SPEC" "$forward_uri")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
LimitNOFILE=1048576
TasksMax=infinity
ExecStart=${execstart}
Restart=always
RestartSec=1
KillMode=process
TimeoutStopSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

cli_main() {
  ensure_root "$@"

  case "${1:-}" in
    -h|--help|-help|help)
      usage_cli
      return 0
      ;;
    -m|-map|--map)
      usage_map
      return 0
      ;;
    -menu|--menu|menu)
      add_log "TaHa Tunnel Manager"
      main_menu
      exit 0
      ;;
  esac


  case "${1:-}" in
    -h|--help|-help|help)
      usage_cli
      return 0
      ;;
    -m|-map|--map)
      usage_map
      return 0
      ;;
  esac

  if (( $# == 0 )); then
    return 99
  fi

  local side_arg="${1:-}"
  shift || true

  case "$side_arg" in
    ir|iran|IR|IRAN) SIDE="IRAN" ;;
    kh|kharej|KH|KHAREJ) SIDE="KHAREJ" ;;
    *)
      usage_cli
      echo
      echo "Hint: use ./taha -m to see mappings"
      return 1
      ;;
  esac

  local method_raw="${1:-}"
  local method=""
  local protospec="${2:-}"
  local tid="${3:-}"
  local peer_ip="${4:-}"
  local tun_port="${5:-}"
  local forward_ports="${6:-}"
  local sshid="${7:-}"

  method="$(normalize_method "$method_raw")" || {
    echo "Invalid method: $method_raw (use: 1/2 or d/r or direct/reverse)"
    echo "Hint: use ./taha -h"
    return 1
  }

  if [[ -z "$protospec" || -z "$tid" || -z "$peer_ip" || -z "$tun_port" ]]; then
    usage_cli
    return 1
  fi

  parse_proto_spec "$protospec" || {
    echo "Invalid proto spec: $protospec"
    echo "Hint: use ./taha -m to see mappings"
    return 1
  }

  if ! resolve_proto_pair "$method" "$P1TOK" "$P2TOK"; then
    echo "Invalid proto combination"
    echo "Hint: use ./taha -m to see mappings"
    return 1
  fi

  if [[ "$method" == "1" ]]; then
    if [[ "$SIDE" == "IRAN" ]]; then
      [[ -n "$forward_ports" ]] || { echo "Forward ports required on IRAN direct."; return 1; }
      make_direct_iran_cli "$tid" "$peer_ip" "$tun_port" "$forward_ports" "$sshid"
    else
      make_direct_kharej_cli "$tid" "$peer_ip" "$tun_port"
    fi
  else
    if [[ "$SIDE" == "IRAN" ]]; then
      make_reverse_iran_cli "$tid" "$peer_ip" "$tun_port"
    else
      [[ -n "$forward_ports" ]] || { echo "Forward ports required on KHAREJ reverse."; return 1; }
      make_reverse_kharej_cli "$tid" "$peer_ip" "$tun_port" "$forward_ports" "$sshid"
    fi
  fi
}



main_menu() {
  local choice=""
  while true; do
    renderx
    echo "1) Install Core"
    echo "2) Direct Method"
    echo "3) Reverse Method"
    echo "4) Service Management"
    echo "5) Service Reset CronJob"
    echo "6) SSH Key Generator"	
    echo "7) Optimizer"
    echo "8) Uninstall"
    echo "0) Exit"
    echo
    read -r -e -p "Select option: " choice
    choice="$(sanitize_input "$choice")"

    case "$choice" in
      1) add_log "Menu: Install Core"; install_core ;;
      2) add_log "Menu: Direct Method"; direct_proto_menu ;;
      3) add_log "Menu: Reverse Method"; reverse_proto_menu ;;
      4) add_log "Menu: Service Management"; service_management_menu ;;
      5) add_log "Menu: Reset CronJob"; service_reset_cronjob_menu ;;
      6) add_log "Menu: SSH Key Generator"; ssh_key_generator_menu ;;	  
      7) add_log "Menu: Optimizer"; optimizer_menu ;;
      8) add_log "Menu: Uninstall"; uninstall_menu ;;
      0) add_log "Bye"; render; exit 0 ;;
      *) add_log "Invalid option: $choice" ;;
    esac
  done
}

main() {
  ensure_root "$@"

  if (( $# == 0 )); then
    add_log "TaHa Tunnel Manager"
    main_menu
    return 0
  fi

  cli_main "$@"
  rc=$?

  if (( rc == 99 )); then
    add_log "TaHa Tunnel Manager"
    main_menu
    return 0
  fi

  return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
