#!/usr/bin/env bash

set +e
set +u
export LC_ALL=C

TAHA_VER="20260217"
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

is_allowed_proto1() {
  local p="$(norm_tok "$1")"
  case "$p" in
    tcp|mtcp|udp|tls|mtls|ws|wss|mws|mwss|h2|h2c|grpc|pht|quic|kcp|icmp|ohttp|otls|ftcp|http|http2|socks4|socks5|forward|relay)
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_allowed_proto2() {
  local p="$(norm_tok "$1")"
  case "$p" in
    tcp|mtcp|udp|tls|mtls|ws|wss|mws|mwss|h2|h2c|grpc|pht|quic|kcp|icmp|ohttp|otls|ftcp|http|http2|socks4|socks5|relay|ssh|raw)
      return 0
      ;;
    *) return 1 ;;
  esac
}

ask_proto_pair_typed() {
  local mode="$1"
  local p1="" p2=""

  while true; do
    render
    echo "Type your proto1 (allowed):"
    echo "tcp,mtcp,udp,tls,mtls,ws,wss,mws,mwss,h2,h2c,grpc,pht,quic,kcp,icmp,ohttp,otls,ftcp,http,http2,socks4,socks5,forward,relay"
    echo
    read -r -e -p "type your proto1: " p1
    p1="$(sanitize_input "$p1")"
    p1="$(norm_tok "$p1")"
    [[ "$p1" == "0" ]] && return 1
    if is_allowed_proto1 "$p1"; then
      PROTO1="$p1"
      break
    fi
    add_log "Invalid proto1: $p1"
  done

  while true; do
    render
    echo "Type your proto2 (allowed):"
    echo "tcp,mtcp,udp,tls,mtls,ws,wss,mws,mwss,h2,h2c,grpc,pht,quic,kcp,icmp,ohttp,otls,ftcp,http,http2,socks4,socks5,relay,ssh,raw"
    echo
    read -r -e -p "type your proto2: " p2
    p2="$(sanitize_input "$p2")"
    p2="$(norm_tok "$p2")"
    [[ "$p2" == "0" ]] && return 1
    if is_allowed_proto2 "$p2"; then
      PROTO2="$p2"
      break
    fi
    add_log "Invalid proto2: $p2"
  done

  return 0
}

custom_target_proto() {
  if [[ "$(norm_tok "$PROTO2")" == "raw" ]]; then
    echo "$(norm_tok "$PROTO1")"
  else
    echo "$(norm_tok "$PROTO2")"
  fi
}

ask_forward_scheme() {
  local method="$1"
  local c=""
  while true; do
    render
    echo "select forward:"
    echo "1) tcp"
    echo "2) udp"
    echo "0) Back"
    echo
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      1)
        if [[ "$method" == "reverse" ]]; then
          FORWARD_SCHEME="rtcp"
        else
          FORWARD_SCHEME="tcp"
        fi
        return 0
        ;;
      2)
        if [[ "$method" == "reverse" ]]; then
          FORWARD_SCHEME="rudp"
        else
          FORWARD_SCHEME="udp"
        fi
        return 0
        ;;
      0) return 1 ;;
      *) add_log "Invalid selection" ;;
    esac
  done
}

append_query_to_uri() {
  local uri="$1"
  local q="$2"
  q="$(sanitize_input "$q")"
  q="${q// /}"
  q="${q//$'\n'/}"
  q="${q//$'\r'/}"
  [[ -z "$q" ]] && { echo "$uri"; return 0; }

  if [[ "$uri" == *\?* ]]; then
    echo "${uri}&${q}"
  else
    echo "${uri}?${q}"
  fi
}

normalize_query_path_kv() {
  local q="$1"
  q="$(sanitize_input "$q")"
  q="${q//$'\n'/}"
  q="${q//$'\r'/}"
  [[ -z "$q" ]] && { echo ""; return 0; }

  local out=""
  local IFS='&'
  read -r -a parts <<<"$q"
  local item k v
  for item in "${parts[@]}"; do
    [[ -z "$item" ]] && continue
    if [[ "$item" == path=* ]]; then
      k="path"
      v="${item#path=}"
      v="$(sanitize_input "$v")"
      v="${v// /}"
      [[ -n "$v" && "$v" != 0 && "$v" != /* ]] && v="/$v"
      item="path=${v}"
    fi
    if [[ -z "$out" ]]; then out="$item"; else out="${out}&${item}"; fi
  done
  echo "$out"
}

sanitize_query_string() {
  local q="$1"
  q="$(sanitize_input "$q")"
  q="${q//$'\n'/}"
  q="${q//$'\r'/}"
  q="${q//\"/}"
  q="${q//\\/}"

  q="$(printf '%s' "$q" | tr -cd '[:alnum:]._:/,&=-')"
  q="${q##&}"
  q="${q%%&}"

  q="$(normalize_query_path_kv "$q")"
  printf '%s' "$q"
}

build_peer_uri() {
  local peer_ip="$1" tun_port="$2" sshid="$3" side_prefix="$4" query_extra="$5"
  query_extra="$(sanitize_query_string "$query_extra")"
  local keydir forward_uri proto

  keydir="$(ssh_key_dir)"

  if [[ "$PROTO2" == "raw" ]]; then
    proto="$PROTO1"
  else
    proto="${PROTO1}+${PROTO2}"
  fi

  if need_ssh_id; then
    forward_uri="${proto}://root@${peer_ip}:${tun_port}?identity=${keydir}/${side_prefix}${sshid}_ed25519"
    if [[ -n "$query_extra" ]]; then
      forward_uri="${forward_uri}&${query_extra}"
    fi
  else
    forward_uri="${proto}://${peer_ip}:${tun_port}"
    forward_uri="$(append_query_to_uri "$forward_uri" "$query_extra")"
  fi

  echo "$forward_uri"
}

should_offer_custom_settings() {
  local p="$(norm_tok "$1")"
  case "$p" in
    udp|mtls|ws|wss|mws|mwss|http2|h2|ssh|pht|grpc|quic|kcp|icmp|http|ohttp|ftcp|mtcp|socks5|relay)
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

ask_int_or_ignore() {
  local prompt="$1" def="$2" v=""
  while true; do
    render >&2
    read -r -e -p "${prompt} (int, default=${def}, 0=ignore): " v
    v="$(sanitize_input "$v")"
    v="${v// /}"
    [[ -z "$v" ]] && v="$def"
    is_uint "$v" || { add_log "Only number allowed"; continue; }
    printf '%s' "$v"
    return 0
  done
}

ask_duration_s_or_ignore() {
  local prompt="$1" def_s="$2" v=""
  local def="${def_s%s}"
  while true; do
    render >&2
    read -r -e -p "${prompt} (seconds, default=${def_s}, 0=ignore): " v
    v="$(sanitize_input "$v")"
    v="${v// /}"
    [[ -z "$v" ]] && v="$def"
    is_uint "$v" || { add_log "Only number allowed"; continue; }
    if [[ "$v" == "0" ]]; then
      printf '%s' "0"
    else
      printf '%s' "${v}s"
    fi
    return 0
  done
}

ask_bool_menu() {
  local prompt="$1" def="$2" c=""
  while true; do
    render >&2
    echo "${prompt} (bool, default=${def})" >&2
    echo "1) false" >&2
    echo "2) true" >&2
    echo "3) ignore" >&2
    echo >&2
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      1) printf '%s' "false"; return 0 ;;
      2) printf '%s' "true"; return 0 ;;
      3) printf '%s' "ignore"; return 0 ;;
      "") printf '%s' "$def"; return 0 ;;
      *) add_log "Invalid bool choice" ;;
    esac
  done
}

ask_mux_version() {
  local c=""
  while true; do
    render >&2
    echo "mux.version" >&2
    echo "1) 1" >&2
    echo "2) 2" >&2
    echo "0) ignore" >&2
    echo >&2
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      1) printf '%s' "1"; return 0 ;;
      2) printf '%s' "2"; return 0 ;;
      0) printf '%s' "0"; return 0 ;;
      *) add_log "Invalid mux.version" ;;
    esac
  done
}


norm_bool_token() {
  local v="$(norm_tok "$1")"
  case "$v" in
    1|false) echo "false" ;;
    2|true)  echo "true" ;;
    3|ignore|0) echo "ignore" ;;
    "") echo "" ;;
    *) echo "$v" ;;
  esac
}

norm_mux_version_token() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  case "$v" in
    "" ) echo "" ;;
    0|ignore) echo "0" ;;
    1) echo "1" ;;
    2) echo "2" ;;
    *) echo "$v" ;;
  esac
}

norm_int_token() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  echo "$v"
}

norm_duration_s_token() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  if [[ "$v" == "0" || "$v" == "ignore" ]]; then
    echo "0"
    return 0
  fi
  if [[ "$v" =~ ^[0-9]+s$ ]]; then
    echo "$v"
  elif [[ "$v" =~ ^[0-9]+$ ]]; then
    echo "${v}s"
  else
    echo "$v"
  fi
}

norm_path_token() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  [[ "$v" == "0" || "$v" == "ignore" ]] && echo "0" && return 0
  [[ "$v" != /* ]] && v="/$v"
  echo "$v"
}

norm_header_token() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  case "$v" in
    0|ignore) echo "0" ;;
    1) echo "Host:example.com" ;;
    2) echo "User-Agent:Mozilla/5.0" ;;
    3) echo "X-Forwarded-For:1.1.1.1" ;;
    4) echo "X-Real-IP:1.1.1.1" ;;
    5) echo "Accept-Language:en-US,en;q=0.9" ;;
    6) echo "Cache-Control:no-cache" ;;
    7) echo "Connection:keep-alive" ;;
    *) echo "$v" ;;
  esac
}


addkv_cli() {
  local __qvar="$1" k="$2" v="$3"
  v="$(sanitize_input "$v")"
  v="${v//$'\n'/}"; v="${v//$'\r'/}"
  v="${v//\"/}"; v="${v//\\/}"; v="${v//\?/}"
  v="${v// /}"
  [[ -z "$v" || "$v" == "0" || "$v" == "ignore" ]] && return 0
  v="${v//&/}"
  v="${v//=/}"
  if [[ "$k" == "path" ]]; then
    [[ "$v" != /* ]] && v="/$v"
  fi
  if [[ -z "${!__qvar}" ]]; then
    printf -v "$__qvar" '%s' "${k}=${v}"
  else
    printf -v "$__qvar" '%s' "${!__qvar}&${k}=${v}"
  fi
}

ask_path_or_ignore() {
  local prompt="$1" def="$2" v=""
  while true; do
    render >&2
    read -r -e -p "${prompt} (path, default=${def}, 0=ignore): " v
    v="$(sanitize_input "$v")"
    v="${v// /}"
    [[ -z "$v" ]] && v="$def"
    if [[ "$v" == "0" ]]; then
      printf '%s' "0"
      return 0
    fi
    [[ "$v" != /* ]] && v="/$v"
    printf '%s' "$v"
    return 0
  done
}


parse_forward_spec_v2() {
  local raw="$1"
  raw="$(sanitize_input "$raw")"
  raw="${raw// /}"
  [[ "$raw" =~ ^(tcp|udp)=.+$ ]] || return 1
  local sch="${raw%%=*}"
  local ps="${raw#*=}"

  parse_ports_spec "$ps" || return 1

  FORWARD_SCHEME="$sch"
  PORT_SPEC="$ps"
  return 0
}

effective_forward_scheme() {
  local method="$1" scheme="$2"
  if [[ "$method" == "reverse" ]]; then
    [[ "$scheme" == "tcp" ]] && echo "rtcp" && return 0
    [[ "$scheme" == "udp" ]] && echo "rudp" && return 0
  fi
  echo "$scheme"
}


csv_get() {
  local csv="$1" idx="$2"
  local IFS=','; read -r -a a <<<"$csv"
  local v="${a[$idx]:-}"
  v="$(sanitize_input "$v")"
  v="${v// /}"
  echo "$v"
}

norm_bool_csv() {
  local v="$(norm_tok "$1")"
  case "$v" in
    "" ) echo "" ;;
    0|ignore|3) echo "0" ;;
    1|false) echo "false" ;;
    2|true) echo "true" ;;
    true|false) echo "$v" ;;
    *) echo "$v" ;;
  esac
}

norm_int_csv() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" || echo "$v"
}

norm_dur_csv() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  if [[ "$v" == "0" || "$v" == "ignore" ]]; then
    echo "0"; return 0
  fi
  if [[ "$v" =~ ^[0-9]+s$ ]]; then
    echo "$v"
  elif [[ "$v" =~ ^[0-9]+$ ]]; then
    echo "${v}s"
  else
    echo "$v"
  fi
}

norm_path_csv() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  [[ "$v" == "0" || "$v" == "ignore" ]] && echo "0" && return 0
  [[ "$v" != /* ]] && v="/$v"
  echo "$v"
}

norm_header_csv() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  [[ "$v" == "0" || "$v" == "ignore" ]] && echo "0" && return 0
  echo "$v"
}

norm_mux_version_csv() {
  local v="$(sanitize_input "$1")"
  v="${v// /}"
  [[ -z "$v" ]] && echo "" && return 0
  [[ "$v" == "0" || "$v" == "ignore" ]] && echo "0" && return 0
  echo "$v"
}

addkv_csv() {
  local __qvar="$1" k="$2" v="$3"
  v="$(sanitize_input "$v")"
  v="${v//$'\n'/}"; v="${v//$'\r'/}"
  v="${v//\"/}"; v="${v//\\/}"; v="${v//\?/}"
  v="${v// /}"

  [[ -z "$v" || "$v" == "0" || "$v" == "ignore" ]] && return 0

  v="${v//&/}"
  v="${v//= /}"
  v="${v//=/}"

  if [[ "$k" == "path" ]]; then
    [[ "$v" != /* ]] && v="/$v"
  fi

  if [[ -z "${!__qvar}" ]]; then
    printf -v "$__qvar" '%s' "${k}=${v}"
  else
    printf -v "$__qvar" '%s' "${!__qvar}&${k}=${v}"
  fi
}


ask_header_pick_or_ignore() {
  local c=""
  while true; do
    render >&2
    echo "header (choose one)" >&2
    echo "1) Host: example.com" >&2
    echo "2) User-Agent: Mozilla/5.0" >&2
    echo "3) X-Forwarded-For: 1.1.1.1" >&2
    echo "4) X-Real-IP: 1.1.1.1" >&2
    echo "5) Accept-Language: en-US,en;q=0.9" >&2
    echo "6) Cache-Control: no-cache" >&2
    echo "7) Connection: keep-alive" >&2
    echo "0) ignore" >&2
    echo >&2
    read -r -e -p "Select: " c
    c="$(sanitize_input "$c")"
    case "$c" in
      0) printf '%s' "0"; return 0 ;;
      1) printf '%s' "Host:example.com"; return 0 ;;
      2) printf '%s' "User-Agent:Mozilla/5.0"; return 0 ;;
      3) printf '%s' "X-Forwarded-For:1.1.1.1"; return 0 ;;
      4) printf '%s' "X-Real-IP:1.1.1.1"; return 0 ;;
      5) printf '%s' "Accept-Language:en-US,en;q=0.9"; return 0 ;;
      6) printf '%s' "Cache-Control:no-cache"; return 0 ;;
      7) printf '%s' "Connection:keep-alive"; return 0 ;;
      *) add_log "Invalid header choice" ;;
    esac
  done
}

ask_custom_settings_menu() {
  local proto="$1"
  local yn=""
  while true; do
    render >&2
    read -r -e -p "custom setting? y/n: " yn
    yn="$(sanitize_input "$yn")"
    yn="$(echo "$yn" | tr 'A-Z' 'a-z')"
    case "$yn" in
      n|no) printf '%s' ""; return 0 ;;
      y|yes) break ;;
      *) add_log "Type y or n" ;;
    esac
  done

  build_query_for_proto "$proto"
}

build_query_for_proto() {
  local proto="$(norm_tok "$1")"
  local q=""

  add_kv() {
    local k="$1" v="$2"
    [[ -z "$v" || "$v" == "0" || "$v" == "ignore" ]] && return 0

    v="$(sanitize_input "$v")"
    v="${v//$'\n'/}"
    v="${v//$'\r'/}"

    v="${v//\"/}"
    v="${v//\\/}"
    v="${v//\?/}"
    v="${v// /}"

    v="${v//&/}"
    v="${v//= /}"
    v="${v//=/}"

    if [[ "$k" == "path" ]]; then
      [[ "$v" != /* ]] && v="/$v"
    fi

    [[ -z "$v" || "$v" == "0" ]] && return 0
    if [[ -z "$q" ]]; then q="${k}=${v}"; else q="${q}&${k}=${v}"; fi
  }

  case "$proto" in
    udp)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      add_kv "keepAlive" "$(ask_bool_menu "keepAlive" "false")"
      add_kv "ttl" "$(ask_duration_s_or_ignore "ttl" "5s")"
      local rv=""
      while true; do
        render
        read -r -e -p "relay (string, default=tcp, 0=ignore): " rv
        rv="$(sanitize_input "$rv")"; rv="$(norm_tok "$rv")"
        [[ -z "$rv" ]] && rv="tcp"
        [[ "$rv" == "0" || "$rv" =~ ^[a-z0-9]+$ ]] && break
        add_log "Invalid relay string"
      done
      add_kv "relay" "$rv"
      add_kv "readBufferSize" "$(ask_int_or_ignore "readBufferSize" "1500")"
      add_kv "readQueueSize" "$(ask_int_or_ignore "readQueueSize" "128")"
      ;;

    mtls)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      add_kv "mux.version" "$(ask_mux_version)"
      add_kv "mux.keepaliveDisabled" "$(ask_bool_menu "mux.keepaliveDisabled" "false")"
      add_kv "mux.keepaliveInterval" "$(ask_duration_s_or_ignore "mux.keepaliveInterval" "10s")"
      add_kv "mux.keepaliveTimeout" "$(ask_duration_s_or_ignore "mux.keepaliveTimeout" "30s")"
      add_kv "mux.maxFrameSize" "$(ask_int_or_ignore "mux.maxFrameSize" "32768")"
      add_kv "mux.maxReceiveBuffer" "$(ask_int_or_ignore "mux.maxReceiveBuffer" "4194304")"
      add_kv "mux.maxStreamBuffer" "$(ask_int_or_ignore "mux.maxStreamBuffer" "65536")"
      ;;

    ws|wss)
      add_kv "path" "$(ask_path_or_ignore "path" "/ws")"
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      local hv="$(ask_header_pick_or_ignore)"; [[ "$hv" != "0" ]] && add_kv "header" "$hv"
      add_kv "handshakeTimeout" "$(ask_duration_s_or_ignore "handshakeTimeout" "5s")"
      add_kv "readHeaderTimeout" "$(ask_duration_s_or_ignore "readHeaderTimeout" "5s")"
      add_kv "readBufferSize" "$(ask_int_or_ignore "readBufferSize" "4096")"
      add_kv "writeBufferSize" "$(ask_int_or_ignore "writeBufferSize" "4096")"
      ;;

    mws|mwss)
      add_kv "path" "$(ask_path_or_ignore "path" "/ws")"
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      local hv="$(ask_header_pick_or_ignore)"; [[ "$hv" != "0" ]] && add_kv "header" "$hv"
      add_kv "handshakeTimeout" "$(ask_duration_s_or_ignore "handshakeTimeout" "5s")"
      add_kv "readHeaderTimeout" "$(ask_duration_s_or_ignore "readHeaderTimeout" "5s")"
      add_kv "readBufferSize" "$(ask_int_or_ignore "readBufferSize" "4096")"
      add_kv "writeBufferSize" "$(ask_int_or_ignore "writeBufferSize" "4096")"
      add_kv "mux.version" "$(ask_mux_version)"
      add_kv "mux.keepaliveDisabled" "$(ask_bool_menu "mux.keepaliveDisabled" "false")"
      add_kv "mux.keepaliveInterval" "$(ask_duration_s_or_ignore "mux.keepaliveInterval" "10s")"
      add_kv "mux.keepaliveTimeout" "$(ask_duration_s_or_ignore "mux.keepaliveTimeout" "30s")"
      add_kv "mux.maxFrameSize" "$(ask_int_or_ignore "mux.maxFrameSize" "32768")"
      add_kv "mux.maxReceiveBuffer" "$(ask_int_or_ignore "mux.maxReceiveBuffer" "4194304")"
      add_kv "mux.maxStreamBuffer" "$(ask_int_or_ignore "mux.maxStreamBuffer" "65536")"
      ;;

    http2|h2|ssh|pht)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      ;;

    grpc)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      add_kv "grpcInsecure" "$(ask_bool_menu "grpcInsecure" "false")"
      add_kv "path" "$(ask_path_or_ignore "path" "/GostTunel/Tunnel")"
      ;;

    quic|kcp|icmp)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      add_kv "keepAlive" "$(ask_bool_menu "keepAlive" "false")"
      add_kv "ttl" "$(ask_duration_s_or_ignore "ttl" "10s")"
      add_kv "handshakeTimeout" "$(ask_duration_s_or_ignore "handshakeTimeout" "5s")"
      add_kv "maxIdleTimeout" "$(ask_duration_s_or_ignore "maxIdleTimeout" "30s")"
      ;;

    http|ohttp)
      local hv="$(ask_header_pick_or_ignore)"
      [[ "$hv" != "0" ]] && add_kv "header" "$hv"
      ;;

    ftcp)
      add_kv "backlog" "$(ask_int_or_ignore "backlog" "128")"
      add_kv "ttl" "$(ask_duration_s_or_ignore "ttl" "5s")"
      add_kv "readBufferSize" "$(ask_int_or_ignore "readBufferSize" "1500")"
      add_kv "readQueueSize" "$(ask_int_or_ignore "readQueueSize" "128")"
      ;;

    mtcp)
      add_kv "mux.version" "$(ask_mux_version)"
      add_kv "mux.keepaliveDisabled" "$(ask_bool_menu "mux.keepaliveDisabled" "false")"
      add_kv "mux.keepaliveInterval" "$(ask_duration_s_or_ignore "mux.keepaliveInterval" "10s")"
      add_kv "mux.keepaliveTimeout" "$(ask_duration_s_or_ignore "mux.keepaliveTimeout" "30s")"
      add_kv "mux.maxFrameSize" "$(ask_int_or_ignore "mux.maxFrameSize" "32768")"
      add_kv "mux.maxReceiveBuffer" "$(ask_int_or_ignore "mux.maxReceiveBuffer" "4194304")"
      add_kv "mux.maxStreamBuffer" "$(ask_int_or_ignore "mux.maxStreamBuffer" "65536")"
      ;;

    socks5)
      add_kv "notls" "$(ask_bool_menu "notls" "false")"
      ;;

    relay)
      add_kv "nodelay" "$(ask_bool_menu "nodelay" "false")"
      ;;

    *)
      add_log "No custom settings for proto: $proto"
      ;;
  esac

  echo "$q"
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

need_ssh_id() {
  [[ "$PROTO1" == "ssh" || "$PROTO2" == "ssh" ]]
}

make_direct_iran() {
  ensure_gost_installed || return 0
  local tid kh_ip tun_port
  ask_until_valid "Input IRAN/KHAREJ tunnel id (1-99):" valid_id_1_99 tid
  ask_until_valid "Input KHAREJ IP:" valid_ipv4 kh_ip
  ask_until_valid "Input TUNNEL PORT:" valid_port tun_port

  ask_forward_scheme "direct" || return 0
  ask_ports

  local target_proto query_extra
  target_proto="$(custom_target_proto)"
  query_extra=""
  if should_offer_custom_settings "$target_proto"; then
    query_extra="$(ask_custom_settings_menu "$target_proto")"
    query_extra="$(sanitize_query_string "$query_extra")"
  fi

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local sshid=""
  if need_ssh_id; then
    ask_until_valid "input ssh id (1-99):" valid_id_1_99 sshid
  fi

  local forward_uri execstart
  forward_uri="$(build_peer_uri "$kh_ip" "$tun_port" "$sshid" "iran" "$query_extra")"
  execstart="$(make_execstart_forwarder_F "$FORWARD_SCHEME" "$PORT_SPEC" "$forward_uri")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${execstart}

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

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

  local target_proto query_extra
  target_proto="$(custom_target_proto)"
  query_extra=""
  if should_offer_custom_settings "$target_proto"; then
    query_extra="$(ask_custom_settings_menu "$target_proto")"
    query_extra="$(sanitize_query_string "$query_extra")"
  fi

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$ir_ip" "0")"
  listen_uri="$(append_query_to_uri "$listen_uri" "$query_extra")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${GOST_BIN} -L "${listen_uri}"

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

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

  local target_proto query_extra
  target_proto="$(custom_target_proto)"
  query_extra=""
  if should_offer_custom_settings "$target_proto"; then
    query_extra="$(ask_custom_settings_menu "$target_proto")"
    query_extra="$(sanitize_query_string "$query_extra")"
  fi

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$kh_ip" "1")"
  listen_uri="$(append_query_to_uri "$listen_uri" "$query_extra")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${GOST_BIN} -L "${listen_uri}"

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

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

  ask_forward_scheme "reverse" || return 0
  ask_ports

  local target_proto query_extra
  target_proto="$(custom_target_proto)"
  query_extra=""
  if should_offer_custom_settings "$target_proto"; then
    query_extra="$(ask_custom_settings_menu "$target_proto")"
    query_extra="$(sanitize_query_string "$query_extra")"
  fi

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local sshid=""
  if need_ssh_id; then
    ask_until_valid "input ssh id (1-99):" valid_id_1_99 sshid
  fi

  local forward_uri execstart
  forward_uri="$(build_peer_uri "$ir_ip" "$tun_port" "$sshid" "kharej" "$query_extra")"
  execstart="$(make_execstart_forwarder_F "$FORWARD_SCHEME" "$PORT_SPEC" "$forward_uri")"

  add_log "Writing unit: $svc"
  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${execstart}

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

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

direct_proto_menu() {
  render
  echo "Direct Method"
  echo
  if ! ask_proto_pair_typed "direct"; then
    add_log "Back"
    return 0
  fi

  add_log "Selected: ${PROTO1}+${PROTO2}"
  if ! select_side_and_build; then return 0; fi

  if [[ "$SIDE" == "IRAN" ]]; then
    make_direct_iran
  else
    make_direct_kharej
  fi
}

reverse_proto_menu() {
  render
  echo "Reverse Method"
  echo
  if ! ask_proto_pair_typed "reverse"; then
    add_log "Back"
    return 0
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

  ./taha <side> <method> <PROTO1+PROTO2> <TID> <PEER_IP> <TUN_PORT> [FORWARD_PORTS] [SSH_ID] [p=PARAMS]

SIDE:
  ir | iran     => IRAN side
  kh | kharej   => KHAREJ side

METHOD:
  1 | d | direct      => Direct
  2 | r | reverse     => Reverse
EOF

  echo
  echo "Direct:"
  echo "  KHAREJ: ./taha kh <method> PROTO1+PROTO2  TID IRAN_IP   TUN_PORT [p=PARAMS]"  
  echo "  IRAN  : ./taha ir <method> PROTO1+PROTO2  TID KHAREJ_IP TUN_PORT FORWARD_PORTS [SSH_ID] [p=PARAMS]"

  echo
  echo "Reverse:"
  echo "  IRAN  : ./taha ir <method> PROTO1+PROTO2  TID KHAREJ_IP TUN_PORT [p=PARAMS]"
  echo "  KHAREJ: ./taha kh <method> PROTO1+PROTO2  TID IRAN_IP   TUN_PORT FORWARD_PORTS [SSH_ID] [p=PARAMS]"
echo
echo "p=PARAMS formats:"
echo "  1) use 0 for ignore"
echo "  2) use true or flase for bool"
echo
echo "PROTOS PARAMETRS:"
echo "  udp    : backlog, keepAlive, ttl, relay, readBufferSize, readQueueSize"
echo
echo "  mtls   : backlog, mux.version, mux.keepaliveDisabled, mux.keepaliveInterval, mux.keepaliveTimeout,"
echo "  mux.maxFrameSize, mux.maxReceiveBuffer, mux.maxStreamBuffer"
echo
echo "  ws/wss : path, backlog, header, handshakeTimeout, readHeaderTimeout, readBufferSize, writeBufferSize"
echo
echo "  mws/mwss: path, backlog, header, handshakeTimeout, readHeaderTimeout, readBufferSize, writeBufferSize,"
echo "  mux.version, mux.keepaliveDisabled, mux.keepaliveInterval, mux.keepaliveTimeout, mux.maxFrameSize,"
echo "  mux.maxReceiveBuffer, mux.maxStreamBuffer"
echo
echo "  http2/h2/ssh/pht: backlog"
echo
echo "  grpc   : backlog, grpcInsecure, path"
echo
echo "  quic/kcp/icmp: backlog, keepAlive, ttl, handshakeTimeout, maxIdleTimeout"
echo
echo "  http/ohttp: header"
echo
echo "  ftcp   : backlog, ttl, readBufferSize, readQueueSize"
echo
echo "  mtcp   : mux.version, mux.keepaliveDisabled, mux.keepaliveInterval, mux.keepaliveTimeout,"
echo "  mux.maxFrameSize, mux.maxReceiveBuffer, mux.maxStreamBuffer"
echo
echo "  socks5 : notls"
echo
echo "  relay  : nodelay"

  echo
  cat <<'EOF'
Notes:
- PROTO1+PROTO2 can be: NAME+NAME
- ALLOW PROTO LIST (https://raw.githubusercontent.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/refs/heads/main/all))
- SSH_ID only required if proto includes ssh (forwarder side)
- p=PARAMS SORT LIST (https://raw.githubusercontent.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/refs/heads/main/all)
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
  echo "Examples:"
  echo "  ./taha kh d relay+ws 9 10.20.30.41 443 udp=2052,2053"  
  echo "  ./taha ir d tls+ws   9 10.20.30.40 443 tcp=2052,2053 p=/wspath,1280,0,0,128,2558,2585"
  echo  
  echo    
  echo "## Direct — method = 1 -  d -  direct"
  echo
  echo "PROTO1 ALLOW LIST :"
  echo "- tcp - mtcp - udp - tls - mtls - ws - wss - mws - mwss"
  echo "- h2 - h2c - grpc - pht - quic - kcp- icmp - ohttp - otls"
  echo "- ftcp - http - http2 - socks4 - socks5 - forward - relay"
  echo 
  echo "PROTO2 ALLOW LIST :"
  echo "- tcp - mtcp - udp - tls - mtls - ws - wss - mws - mwss - h2"
  echo "- h2c - grpc - pht - quic - kcp - icmp - ohttp - otls - ftcp"
  echo "- http - http2 - socks4  - socks5 - relay - ssh - raw"
  echo
  echo
  echo "## Reverse — method = 2 -  r -  reverse"
  echo
  echo "PROTO1 ALLOW LIST :"
  echo "- http - socks5"
  echo
  echo "PROTO1 ALLOW LIST JUST WHEN PROTO2 is raw :"
  echo "- tcp - tls - ws - wss - mws - mwss - h2"
  echo "- h2c - grpc - quic - kcp - ssh"
  echo
  echo "PROTO2 ALLOW LIST :"
  echo "- tcp - mtcp - udp - tls - mtls - ws - wss - mws - mwss - h2 - h2c"
  echo "- grpc - pht - quic - kcp - icmp - ohttp - otls - ftcp - http - http2"
  echo "- socks4 - socks5 - relay - ssh - raw"

}

cli_params_to_query() {
  local p="$1"
  p="$(sanitize_input "$p")"
  [[ -z "$p" ]] && { echo ""; return 0; }
  p="${p#p=}"

  if [[ "$p" == *"="* || "$p" == *"&"* ]]; then
    local qraw
    qraw="$(sanitize_query_string "$p")"
    echo "$qraw"
    return 0
  fi

  local eff
  eff="$(custom_target_proto)"

  local q=""
  local csv="$p"

  case "$eff" in
    udp)
      addkv_cli q "backlog"        "$(norm_int_token     "$(csv_get "$csv" 0 "128")")"
      addkv_cli q "keepAlive"      "$(norm_bool_token    "$(csv_get "$csv" 1 "false")")"
      addkv_cli q "ttl"            "$(norm_duration_s_token "$(csv_get "$csv" 2 "5")")"
      addkv_cli q "relay"          "$(norm_tok          "$(csv_get "$csv" 3 "tcp")")"
      addkv_cli q "readBufferSize" "$(norm_int_token     "$(csv_get "$csv" 4 "1500")")"
      addkv_cli q "readQueueSize"  "$(norm_int_token     "$(csv_get "$csv" 5 "128")")"
      ;;

    mtls)
      addkv_cli q "backlog"              "$(norm_int_token "$(csv_get "$csv" 0 "128")")"
      addkv_cli q "mux.version"          "$(norm_mux_version_token "$(csv_get "$csv" 1 "0")")"
      addkv_cli q "mux.keepaliveDisabled" "$(norm_bool_token "$(csv_get "$csv" 2 "false")")"
      addkv_cli q "mux.keepaliveInterval" "$(norm_duration_s_token "$(csv_get "$csv" 3 "10")")"
      addkv_cli q "mux.keepaliveTimeout"  "$(norm_duration_s_token "$(csv_get "$csv" 4 "30")")"
      addkv_cli q "mux.maxFrameSize"      "$(norm_int_token "$(csv_get "$csv" 5 "32768")")"
      addkv_cli q "mux.maxReceiveBuffer"  "$(norm_int_token "$(csv_get "$csv" 6 "4194304")")"
      addkv_cli q "mux.maxStreamBuffer"   "$(norm_int_token "$(csv_get "$csv" 7 "65536")")"
      ;;

    ws|wss)
      addkv_cli q "path"              "$(norm_path_token "$(csv_get "$csv" 0 "/ws")")"
      addkv_cli q "backlog"           "$(norm_int_token  "$(csv_get "$csv" 1 "128")")"
      addkv_cli q "header"            "$(norm_header_token "$(csv_get "$csv" 2 "0")")"
      addkv_cli q "handshakeTimeout"  "$(norm_duration_s_token "$(csv_get "$csv" 3 "5")")"
      addkv_cli q "readHeaderTimeout" "$(norm_duration_s_token "$(csv_get "$csv" 4 "5")")"
      addkv_cli q "readBufferSize"    "$(norm_int_token  "$(csv_get "$csv" 5 "4096")")"
      addkv_cli q "writeBufferSize"   "$(norm_int_token  "$(csv_get "$csv" 6 "4096")")"
      ;;

    mws|mwss)
      addkv_cli q "path"              "$(norm_path_token "$(csv_get "$csv" 0 "/ws")")"
      addkv_cli q "backlog"           "$(norm_int_token  "$(csv_get "$csv" 1 "128")")"
      addkv_cli q "header"            "$(norm_header_token "$(csv_get "$csv" 2 "0")")"
      addkv_cli q "handshakeTimeout"  "$(norm_duration_s_token "$(csv_get "$csv" 3 "5")")"
      addkv_cli q "readHeaderTimeout" "$(norm_duration_s_token "$(csv_get "$csv" 4 "5")")"
      addkv_cli q "readBufferSize"    "$(norm_int_token  "$(csv_get "$csv" 5 "4096")")"
      addkv_cli q "writeBufferSize"   "$(norm_int_token  "$(csv_get "$csv" 6 "4096")")"

      addkv_cli q "mux.version"           "$(norm_mux_version_token "$(csv_get "$csv" 7 "0")")"
      addkv_cli q "mux.keepaliveDisabled" "$(norm_bool_token "$(csv_get "$csv" 8 "false")")"
      addkv_cli q "mux.keepaliveInterval" "$(norm_duration_s_token "$(csv_get "$csv" 9 "10")")"
      addkv_cli q "mux.keepaliveTimeout"  "$(norm_duration_s_token "$(csv_get "$csv" 10 "30")")"
      addkv_cli q "mux.maxFrameSize"      "$(norm_int_token "$(csv_get "$csv" 11 "32768")")"
      addkv_cli q "mux.maxReceiveBuffer"  "$(norm_int_token "$(csv_get "$csv" 12 "4194304")")"
      addkv_cli q "mux.maxStreamBuffer"   "$(norm_int_token "$(csv_get "$csv" 13 "65536")")"
      ;;

    http2|h2|ssh|pht)
      addkv_cli q "backlog" "$(norm_int_token "$(csv_get "$csv" 0 "128")")"
      ;;

    grpc)
      addkv_cli q "backlog"      "$(norm_int_token "$(csv_get "$csv" 0 "128")")"
      addkv_cli q "grpcInsecure" "$(norm_bool_token "$(csv_get "$csv" 1 "false")")"
      addkv_cli q "path"         "$(norm_path_token "$(csv_get "$csv" 2 "/GostTunel/Tunnel")")"
      ;;

    quic|kcp|icmp)
      addkv_cli q "backlog"          "$(norm_int_token "$(csv_get "$csv" 0 "128")")"
      addkv_cli q "keepAlive"        "$(norm_bool_token "$(csv_get "$csv" 1 "false")")"
      addkv_cli q "ttl"              "$(norm_duration_s_token "$(csv_get "$csv" 2 "10")")"
      addkv_cli q "handshakeTimeout" "$(norm_duration_s_token "$(csv_get "$csv" 3 "5")")"
      addkv_cli q "maxIdleTimeout"   "$(norm_duration_s_token "$(csv_get "$csv" 4 "30")")"
      ;;

    http|ohttp)
      addkv_cli q "header" "$(norm_header_token "$(csv_get "$csv" 0 "0")")"
      ;;

    ftcp)
      addkv_cli q "backlog"        "$(norm_int_token "$(csv_get "$csv" 0 "128")")"
      addkv_cli q "ttl"            "$(norm_duration_s_token "$(csv_get "$csv" 1 "5")")"
      addkv_cli q "readBufferSize" "$(norm_int_token "$(csv_get "$csv" 2 "1500")")"
      addkv_cli q "readQueueSize"  "$(norm_int_token "$(csv_get "$csv" 3 "128")")"
      ;;

    mtcp)
      addkv_cli q "mux.version"           "$(norm_mux_version_token "$(csv_get "$csv" 0 "0")")"
      addkv_cli q "mux.keepaliveDisabled" "$(norm_bool_token "$(csv_get "$csv" 1 "false")")"
      addkv_cli q "mux.keepaliveInterval" "$(norm_duration_s_token "$(csv_get "$csv" 2 "10")")"
      addkv_cli q "mux.keepaliveTimeout"  "$(norm_duration_s_token "$(csv_get "$csv" 3 "30")")"
      addkv_cli q "mux.maxFrameSize"      "$(norm_int_token "$(csv_get "$csv" 4 "32768")")"
      addkv_cli q "mux.maxReceiveBuffer"  "$(norm_int_token "$(csv_get "$csv" 5 "4194304")")"
      addkv_cli q "mux.maxStreamBuffer"   "$(norm_int_token "$(csv_get "$csv" 6 "65536")")"
      ;;

    socks5)
      addkv_cli q "notls" "$(norm_bool_token "$(csv_get "$csv" 0 "false")")"
      ;;

    relay)
      addkv_cli q "nodelay" "$(norm_bool_token "$(csv_get "$csv" 0 "false")")"
      ;;

    *)
      echo ""
      return 0
      ;;
  esac

  q="$(sanitize_query_string "$q")"
  echo "$q"
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

resolve_proto_pair() {
  local method="$1" t1="$2" t2="$3"
  PROTO1="$(norm_tok "$t1")"
  PROTO2="$(norm_tok "$t2")"
  return 0
}

make_direct_iran_cli() {
  ensure_gost_installed || return 1
  local tid="$1" kh_ip="$2" tun_port="$3" forward_spec="$4" sshid="${5:-}" query_extra="${6:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$kh_ip" || { echo "Invalid KHAREJ IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  parse_forward_spec_v2 "$forward_spec" || { echo "Invalid FORWARD_PORTS (use tcp=... or udp=...)"; return 1; }

  if need_ssh_id; then
    valid_id_1_99 "$sshid" || { echo "SSH_ID required/invalid"; return 1; }
  fi

  query_extra="$(sanitize_query_string "$query_extra")"

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local forward_uri execstart
  forward_uri="$(build_peer_uri "$kh_ip" "$tun_port" "$sshid" "iran" "$query_extra")"

  local scheme_eff
  scheme_eff="$(effective_forward_scheme "direct" "$FORWARD_SCHEME")"
  execstart="$(make_execstart_forwarder_F "$scheme_eff" "$PORT_SPEC" "$forward_uri")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${execstart}

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}

make_direct_kharej_cli() {
  ensure_gost_installed || return 1
  local tid="$1" ir_ip="$2" tun_port="$3" query_extra="${4:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$ir_ip" || { echo "Invalid IRAN IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  query_extra="$(sanitize_query_string "$query_extra")"

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$ir_ip" "0")"
  listen_uri="$(append_query_to_uri "$listen_uri" "$query_extra")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${GOST_BIN} -L "${listen_uri}"

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}


make_reverse_iran_cli() {
  ensure_gost_installed || return 1
  local tid="$1" kh_ip="$2" tun_port="$3" query_extra="${4:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$kh_ip" || { echo "Invalid KHAREJ IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  query_extra="$(sanitize_query_string "$query_extra")"

  local svc="gost-iran-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local listen_uri
  listen_uri="$(build_listen_uri_admission "$PROTO1" "$PROTO2" "$tun_port" "$kh_ip" "1")"
  listen_uri="$(append_query_to_uri "$listen_uri" "$query_extra")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-iran-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${GOST_BIN} -L "${listen_uri}"

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}


make_reverse_kharej_cli() {
  ensure_gost_installed || return 1
  local tid="$1" ir_ip="$2" tun_port="$3" forward_spec="$4" sshid="${5:-}" query_extra="${6:-}"

  valid_id_1_99 "$tid" || { echo "Invalid TID"; return 1; }
  valid_ipv4 "$ir_ip" || { echo "Invalid IRAN IP"; return 1; }
  valid_port "$tun_port" || { echo "Invalid tunnel port"; return 1; }

  parse_forward_spec_v2 "$forward_spec" || { echo "Invalid FORWARD_PORTS (use tcp=... or udp=...)"; return 1; }

  if need_ssh_id; then
    valid_id_1_99 "$sshid" || { echo "SSH_ID required/invalid"; return 1; }
  fi

  query_extra="$(sanitize_query_string "$query_extra")"

  local svc="gost-kharej-${tid}.service"
  local svc_path="${SYS_DIR}/${svc}"

  local forward_uri execstart
  forward_uri="$(build_peer_uri "$ir_ip" "$tun_port" "$sshid" "kharej" "$query_extra")"

  local scheme_eff
  scheme_eff="$(effective_forward_scheme "reverse" "$FORWARD_SCHEME")"
  execstart="$(make_execstart_forwarder_F "$scheme_eff" "$PORT_SPEC" "$forward_uri")"

  write_atomic "$svc_path" <<EOF
[Unit]
Description=gost-kharej-${tid}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root

ExecStart=${execstart}

Restart=always
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=30
KillSignal=SIGTERM
SendSIGKILL=yes
FinalKillSignal=SIGKILL
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=0
LimitMEMLOCK=infinity
TasksMax=infinity
OOMScoreAdjust=-900
OOMPolicy=continue
Nice=-5
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  enable_start "$svc"
  show_status "$svc"
}


cli_main() {
  ensure_root "$@"

  case "${1:-}" in
    -h|--help|-help|help) usage_cli; return 0 ;;
    -m|-map|--map) usage_map; return 0 ;;
    -menu|--menu|menu) add_log "TaHa Tunnel Manager"; main_menu; exit 0 ;;
  esac

  if (( $# == 0 )); then
    return 99
  fi

  local side_arg="${1:-}"; shift || true
  case "$side_arg" in
    ir|iran|IR|IRAN) SIDE="IRAN" ;;
    kh|kharej|KH|KHAREJ) SIDE="KHAREJ" ;;
    *) usage_cli; echo; echo "Hint: use ./taha -m to see mappings"; return 1 ;;
  esac

  local method_raw="${1:-}"
  local method=""
  method="$(normalize_method "$method_raw")" || {
    echo "Invalid method: $method_raw (use: 1/2 or d/r or direct/reverse)"
    echo "Hint: use ./taha -h"
    return 1
  }

  local protospec="${2:-}"
  local tid="${3:-}"
  local peer_ip="${4:-}"
  local tun_port="${5:-}"

  if [[ -z "$protospec" || -z "$tid" || -z "$peer_ip" || -z "$tun_port" ]]; then
    usage_cli
    return 1
  fi

  parse_proto_spec "$protospec" || { echo "Invalid proto spec: $protospec"; return 1; }
  resolve_proto_pair "$method" "$P1TOK" "$P2TOK" || { echo "Invalid proto combination"; return 1; }

  shift 5 || true

  local pextra=""
  local -a rest=()
  local a
  for a in "$@"; do
    if [[ "$a" == p=* ]]; then
      pextra="$a"
    else
      rest+=("$a")
    fi
  done

  local forward_ports=""
  local sshid=""

  if [[ "$method" == "1" && "$SIDE" == "IRAN" ]]; then
    forward_ports="${rest[0]:-}"
    [[ -n "$forward_ports" ]] || { echo "Forward ports required on IRAN direct."; return 1; }
    rest=("${rest[@]:1}")
  elif [[ "$method" == "2" && "$SIDE" == "KHAREJ" ]]; then
    forward_ports="${rest[0]:-}"
    [[ -n "$forward_ports" ]] || { echo "Forward ports required on KHAREJ reverse."; return 1; }
    rest=("${rest[@]:1}")
  fi

  if need_ssh_id; then
    if [[ ( "$method" == "1" && "$SIDE" == "IRAN" ) || ( "$method" == "2" && "$SIDE" == "KHAREJ" ) ]]; then
      sshid="${rest[0]:-}"
      [[ -n "$sshid" ]] || { echo "SSH_ID required for ssh proto on forwarder side."; return 1; }
      rest=("${rest[@]:1}")
    fi
  fi

  local query_extra=""
  if [[ -n "$pextra" ]]; then
    query_extra="$(cli_params_to_query "$pextra")"
    query_extra="$(sanitize_query_string "$query_extra")"
  fi

  if [[ "$method" == "1" ]]; then
    if [[ "$SIDE" == "IRAN" ]]; then
      make_direct_iran_cli "$tid" "$peer_ip" "$tun_port" "$forward_ports" "$sshid" "$query_extra"
    else
      make_direct_kharej_cli "$tid" "$peer_ip" "$tun_port" "$query_extra"
    fi
  else
    if [[ "$SIDE" == "IRAN" ]]; then
      make_reverse_iran_cli "$tid" "$peer_ip" "$tun_port" "$query_extra"
    else
      make_reverse_kharej_cli "$tid" "$peer_ip" "$tun_port" "$forward_ports" "$sshid" "$query_extra"
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
    echo "8) RUN WEB PANEL"
    echo "9) Uninstall"
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
      8)
        add_log "Menu: Web Panel"

        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        PANEL_SCRIPT="$SCRIPT_DIR/taha-webui.sh"
        PANEL_URL="https://raw.githubusercontent.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/refs/heads/main/taha-webui.sh"

        if [[ ! -f "$PANEL_SCRIPT" ]]; then
          add_log "Panel script not found. Downloading..."

          if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$PANEL_URL" -o "$PANEL_SCRIPT"
          else
            wget -q "$PANEL_URL" -O "$PANEL_SCRIPT"
          fi

          if [[ ! -s "$PANEL_SCRIPT" ]]; then
            add_log "Download failed!"
            render
            pause_enter
            break
          fi

          chmod +x "$PANEL_SCRIPT"
          add_log "Downloaded successfully."
        fi

        bash "$PANEL_SCRIPT"
        ;;
      9) add_log "Menu: Uninstall"; uninstall_menu ;;
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
