#!/usr/bin/env bash
set +e
set +u

DIR="$(cd "$(dirname "$0")" && pwd)"

TAHA="$DIR/taha"
TAHA_SH="$DIR/taha.sh"

TAHA_URL="https://raw.githubusercontent.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/main/taha"
TAHA_SH_URL="https://raw.githubusercontent.com/ToolSeRF/TaHa-Direct-Reverse-Tunnel-Runner/main/taha.sh"

TS="$(date +%Y%m%d-%H%M%S)"

[[ -f "$TAHA" ]] && cp -f "$TAHA" "$TAHA.bak.$TS"
[[ -f "$TAHA_SH" ]] && cp -f "$TAHA_SH" "$TAHA_SH.bak.$TS"

rm -f "$TAHA" "$TAHA_SH"

if command -v wget >/dev/null 2>&1; then
  wget -q -O "$TAHA" "${TAHA_URL}?$(date +%s)"
  wget -q -O "$TAHA_SH" "${TAHA_SH_URL}?$(date +%s)"
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL "${TAHA_URL}?$(date +%s)" -o "$TAHA"
  curl -fsSL "${TAHA_SH_URL}?$(date +%s)" -o "$TAHA_SH"
else
  echo "wget or curl not found!"
  exit 1
fi

chmod +x "$TAHA" 2>/dev/null
chmod +x "$TAHA_SH" 2>/dev/null

echo "update done!"
