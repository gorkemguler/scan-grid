#!/usr/bin/env bash
# Shared helpers for the install scripts. Source this; don't run it.
set -euo pipefail

SG_PREFIX="${SG_PREFIX:-/opt/scangrid}"
SG_ETC="${SG_ETC:-/etc/scangrid}"
SG_USER="${SG_USER:-scangrid}"
NS_REPO_URL="${NS_REPO_URL:-https://github.com/gorkemguler/scan-grid.git}"
NS_REF="${NS_REF:-main}"

log() { printf '\033[1;36m[scangrid]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[scangrid] %s\033[0m\n' "$*" >&2; exit 1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

ensure_packages() {
  log "apt install: $*"
  command -v apt-get >/dev/null || die "expects apt (Raspberry Pi OS / Debian)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

ensure_user() {
  id "$SG_USER" >/dev/null 2>&1 || {
    log "creating system user $SG_USER"
    useradd --system --home-dir "$SG_PREFIX" --shell /usr/sbin/nologin "$SG_USER"
  }
}

sync_source() {
  mkdir -p "$SG_PREFIX"
  if [ -d "$SG_PREFIX/src/.git" ]; then
    git -C "$SG_PREFIX/src" fetch --depth 1 origin "$NS_REF"
    git -C "$SG_PREFIX/src" reset --hard "origin/$NS_REF"
  else
    git clone --depth 1 --branch "$NS_REF" "$NS_REPO_URL" "$SG_PREFIX/src"
  fi
}

build_venv() {
  log "building venv"
  python3 -m venv "$SG_PREFIX/venv"
  "$SG_PREFIX/venv/bin/pip" install -q --upgrade pip
  "$SG_PREFIX/venv/bin/pip" install -q "$SG_PREFIX/src"
}

write_env_if_absent() {
  mkdir -p "$SG_ETC"
  if [ -f "$SG_ETC/scangrid.env" ]; then
    log "$SG_ETC/scangrid.env exists, leaving it"
    return
  fi
  log "writing starter $SG_ETC/scangrid.env (EDIT IT - especially SCANGRID_ALLOWLIST)"
  local token
  token="$("$SG_PREFIX/venv/bin/scangrid" gen-token)"
  sed "s/^SCANGRID_API_TOKEN=.*/SCANGRID_API_TOKEN=${token}/" \
      "$SG_PREFIX/src/.env.example" > "$SG_ETC/scangrid.env"
  chmod 640 "$SG_ETC/scangrid.env"
  chgrp "$SG_USER" "$SG_ETC/scangrid.env"
}

install_unit() {
  local unit="$1"
  install -m 644 "$SG_PREFIX/src/deploy/systemd/$unit" "/etc/systemd/system/$unit"
  systemctl daemon-reload
}

setenv() {  # setenv KEY value  (in the env file, escaping # and /)
  local key="$1" val="$2"
  local esc; esc=$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')
  sed -i "s/^${key}=.*/${key}=${esc}/" "$SG_ETC/scangrid.env"
}
