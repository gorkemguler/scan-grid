#!/usr/bin/env bash
# Install ScanGrid as a WORKER on this Raspberry Pi.
#   sudo NS_ORCH_URL=http://192.168.1.2:8090 NS_TOKEN=... NS_ALLOWLIST=192.168.1.0/24 ./install-worker.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_root
ensure_packages git python3 python3-venv python3-dev nmap libcap2-bin curl ca-certificates
ensure_user
sync_source
build_venv
write_env_if_absent

setenv SCANGRID_ROLE worker
[ -n "${NS_ORCH_URL:-}"  ] && setenv SCANGRID_ORCHESTRATOR_URL "$NS_ORCH_URL"
[ -n "${NS_TOKEN:-}"     ] && setenv SCANGRID_API_TOKEN "$NS_TOKEN"
[ -n "${NS_ALLOWLIST:-}" ] && setenv SCANGRID_ALLOWLIST "$NS_ALLOWLIST"
[ -n "${NS_WORKER_ID:-}" ] && setenv SCANGRID_WORKER_ID "$NS_WORKER_ID"

install_unit scangrid-worker.service
systemctl enable --now scangrid-worker.service

log "worker started. IMPORTANT: SCANGRID_ALLOWLIST in $SG_ETC/scangrid.env must match the orchestrator's."
log "follow it:  journalctl -u scangrid-worker -f"
