#!/usr/bin/env bash
# Install ScanGrid as the ORCHESTRATOR on this Raspberry Pi.
#   sudo NS_REPO_URL=https://github.com/you/scan-grid.git ./install-orchestrator.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh"

require_root
ensure_packages git python3 python3-venv python3-dev curl ca-certificates
ensure_user
sync_source
build_venv
write_env_if_absent
setenv SCANGRID_ROLE orchestrator
[ -n "${NS_ALLOWLIST:-}" ] && setenv SCANGRID_ALLOWLIST "$NS_ALLOWLIST"
[ -n "${NS_TOKEN:-}" ]     && setenv SCANGRID_API_TOKEN "$NS_TOKEN"

install -d -o "$SG_USER" -g "$SG_USER" /var/lib/scangrid
install_unit scangrid-orchestrator.service
systemctl enable --now scangrid-orchestrator.service

log "orchestrator up on http://$(hostname -I | awk '{print $1}'):8090/"
log "NEXT: edit $SG_ETC/scangrid.env - set SCANGRID_ALLOWLIST to ranges you may scan,"
log "      then: systemctl restart scangrid-orchestrator"
