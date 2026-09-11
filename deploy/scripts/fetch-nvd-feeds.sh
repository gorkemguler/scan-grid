#!/usr/bin/env bash
# Download + decompress NVD JSON feeds for the offline CVE provider.
# Needs a few GB of disk. Run on the ORCHESTRATOR.
#   SCANGRID_NVD_FEED_DIR=/var/lib/scangrid/nvd ./fetch-nvd-feeds.sh [START_YEAR]
set -euo pipefail

DEST="${SCANGRID_NVD_FEED_DIR:-/var/lib/scangrid/nvd}"
START="${1:-2015}"
END="$(date -u +%Y)"
BASE="https://nvd.nist.gov/feeds/json/cve/1.1"

command -v gunzip >/dev/null || { echo "need gunzip" >&2; exit 1; }
mkdir -p "$DEST"

for year in $(seq "$START" "$END"); do
  url="$BASE/nvdcve-1.1-${year}.json.gz"
  echo "-> $url"
  if curl -fsSL --retry 2 -o "$DEST/nvdcve-1.1-${year}.json.gz" "$url"; then
    gunzip -f "$DEST/nvdcve-1.1-${year}.json.gz"
  else
    echo "   (skipped $year)" >&2
  fi
done

echo "done. $(ls -1 "$DEST"/*.json 2>/dev/null | wc -l) feed file(s) in $DEST"
echo "set SCANGRID_CVE_PROVIDER=offline and SCANGRID_NVD_FEED_DIR=$DEST"
