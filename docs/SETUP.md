# Manual setup

Automated path: [`deploy/ansible/`](../deploy/ansible/README.md). This is the
by-hand version - **two Pis** (§1–2) or **one Pi, both roles** (§1b).

## Requirements checklist

| | Need |
|---|---|
| Board(s) | Raspberry Pi 3B or newer. Two for the split layout, one for all-in-one, +N for extra workers. Pi 4B 2 GB is the tested target. |
| microSD | 8 GB minimum, 16–32 GB recommended. `cve_provider=offline` needs +10–15 GB. |
| OS | Raspberry Pi OS Lite 64-bit (Bookworm) - Python 3.11. Ubuntu Server 24.04 also fine. |
| Python | 3.11+. |
| Packages | `git`, `python3-venv` on both roles; **`nmap` + `libcap2-bin` on the worker**. |
| Privilege | `sudo` for install. `-sS` scans need `CAP_NET_RAW` on the worker (systemd unit grants it) - or use `-sT`. |
| Network | Worker → orchestrator outbound only. Orchestrator → internet only for `cve_provider=nvd_api`. |
| Authorisation | You must be allowed to scan every range in `SCANGRID_ALLOWLIST`. See [`SAFETY.md`](SAFETY.md). |

Per-role RAM figures and the board matrix are in the README's **Hardware &
requirements**.

## 0. Prepare the Pi(s)

* Flash Raspberry Pi OS Lite 64-bit (Bookworm), SSH enabled, static leases.
  * two-Pi: `pi-orchestrator` → `192.168.1.2`, `pi-worker` → `192.168.1.3`
  * one-Pi: `pi-scangrid` → `192.168.1.2`
* Decide the ranges you are **authorised** to scan, e.g. `192.168.1.0/24`.

One shared token:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## 1. Orchestrator (`pi-orchestrator`)

```bash
sudo apt update && sudo apt install -y git python3-venv
git clone https://github.com/gorkemguler/scan-grid.git && cd scan-grid
sudo NS_REPO_URL="$PWD/.git" deploy/scripts/install-orchestrator.sh
$EDITOR /etc/scangrid/scangrid.env      # set API_TOKEN, ALLOWLIST, notify
sudo systemctl restart scangrid-orchestrator
```

Manual variant:

```bash
python3 -m venv ~/sg && ~/sg/bin/pip install -e .
cat > ~/sg.env <<'EOF'
SCANGRID_ROLE=orchestrator
SCANGRID_DATA_DIR=/home/pi/sg-data
SCANGRID_API_TOKEN=<token>
SCANGRID_ALLOWLIST=192.168.1.0/24
SCANGRID_CVE_PROVIDER=nvd_api
SCANGRID_NVD_API_KEY=<optional, from nvd.nist.gov/developers/request-an-api-key>
SCANGRID_NOTIFY_BACKEND=ntfy
SCANGRID_NTFY_TOPIC=my-scangrid-abc123
EOF
set -a && . ~/sg.env && set +a
~/sg/bin/scangrid orchestrator
```

Open `http://192.168.1.2:8090/`.

## 2. Worker (`pi-worker`)

```bash
sudo apt update && sudo apt install -y git python3-venv nmap libcap2-bin
git clone https://github.com/gorkemguler/scan-grid.git && cd scan-grid
sudo NS_ORCH_URL=http://192.168.1.2:8090 \
     NS_TOKEN=<token> \
     NS_ALLOWLIST=192.168.1.0/24 \
     deploy/scripts/install-worker.sh
```

Verify:

```bash
journalctl -u scangrid-worker -f
```

## 1b. One Pi - orchestrator **and** worker on the same board

Do §0, then run **both** installers on the one Pi. The first writes
`/etc/scangrid/scangrid.env` (fresh token); the second reuses it. Each systemd
unit pins its own role. `SCANGRID_ALLOWLIST` must be identical for both - it
lives once in that shared file.

```bash
sudo apt update && sudo apt install -y git python3-venv nmap libcap2-bin
git clone https://github.com/gorkemguler/scan-grid.git && cd scan-grid

# 1) orchestrator
sudo NS_REPO_URL="$PWD/.git" NS_ALLOWLIST=192.168.1.0/24 \
     deploy/scripts/install-orchestrator.sh

# 2) worker (same box). Orchestrator URL defaults to http://127.0.0.1:8090.
sudo NS_REPO_URL="$PWD/.git" NS_ALLOWLIST=192.168.1.0/24 \
     deploy/scripts/install-worker.sh

# 3) set CVE / notify options once, then restart the orchestrator
sudo sed -i 's/^SCANGRID_NOTIFY_BACKEND=.*/SCANGRID_NOTIFY_BACKEND=ntfy/' /etc/scangrid/scangrid.env
sudo sed -i 's/^SCANGRID_NTFY_TOPIC=.*/SCANGRID_NTFY_TOPIC=my-scangrid-abc123/' /etc/scangrid/scangrid.env
sudo systemctl restart scangrid-orchestrator

systemctl status scangrid-orchestrator scangrid-worker --no-pager
```

Open `http://192.168.1.2:8090/`, then jump to §3. Non-persistent alternative
(dev): `scangrid orchestrator &` in one shell, `SCANGRID_ROLE=worker scangrid worker`
in another (both read `./.env`).

## 3. Add a target and scan

```bash
sudo -u scangrid /opt/scangrid/venv/bin/scangrid \
  --help   # (env is read from /etc/scangrid/scangrid.env via the service;
           #  for a one-off CLI run, export it first)

set -a; . /etc/scangrid/scangrid.env; set +a
/opt/scangrid/venv/bin/scangrid check-allowlist 192.168.1.0/24    # dry run
/opt/scangrid/venv/bin/scangrid add-target home 192.168.1.0/24 --every 1440 --scan-now
```

Watch the job on the dashboard's **Jobs** tab; hosts appear under **Inventory**,
CVE matches under **Findings**, deltas under **Changes** (needs ≥2 scans).

## 4. CVE data

* **`nvd_api`** (default) - nothing to install. Get a free API key from
  <https://nvd.nist.gov/developers/request-an-api-key> and set
  `SCANGRID_NVD_API_KEY` to lift the rate limit.
* **`offline`** - run `deploy/scripts/fetch-nvd-feeds.sh` (needs a few GB and
  `SCANGRID_NVD_FEED_DIR` space). Use only if the orchestrator has no internet.

## 5. Notifications

Set on the orchestrator, restart it. `ntfy` / `telegram` / `webhook` - same keys
as the `.env.example`. Severity floor: `SCANGRID_NOTIFY_MIN_SEVERITY` (default
`medium`).

## Troubleshooting

| Symptom | Check |
|---|---|
| job stuck `queued` | worker running? `journalctl -u scangrid-worker`; token match? |
| job `error: refusing to scan unauthorised hosts` | target spec resolves outside `SCANGRID_ALLOWLIST` |
| job `error: nmap not found` | install `nmap` on the **worker** |
| `-sS` permission denied | worker needs `CAP_NET_RAW` (systemd unit grants it) or use `-sT` in `DEFAULT_NMAP_ARGS` |
| no findings | `cve_provider`? NVD throttling without a key is slow - watch `enrich` logs |
| `422` creating a target | nothing in the spec is inside the allowlist (`check-allowlist` to see) |
