# Ansible deployment

Provisions the orchestrator + worker(s) from your workstation - two Pis, one Pi
running both roles, or one orchestrator with many workers.

## Prerequisites

* Ansible 2.15+ (`pipx install ansible`).
* SSH key access + passwordless sudo on the Pi(s).
* Raspberry Pi OS Lite 64-bit (Bookworm), Pi 3B or newer.

## Use

```bash
cp inventory.example.ini inventory.ini
$EDITOR inventory.ini      # IPs, api_token, ALLOWLIST, orchestrator_url, cve/notify
ansible-playbook -i inventory.ini site.yml
```

Re-run to pull the latest commit and restart services.

**One Pi, both roles:** put the same host in `[orchestrator]` and `[worker]`, set
`scangrid_orchestrator_url=http://127.0.0.1:8090`. **Many workers:** add more
hosts under `[worker]`. The example inventory has both variants as comments.

## What it does

| Step | orchestrator | worker |
|---|:--:|:--:|
| apt deps (+ nmap, libcap2-bin on worker) | ✓ | ✓ |
| `scangrid` user, dirs, clone, venv | ✓ | ✓ |
| render `/etc/scangrid/scangrid.env` from inventory | ✓ | ✓ |
| install + enable systemd unit | ✓ | ✓ |
| health-check the API | ✓ | |
| assert allowlist is RFC1918/loopback (unless `allow_public_targets`) | | ✓ |
| optional `add-target` from `scangrid_seed_target_spec` | ✓ | |
| log tail | | ✓ |

## Seeding a first target

Add to the inventory to have the playbook create one:

```ini
scangrid_seed_target_name=home
scangrid_seed_target_spec=192.168.1.0/24
scangrid_seed_target_every=1440
```

## Notes

* The env file is templated every run - change values in the inventory.
* `--limit worker` / `--limit orchestrator` to touch one role.
* `--check --diff` for a dry run.
