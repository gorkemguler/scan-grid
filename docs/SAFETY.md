# Safety, ethics and legal

ScanGrid performs **active** network scanning (`nmap`, including `-sS`/`-sV`).
Active scanning of systems you do not own or administer, without prior written
authorisation, is illegal in many jurisdictions (e.g. the US CFAA, the UK
Computer Misuse Act, similar laws elsewhere) regardless of intent.

## Only scan what you are authorised to scan

* Set `SCANGRID_ALLOWLIST` to the exact ranges you own or run.
* Keep `SCANGRID_ALLOW_PUBLIC_TARGETS=false` (the default). Turn it on **only**
  for hosts you have explicit, documented permission to test (e.g. your own VPS,
  a lab you rent, a client engagement with a signed scope).
* For a workplace or shared network, get written sign-off from whoever operates
  it before pointing ScanGrid at it.

## How the tool enforces this

| Layer | Check |
|---|---|
| target creation (`POST /api/targets`, `add-target`) | the spec must resolve to at least one IP inside the allowlist; anything outside is reported and dropped |
| job creation | re-resolves the spec; queues only in-scope hosts |
| worker, before nmap | `assert_hosts_allowed()` re-checks every host against the allowlist reloaded from config; a mismatch fails the job |
| nmap arguments | `exploit`, `brute`, `dos`, `malware` NSE script categories are stripped; `-oN/-oX/...` redirections are stripped |

These are safety rails, not permission. They stop accidents; they do not make
unauthorised scanning acceptable.

## What ScanGrid does NOT do

* No exploitation, no brute forcing, no denial-of-service, no traffic that tries
  to change a target's state.
* No credential testing.
* No scanning outside the configured allowlist.

CVE findings are produced by matching service banners to NVD data. They are a
**triage aid** and include false positives and false negatives. Verify before
acting, and never treat "no findings" as "not vulnerable".

## Rate and load

Default args are deliberately gentle (`-T3`, `--top-ports 1000`,
`--version-light`). If you widen them, keep an eye on fragile devices
(printers, IoT, OT/ICS) which can misbehave under scan load. Consider
`--scan-delay` and excluding those hosts.

## Reporting a vulnerability in ScanGrid

Open a private [GitHub Security Advisory](../../security/advisories/new) or email
the maintainer in `pyproject.toml`. Please don't file public issues for
exploitable bugs.
