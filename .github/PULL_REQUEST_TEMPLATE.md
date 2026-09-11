## What & why

<!-- short description; link the issue -->

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest` passes
- [ ] package still imports without `nmap` installed
- [ ] allowlist still refuses out-of-scope hosts (test added if this PR touches that path)
- [ ] new config in `Settings` **and** `.env.example`
- [ ] docs / CHANGELOG updated if behaviour changed
