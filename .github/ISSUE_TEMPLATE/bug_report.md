---
name: Bug report
about: Something isn't working
labels: bug
---

**What happened**

**Expected**

**Role / version**
- role: orchestrator / worker
- `scangrid version`:
- OS:

**Logs**
```
journalctl -u scangrid-<role> -n 100 --no-pager
```

**Config (redact secrets)**
```
scangrid config
```
