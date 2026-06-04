# `policy.py` — Security Policy Engine

## Overview

`policy.py` manages the **WAF's operating rules and decision thresholds**. It is the policy layer that sits above the ML models — it defines what mode the WAF runs in, which IPs and paths are explicitly allowed or blocked regardless of ML scores, and what confidence thresholds trigger a block.

It maps directly to open-appsec's **policy management** subsystem, which also uses declarative configuration files (YAML in open-appsec, JSON here) and supports hot reload.

---

## Responsibilities

1. **Load / persist** the policy from `config/policy.json`
2. **Apply IP and path rules** to every request *before* ML inference
3. **Expose thresholds** used by `waf_engine.py` for final block decisions
4. **Support hot update** via REST API (`PUT /policy/mode`, `POST /policy/rules`, etc.)

---

## Policy Schema

```json
{
  "version": "1.0",
  "mode": "prevent",
  "rules": {
    "ip_allowlist": ["192.168.1.100"],
    "ip_blocklist": ["10.0.0.5"],
    "path_allowlist": ["/health", "/metrics"],
    "path_blocklist": ["/admin", "/phpmyadmin"]
  },
  "thresholds": {
    "ml_block_score": 0.50,
    "unsupervised_block_score": 0.75,
    "combined_block_score": 0.65
  },
  "rate_limits": {
    "default_rpm": 120,
    "burst_limit": 30
  }
}
```

---

## Operating Modes

| Mode | Behaviour |
|---|---|
| `prevent` | Block requests that exceed thresholds. Default production mode. |
| `detect` | Log everything, block nothing. Useful for testing new rules without impacting users. |
| `monitor` | Completely passive — records all requests, never blocks. Useful for baselining. |

The mode affects the entire pipeline: even if `ips_engine` matches a Log4Shell signature, in `monitor` mode the request is logged but allowed through.

---

## Rule Priority Order

Rules are evaluated in this order (higher priority first):

```
IP Allowlist  →  IP Blocklist  →  Path Allowlist  →  Path Blocklist  →  ML / Thresholds
```

If an IP is in the allowlist, the request is **immediately allowed** — no further stages run. This is critical for health-check IPs, internal monitoring agents, and trusted upstream proxies.

---

## Rule Compilation

Path rules support **regular expressions** and are compiled to `re.Pattern` objects at load time (not per-request). This is important for performance — regex compilation is expensive and only runs when the policy changes.

```python
'path_blocklist_re': [
    re.compile(p, re.I) for p in rules.get('path_blocklist', [])
]
```

The `re.I` flag makes all patterns case-insensitive, which is appropriate for URL path matching.

---

## ML Decision Thresholds

The thresholds determine how aggressive the WAF is:

| Threshold | Default | Meaning |
|---|---|---|
| `ml_block_score` | 0.50 | Block if supervised RF probability ≥ 0.50 |
| `unsupervised_block_score` | 0.75 | Block if Isolation Forest anomaly score ≥ 0.75 |
| `combined_block_score` | 0.65 | Block if weighted fusion score ≥ 0.65 |

Lower thresholds → more aggressive (more false positives). Higher thresholds → more permissive (more false negatives). The dashboard's **Policy Manager** tab exposes sliders for real-time adjustment.

---

## Interaction with Other Files

| File | How It Uses `policy.py` |
|---|---|
| `app/waf_engine.py` | Calls `check_request()` (IP/path rules) and `get_thresholds()` (ML cutoffs) |
| `app/main.py` | Calls `add_rule()`, `remove_rule()`, `update_policy()` from REST endpoints |
| `app/middleware/rate_limiter.py` | Reads `rate_limits.default_rpm` and `burst_limit` |

---

## Hot Reload Flow

```
User clicks "Save Thresholds" in dashboard
    → PUT /policy/thresholds
    → main.py: policy.update_policy({'thresholds': {...}})
    → policy.py: _deep_merge(), _compile_rules(), save()
    → config/policy.json updated on disk
    → Next request uses new thresholds immediately
```

No server restart required — the in-memory `_policy` dict is updated atomically.

---

## open-appsec Equivalent

open-appsec policies are defined in YAML and applied to "assets" (specific web applications). The rule hierarchy (explicit IP/path rules taking priority over ML decisions) is identical. open-appsec also supports three modes: **Prevent**, **Detect**, and **Inactive** (equivalent to Monitor here).

The key difference: open-appsec policies can be scoped per-asset (per domain/port), while this implementation applies a single global policy. Adding per-application policy would require adding an `asset_id` field to each request and a nested policy structure.
