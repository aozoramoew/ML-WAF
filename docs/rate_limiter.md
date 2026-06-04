# `rate_limiter.py` — Rate Limiting Middleware

## Overview

`rate_limiter.py` is **Stage 1** in the WAF pipeline. It implements a token-bucket style sliding window to prevent brute force, credential stuffing, and volumetric DDoS attacks at the application layer.

---

## Mechanism

The rate limiter tracks request timestamps per IP address using a `collections.deque` (double-ended queue). When a new request arrives, it:
1. Adds the current timestamp to the IP's deque.
2. Removes all timestamps older than the `RATE_LIMIT_WINDOW` (default 60 seconds).
3. Checks if the remaining length exceeds the limit.

```python
def _count_in_window(dq: Deque[float], window: float, now: float) -> int:
    while dq and dq[0] < now - window:
        dq.popleft()
    return len(dq)
```

---

## Multi-Tiered Limits

The module implements three tiers of rate limiting:

1. **Global Limit**: `100 requests per 60 seconds` (configurable). Applies to all normal endpoints.
2. **Sensitive Endpoint Limit**: `10 requests per 60 seconds`. Automatically applied to authentication and registration paths (`/login`, `/admin`, `/api/auth`) to thwart credential stuffing and brute-forcing.
3. **Burst Limit (Micro-DDoS)**: `30 requests per 5 seconds`. Detects aggressive volumetric attacks.

---

## Penalty Box

If an IP exceeds the **Burst Limit**, it is placed in a "penalty box" — it is hard-blocked for 5 minutes (`BLOCK_DURATION`). During this time, the sliding window check is bypassed entirely, and all requests are immediately rejected with a `retry_after` response. This saves CPU cycles during an active attack.

```python
if ip in _blocked:
    if now < _blocked[ip]:
        return {'block': True, ...}
```

---

## Integration with Policy Engine

While the defaults are hardcoded, the rate limits are designed to be overridden by the global policy engine (`policy.json` -> `rate_limits`). If an IP is in the policy's `ip_allowlist`, it bypasses this module entirely via the check in `waf_engine.py`.

---

## Dashboard Metrics

The module provides a `get_stats()` function that returns:
- Total active IPs being tracked
- Number of currently hard-blocked IPs
- Top 10 IPs by request volume in the current window

These metrics can be used to identify distributed attacks where no single IP exceeds the threshold, but the aggregate volume is suspiciously high.

---

## open-appsec Equivalent

open-appsec includes advanced Rate Limiting capable of tracking sessions across IPs using cookies, headers, or JWT claims. While this implementation currently tracks solely by IP, the architecture supports expanding to identity-based limiting by extracting user IDs from JWTs in Stage 7.
