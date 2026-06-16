"""
Rate Limiting Middleware

Tracks per-IP request counts within a sliding window and blocks IPs that
exceed configurable thresholds. Supports JWT / cookie / header key extraction
for more granular identity tracking.
"""

import time
import os
from collections import defaultdict, deque
from typing import Dict, Deque, Optional, Tuple

RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
RATE_LIMIT_WINDOW   = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))

# Separate tighter limits for sensitive endpoints
SENSITIVE_PATHS  = {'/admin', '/login', '/api/auth', '/register'}
SENSITIVE_LIMIT  = 10   # per window
BURST_LIMIT      = 30   # max requests in 5 seconds (DDoS detection)
BURST_WINDOW     = 5

# ip → deque of timestamps
_windows:  Dict[str, Deque[float]] = defaultdict(deque)
_burst:    Dict[str, Deque[float]] = defaultdict(deque)
_blocked:  Dict[str, float]        = {}   # ip → block-until timestamp
BLOCK_DURATION = 300  # 5 minutes


def _count_in_window(dq: Deque[float], window: float, now: float) -> int:
    while dq and dq[0] < now - window:
        dq.popleft()
    return len(dq)


def check(request_data: dict) -> dict:
    """
    Returns:
        dict with keys: block (bool), reason (str), requests_in_window (int),
                        limit (int), window_seconds (int), retry_after (int)
    """
    ip  = request_data.get('ip', '0.0.0.0')  # nosec B104 — default for missing field, not a bind address
    url = request_data.get('url', '/')
    now = time.time()

    # ── Check if already hard-blocked ────────────────────────────────
    if ip in _blocked:
        if now < _blocked[ip]:
            retry = int(_blocked[ip] - now)
            return {
                'block': True,
                'reason': f'IP temporarily blocked — too many violations',
                'retry_after': retry,
                'requests_in_window': RATE_LIMIT_REQUESTS,
                'limit': RATE_LIMIT_REQUESTS,
                'window_seconds': RATE_LIMIT_WINDOW,
            }
        else:
            del _blocked[ip]

    # ── Burst check (DDoS indicator) ──────────────────────────────────
    burst_dq = _burst[ip]
    burst_dq.append(now)
    burst_count = _count_in_window(burst_dq, BURST_WINDOW, now)
    if burst_count > BURST_LIMIT:
        _blocked[ip] = now + BLOCK_DURATION
        return {
            'block': True,
            'reason': f'Burst rate exceeded: {burst_count} reqs in {BURST_WINDOW}s',
            'retry_after': BLOCK_DURATION,
            'requests_in_window': burst_count,
            'limit': BURST_LIMIT,
            'window_seconds': BURST_WINDOW,
        }

    # ── Sensitive endpoint stricter limit ─────────────────────────────
    path = url.split('?')[0]
    is_sensitive = any(path.startswith(p) for p in SENSITIVE_PATHS)
    effective_limit = SENSITIVE_LIMIT if is_sensitive else RATE_LIMIT_REQUESTS

    # ── Sliding window check ──────────────────────────────────────────
    win_dq = _windows[ip]
    win_dq.append(now)
    count = _count_in_window(win_dq, RATE_LIMIT_WINDOW, now)

    if count > effective_limit:
        return {
            'block': True,
            'reason': f'Rate limit exceeded: {count}/{effective_limit} req/{RATE_LIMIT_WINDOW}s',
            'retry_after': int(RATE_LIMIT_WINDOW - (now - win_dq[0])),
            'requests_in_window': count,
            'limit': effective_limit,
            'window_seconds': RATE_LIMIT_WINDOW,
        }

    return {
        'block': False,
        'reason': 'OK',
        'requests_in_window': count,
        'limit': effective_limit,
        'window_seconds': RATE_LIMIT_WINDOW,
        'retry_after': 0,
    }


def get_stats() -> dict:
    """Return current rate limiter state for the dashboard."""
    now = time.time()
    top_ips = []
    for ip, dq in _windows.items():
        cnt = _count_in_window(dq, RATE_LIMIT_WINDOW, now)
        if cnt > 0:
            top_ips.append({'ip': ip, 'count': cnt})
    top_ips.sort(key=lambda x: -x['count'])
    return {
        'active_ips': len(_windows),
        'blocked_ips': len(_blocked),
        'top_ips': top_ips[:10],
    }
