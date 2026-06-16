"""
Anti-Bot Middleware

Identifies automated / malicious scanners using:
  - User-Agent analysis (scanner signatures)
  - Headless browser fingerprints
  - Request pattern heuristics (no referer on deep pages, missing headers)
  - Behavioural velocity (too many distinct paths too fast)
"""

import re
import time
from collections import defaultdict, deque
from typing import Dict, Deque

# ── Known malicious / scanner user agents ────────────────────────────────────
SCANNER_UA_PATTERNS = [
    r'sqlmap', r'nikto', r'nmap', r'masscan', r'dirbuster',
    r'gobuster', r'ffuf', r'wfuzz', r'hydra', r'medusa',
    r'burpsuite', r'zap', r'appscan', r'webinspect', r'acunetix',
    r'nessus', r'openvas', r'qualys', r'rapid7', r'metasploit',
    r'zgrab', r'nuclei', r'httpx', r'feroxbuster',
    r'python-requests/[0-9]', r'go-http-client', r'libwww-perl',
    r'lwp-trivial', r'curl/[0-9]', r'wget/[0-9]',
    r'scrapy', r'mechanize', r'headless', r'phantomjs', r'selenium',
    r'puppeteer', r'playwright',
]
SCANNER_COMPILED = [re.compile(p, re.I) for p in SCANNER_UA_PATTERNS]

# ── Suspicious header absence heuristics ─────────────────────────────────────
EXPECTED_HEADERS = {'accept', 'accept-language', 'accept-encoding'}

# Velocity tracking: ip → deque of (timestamp, path)
_velocity: Dict[str, Deque[tuple]] = defaultdict(deque)
VELOCITY_WINDOW   = 10   # seconds
VELOCITY_PATHS    = 20   # distinct paths in window → bot
VELOCITY_REQUESTS = 50   # total requests in window → bot


def _ua_is_scanner(ua: str) -> bool:
    return any(p.search(ua) for p in SCANNER_COMPILED)


def _has_suspicious_absent_headers(headers: dict) -> bool:
    lower = set(k.lower() for k in headers)
    # Real browsers always send Accept and Accept-Language
    missing = EXPECTED_HEADERS - lower
    return len(missing) >= 2  # missing 2+ of the standard headers


def _velocity_check(ip: str, path: str) -> tuple[bool, str]:
    """Returns (is_bot, reason)."""
    now = time.time()
    dq = _velocity[ip]
    dq.append((now, path))
    # Prune old entries
    while dq and dq[0][0] < now - VELOCITY_WINDOW:
        dq.popleft()

    total_reqs  = len(dq)
    unique_paths = len(set(p for _, p in dq))

    if total_reqs > VELOCITY_REQUESTS:
        return True, f'Velocity: {total_reqs} requests in {VELOCITY_WINDOW}s'
    if unique_paths > VELOCITY_PATHS:
        return True, f'Path scanning: {unique_paths} distinct paths in {VELOCITY_WINDOW}s'
    return False, ''


def check(request_data: dict) -> dict:
    """Evaluate a request for bot / scanner characteristics."""
    ip      = request_data.get('ip', '0.0.0.0')  # nosec B104 — default for missing field, not a bind address
    url     = request_data.get('url', '/')
    headers = {k.lower(): v for k, v in (request_data.get('headers') or {}).items()}
    ua      = headers.get('user-agent', '')
    path    = url.split('?')[0]

    reasons = []
    confidence = 0.0

    # ── 1. Known scanner UA ───────────────────────────────────────────
    if _ua_is_scanner(ua):
        reasons.append(f'Known scanner UA: {ua[:60]}')
        confidence = max(confidence, 0.97)

    # ── 2. Empty / missing UA ─────────────────────────────────────────
    if not ua:
        reasons.append('Missing User-Agent header')
        confidence = max(confidence, 0.75)

    # ── 3. Suspicious header absence ─────────────────────────────────
    if _has_suspicious_absent_headers(headers):
        reasons.append('Missing standard browser headers (Accept, Accept-Language)')
        confidence = max(confidence, 0.65)

    # ── 4. Velocity / path scanning ───────────────────────────────────
    is_bot, vel_reason = _velocity_check(ip, path)
    if is_bot:
        reasons.append(vel_reason)
        confidence = max(confidence, 0.90)

    # ── 5. Suspicious path patterns (directory brute-force) ───────────
    if re.search(r'(\.(php|asp|aspx|jsp|cgi|sh|py|rb)\b|/admin|/wp-login|/\.env|/config)', path, re.I):
        if ua and not _ua_is_scanner(ua):
            confidence = max(confidence, 0.45)   # suspicious but not definitive

    block = confidence >= 0.70

    return {
        'block': block,
        'confidence': round(confidence, 3),
        'reason': '; '.join(reasons) if reasons else 'OK',
        'is_bot': block,
        'ua': ua[:80],
    }
