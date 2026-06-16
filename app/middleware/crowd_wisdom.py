"""
Crowd Wisdom Middleware — powered by CrowdSec CTI

Checks incoming IP addresses against:
  1. CrowdSec CTI API (real-time threat intelligence from 64,000+ contributing servers)
  2. Local offline blocklist (always available, no API key needed)

CrowdSec free tier: https://app.crowdsec.net/  →  Settings → API Keys
Set CROWDSEC_API_KEY in your .env file to enable live lookups.
"""

import os
import time
import asyncio
import ipaddress
from typing import Optional
import httpx

CROWDSEC_API_KEY  = os.getenv('CROWDSEC_API_KEY', '')
CROWDSEC_CTI_URL  = 'https://cti.api.crowdsec.net/v2/smoke/{ip}'
CACHE_TTL         = 3600  # cache results for 1 hour
REQUEST_TIMEOUT   = 2.0   # seconds — fail fast to not slow WAF

# ── In-memory cache: ip → (result_dict, expiry_timestamp) ──────────────────
_cache: dict = {}

# ── Embedded offline blocklist (well-known malicious IP ranges / tor exits) ──
# Keep this small — supplement with CrowdSec for production use
_OFFLINE_BLOCKLIST_CIDRS = [
    # Tor exit nodes (representative sample)
    '185.220.101.0/24', '185.220.102.0/24', '185.220.103.0/24',
    '192.42.116.0/24',  '176.10.104.0/24',
    # Known scanner farms
    '89.248.165.0/24',  '89.248.167.0/24',
    '94.102.49.0/24',   '80.82.77.0/24',
    # Shodan scanners
    '66.240.192.0/24',  '66.240.236.0/24', '71.6.135.0/24',
    # Censys
    '162.142.125.0/24', '167.94.138.0/24', '167.94.145.0/24',
    '167.94.146.0/24',
    # Known C2 / malware hosts (sample)
    '5.188.86.0/24',    '5.188.87.0/24',
    '179.43.128.0/24',  '91.108.4.0/24',
]

_offline_networks = []
for cidr in _OFFLINE_BLOCKLIST_CIDRS:
    try:
        _offline_networks.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass


def _in_offline_blocklist(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _offline_networks)
    except ValueError:
        return False


async def _crowdsec_lookup(ip: str) -> Optional[dict]:
    """Query CrowdSec CTI API for an IP's reputation."""
    if not CROWDSEC_API_KEY:
        return None

    # Check cache
    cached = _cache.get(ip)
    if cached and time.time() < cached[1]:
        return cached[0]

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(
                CROWDSEC_CTI_URL.format(ip=ip),
                headers={'x-api-key': CROWDSEC_API_KEY},
            )
        if resp.status_code == 200:
            data = resp.json()
            _cache[ip] = (data, time.time() + CACHE_TTL)
            return data
    except Exception:  # nosec B110 — intentional fail-open: WAF must not block if reputation API is down
        pass   # Fail open — don't block if API is unreachable
    return None


async def check(request_data: dict) -> dict:
    """
    Async crowd wisdom check.
    Returns block=True if IP is known-malicious.
    """
    ip = request_data.get('ip', '0.0.0.0')  # nosec B104 — default for missing field, not a bind address

    # ── 1. Offline blocklist (always fast) ───────────────────────────
    if _in_offline_blocklist(ip):
        return {
            'block': True,
            'reason': f'IP {ip} found in offline threat intelligence blocklist',
            'source': 'offline_blocklist',
            'confidence': 0.85,
            'attack_type': 'known_bad_ip',
        }

    # ── 2. CrowdSec CTI API ───────────────────────────────────────────
    cti_data = await _crowdsec_lookup(ip)
    if cti_data:
        scores = cti_data.get('scores', {}).get('overall', {})
        aggressiveness = float(scores.get('aggressiveness', 0))
        trust          = float(scores.get('trust', 0))
        anomaly        = float(scores.get('anomaly', 0))

        # Block if high aggressiveness or very low trust
        composite = (aggressiveness * 0.5 + anomaly * 0.3 + max(0, 1 - trust) * 0.2)

        classifications = cti_data.get('classifications', {}).get('classifications', [])
        class_names = [c.get('name', '') for c in classifications]

        if composite > 0.7 or trust < 0.1:
            return {
                'block': True,
                'reason': f'CrowdSec CTI: IP classified as malicious (score={composite:.2f})',
                'source': 'crowdsec_cti',
                'confidence': min(composite, 0.99),
                'classifications': class_names,
                'attack_type': 'known_bad_ip',
            }

    return {
        'block': False,
        'reason': 'IP not found in threat intelligence sources',
        'source': 'offline_blocklist' if not CROWDSEC_API_KEY else 'crowdsec_cti',
    }


def get_stats() -> dict:
    return {
        'crowdsec_enabled': bool(CROWDSEC_API_KEY),
        'offline_ranges': len(_offline_networks),
        'cache_entries': len(_cache),
    }
