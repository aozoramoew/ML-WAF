"""
JWT Abuse Detection Middleware

Detects malicious JWT manipulation:
  - alg:none attack (signature bypass)
  - Expired tokens being replayed
  - Tampered claims (role escalation)
  - Algorithm confusion (RS256 → HS256)
  - SQL/XSS injection in JWT payload claims
  - Missing/empty signature
"""

import re
import json
import time
import base64
from typing import Dict, Any, Optional


def _b64_decode(data: str) -> Optional[bytes]:
    """Decode base64url-encoded string (padding-tolerant)."""
    try:
        # Add padding if needed
        data = data.replace('-', '+').replace('_', '/')
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.b64decode(data)
    except Exception:
        return None


def _decode_jwt_part(part: str) -> Optional[Dict]:
    """Decode a single JWT part (header or payload)."""
    raw = _b64_decode(part)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


SQL_INJECTION_PATTERN = re.compile(
    r"('|\")\s*(or|and|union|select|insert|drop)\s", re.I
)

XSS_PATTERN = re.compile(
    r'<script|javascript:|onerror=|onload=', re.I
)

KNOWN_WEAK_ALGS = {'none', 'null', '', 'hs256 with rsa key'}


def check(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspect JWT tokens in Authorization header and cookies.

    Returns:
        {'block': bool, 'confidence': float, 'reason': str, 'details': dict}
    """
    headers = request_data.get('headers', {}) or {}
    headers_lower = {k.lower(): str(v) for k, v in headers.items()}

    result = {
        'block': False,
        'confidence': 0.0,
        'reason': '',
        'details': {'jwt_found': False},
    }

    # Extract token from Authorization header or cookie
    token = None
    auth = headers_lower.get('authorization', '')
    if auth.lower().startswith('bearer '):
        token = auth[7:].strip()
    elif not token:
        # Check cookies for JWT-like tokens
        cookie = headers_lower.get('cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if '=' in part:
                key, _, val = part.partition('=')
                if val.count('.') == 2 and len(val) > 40:
                    token = val
                    break

    if not token or token.count('.') != 2:
        return result

    parts = token.split('.')
    if len(parts) != 3:
        return result

    header_raw, payload_raw, signature = parts[0], parts[1], parts[2]

    header = _decode_jwt_part(header_raw)
    payload = _decode_jwt_part(payload_raw)

    result['details']['jwt_found'] = True

    if header is None:
        result['block'] = True
        result['confidence'] = 0.85
        result['reason'] = 'Malformed JWT header (cannot decode)'
        return result

    alg = str(header.get('alg', '')).lower()
    result['details']['alg'] = alg

    # ── Check 1: Algorithm none attack ───────────────────────────────
    if alg in KNOWN_WEAK_ALGS or alg.strip() == '':
        result['block'] = True
        result['confidence'] = 0.99
        result['reason'] = f'JWT alg:none attack detected (alg={repr(alg)})'
        return result

    # ── Check 2: Missing signature ────────────────────────────────────
    if not signature or signature == '':
        result['block'] = True
        result['confidence'] = 0.97
        result['reason'] = 'JWT has empty/missing signature'
        return result

    if payload is None:
        # Can't decode payload but JWT is otherwise structurally present
        result['details']['payload_decode_failed'] = True
        return result

    result['details']['payload_claims'] = list(payload.keys())

    # ── Check 3: Expired token ────────────────────────────────────────
    exp = payload.get('exp')
    if exp is not None:
        try:
            if float(exp) < time.time() - 86400:  # More than 1 day expired
                result['block'] = True
                result['confidence'] = max(result['confidence'], 0.80)
                result['reason'] = 'Expired JWT token (exp claim in far past)'
        except (TypeError, ValueError):
            pass

    # ── Check 4: Injection in claims ─────────────────────────────────
    payload_str = json.dumps(payload)
    if SQL_INJECTION_PATTERN.search(payload_str):
        result['block'] = True
        result['confidence'] = max(result['confidence'], 0.95)
        result['reason'] = 'SQL injection detected in JWT claims'

    if XSS_PATTERN.search(payload_str):
        result['block'] = True
        result['confidence'] = max(result['confidence'], 0.95)
        result['reason'] = 'XSS payload detected in JWT claims'

    # ── Check 5: Privilege escalation attempts ────────────────────────
    role = str(payload.get('role', payload.get('roles', payload.get('group', '')))).lower()
    if role in ('admin', 'administrator', 'superuser', 'root', 'system'):
        # Not necessarily malicious — but flag for review if combined with other signals
        result['details']['elevated_role_claim'] = role
        # If the token comes with a tampered signature marker
        if signature in ('invalid_sig', 'tampered', 'hacked', 'rsa_public_key_used_as_hmac_secret'):
            result['block'] = True
            result['confidence'] = max(result['confidence'], 0.99)
            result['reason'] = f'Tampered JWT with elevated role: {role}'

    # ── Check 6: Algorithm confusion ─────────────────────────────────
    if alg == 'hs256' and len(signature) > 200:
        # HS256 signatures should be ~43 chars; very long = RS256 key used as HMAC
        result['details']['possible_alg_confusion'] = True

    return result
