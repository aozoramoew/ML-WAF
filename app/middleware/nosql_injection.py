"""
NoSQL Injection Detection Middleware

Detects MongoDB, CouchDB, and generic NoSQL injection attacks:
  - MongoDB operator injection ($where, $gt, $ne, $regex, etc.)
  - JavaScript injection via $where clause
  - JSON-based operator injection in request body
  - URL parameter operator injection
  - Redis protocol injection
"""

import re
import json
from typing import Dict, Any

# ── MongoDB operator patterns ──────────────────────────────────────────────────
MONGO_OPERATORS = [
    '$where', '$gt', '$lt', '$gte', '$lte', '$ne', '$eq',
    '$in', '$nin', '$or', '$and', '$not', '$nor',
    '$exists', '$type', '$regex', '$text', '$mod',
    '$elemMatch', '$all', '$size', '$slice',
    '$expr', '$jsonSchema', '$geoWithin',
]

# URL-encoded operator forms ([$ne]=, [$gt]=, etc.)
URL_OPERATOR_PATTERN = re.compile(
    r'\[(\$[a-zA-Z]+)\]', re.I
)

# JS code in $where
JS_IN_WHERE_PATTERN = re.compile(
    r'\$where.*?(function|sleep|while|return|this\.|db\.)', re.I | re.S
)

# Redis protocol injection
REDIS_PROTOCOL_PATTERN = re.compile(
    r'\*\d+\r?\n\$\d+\r?\n', re.S
)

# Suspicious JSON structures
OPERATOR_IN_JSON_PATTERN = re.compile(
    r'"?\$[a-zA-Z]+"?\s*:', re.I
)


def check(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspect request for NoSQL injection attempts.

    Returns:
        {'block': bool, 'confidence': float, 'reason': str, 'details': dict}
    """
    url = str(request_data.get('url', ''))
    body = str(request_data.get('body', '') or '')
    headers = request_data.get('headers', {}) or {}
    content_type = str(headers.get('Content-Type', headers.get('content-type', ''))).lower()

    result = {
        'block': False,
        'confidence': 0.0,
        'reason': '',
        'details': {},
        'operators_found': [],
    }

    full = (url + ' ' + body).lower()
    operators_found = []

    # ── 1. Check for MongoDB operators in URL params ──────────────────
    url_ops = URL_OPERATOR_PATTERN.findall(url)
    if url_ops:
        operators_found.extend(url_ops)
        result['block'] = True
        result['confidence'] = 0.95
        result['reason'] = f'NoSQL operator injection in URL params: {url_ops}'

    # ── 2. Check for MongoDB operators in plain text ──────────────────
    for op in MONGO_OPERATORS:
        if op in full:
            operators_found.append(op)

    if len(operators_found) >= 2:
        result['block'] = True
        result['confidence'] = max(result['confidence'], 0.90)
        result['reason'] = f'Multiple NoSQL operators detected: {operators_found[:5]}'

    # ── 3. JSON body analysis ─────────────────────────────────────────
    if body and ('json' in content_type or body.strip().startswith('{')):
        try:
            parsed = json.loads(body)
            json_str = json.dumps(parsed)
            json_ops = OPERATOR_IN_JSON_PATTERN.findall(json_str)
            if json_ops:
                operators_found.extend(json_ops)
                result['block'] = True
                result['confidence'] = max(result['confidence'], 0.92)
                result['reason'] = f'NoSQL operators in JSON body: {json_ops[:5]}'
        except (json.JSONDecodeError, ValueError):
            # If we can't parse JSON but see operators, flag as suspicious
            if OPERATOR_IN_JSON_PATTERN.search(body):
                result['block'] = True
                result['confidence'] = max(result['confidence'], 0.80)
                result['reason'] = 'Malformed JSON with NoSQL operators'

    # ── 4. JavaScript injection via $where ────────────────────────────
    if JS_IN_WHERE_PATTERN.search(full):
        result['block'] = True
        result['confidence'] = max(result['confidence'], 0.97)
        result['reason'] = 'JavaScript injection via $where operator'

    # ── 5. Redis protocol injection ───────────────────────────────────
    if REDIS_PROTOCOL_PATTERN.search(body):
        result['block'] = True
        result['confidence'] = max(result['confidence'], 0.98)
        result['reason'] = 'Redis protocol injection detected'

    result['operators_found'] = list(set(operators_found))
    result['details'] = {
        'url_operators': url_ops if 'url_ops' in dir() else [],
        'total_operators': len(result['operators_found']),
    }

    return result
