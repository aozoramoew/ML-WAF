"""
API Discovery & Schema Validation Module

Tracks all endpoints accessed, infers schema (parameters, methods, content-types)
and flags requests to undiscovered / out-of-spec endpoints.
Can optionally validate against an OpenAPI spec (JSON).
"""

import re
import json
import time
from collections import defaultdict
from typing import Dict, List, Optional, Any

# ── Endpoint registry ─────────────────────────────────────────────────────────
# path_template → {methods: set, params: set, seen: int, first_seen: float}
_endpoints: Dict[str, dict] = {}
_param_re  = re.compile(r'/\d+')           # turn /123 → /{id}
_uuid_re   = re.compile(r'/[0-9a-f\-]{36}')


def _normalize_path(path: str) -> str:
    """Replace numeric / UUID path segments with placeholders."""
    p = _param_re.sub('/{id}', path)
    p = _uuid_re.sub('/{uuid}', p)
    return p.split('?')[0]   # strip query string


def _extract_params(url: str) -> set:
    if '?' not in url:
        return set()
    qs = url.split('?', 1)[1]
    return {kv.split('=')[0] for kv in qs.split('&') if '=' in kv}


def record(request_data: dict) -> dict:
    """
    Record an observed API call into the discovery registry.
    Returns schema anomaly details.
    """
    url    = request_data.get('url', '/')
    method = request_data.get('method', 'GET').upper()
    path   = _normalize_path(url)
    params = _extract_params(url)
    now    = time.time()

    anomalies: List[str] = []

    if path not in _endpoints:
        _endpoints[path] = {
            'methods': set(),
            'params': set(),
            'seen': 0,
            'first_seen': now,
            'last_seen': now,
            'is_new': True,
        }

    ep = _endpoints[path]
    ep['seen'] += 1
    ep['last_seen'] = now

    # ── Method anomaly ────────────────────────────────────────────────
    if method not in ep['methods']:
        if ep['methods']:  # Not first time we've seen this endpoint
            anomalies.append(f'New HTTP method on known endpoint: {method} {path}')
        ep['methods'].add(method)

    # ── New parameter anomaly ──────────────────────────────────────────
    new_params = params - ep['params']
    if new_params and ep['params']:
        anomalies.append(f'Unexpected parameters on {path}: {", ".join(new_params)}')
    ep['params'].update(params)

    # ── Suspicious endpoint patterns ──────────────────────────────────
    suspicious_patterns = [
        r'/admin', r'/actuator', r'/\.env', r'/config', r'/__debug',
        r'/phpinfo', r'/server-status', r'/wp-admin', r'/wp-login',
        r'/\.git', r'/\.svn', r'/backup', r'\.bak$', r'\.sql$',
    ]
    is_suspicious = any(re.search(p, path, re.I) for p in suspicious_patterns)
    if is_suspicious:
        anomalies.append(f'Probe of sensitive/admin endpoint: {path}')

    block = is_suspicious and ep['seen'] <= 2  # Block first probes only

    return {
        'block': block,
        'endpoint': path,
        'method': method,
        'params': list(params),
        'is_new_endpoint': ep.get('is_new', False),
        'anomalies': anomalies,
        'reason': '; '.join(anomalies) if anomalies else 'OK',
        'attack_type': 'api_abuse' if block else None,
    }


def get_discovered_endpoints() -> List[dict]:
    """Return all discovered endpoints sorted by request count."""
    result = []
    for path, ep in _endpoints.items():
        result.append({
            'path': path,
            'methods': sorted(ep['methods']),
            'params': sorted(ep['params']),
            'seen': ep['seen'],
            'first_seen': ep['first_seen'],
            'last_seen': ep['last_seen'],
        })
    return sorted(result, key=lambda x: -x['seen'])


_anomaly_count = 0

def get_stats() -> dict:
    global _anomaly_count
    endpoint_map = {
        path: {
            'methods': sorted(ep['methods']),
            'count': ep['seen'],
            'anomaly': ep.get('anomaly', False),
        }
        for path, ep in _endpoints.items()
    }
    return {
        'endpoints': len(_endpoints),
        'anomalies': _anomaly_count,
        'total_endpoints': len(_endpoints),
        'top_endpoints': get_discovered_endpoints()[:10],
        'endpoint_map': endpoint_map,
    }
