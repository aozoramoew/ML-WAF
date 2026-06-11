"""
ML-WAF Policy Engine — YAML/JSON-based security policy management.

Supports:
  - IP allowlist/blocklist rules
  - Path-based allow/block rules with regex support
  - Rate limit overrides per IP or path
  - Custom header rules
  - Hot reload via POST /policy/reload
"""

import re
import json
import copy
from pathlib import Path
from typing import Dict, List, Optional, Any

ROOT = Path(__file__).parent.parent
POLICY_PATH = ROOT / 'config' / 'policy.json'

# ── Default policy ─────────────────────────────────────────────────────────────
DEFAULT_POLICY = {
    'version': '1.0',
    'mode': 'prevent',  # 'prevent' | 'detect' | 'monitor'
    'rules': {
        'ip_allowlist': [],
        'ip_blocklist': [],
        'path_allowlist': [],
        'path_blocklist': [],
        'custom': [],
    },
    'thresholds': {
        'ml_block_score': 0.50,
        'unsupervised_block_score': 0.75,
        'combined_block_score': 0.65,
    },
    'rate_limits': {
        'default_rpm': 120,
        'burst_limit': 30,
    }
}

# ── In-memory policy state ─────────────────────────────────────────────────────
_policy: Dict = {}
_compiled_rules: Dict = {}


def _compile_rules():
    global _compiled_rules
    rules = _policy.get('rules', {})
    _compiled_rules = {
        'ip_blocklist': set(rules.get('ip_blocklist', [])),
        'ip_allowlist': set(rules.get('ip_allowlist', [])),
        'path_blocklist_re': [
            re.compile(p, re.I) for p in rules.get('path_blocklist', [])
        ],
        'path_allowlist_re': [
            re.compile(p, re.I) for p in rules.get('path_allowlist', [])
        ],
        'custom': rules.get('custom', []),
    }


def load() -> Dict:
    """Load policy from disk, falling back to defaults."""
    global _policy
    POLICY_PATH.parent.mkdir(exist_ok=True)

    if POLICY_PATH.exists():
        try:
            with open(POLICY_PATH) as f:
                _policy = json.load(f)
        except Exception as e:
            print(f'[Policy] Failed to load {POLICY_PATH}: {e}')
            _policy = copy.deepcopy(DEFAULT_POLICY)
    else:
        _policy = copy.deepcopy(DEFAULT_POLICY)
        save()

    _compile_rules()
    return _policy


def save() -> None:
    """Persist current policy to disk."""
    POLICY_PATH.parent.mkdir(exist_ok=True)
    with open(POLICY_PATH, 'w') as f:
        json.dump(_policy, f, indent=2)


def get_policy() -> Dict:
    if not _policy:
        load()
    return _policy


def update_policy(updates: Dict) -> Dict:
    """Update policy fields and save."""
    if not _policy:
        load()
    _deep_merge(_policy, updates)
    _compile_rules()
    save()
    return _policy


def _deep_merge(base: dict, updates: dict):
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def add_rule(rule_type: str, value: str) -> Dict:
    """
    Add a rule to the policy.
    rule_type: 'ip_allowlist' | 'ip_blocklist' | 'path_allowlist' | 'path_blocklist'
    """
    if not _policy:
        load()

    valid_types = ['ip_allowlist', 'ip_blocklist', 'path_allowlist', 'path_blocklist']
    if rule_type not in valid_types:
        raise ValueError(f'Invalid rule type: {rule_type}. Must be one of {valid_types}')

    rules_list = _policy['rules'][rule_type]
    if value not in rules_list:
        rules_list.append(value)
        _compile_rules()
        save()

    return _policy


def remove_rule(rule_type: str, value: str) -> Dict:
    """Remove a rule from the policy."""
    if not _policy:
        load()

    rules_list = _policy['rules'].get(rule_type, [])
    if value in rules_list:
        rules_list.remove(value)
        _compile_rules()
        save()

    return _policy


def check_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply policy rules to a request.

    Returns:
        {'block': bool, 'reason': str, 'action': 'allow'|'block'|'monitor'}
    """
    if not _policy:
        load()

    ip = str(request_data.get('ip', ''))
    url = str(request_data.get('url', ''))
    path = url.split('?', 1)[0]
    mode = _policy.get('mode', 'prevent')

    # IP allowlist takes highest priority
    if ip in _compiled_rules.get('ip_allowlist', set()):
        return {'block': False, 'reason': 'IP allowlisted', 'action': 'allow'}

    # IP blocklist
    if ip in _compiled_rules.get('ip_blocklist', set()):
        if mode == 'monitor':
            return {'block': False, 'reason': 'IP blocklisted (monitor mode)', 'action': 'monitor'}
        return {'block': True, 'reason': f'IP blocklisted: {ip}', 'action': 'block'}

    # Path allowlist
    for pattern in _compiled_rules.get('path_allowlist_re', []):
        if pattern.search(path):
            return {'block': False, 'reason': f'Path allowlisted: {pattern.pattern}', 'action': 'allow'}

    # Path blocklist
    for pattern in _compiled_rules.get('path_blocklist_re', []):
        if pattern.search(path):
            if mode == 'monitor':
                return {'block': False, 'reason': 'Path blocked (monitor mode)', 'action': 'monitor'}
            return {'block': True, 'reason': f'Path blocklisted: {pattern.pattern}', 'action': 'block'}

    return {'block': False, 'reason': '', 'action': mode}


def get_thresholds() -> Dict:
    if not _policy:
        load()
    return _policy.get('thresholds', DEFAULT_POLICY['thresholds'])


# Initialize on import
load()
