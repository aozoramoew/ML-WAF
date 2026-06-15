"""
ML WAF Engine — Core ML inference and decision pipeline.

Runs every incoming request through the full 9-stage security stack:
  1. Rate Limiter
  2. Anti-Bot
  3. Crowd Wisdom (IP reputation)
  4. IPS Engine (CVE signatures)
  5. File Security
  6. NoSQL Injection detection
  7. JWT Abuse detection
  8. ML Model — Supervised (Random Forest)
  9. ML Model — Unsupervised (Isolation Forest baseline)
 10. API Discovery (non-blocking, always records)

Emits results to the WebSocket broadcast manager.

open-appsec compatible architecture:
  - Supervised model: trained offline on millions of samples
  - Unsupervised model: learns per-environment normal traffic in real time
  - Confidence fusion: weighted combination of both models
"""

import json
import time
import uuid
import asyncio
import joblib
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any

ROOT = Path(__file__).parent.parent

# ── Lazy model loading ────────────────────────────────────────────────────────
_model = None
_metrics: Dict = {}

def _load_model():
    global _model, _metrics
    model_path   = ROOT / 'models' / 'waf_model.pkl'
    metrics_path = ROOT / 'models' / 'metrics.json'

    if model_path.exists():
        _model = joblib.load(model_path)
        print(f'[WAF] Model loaded: {model_path}')
    else:
        print('[WAF] WARNING: No trained model found. Run: python -m ml.train')

    if metrics_path.exists():
        with open(metrics_path) as f:
            _metrics = json.load(f)

def get_model():
    global _model
    if _model is None:
        _load_model()
    return _model

def is_model_loaded() -> bool:
    """Returns True if the model is currently loaded in memory."""
    return _model is not None

def load_models():
    """Public hot-reload: forces a fresh load of the .pkl model from disk.
    Called by the /ml/retrain endpoint after background training completes."""
    global _model, _metrics
    _model = None
    _metrics = {}
    _load_model()

def get_metrics() -> dict:
    if not _metrics:
        _load_model()
    return _metrics


# ── Import middleware modules ─────────────────────────────────────────────────
from app.middleware import (
    rate_limiter, anti_bot, ips_engine,
    file_security, crowd_wisdom,
)
from app.middleware import nosql_injection, jwt_abuse
from app.api_discovery import record as api_record
from app import policy
from ml.feature_extractor import extract_features, features_to_array, FEATURE_NAMES
from ml.unsupervised import get_baseline, save_baseline

# ── Learning mode flag ────────────────────────────────────────────────────────
_learning_enabled = True

def set_learning(enabled: bool):
    global _learning_enabled
    _learning_enabled = enabled

def is_learning() -> bool:
    return _learning_enabled

# ── Statistics tracking ───────────────────────────────────────────────────────
_stats = {
    'total': 0,
    'blocked': 0,
    'allowed': 0,
    'attack_counts': {},
    'blocked_by': {},
    'req_history': [],   # list of (timestamp, is_blocked) for time-series
}

ATTACK_LABELS = {
    0: 'normal',
    1: 'sqli',
    2: 'xss',
    3: 'path_traversal',
    4: 'cmd_injection',
    5: 'nosql_injection',
    6: 'jwt_abuse',
    7: 'ssrf',
    8: 'xxe',
    9: 'idor',
}

# Attack type → class index mapping (built during training, Random Forest classes)
def _infer_attack_type(features: dict) -> str:
    if features.get('has_script_tag', 0) or features.get('xss_pattern_count', 0) > 1:
        return 'xss'
    if features.get('sql_keyword_count', 0) > 1 or features.get('has_union', 0) \
            or features.get('sql_tautology', 0):
        return 'sqli'
    if features.get('cmd_injection_count', 0) > 0:
        return 'cmd_injection'
    if features.get('path_traversal_count', 0) > 0 or features.get('has_dotdot', 0):
        return 'path_traversal'
    if features.get('nosql_operator_count', 0) > 1:
        return 'nosql_injection'
    if features.get('has_aws_metadata', 0) or features.get('has_internal_ip', 0):
        return 'ssrf'
    if features.get('has_xml_doctype', 0):
        return 'xxe'
    if features.get('jwt_alg_none', 0):
        return 'jwt_abuse'
    if features.get('has_idor_pattern', 0):
        return 'idor'
    return 'unknown'


async def analyze(request_data: dict) -> dict:
    """
    Run a request through the full WAF pipeline and return a decision.

    Args:
        request_data: {method, url, headers, body, ip, files (optional)}

    Returns:
        Full analysis result dict
    """
    req_id    = str(uuid.uuid4())[:8]
    timestamp = time.time()

    result = {
        'id':              req_id,
        'timestamp':       timestamp,
        'method':          request_data.get('method', 'GET'),
        'url':             request_data.get('url', '/'),
        'ip':              request_data.get('ip', '0.0.0.0'),
        'decision':        'ALLOW',
        'confidence':      1.0,
        'attack_type':     'normal',
        'blocked_by':      None,
        'modules':         {},
        'features':        {},
        'ml_score':        0.0,
        'unsupervised_score': 0.0,
    }

    # ── Stage 0: Policy (IP/path allow/blocklists) ────────────────────
    policy_result = policy.check_request(request_data)
    if policy_result['action'] == 'allow':
        result['modules']['policy'] = policy_result
        _update_stats(result, blocked=False)
        return result
    if policy_result['block']:
        return _finalize(result, 'policy', 'policy_blocklist', 1.0, timestamp)

    # ── Feature extraction (used by ML stages and as attack-type fallback
    #    for any earlier stage that blocks without a specific type) ──────
    features = extract_features(request_data)
    result['features'] = {k: round(float(v), 4) for k, v in features.items()}
    feature_arr = features_to_array(features).reshape(1, -1)

    # ── Stage 1: Rate Limiter ─────────────────────────────────────────
    rl = rate_limiter.check(request_data)
    result['modules']['rate_limiter'] = rl
    if rl['block']:
        return _finalize(result, 'rate_limiter', 'rate_limit', rl.get('confidence', 1.0), timestamp)

    # ── Stage 2: Anti-Bot ─────────────────────────────────────────────
    ab = anti_bot.check(request_data)
    result['modules']['anti_bot'] = ab
    if ab['block']:
        return _finalize(result, 'anti_bot', 'bot_detected', ab.get('confidence', 0.9), timestamp)

    # ── Stage 3: Crowd Wisdom ─────────────────────────────────────────
    cw = await crowd_wisdom.check(request_data)
    result['modules']['crowd_wisdom'] = cw
    if cw['block']:
        return _finalize(result, 'crowd_wisdom', 'known_bad_ip', cw.get('confidence', 0.85), timestamp)

    # ── Stage 4: IPS Engine ───────────────────────────────────────────
    ips = ips_engine.check(request_data)
    result['modules']['ips'] = ips
    if ips['block']:
        attack = _infer_attack_type(features)
        if attack == 'unknown':
            attack = 'ips_match'
        return _finalize(result, 'ips', attack, ips.get('confidence', 0.95), timestamp)

    # ── Stage 5: File Security ────────────────────────────────────────
    fs = file_security.check(request_data)
    result['modules']['file_security'] = fs
    if fs['block']:
        return _finalize(result, 'file_security', 'malicious_upload', 0.99, timestamp)

    # ── Stage 6: NoSQL Injection ──────────────────────────────────────
    nosql = nosql_injection.check(request_data)
    result['modules']['nosql_injection'] = nosql
    if nosql['block']:
        return _finalize(result, 'nosql_injection', 'nosql_injection', nosql.get('confidence', 0.92), timestamp)

    # ── Stage 7: JWT Abuse ────────────────────────────────────────────
    jwt = jwt_abuse.check(request_data)
    result['modules']['jwt_abuse'] = jwt
    if jwt['block']:
        return _finalize(result, 'jwt_abuse', 'jwt_abuse', jwt.get('confidence', 0.97), timestamp)

    # ── Stage 8: ML Model (Supervised) ───────────────────────────────
    model = get_model()

    ml_result = {'block': False, 'confidence': 0.0, 'score': 0.0}
    if model is not None:
        proba = model.predict_proba(feature_arr)[0]
        malicious_score = float(proba[1])
        ml_result['score'] = round(malicious_score, 4)
        ml_result['confidence'] = round(malicious_score, 4)

        ml_block_score = policy.get_thresholds().get('ml_block_score', 0.90)
        if malicious_score >= ml_block_score:
            ml_result['block'] = True
            ml_result['attack_type'] = _infer_attack_type(features)
    else:
        # Fallback: rule-based when model not yet trained
        ml_result = _rule_based_check(features)

    result['modules']['ml_waf'] = ml_result
    result['ml_score'] = ml_result['score']

    if ml_result['block']:
        attack = ml_result.get('attack_type', _infer_attack_type(features))
        return _finalize(result, 'ml_waf', attack, ml_result['confidence'], timestamp)

    # ── Stage 9: Unsupervised Model ───────────────────────────────────
    baseline = get_baseline()
    feature_vec = features_to_array(features)
    unsupervised = baseline.score(feature_vec, request_data)
    result['modules']['unsupervised'] = unsupervised
    result['unsupervised_score'] = unsupervised.get('anomaly_score', 0.0)

    unsupervised_block_score = policy.get_thresholds().get('unsupervised_block_score', 0.75)
    is_anomaly = unsupervised.get('anomaly_score', 0.0) >= unsupervised_block_score
    if is_anomaly:
        # Unsupervised doesn't block on its own — it boosts the supervised score
        # Only block if combined confidence exceeds threshold
        combined = _fuse_confidence(ml_result['score'], unsupervised['anomaly_score'])
        combined_block_score = policy.get_thresholds().get('combined_block_score', 0.85)
        if combined >= combined_block_score:
            return _finalize(result, 'unsupervised', 'behavioral_anomaly', combined, timestamp)

    # ── Stage 10: API Discovery (always runs, rarely blocks) ──────────
    api = api_record(request_data)
    result['modules']['api_discovery'] = api
    if api['block']:
        return _finalize(result, 'api_discovery', 'api_abuse', 0.75, timestamp)

    # ── Allowed — teach the unsupervised model ────────────────────────
    if _learning_enabled:
        baseline.learn(feature_vec, request_data)

    _update_stats(result, blocked=False)
    return result


def _fuse_confidence(supervised_score: float, unsupervised_score: float) -> float:
    """
    Weighted fusion of supervised and unsupervised model scores.

    Mirrors the open-appsec two-phase confidence scoring:
      - Supervised is the primary signal (trained on global patterns)
      - Unsupervised adds environment-specific context
    """
    weight_sup = 0.7
    weight_uns = 0.3
    return round(supervised_score * weight_sup + unsupervised_score * weight_uns, 4)


def _finalize(result: dict, blocked_by: str, attack_type: str, confidence: float, ts: float) -> dict:
    mode = policy.get_policy().get('mode', 'prevent')

    result['blocked_by']  = blocked_by
    result['attack_type'] = attack_type
    result['confidence']  = round(confidence, 4)

    if mode == 'prevent':
        result['decision'] = 'BLOCK'
        _update_stats(result, blocked=True)
    else:
        # detect/monitor: record what *would* have been blocked, but allow it through
        result['decision'] = 'ALLOW'
        result['would_block'] = True
        _update_stats(result, blocked=False)

    return result


def _rule_based_check(features: dict) -> dict:
    """Simple rule-based fallback when model hasn't been trained yet."""
    score = 0.0
    attack = 'unknown'

    if features.get('sql_keyword_count', 0) >= 2:
        score = max(score, 0.9); attack = 'sqli'
    if features.get('xss_pattern_count', 0) >= 2:
        score = max(score, 0.9); attack = 'xss'
    if features.get('path_traversal_count', 0) >= 1:
        score = max(score, 0.85); attack = 'path_traversal'
    if features.get('cmd_injection_count', 0) >= 1:
        score = max(score, 0.85); attack = 'cmd_injection'
    if features.get('has_script_tag', 0):
        score = max(score, 0.8); attack = 'xss'
    if features.get('nosql_operator_count', 0) >= 2:
        score = max(score, 0.88); attack = 'nosql_injection'
    if features.get('has_aws_metadata', 0) or features.get('has_non_http_proto', 0):
        score = max(score, 0.85); attack = 'ssrf'
    if features.get('has_xml_doctype', 0):
        score = max(score, 0.85); attack = 'xxe'
    if features.get('jwt_alg_none', 0):
        score = max(score, 0.99); attack = 'jwt_abuse'

    return {
        'block': score >= 0.5,
        'score': score,
        'confidence': score,
        'attack_type': attack,
        'note': 'rule-based (model not trained)',
    }


def _update_stats(result: dict, blocked: bool):
    _stats['total'] += 1
    now = time.time()

    if blocked:
        _stats['blocked'] += 1
        at = result.get('attack_type', 'unknown')
        _stats['attack_counts'][at] = _stats['attack_counts'].get(at, 0) + 1
        by = result.get('blocked_by', 'unknown')
        _stats['blocked_by'][by] = _stats['blocked_by'].get(by, 0) + 1
    else:
        _stats['allowed'] += 1
        # detect/monitor mode: still surface what *would* have been blocked
        if result.get('would_block'):
            at = result.get('attack_type', 'unknown')
            _stats['attack_counts'][at] = _stats['attack_counts'].get(at, 0) + 1
            by = result.get('blocked_by', 'unknown')
            _stats['blocked_by'][by] = _stats['blocked_by'].get(by, 0) + 1

    # Keep last 300 data points for time-series chart
    _stats['req_history'].append({'t': now, 'blocked': blocked})
    if len(_stats['req_history']) > 300:
        _stats['req_history'].pop(0)


def get_stats() -> dict:
    baseline = get_baseline()
    return {
        **_stats,
        'block_rate': round(_stats['blocked'] / max(_stats['total'], 1), 4),
        'threat_level': _calculate_threat_level(),
        'model_loaded': _model is not None,
        'learning_enabled': _learning_enabled,
        'unsupervised': baseline.get_stats(),
    }


def _calculate_threat_level() -> str:
    if _stats['total'] == 0:
        return 'low'
    block_rate = _stats['blocked'] / _stats['total']
    if block_rate > 0.5:
        return 'critical'
    if block_rate > 0.3:
        return 'high'
    if block_rate > 0.1:
        return 'medium'
    return 'low'


def reset_stats():
    global _stats
    _stats = {
        'total': 0, 'blocked': 0, 'allowed': 0,
        'attack_counts': {}, 'blocked_by': {}, 'req_history': [],
    }
