"""Tests for ml.feature_extractor — known payloads -> expected feature flags."""

import pytest

from ml.feature_extractor import extract_features, features_to_array, FEATURE_NAMES


def _request(method='GET', url='/', headers=None, body=''):
    return {
        'method': method,
        'url': url,
        'headers': headers or {},
        'body': body,
        'ip': '203.0.113.10',
    }


# ── SQL Injection ──────────────────────────────────────────────────────────

def test_sqli_tautology_detected():
    f = extract_features(_request(url="/login?user=admin&pass=' OR '1'='1"))
    assert f['sql_tautology'] == 1.0
    assert f['single_quotes'] > 0


def test_sqli_tautology_url_encoded_detected():
    f = extract_features(_request(url="/login?user=admin&pass=%27%20OR%20%271%27%3D%271"))
    assert f['sql_tautology'] == 1.0


def test_sqli_union_select_detected():
    f = extract_features(_request(
        url="/products?id=1 UNION SELECT username,password FROM users--"
    ))
    assert f['has_union'] == 1.0
    assert f['has_select'] == 1.0
    assert f['has_comment'] == 1.0
    assert f['sql_keyword_count'] >= 2


def test_sqli_drop_table_detected():
    f = extract_features(_request(
        method='POST', url='/comment', body="id=1'; DROP TABLE users;--"
    ))
    assert f['has_drop'] == 1.0
    assert f['semicolons'] > 0


# ── XSS ───────────────────────────────────────────────────────────────────

def test_xss_script_tag_detected():
    f = extract_features(_request(url="/search?q=<script>alert(1)</script>"))
    assert f['has_script_tag'] == 1.0
    assert f['xss_pattern_count'] >= 2
    assert f['angle_brackets'] >= 4


def test_xss_event_handler_detected():
    f = extract_features(_request(url="/search?q=<img src=x onerror=alert(1)>"))
    assert f['has_event_handler'] == 1.0


def test_xss_template_injection_detected():
    f = extract_features(_request(url="/search?q={{7*7}}"))
    assert f['has_template_injection'] == 1.0


# ── Path traversal ───────────────────────────────────────────────────────

def test_path_traversal_etc_passwd_detected():
    f = extract_features(_request(url="/download?file=../../../../etc/passwd"))
    assert f['has_dotdot'] == 1.0
    assert f['has_etc_passwd'] == 1.0
    assert f['path_traversal_count'] >= 1


def test_path_traversal_null_byte_detected():
    f = extract_features(_request(url="/download?file=../../etc/passwd%00.jpg"))
    assert f['has_null_byte'] == 1.0


# ── Command injection ──────────────────────────────────────────────────────

def test_cmd_injection_detected():
    f = extract_features(_request(url="/ping?host=localhost; cat /etc/passwd"))
    assert f['cmd_injection_count'] >= 1
    assert f['has_pipe'] == 0.0  # no pipe char in this payload


def test_cmd_injection_backtick_and_dollar_paren_detected():
    f = extract_features(_request(method='POST', url='/admin/exec', body="cmd=`id`&extra=$(whoami)"))
    assert f['has_backtick'] == 1.0
    assert f['has_dollar_paren'] == 1.0


# ── NoSQL injection ─────────────────────────────────────────────────────────

def test_nosql_where_operator_detected():
    f = extract_features(_request(
        method='POST', url='/login',
        headers={'Content-Type': 'application/json'},
        body='{"$where": "1==1"}',
    ))
    assert f['has_nosql_where'] == 1.0
    assert f['nosql_operator_count'] >= 1
    assert f['body_is_json'] == 1.0


def test_nosql_ne_operator_url_encoded_detected():
    f = extract_features(_request(
        method='POST', url='/login',
        body='username[$ne]=invalid&password[$ne]=invalid',
    ))
    assert f['has_nosql_ne'] == 1.0


# ── SSRF ─────────────────────────────────────────────────────────────────

def test_ssrf_aws_metadata_detected():
    f = extract_features(_request(url="/api/fetch?url=http://169.254.169.254/latest/meta-data/"))
    assert f['has_aws_metadata'] == 1.0
    assert f['ssrf_pattern_count'] >= 1


def test_ssrf_internal_ip_detected():
    f = extract_features(_request(url="/proxy?target=http://192.168.1.1/admin"))
    assert f['has_internal_ip'] == 1.0


def test_ssrf_file_protocol_detected():
    f = extract_features(_request(url="/api/fetch?url=file:///etc/passwd"))
    assert f['has_file_proto'] == 1.0


# ── XXE ──────────────────────────────────────────────────────────────────

def test_xxe_doctype_detected():
    payload = (
        '<?xml version="1.0"?><!DOCTYPE root '
        '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    )
    f = extract_features(_request(method='POST', url='/api/upload',
                                   headers={'Content-Type': 'application/xml'},
                                   body=payload))
    assert f['has_xml_doctype'] == 1.0
    assert f['has_xml_declaration'] == 1.0
    assert f['xxe_pattern_count'] >= 1


# ── JWT abuse ────────────────────────────────────────────────────────────

def test_jwt_alg_none_detected():
    # {"alg":"none","typ":"JWT"} base64url-encoded, no signature
    token = (
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'
        'eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.'
    )
    f = extract_features(_request(
        url='/rest/user/whoami',
        headers={'Authorization': f'Bearer {token}'},
    ))
    assert f['has_jwt'] == 1.0
    assert f['jwt_alg_none'] == 1.0
    assert f['jwt_no_signature'] == 1.0


def test_valid_looking_jwt_does_not_trigger_alg_none():
    token = (
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.'
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    )
    f = extract_features(_request(
        url='/api/users/me',
        headers={'Authorization': f'Bearer {token}'},
    ))
    assert f['has_jwt'] == 1.0
    assert f['jwt_alg_none'] == 0.0


# ── IDOR ─────────────────────────────────────────────────────────────────

def test_idor_path_pattern_detected():
    f = extract_features(_request(url="/api/users/2/orders"))
    assert f['has_idor_pattern'] == 1.0
    assert f['path_has_int_id'] == 1.0


# ── Normal traffic should not trip attack flags ────────────────────────────

def test_normal_get_request_is_clean():
    f = extract_features(_request(
        url='/tienda1/publico/productos.jsp?id=1&page=2',
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html',
            'Accept-Language': 'en-US',
        },
    ))
    assert f['sql_tautology'] == 0.0
    assert f['has_script_tag'] == 0.0
    assert f['has_dotdot'] == 0.0
    assert f['cmd_injection_count'] == 0
    assert f['suspicious_ua'] == 0.0


def test_normal_post_json_request_is_clean():
    f = extract_features(_request(
        method='POST', url='/rest/user/login',
        headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        body='{"email":"user@example.com","password":"hunter2"}',
    ))
    assert f['body_is_json'] == 1.0
    assert f['has_nosql_where'] == 0.0
    assert f['sql_keyword_count'] == 0


# ── Bot / scanner UA ────────────────────────────────────────────────────────

def test_suspicious_scanner_ua_detected():
    f = extract_features(_request(
        url='/admin', headers={'User-Agent': 'sqlmap/1.7.8#stable'},
    ))
    assert f['suspicious_ua'] == 1.0


# ── Feature vector shape / ordering ─────────────────────────────────────────

def test_features_to_array_matches_feature_names_order_and_length():
    f = extract_features(_request(url='/'))
    arr = features_to_array(f)
    assert len(arr) == len(FEATURE_NAMES) == 75
    for name, value in zip(FEATURE_NAMES, arr):
        assert value == pytest.approx(f[name])


def test_features_to_array_handles_missing_keys_with_default():
    arr = features_to_array({})
    assert len(arr) == len(FEATURE_NAMES)
    assert all(v == 0.0 for v in arr)
