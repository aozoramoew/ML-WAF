"""ML-WAF Feature Extractor — converts raw HTTP request dicts into ML feature vectors.

Extended to cover all attack types:
  - SQL Injection (classic, blind, union, time-based)
  - XSS (reflected, stored, DOM, obfuscated)
  - Path Traversal (unix, windows, encoded)
  - Command Injection
  - NoSQL Injection (MongoDB operators, JS injection)
  - JWT Abuse (alg:none, tampered claims)
  - IDOR (object reference manipulation patterns)
  - SSRF (internal network probing)
  - XXE (XML external entity)
  - HTTP Parameter Pollution
"""

import re
import math
import json
import base64
import numpy as np
from typing import Dict, Any
from urllib.parse import unquote_plus

# ── Attack pattern libraries ──────────────────────────────────────────────────

SQL_KEYWORDS = [
    'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
    'exec', 'execute', 'xp_', 'sp_', 'information_schema', 'sys.',
    'sysobjects', 'syscolumns', 'waitfor', 'delay', 'benchmark',
    'sleep(', 'load_file', 'outfile', 'dumpfile', 'char(',
    'ascii(', 'substring(', 'concat(', 'group_concat', 'having',
    'order by', 'group by', '1=1', "or 1", "and 1",
    'sqlite_master', 'attach database', 'extractvalue', 'updatexml',
]

XSS_PATTERNS = [
    '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
    'onclick=', 'onmouseover=', 'onfocus=', 'onblur=', 'alert(',
    'prompt(', 'confirm(', 'document.cookie', 'document.write',
    'window.location', 'eval(', '<img', '<iframe', '<object',
    '<embed', '<svg', 'vbscript:', 'expression(', 'fromcharcode',
    'innerhtml', 'src=x', '<marquee', 'onstart=', 'ontoggle=',
    'constructor.constructor', '{{', '${', '#{',  # template injection
]

PATH_TRAVERSAL_PATTERNS = [
    '../', '..\\', '.%2e', '%2e.', '%2f..', '..%5c', '%252e',
    '%c0%ae', '..../', '\\./', '/etc/passwd', '/etc/shadow',
    'windows/system32', 'c:\\windows', 'boot.ini', 'win.ini',
    '/proc/self', 'php.ini',
]

CMD_INJECTION_PATTERNS = [
    '; ls', '; cat', '| ls', '| cat', '&& ls', '&& cat',
    '`ls`', '`id`', '$(id)', '$(ls)', '; id', '| id',
    '; whoami', 'nc -', 'wget http', 'curl http',
    '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell',
    '; uname', 'ping -c', '| nc', '/tmp/shell',
]

NOSQL_PATTERNS = [
    '$where', '$gt', '$lt', '$ne', '$eq', '$in', '$nin',
    '$regex', '$exists', '$or', '$and', '$not',
    '$elemMatch', '$all', '$size', '$type',
    'mapreduce', 'findandmodify', '_id', 'objectid(',
    '[$ne]', '[$gt]', '[$regex]', '[$where]',  # URL-encoded operator injection
]

SSRF_PATTERNS = [
    '169.254.169.254',  # AWS/GCP/Azure metadata
    'metadata.google.internal',
    '100.100.100.200',  # Alibaba metadata
    '192.168.', '10.0.', '172.16.', '172.17.',  # private networks
    '127.0.0.1', 'localhost', '0.0.0.0',
    'file://', 'dict://', 'gopher://', 'ldap://', 'ftp://',
    '0x7f', '2130706433',  # hex/decimal for 127.0.0.1
]

XXE_PATTERNS = [
    '<!doctype', '<!entity', 'system "', "system '",
    '<?xml', '<!element', 'cdata[', '%xxe', '&xxe;',
    'file:///', '&file;', '&xxe;', 'lolz', 'billion laughs',
]

JWT_PATTERNS = [
    'eyjaigcialginojub',  # common jwt prefixes (base64)
    'eyj',  # all JWTs start with eyJ
    '"alg":"none"', '"alg": "none"',
    'alg=none', 'alg%3Anone',
]

BOT_UA_PATTERNS = [
    'bot', 'crawler', 'spider', 'scraper', 'curl/', 'wget/',
    'python-requests', 'python-httplib', 'java/', 'ruby/',
    'go-http-client', 'libwww', 'perl', 'nikto', 'nmap',
    'sqlmap', 'burpsuite', 'masscan', 'dirbuster', 'hydra',
    'metasploit', 'havij', 'acunetix', 'nessus', 'openvas',
    'zgrab', 'nuclei', 'ffuf', 'gobuster', 'wfuzz', 'owasp',
]

IDOR_PATHS = re.compile(
    r'/(users?|accounts?|orders?|baskets?|payments?|addresses|profiles?|memories|deliverys?)'
    r'/(\d+|[0-9a-f-]{36})',
    re.I
)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    total = len(text)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


def _special_chars(text: str) -> int:
    special = set("'\";<>()[]{}|&`$\\/%+#@!~^*")
    return sum(1 for c in text if c in special)


def _looks_like_jwt(value: str) -> bool:
    """Check if a string looks like a JWT (3 base64url parts)."""
    parts = value.split('.')
    if len(parts) != 3:
        return False
    try:
        # Decode header
        header_b64 = parts[0] + '=='
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        return 'alg' in header
    except Exception:
        return len(parts[0]) > 20 and len(parts[1]) > 20


def _jwt_alg_none(value: str) -> bool:
    """Check if JWT uses alg:none."""
    parts = value.split('.')
    if len(parts) < 2:
        return False
    try:
        header_b64 = parts[0] + '=='
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        return str(header.get('alg', '')).lower() in ('none', 'null', '')
    except Exception:
        return False


def extract_features(request_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract 75 ML-ready features from an HTTP request dictionary.

    Expected keys: method, url, headers (dict), body, ip
    """
    url = str(request_data.get('url', ''))
    method = str(request_data.get('method', 'GET')).upper()
    raw_headers = request_data.get('headers', {}) or {}
    headers = {k.lower(): str(v) for k, v in raw_headers.items()}
    body = str(request_data.get('body', '') or '')
    ip = str(request_data.get('ip', ''))

    path = url.split('?', 1)[0]
    query = url.split('?', 1)[1] if '?' in url else ''

    # Decode percent-encoding for pattern matching so that e.g. %27 OR %271%27=%271
    # is recognized the same as ' OR '1'='1. Structural features (url_length,
    # pct_encoded, etc.) still use the raw url/path/query above.
    decoded_url = unquote_plus(url)
    decoded_body = unquote_plus(body)
    full = (decoded_url + ' ' + decoded_body).lower()
    full_with_headers = (full + ' ' + str(headers)).lower()

    f: Dict[str, float] = {}

    # ── URL structural features ──────────────────────────────────────
    f['url_length'] = min(len(url), 4000)
    f['path_length'] = len(path)
    f['query_length'] = len(query)
    f['url_depth'] = path.count('/')
    f['num_params'] = query.count('&') + 1 if query else 0
    f['pct_encoded'] = url.count('%')
    f['double_encoded'] = url.count('%25')

    # ── Special character features ───────────────────────────────────
    f['special_chars_url'] = _special_chars(url)
    f['special_chars_body'] = _special_chars(body)
    f['single_quotes'] = full.count("'")
    f['double_quotes'] = full.count('"')
    f['semicolons'] = full.count(';')
    f['comment_markers'] = full.count('--') + full.count('/*') + full.count('#')
    f['angle_brackets'] = full.count('<') + full.count('>')

    # ── SQL Injection features ───────────────────────────────────────
    f['sql_keyword_count'] = sum(1 for kw in SQL_KEYWORDS if kw in full)
    f['has_union'] = float('union' in full)
    f['has_select'] = float('select' in full)
    f['has_drop'] = float('drop' in full)
    f['sql_tautology'] = float(bool(re.search(r"'?\s*(or|and)\s+'?1'?\s*=\s*'?1", full, re.I)))
    f['has_comment'] = float('--' in full or '/*' in full)
    f['has_hex_encode'] = float(bool(re.search(r'0x[0-9a-f]{2,}', full, re.I)))

    # ── XSS features ────────────────────────────────────────────────
    f['xss_pattern_count'] = sum(1 for p in XSS_PATTERNS if p.lower() in full)
    f['has_script_tag'] = float('<script' in full)
    f['has_event_handler'] = float(bool(re.search(r'on\w+\s*=', full, re.I)))
    f['has_javascript_uri'] = float('javascript:' in full)
    f['has_html_entity'] = float('&lt;' in full or '&gt;' in full or '&#' in full)
    f['has_template_injection'] = float('{{' in full or '${' in full or '#{' in full)

    # ── Path Traversal features ──────────────────────────────────────
    f['path_traversal_count'] = sum(1 for p in PATH_TRAVERSAL_PATTERNS if p.lower() in full)
    f['has_dotdot'] = float('../' in full or '..' in path)
    f['has_etc_passwd'] = float('/etc/passwd' in full or 'etc%2fpasswd' in full)
    f['has_null_byte'] = float('%00' in full or '\x00' in full)

    # ── Command Injection features ───────────────────────────────────
    f['cmd_injection_count'] = sum(1 for p in CMD_INJECTION_PATTERNS if p.lower() in full)
    f['has_pipe'] = float('|' in full)
    f['has_backtick'] = float('`' in full)
    f['has_dollar_paren'] = float('$(' in full)

    # ── NoSQL Injection features ─────────────────────────────────────
    f['nosql_operator_count'] = sum(1 for p in NOSQL_PATTERNS if p in full)
    f['has_nosql_where'] = float('$where' in full)
    f['has_nosql_ne'] = float('$ne' in full or '[$ne]' in full)
    f['has_nosql_regex'] = float('$regex' in full or '[$regex]' in full)

    # ── SSRF features ────────────────────────────────────────────────
    f['ssrf_pattern_count'] = sum(1 for p in SSRF_PATTERNS if p in full)
    f['has_internal_ip'] = float(bool(re.search(
        r'(127\.0\.0\.1|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)', full
    )))
    f['has_aws_metadata'] = float('169.254.169.254' in full)
    f['has_file_proto'] = float('file://' in full)
    f['has_non_http_proto'] = float(bool(re.search(r'(dict|gopher|ldap|ftp|sftp)://', full)))

    # ── XXE features ─────────────────────────────────────────────────
    f['xxe_pattern_count'] = sum(1 for p in XXE_PATTERNS if p in full)
    f['has_xml_doctype'] = float('<!doctype' in full or '<!entity' in full)
    f['has_xml_declaration'] = float('<?xml' in full)

    # ── JWT Abuse features ───────────────────────────────────────────
    auth_header = headers.get('authorization', '')
    bearer_token = auth_header.replace('Bearer ', '').replace('bearer ', '').strip()
    f['has_jwt'] = float(_looks_like_jwt(bearer_token))
    f['jwt_alg_none'] = float(_jwt_alg_none(bearer_token) if bearer_token else False)
    f['jwt_no_signature'] = float(
        bearer_token.endswith('.') if bearer_token else False
    )

    # ── IDOR features ────────────────────────────────────────────────
    f['has_idor_pattern'] = float(bool(IDOR_PATHS.search(path)))
    f['path_has_int_id'] = float(bool(re.search(r'/\d+', path)))

    # ── HTTP Method features ─────────────────────────────────────────
    method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3,
                  'OPTIONS': 4, 'HEAD': 5, 'PATCH': 6, 'TRACE': 7}
    f['method_encoded'] = float(method_map.get(method, 8))
    f['is_post'] = float(method == 'POST')
    f['is_delete'] = float(method == 'DELETE')
    f['is_trace'] = float(method == 'TRACE')

    # ── Body features ────────────────────────────────────────────────
    f['body_length'] = min(len(body), 50000)
    f['body_entropy'] = _entropy(body[:500])
    f['body_has_base64'] = float(bool(re.search(r'[A-Za-z0-9+/]{20,}={0,2}', body)))
    f['body_has_xml'] = float('<?xml' in body.lower() or '<root>' in body.lower())
    f['body_is_json'] = float(body.strip().startswith('{') or body.strip().startswith('['))
    f['body_has_json_operators'] = float(bool(re.search(r'\$\w+', body)))

    # ── Header features ──────────────────────────────────────────────
    ua = headers.get('user-agent', '')
    f['ua_length'] = len(ua)
    f['suspicious_ua'] = float(any(b in ua.lower() for b in BOT_UA_PATTERNS))
    f['has_referer'] = float('referer' in headers)
    f['has_cookie'] = float('cookie' in headers)
    f['has_auth_header'] = float('authorization' in headers)
    f['has_content_type'] = float('content-type' in headers)
    f['num_headers'] = float(len(headers))

    # ── Entropy features ─────────────────────────────────────────────
    f['query_entropy'] = _entropy(query[:300])
    f['url_entropy'] = _entropy(url[:300])
    f['body_token_entropy'] = _entropy(re.sub(r'\s+', '', body)[:300])

    # ── Parameter pollution features ─────────────────────────────────
    param_names = re.findall(r'([^&=?]+)=', query)
    f['duplicate_params'] = float(len(param_names) != len(set(param_names)))
    f['num_query_params'] = float(len(param_names))
    f['max_param_value_length'] = float(max(
        (len(v) for v in re.findall(r'=[^&]*', query)),
        default=0
    ))

    return f


# Ordered list of feature names — must remain stable for model compatibility
FEATURE_NAMES: list = list(extract_features(
    {'method': 'GET', 'url': '/', 'headers': {}, 'body': ''}
).keys())


def features_to_array(features: Dict[str, float]) -> np.ndarray:
    """Convert a feature dict → numpy float32 array in canonical order."""
    return np.array([features.get(n, 0.0) for n in FEATURE_NAMES], dtype=np.float32)
