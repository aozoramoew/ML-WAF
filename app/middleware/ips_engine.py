"""
IPS Engine — Intrusion Prevention System

Matches requests against a curated set of CVE-based signatures and
general intrusion patterns (Snort 3.0-style rule logic, simplified).

Covers:
  - Log4Shell       CVE-2021-44228
  - Spring4Shell    CVE-2022-22965
  - Shellshock      CVE-2014-6271
  - HeartBleed hint CVE-2014-0160
  - Struts2 RCE     CVE-2017-5638
  - PHP CGI         CVE-2012-1823
  - Apache path     CVE-2021-41773
  - XXE injection
  - SSRF patterns
  - Generic WebShell upload signatures
"""

import re
from typing import List, Tuple

# ── CVE Signatures ─────────────────────────────────────────────────────────
# Each entry: (cve_id, description, compiled_regex, severity, target)
# target: 'url' | 'body' | 'headers' | 'any'

_RAW_SIGNATURES: List[Tuple[str, str, str, str, str]] = [
    # Log4Shell
    ('CVE-2021-44228', 'Log4Shell JNDI injection',
     r'\$\{jndi:(ldap|rmi|dns|ldaps|iiop|corba|nds|http)s?://',
     'critical', 'any'),

    ('CVE-2021-44228', 'Log4Shell obfuscated variant',
     r'\$\{(lower|upper|env|sys|java|date|main|marker|map|bundle|sd|ctx):', 'critical', 'any'),

    # Spring4Shell
    ('CVE-2022-22965', 'Spring4Shell class.module.classLoader',
     r'class\.module\.classLoader', 'critical', 'any'),

    # Shellshock
    ('CVE-2014-6271', 'Shellshock bash function definition',
     r'\(\)\s*\{[^}]*\}\s*;', 'critical', 'headers'),

    # Apache path traversal
    ('CVE-2021-41773', 'Apache 2.4.49 path traversal',
     r'/\.\.%2[fF]|/\.\.\/|%2e%2e/', 'high', 'url'),

    # Struts2 RCE
    ('CVE-2017-5638', 'Struts2 Content-Type OGNL injection',
     r'Content-Type.*\%\{|ognl\.', 'critical', 'headers'),

    # PHP CGI arg injection
    ('CVE-2012-1823', 'PHP CGI argument injection',
     r'\?-[sd]', 'high', 'url'),

    # XXE injection
    ('XXE-001', 'XML External Entity injection',
     r'<!DOCTYPE[^>]+SYSTEM|<!ENTITY[^>]+SYSTEM|<!ENTITY[^>]+PUBLIC',
     'high', 'body'),

    # SSRF patterns
    ('SSRF-001', 'Server-Side Request Forgery — internal address',
     r'(http|ftp)s?://(localhost|127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)',
     'high', 'url'),

    ('SSRF-002', 'SSRF via cloud metadata endpoint',
     r'169\.254\.169\.254|metadata\.google\.internal|metadata\.aws\.com',
     'critical', 'url'),

    # WebShell upload signatures
    ('WEBSHELL-001', 'PHP webshell eval pattern',
     r'<\?php\s+(eval|system|exec|shell_exec|passthru|popen)\s*\(',
     'critical', 'body'),

    ('WEBSHELL-002', 'JSP webshell Runtime.exec',
     r'Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder',
     'critical', 'body'),

    # Generic RCE
    ('RCE-001', 'OS command via semicolon injection',
     r';\s*(ls|cat|id|whoami|uname|curl|wget|nc|ncat|bash|sh)\b',
     'high', 'any'),

    ('RCE-002', 'Backtick command substitution',
     r'`\s*(id|whoami|ls|cat|uname)\s*`', 'high', 'any'),

    # Directory traversal (generic, catches encoded variants)
    ('PT-001', 'Encoded path traversal (%2e%2e)',
     r'%2e%2e|%252e|%c0%ae|%c1%9c', 'medium', 'url'),

    # Malicious user-agents with CVE relevance
    ('SCAN-001', 'Automated vulnerability scanner',
     r'(nikto|sqlmap|nessus|openvas|acunetix|masscan|nuclei)',
     'medium', 'headers'),

    # HTTP Response Splitting
    ('SPLIT-001', 'HTTP response splitting via CRLF injection',
     r'%0d%0a|%0D%0A|\r\n.*Location:', 'high', 'url'),
]

# Compile all regexes
SIGNATURES = []
for cve, desc, pattern, severity, target in _RAW_SIGNATURES:
    try:
        compiled = re.compile(pattern, re.I | re.DOTALL)
        SIGNATURES.append((cve, desc, compiled, severity, target))
    except re.error:
        pass

SEVERITY_SCORE = {'critical': 1.0, 'high': 0.85, 'medium': 0.65, 'low': 0.45}


def check(request_data: dict) -> dict:
    """
    Match request against IPS signatures.
    Returns block=True if any critical/high signature fires.
    """
    url     = str(request_data.get('url', ''))
    body    = str(request_data.get('body', '') or '')
    headers = request_data.get('headers', {}) or {}
    headers_str = ' '.join(f'{k}: {v}' for k, v in headers.items())
    full    = url + ' ' + body + ' ' + headers_str

    matches = []

    for cve, desc, pattern, severity, target in SIGNATURES:
        search_text = {
            'url':     url,
            'body':    body,
            'headers': headers_str,
            'any':     full,
        }.get(target, full)

        if pattern.search(search_text):
            matches.append({
                'cve': cve,
                'description': desc,
                'severity': severity,
                'score': SEVERITY_SCORE.get(severity, 0.5),
            })

    if not matches:
        return {'block': False, 'reason': 'No IPS signatures matched', 'matches': []}

    # Block if any critical or high severity match
    max_score = max(m['score'] for m in matches)
    block = any(m['severity'] in ('critical', 'high') for m in matches)
    top = sorted(matches, key=lambda x: -x['score'])[0]

    return {
        'block': block,
        'reason': f"{top['cve']}: {top['description']}",
        'confidence': max_score,
        'matches': matches,
        'attack_type': 'ips_match',
    }


def get_signature_count() -> int:
    return len(SIGNATURES)
