# `ips_engine.py` — Intrusion Prevention System

## Overview

`ips_engine.py` is **Stage 4** of the WAF pipeline. It functions as a signature-based Intrusion Prevention System (IPS). While the ML models are designed to catch generalised and zero-day attacks, the IPS engine is designed to catch **specific, known, high-severity CVEs** with near 100% precision using compiled regular expressions.

---

## Supported Signatures (18 total)

| ID | CVE / Tag | Description | Severity | Target |
|---|---|---|---|---|
| 1 | CVE-2021-44228 | Log4Shell JNDI injection (`${jndi:ldap://...}`) | critical | any |
| 2 | CVE-2021-44228 | Log4Shell obfuscated variant (`${lower:j}${upper:n}di:`) | critical | any |
| 3 | CVE-2022-22965 | Spring4Shell `class.module.classLoader` manipulation | critical | any |
| 4 | CVE-2022-42889 | Text4Shell Apache Commons Text interpolation (`${script:}`, `${dns:}`, `${url:}`, `${base64decoder:}`, `${urlencode:}`) | critical | any |
| 5 | CVE-2014-6271 | Shellshock bash function definition in headers (`() { :; };`) | critical | headers |
| 6 | CVE-2021-41773 | Apache 2.4.49 path traversal (`..%2F`) | high | url |
| 7 | CVE-2017-5638 | Struts2 OGNL injection in Content-Type | critical | headers |
| 8 | CVE-2012-1823 | PHP CGI argument injection (`?-s`, `?-d`) | high | url |
| 9 | XXE-001 | XML External Entity injection (`<!DOCTYPE SYSTEM`, `<!ENTITY`) | high | body |
| 10 | SSRF-001 | SSRF to internal addresses (`localhost`, `127.*`, `192.168.*`, `10.*`) | high | url |
| 11 | SSRF-002 | SSRF to cloud metadata endpoint (`169.254.169.254`, `metadata.google.internal`) | critical | url |
| 12 | WEBSHELL-001 | PHP webshell eval pattern (`<?php eval(`, `system(`) | critical | body |
| 13 | WEBSHELL-002 | JSP webshell `Runtime.getRuntime().exec()` | critical | body |
| 14 | RCE-001 | OS command via semicolon injection (`; ls`, `; cat`, `; whoami`) | high | any |
| 15 | RCE-002 | Backtick command substitution (`` `id` ``, `` `whoami` ``) | high | any |
| 16 | PT-001 | Encoded path traversal (`%2e%2e`, `%252e`, `%c0%ae`) | medium | url |
| 17 | SCAN-001 | Automated vulnerability scanner UA (nikto, sqlmap, nessus, nuclei) | medium | headers |
| 18 | SPLIT-001 | HTTP response splitting via CRLF injection (`%0d%0a`) | high | url |

---

## Targeted Inspection

Each signature specifies a `target` field to focus scanning on the most relevant part of the request — avoiding unnecessary full-string searches:

```python
search_text = {
    'url':     url,
    'body':    body,
    'headers': headers_str,
    'any':     url + ' ' + body + ' ' + headers_str,
}.get(target, full)
```

Log4Shell and Text4Shell use `target='any'` because these injection strings can appear in any header, URL parameter, or body field.

---

## Severity & Scoring

```python
SEVERITY_SCORE = {'critical': 1.0, 'high': 0.85, 'medium': 0.65, 'low': 0.45}
```

When multiple signatures match:
- All matches are collected and returned in the result.
- **Block is triggered if any match has severity `critical` or `high`.**
- `confidence` is set to the maximum score across all matches.
- The top-severity match is used as the `reason` string.

`medium` signatures (path traversal encoding, scanner UA) do not block alone — they add context for the ML stages downstream.

---

## Return Value

```python
{
    'block': True,
    'reason': 'CVE-2021-44228: Log4Shell JNDI injection',
    'confidence': 1.0,
    'matches': [
        {'cve': 'CVE-2021-44228', 'description': '...', 'severity': 'critical', 'score': 1.0}
    ],
    'attack_type': 'ips_match',
}
```

Note: `attack_type` is set to `'ips_match'` here, but `waf_engine.py` overrides this with the result of `_infer_attack_type(features)` which uses the already-computed feature vector to produce a more specific label (`sqli`, `xss`, `cmd_injection`, etc.).

---

## Integration in the Pipeline

The IPS runs at Stage 4, before the ML engine (Stages 8–9). If an exact CVE signature matches, the pipeline short-circuits and no ML inference runs — saving CPU for ambiguous cases. This is the same architectural pattern used by open-appsec: cheap rule-based pre-filter before expensive ML scoring.

---

## open-appsec Equivalent

open-appsec includes an **IPS engine** with thousands of Snort-compatible signatures, automatically updated via threat intelligence feeds. This implementation covers ~18 hand-picked high-value CVEs and generic patterns. The "2,800 CVEs" figure in open-appsec marketing refers to Premium-tier signature coverage not available in the Community Edition — this project's IPS coverage is roughly equivalent to open-appsec Community tier.
