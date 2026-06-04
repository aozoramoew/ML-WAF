# `ips_engine.py` — Intrusion Prevention System

## Overview

`ips_engine.py` is **Stage 4** of the WAF pipeline. It functions as a signature-based Intrusion Prevention System (IPS). While the ML models are designed to catch generalized and zero-day attacks, the IPS engine is designed to catch **specific, known, high-severity CVEs** with near 100% precision.

---

## Supported Signatures

The module uses a compiled list of regular expressions targeting specific vulnerabilities:

- **Log4Shell (CVE-2021-44228)**: Detects JNDI injection patterns (`${jndi:ldap://...}`) and common obfuscation techniques (`${lower:j}${upper:n}di:...`).
- **Spring4Shell (CVE-2022-22965)**: Detects classloader manipulation (`class.module.classLoader`).
- **Shellshock (CVE-2014-6271)**: Detects malicious bash function definitions in headers (`() { :; };`).
- **Apache Path Traversal (CVE-2021-41773)**: Detects specific encoded traversal payloads targeting Apache 2.4.49.
- **Struts2 RCE (CVE-2017-5638)**: Detects OGNL injection in the `Content-Type` header.
- **XXE Injection**: Detects `<!DOCTYPE SYSTEM>` and external entity references.
- **SSRF**: Detects requests attempting to access local networks (`127.0.0.1`, `192.168.x.x`) or cloud metadata services (`169.254.169.254`).
- **Webshells**: Detects common PHP and JSP webshell execution patterns (`eval(`, `Runtime.getRuntime().exec(`).
- **Generic RCE**: Detects OS command injection via semicolons (`; ls`) or backticks (`` `id` ``).

---

## Targeted Inspection

To maximize performance, signatures are mapped to specific parts of the HTTP request (`target`):

- `url`: Only regex-searches the URL string.
- `body`: Only searches the payload body.
- `headers`: Only searches the concatenated header strings.
- `any`: Searches a concatenated string of the URL, body, and headers (used for sweeping exploits like Log4Shell that can be injected anywhere).

```python
search_text = {
    'url':     url,
    'body':    body,
    'headers': headers_str,
    'any':     full,
}.get(target, full)
```

---

## Severity & Scoring

Each signature has an associated severity level (`critical`, `high`, `medium`, `low`). 

If multiple signatures match, the module returns all matches but uses the highest severity to determine the final action. **Any match of `high` or `critical` severity results in an immediate block.**

---

## Integration in the Pipeline

The IPS runs before the ML engine. If an exact CVE signature matches, there is no need to spend CPU cycles running the Random Forest or Isolation Forest models. The IPS provides a fast, definitive block for known threats.

---

## open-appsec Equivalent

open-appsec includes an **IPS engine** featuring thousands of Snort-compatible signatures, automatically updated via threat intelligence feeds. It uses this signature engine as a pre-filter before its ML model, serving the exact same architectural purpose as this module: quickly eliminating known bad traffic so the ML model can focus on the ambiguous cases.
