# `jwt_abuse.py` — JWT Abuse Detection

## Overview

`jwt_abuse.py` is **Stage 7** of the WAF pipeline. JSON Web Tokens (JWTs) are the standard for stateless authentication, but they introduce unique attack vectors. This module extracts JWTs from HTTP requests (headers or cookies) and inspects them for common vulnerabilities, cryptographic attacks, and payload manipulation.

---

## Detection Capabilities

### 1. `alg:none` Attack
The classic JWT vulnerability. An attacker changes the header algorithm to `none`, removes the signature, and manipulates the payload. The module blocks this with 99% confidence.
```python
KNOWN_WEAK_ALGS = {'none', 'null', '', 'hs256 with rsa key'}
```

### 2. Missing Signatures
Tokens that contain the standard three parts (header, payload, signature) but leave the signature segment empty are blocked immediately.

### 3. Expired Token Replay
The module parses the `exp` (expiration) claim. While the upstream application should validate expiration, the WAF proactively blocks tokens that are egregiously expired (e.g., > 1 day in the past), mitigating replay attacks of stolen, ancient tokens.

### 4. Injection in Claims
Attackers often place SQLi or XSS payloads inside JWT claims (e.g., setting their username to `<script>alert(1)</script>`), knowing that backend systems often blindly trust the contents of a validated JWT. The WAF inspects the decoded JSON payload against SQLi and XSS regex patterns.

### 5. Privilege Escalation & Tampering
If a token claims a highly privileged role (`admin`, `root`, `superuser`) *and* contains known markers of a tampered signature (used in the simulation datasets), it is blocked. (In a real-world scenario, the WAF cannot verify the HMAC signature without the secret key, so it relies on structural anomalies and ML features).

### 6. Algorithm Confusion (RS256 → HS256)
Detects situations where an attacker might be attempting to force the server to evaluate an asymmetric public key using a symmetric algorithm. It does this by checking if the algorithm is `HS256` but the signature length is abnormally long (>200 chars, typical of an RSA key).

---

## Token Extraction

The module is designed to find JWTs wherever they commonly live:
1. The `Authorization: Bearer <token>` header.
2. The `Cookie` header (scanning all key-value pairs for strings containing two periods (`.`) that are long enough to be JWTs).

---

## Integration in the Pipeline

This module runs just before the ML engines. The features extracted here (like algorithm tampering or SQLi in claims) complement the ML engine's analysis.

---

## open-appsec Equivalent

open-appsec's engine natively decodes base64 and JSON, allowing its standard rules and ML models to automatically inspect the contents of JWTs. This Python module explicitly extracts and decodes the JWTs to perform targeted checks, replicating the deep-inspection capabilities of the open-appsec parser.
