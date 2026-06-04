# `nosql_injection.py` — NoSQL Injection Detection

## Overview

`nosql_injection.py` is **Stage 6** of the WAF pipeline. Traditional SQL injection protections (which look for `UNION SELECT`, `' OR 1=1`, etc.) are entirely blind to NoSQL injection attacks, which manipulate query logic using JSON structures and specific operators. This middleware specifically targets MongoDB, CouchDB, and Redis injection vulnerabilities.

---

## Detection Strategies

### 1. URL-Encoded Operators
Attackers often pass NoSQL operators via URL query parameters. The module detects patterns like `?username[$ne]=admin`:
```python
URL_OPERATOR_PATTERN = re.compile(r'\[(\$[a-zA-Z]+)\]', re.I)
```

### 2. JSON Body Analysis
The module safely attempts to parse the request body as JSON. If successful, it serializes it back to a string and searches for MongoDB operators (e.g., `{"$gt": ""}`). 
If parsing fails (malformed JSON) but operators are present, it still flags the request as highly suspicious.

### 3. JavaScript `$where` Injection
MongoDB's `$where` operator allows the execution of arbitrary JavaScript on the server. The module specifically looks for JS execution keywords (`function`, `sleep`, `while`, `this.`, `db.`) in proximity to a `$where` operator, blocking them with 97% confidence.

### 4. Redis Protocol Injection
Detects attempts to inject raw Redis Protocol (RESP) commands into the HTTP body, a technique often used in Server-Side Request Forgery (SSRF) chains to achieve Remote Code Execution (RCE) via Redis.
```python
REDIS_PROTOCOL_PATTERN = re.compile(r'\*\d+\r?\n\$\d+\r?\n', re.S)
```

---

## Output

The module returns the specific operators found and uses a sliding confidence scale depending on the context of the discovery (e.g., operators in parsed JSON yield higher confidence than a plaintext match).

```python
return {
    'block': True,
    'confidence': 0.95,
    'reason': 'NoSQL operator injection in URL params: [$ne]',
    'operators_found': ['$ne']
}
```

---

## Integration in the Pipeline

This module provides dedicated coverage for NoSQL vulnerabilities. It is positioned after generic IPS checks but before the ML models. While the ML models *also* learn to detect NoSQL injection (via the `nosql_operator_count` feature in `feature_extractor.py`), this middleware provides a hard block for blatant operator abuse, ensuring 100% catch rates for common payloads.

---

## open-appsec Equivalent

open-appsec handles NoSQL injection through its contextual parsing engine, which understands JSON and URL-encoded structures natively. This Python module replicates that capability by specifically targeting the syntax and structural patterns unique to NoSQL databases.
