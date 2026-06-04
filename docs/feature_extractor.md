# `feature_extractor.py` — HTTP Request Feature Engineering

## Overview

`feature_extractor.py` solves the fundamental problem in ML-based security: **how do you turn a raw HTTP request into numbers that a classifier can reason about?**

It takes a request dictionary (method, URL, headers, body, IP) and returns a fixed-length **75-dimensional numerical feature vector**. This vector is what the Random Forest actually operates on.

---

## Why Feature Engineering Matters

A neural network could theoretically operate on raw bytes. But for a WAF use case, **hand-engineered features dramatically outperform raw representations** because:

1. **Attack patterns are known** — we know SQLi uses `UNION SELECT`, XSS uses `<script>`, etc.
2. **Generalisation** — a feature like `sql_keyword_count` catches both `UNION SELECT` and `union select` and `%55nion %53elect` (URL-encoded).
3. **Efficiency** — 75 floats are computed in microseconds; raw-byte deep learning requires GPUs.
4. **Explainability** — each feature has a human-readable name, enabling the "why was this blocked?" dashboard explanation.

This philosophy exactly matches open-appsec's approach: they use a rich, manually-designed feature vocabulary that encodes web-security domain knowledge.

---

## Feature Categories

### 1. Structural Features (8 features)

Basic request anatomy. These alone can catch anomalies like abnormally long URLs or overly large bodies.

| Feature | Description |
|---|---|
| `url_length` | Total character length of the URL |
| `url_param_count` | Number of `?key=value` pairs |
| `body_length` | Byte length of request body |
| `header_count` | Number of HTTP headers |
| `path_depth` | Count of `/` segments in URL path |
| `has_body` | 1 if body is non-empty |
| `content_type_is_json` | 1 if Content-Type is application/json |
| `content_type_is_xml` | 1 if Content-Type is text/xml |

### 2. Entropy Features (3 features)

Shannon entropy measures the **randomness/compressibility** of a string. Encoded or obfuscated payloads have high entropy; normal English text has low entropy. This catches base64-encoded payloads, encrypted shellcode, and heavily obfuscated XSS.

```
H(X) = -Σ p(x) log₂ p(x)
```

| Feature | Description |
|---|---|
| `url_entropy` | Shannon entropy of the full URL string |
| `body_entropy` | Shannon entropy of the request body |
| `param_value_max_entropy` | Max entropy across all URL parameter values |

### 3. Attack Pattern Count Features (40+ features)

For each attack category, we count the number of matches against a curated pattern library. The count (not just presence) captures severity — a URL with 5 SQL keywords is far more suspicious than one with 1.

**SQL Injection** (features: `sql_keyword_count`, `union_detected`, `comment_pattern`, `blind_sqli_pattern`):
```python
SQL_KEYWORDS = ['select', 'union', 'insert', 'update', 'drop', 'exec', ...]
```

**XSS** (features: `xss_pattern_count`, `script_tag_count`, `event_handler_count`):
```python
XSS_PATTERNS = ['<script', 'javascript:', 'onerror=', 'alert(', ...]
```

**Path Traversal** (features: `path_traversal_count`, `absolute_path_detected`):
```python
PATH_TRAVERSAL_PATTERNS = ['../', '..\\', '.%2e', '%c0%ae', ...]
```

**Command Injection** (features: `cmd_injection_count`):
```python
CMD_INJECTION_PATTERNS = ['; ls', '| cat', '$(id)', '/bin/bash', ...]
```

**NoSQL Injection** (features: `nosql_operator_count`):
```python
NOSQL_PATTERNS = ['$where', '$ne', '$gt', '$regex', '[$ne]', ...]
```

**SSRF** (features: `ssrf_pattern_count`):
Detects cloud metadata URLs (169.254.169.254), private IP ranges, and non-HTTP schemes (file://, gopher://).

**XXE** (features: `xxe_pattern_count`):
Detects `<!DOCTYPE`, `<!ENTITY SYSTEM`, and external entity references in XML bodies.

**IDOR** (features: `idor_pattern_count`):
Detects sequential integer IDs, UUIDs, and object reference manipulation patterns in URLs.

### 4. Encoding Features (4 features)

Attackers frequently encode payloads to bypass signature-based WAFs.

| Feature | Description |
|---|---|
| `url_encoded_ratio` | Fraction of characters that are `%xx` sequences |
| `double_encoded` | 1 if `%25` (double-percent encoding) found |
| `base64_in_params` | 1 if any parameter value appears to be base64 |
| `hex_encoded_chars` | Count of `\xNN` hex sequences |

### 5. Behavioral/Metadata Features (8 features)

| Feature | Description |
|---|---|
| `is_bot_ua` | 1 if User-Agent matches known scanner (sqlmap, nikto, dirbuster…) |
| `missing_host_header` | 1 if Host header absent (abnormal for real browsers) |
| `has_xforwardedfor` | 1 if X-Forwarded-For header present |
| `method_is_unusual` | 1 for TRACE, CONNECT, OPTIONS (rarely legitimate) |
| `has_suspicious_headers` | 1 if JNDI patterns in any header (Log4Shell) |
| `param_pollution` | 1 if same parameter key appears multiple times |
| `is_private_ip` | 1 if source IP is in RFC1918 range |
| `body_has_script` | 1 if body contains HTML script tags |

---

## Data Flow

```
raw_request (dict)
    │
    ▼
extract_features(request) → feature_dict (named floats)
    │
    ▼
features_to_array(feature_dict) → numpy array [75 floats]
    │
    ▼
Random Forest model → probability score (0.0–1.0)
```

The `FEATURE_NAMES` constant exports the ordered list of feature names, which is also stored in `models/metrics.json` to enable feature importance display in the dashboard.

---

## Relationship to Other Files

| File | Relationship |
|---|---|
| `ml/train.py` | Calls `extract_features()` + `features_to_array()` for every training sample |
| `app/waf_engine.py` | Calls `extract_features()` + `features_to_array()` at Stage 8 for every live request |
| `ml/dataset_generator.py` | Provides the training requests that `train.py` feeds to this module |
| `static/index.html` | Displays `ev.features` dict (returned from `waf_engine.analyze`) in the detail modal |

---

## open-appsec Equivalent

open-appsec uses a proprietary feature vocabulary of 100+ features, kept confidential. Based on their published papers and the nginx-attachment repo, the feature categories are very similar to this implementation: structural, entropy, pattern-count, and behavioral. The main difference is that open-appsec computes features in C++ for microsecond latency, while this Python implementation takes ~1–5ms per request.
