# `feature_extractor.py` — HTTP Request Feature Engineering

## Overview

`feature_extractor.py` converts a raw HTTP request dictionary into a **fixed-length 75-dimensional float32 feature vector** that the Random Forest (or Gradient Boosting) classifier operates on.

The core function is `extract_features(request_data)` which returns a named dict of floats. `features_to_array(feature_dict)` then converts it to a numpy array in the stable canonical order defined by `FEATURE_NAMES`.

---

## Why Feature Engineering Matters

A neural network could theoretically operate on raw bytes. But for a WAF use case, **hand-engineered features dramatically outperform raw representations** because:

1. **Attack patterns are known** — SQLi uses `UNION SELECT`, XSS uses `<script>`, etc.
2. **Generalisation across encoding** — `sql_keyword_count` catches both `UNION SELECT` and `%55nion%20%53elect` (URL-encoded), because the extractor URL-decodes the input before pattern matching.
3. **Efficiency** — 75 floats are computed in microseconds; raw-byte deep learning requires GPUs.
4. **Explainability** — each feature has a human-readable name, enabling the "Why was this blocked?" detail modal in the dashboard.

---

## URL Decoding Before Pattern Matching

A key design decision: the extractor URL-decodes (`unquote_plus`) the URL and body into a `full` string used for **all pattern matching**, while **structural features** (`url_length`, `pct_encoded`, `double_encoded`, etc.) still use the raw strings.

This means `%27 OR %271%27=%271` is correctly recognised as a SQL tautology, while the raw encoding level is still captured in structural features.

---

## Feature Groups (75 total)

### 1. URL Structural Features (7)

| Feature | Description |
|---|---|
| `url_length` | Raw URL character length (capped at 4000) |
| `path_length` | Length of the URL path (before `?`) |
| `query_length` | Length of the query string (after `?`) |
| `url_depth` | Count of `/` in the URL path |
| `num_params` | Number of `&`-delimited parameters in query |
| `pct_encoded` | Count of `%` characters in raw URL |
| `double_encoded` | Count of `%25` (double percent-encoding) in raw URL |

### 2. Special Character Features (7)

Counted on the **decoded** `full` string (URL + body):

| Feature | Description |
|---|---|
| `special_chars_url` | Count of `'";:<>()[]{}|&` `` ` `` `$\/%+#@!~^*` in raw URL |
| `special_chars_body` | Same set counted in raw body |
| `single_quotes` | Count of `'` in decoded full string |
| `double_quotes` | Count of `"` in decoded full string |
| `semicolons` | Count of `;` in decoded full string |
| `comment_markers` | Combined count of `--`, `/*`, `#` |
| `angle_brackets` | Combined count of `<` and `>` |

### 3. SQL Injection Features (7)

| Feature | Description |
|---|---|
| `sql_keyword_count` | Count of SQL keywords matched (`select`, `union`, `drop`, `sleep(`, etc.) |
| `has_union` | 1 if `union` present |
| `has_select` | 1 if `select` present |
| `has_drop` | 1 if `drop` present |
| `sql_tautology` | 1 if pattern `'? OR/AND '?1'?='?1` matched |
| `has_comment` | 1 if `--` or `/*` present |
| `has_hex_encode` | 1 if `0x[0-9a-f]{2,}` pattern matched |

SQL keywords list includes: `select`, `union`, `insert`, `update`, `delete`, `drop`, `create`, `exec`, `execute`, `xp_`, `sp_`, `information_schema`, `sys.`, `sysobjects`, `syscolumns`, `waitfor`, `delay`, `benchmark`, `sleep(`, `load_file`, `outfile`, `dumpfile`, `char(`, `ascii(`, `substring(`, `concat(`, `group_concat`, `having`, `order by`, `group by`, `1=1`, `or 1`, `and 1`, `sqlite_master`, `attach database`, `extractvalue`, `updatexml`.

### 4. XSS Features (6)

| Feature | Description |
|---|---|
| `xss_pattern_count` | Count of XSS patterns matched (see list below) |
| `has_script_tag` | 1 if `<script` present |
| `has_event_handler` | 1 if `on\w+=` regex matched (e.g. `onerror=`) |
| `has_javascript_uri` | 1 if `javascript:` present |
| `has_html_entity` | 1 if `&lt;`, `&gt;`, or `&#` present |
| `has_template_injection` | 1 if `{{`, `${`, or `#{` present |

XSS patterns include: `<script`, `</script>`, `javascript:`, `onerror=`, `onload=`, `onclick=`, `onmouseover=`, `onfocus=`, `onblur=`, `alert(`, `prompt(`, `confirm(`, `document.cookie`, `document.write`, `window.location`, `eval(`, `<img`, `<iframe`, `<object`, `<embed`, `<svg`, `vbscript:`, `expression(`, `fromcharcode`, `innerhtml`, `src=x`, `<marquee`, `onstart=`, `ontoggle=`, `constructor.constructor`, `{{`, `${`, `#{`.

### 5. Path Traversal Features (4)

| Feature | Description |
|---|---|
| `path_traversal_count` | Count of path traversal patterns matched |
| `has_dotdot` | 1 if `../` in decoded string or `..` in raw path |
| `has_etc_passwd` | 1 if `/etc/passwd` or `etc%2fpasswd` present |
| `has_null_byte` | 1 if `%00` or null byte `\x00` present |

Patterns: `../`, `..\`, `.%2e`, `%2e.`, `%2f..`, `..%5c`, `%252e`, `%c0%ae`, `..../`, `\./)`, `/etc/passwd`, `/etc/shadow`, `windows/system32`, `c:\windows`, `boot.ini`, `win.ini`, `/proc/self`, `php.ini`.

### 6. Command Injection Features (4)

| Feature | Description |
|---|---|
| `cmd_injection_count` | Count of command injection patterns matched |
| `has_pipe` | 1 if `|` in decoded string |
| `has_backtick` | 1 if `` ` `` in decoded string |
| `has_dollar_paren` | 1 if `$(` in decoded string |

Patterns: `; ls`, `; cat`, `| ls`, `| cat`, `&& ls`, `&& cat`, `` `ls` ``, `` `id` ``, `$(id)`, `$(ls)`, `; id`, `| id`, `; whoami`, `nc -`, `wget http`, `curl http`, `/bin/sh`, `/bin/bash`, `cmd.exe`, `powershell`, `; uname`, `ping -c`, `| nc`, `/tmp/shell`.

### 7. NoSQL Injection Features (4)

| Feature | Description |
|---|---|
| `nosql_operator_count` | Count of NoSQL operator patterns matched |
| `has_nosql_where` | 1 if `$where` present |
| `has_nosql_ne` | 1 if `$ne` or `[$ne]` present |
| `has_nosql_regex` | 1 if `$regex` or `[$regex]` present |

Patterns include MongoDB operators: `$where`, `$gt`, `$lt`, `$ne`, `$eq`, `$in`, `$nin`, `$regex`, `$exists`, `$or`, `$and`, `$not`, `$elemMatch`, `$all`, `$size`, `$type`, `mapreduce`, `findandmodify`, `_id`, `objectid(`, `[$ne]`, `[$gt]`, `[$regex]`, `[$where]`.

### 8. SSRF Features (5)

| Feature | Description |
|---|---|
| `ssrf_pattern_count` | Count of SSRF patterns matched |
| `has_internal_ip` | 1 if `127.0.0.1`, `192.168.*`, `10.*`, or `172.16-31.*` present |
| `has_aws_metadata` | 1 if `169.254.169.254` present |
| `has_file_proto` | 1 if `file://` present |
| `has_non_http_proto` | 1 if `dict://`, `gopher://`, `ldap://`, `ftp://`, or `sftp://` present |

### 9. XXE Features (3)

| Feature | Description |
|---|---|
| `xxe_pattern_count` | Count of XXE patterns matched |
| `has_xml_doctype` | 1 if `<!doctype` or `<!entity` present |
| `has_xml_declaration` | 1 if `<?xml` present |

### 10. JWT Abuse Features (3)

Evaluated on the `Authorization: Bearer <token>` header value:

| Feature | Description |
|---|---|
| `has_jwt` | 1 if the bearer token decodes as a valid JWT (has `alg` in header) |
| `jwt_alg_none` | 1 if JWT header has `alg: none` / `null` / empty |
| `jwt_no_signature` | 1 if bearer token ends with `.` (missing signature segment) |

### 11. IDOR Features (2)

| Feature | Description |
|---|---|
| `has_idor_pattern` | 1 if URL path matches `/(users?|orders?|baskets?|payments?|...)/<id>` |
| `path_has_int_id` | 1 if URL path contains a bare integer segment (`/123`) |

### 12. HTTP Method Features (4)

| Feature | Description |
|---|---|
| `method_encoded` | Numeric encoding: GET=0, POST=1, PUT=2, DELETE=3, OPTIONS=4, HEAD=5, PATCH=6, TRACE=7 |
| `is_post` | 1 if method is POST |
| `is_delete` | 1 if method is DELETE |
| `is_trace` | 1 if method is TRACE |

### 13. Body Features (6)

| Feature | Description |
|---|---|
| `body_length` | Raw body length (capped at 50,000) |
| `body_entropy` | Shannon entropy of first 500 body chars |
| `body_has_base64` | 1 if base64-like sequence (`[A-Za-z0-9+/]{20,}={0,2}`) in body |
| `body_has_xml` | 1 if `<?xml` or `<root>` in body |
| `body_is_json` | 1 if body starts with `{` or `[` |
| `body_has_json_operators` | 1 if `$\w+` pattern in body (NoSQL/JSON operator injection) |

### 14. Header Features (7)

| Feature | Description |
|---|---|
| `ua_length` | Length of User-Agent header |
| `suspicious_ua` | 1 if UA contains known scanner string (sqlmap, nikto, nmap, burpsuite, etc.) |
| `has_referer` | 1 if Referer header present |
| `has_cookie` | 1 if Cookie header present |
| `has_auth_header` | 1 if Authorization header present |
| `has_content_type` | 1 if Content-Type header present |
| `num_headers` | Total count of request headers |

### 15. Entropy Features (3)

| Feature | Description |
|---|---|
| `query_entropy` | Shannon entropy of query string (first 300 chars) |
| `url_entropy` | Shannon entropy of full URL (first 300 chars) |
| `body_token_entropy` | Shannon entropy of body with whitespace removed (first 300 chars) |

High entropy indicates encoded/obfuscated payloads, base64 shellcode, or heavily randomized attack strings.

### 16. Parameter Pollution Features (3)

| Feature | Description |
|---|---|
| `duplicate_params` | 1 if any parameter key appears more than once in query |
| `num_query_params` | Count of distinct parameter keys in query |
| `max_param_value_length` | Length of the longest individual parameter value |

---

## Data Flow

```
raw request dict {method, url, headers, body, ip}
        │
        ▼
extract_features(request_data)
  ├─ URL-decode url + body → full (for pattern matching)
  ├─ Keep raw url/path/query (for structural features)
  └─ Returns feature_dict {name: float, ...}  (75 entries)
        │
        ▼
features_to_array(feature_dict)
  └─ Returns np.ndarray shape=(75,) dtype=float32  (canonical FEATURE_NAMES order)
        │
        ▼
model.predict_proba(arr.reshape(1,-1))[0][1]
  └─ Returns malicious probability score 0.0–1.0
```

`FEATURE_NAMES` is defined by calling `extract_features` once on a dummy request at import time and taking the resulting dict keys — this guarantees the training and inference order are always identical.

---

## Relationship to Other Files

| File | Relationship |
|---|---|
| `ml/train.py` | Calls `extract_features()` + `features_to_array()` for every training sample |
| `app/waf_engine.py` | Calls them at Stage 8 (supervised ML) for every live request; also uses `features` for `_infer_attack_type()` in earlier stages |
| `ml/dataset_generator.py` | Provides the training requests that `train.py` feeds to this module |
| `static/index.html` | Displays `result.features` dict in the per-event detail modal |
| `models/metrics.json` | Stores `feature_names` and `feature_importances` for the dashboard ML tab |

---

## open-appsec Equivalent

open-appsec uses a proprietary feature vocabulary of 100+ features, kept confidential. Based on published papers and the nginx-attachment source, the feature categories are very similar: structural, entropy, pattern-count, and behavioral. The main difference is that open-appsec computes features in C++ for microsecond latency, while this Python implementation takes ~1–5ms per request.
