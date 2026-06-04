# `dataset_generator.py` — Synthetic Attack Dataset Generator

## Overview

`dataset_generator.py` creates the **labeled training dataset** used to teach the Random Forest what attacks look like. Because publicly available labeled WAF datasets are scarce and often cover only one or two attack types, this module synthetically generates realistic HTTP requests across **13 attack categories** plus normal traffic.

The generator is also used at runtime by the **simulation engine** to produce live attack traffic for the dashboard demo.

---

## Why Synthetic Data?

Real labeled WAF datasets (CSIC 2010, OWASP WebGoat traffic) have significant limitations:
- Narrow attack coverage (mostly SQLi + path traversal)
- Fixed payload patterns that don't generalise
- Imbalanced classes (often 80%+ normal)
- No modern attack types (NoSQL injection, JWT abuse, SSRF didn't exist in 2010)

Synthetic data lets us:
- Control class balance precisely
- Cover all modern OWASP Top-10 categories
- Generate arbitrary scale (10K to 1M samples)
- Include real payloads from OWASP Juice Shop challenges

---

## Dataset Composition

| Attack Type | Sample Count | Source |
|---|---|---|
| Normal traffic | 4,000 | Simulated e-commerce patterns |
| SQL Injection | 2,100 | CSIC 2010 payloads + extended |
| XSS | 1,800 | OWASP Juice Shop challenges |
| Path Traversal | 900 | Common traversal sequences |
| Command Injection | 600 | Linux/Windows command injection |
| NoSQL Injection | 800 | MongoDB operator injection |
| JWT Abuse | 600 | alg:none, tampered tokens |
| SSRF | 500 | Cloud metadata, SSRF |
| XXE | 400 | XML entity injection |
| IDOR | 500 | Object reference manipulation |
| HTTP Parameter Pollution | 400 | HTTPParams fuzzing dataset |
| Log4Shell / IPS Evasion | 200 | CVE-2021-44228 patterns |
| Bot Scanning | 300 | Known scanner fingerprints |

**Total: ~13,100 samples**

---

## CSIC 2010 Parser

The module also contains `parse_csic_2010()` — a parser for the HTTP Archive format used by the CSIC 2010 dataset:

```
GET /tienda1/publico/anadir.jsp HTTP/1.1
Host: localhost
Connection: keep-alive
...
[blank line]
```

The parser extracts method, URL, headers, and body into the same dict format used everywhere else, enabling seamless mixing of real and synthetic data.

---

## Request Dict Schema

Every generated request is a Python dict with this schema:

```python
{
    'method':      'POST',
    'url':         '/api/login',
    'headers':     {'Content-Type': 'application/json'},
    'body':        '{"username":{"$ne":null},"password":{"$ne":null}}',
    'ip':          '203.0.113.42',
    'label':       1,              # 0 = normal, 1 = attack
    'attack_type': 'nosql_injection'
}
```

This schema is shared by: `train.py`, `simulator.py`, `waf_engine.analyze()`, and `feature_extractor.extract_features()`. It is the universal "request representation" throughout the project.

---

## Normal Traffic Generation

Normal traffic is not just random noise — it simulates realistic e-commerce application behavior:

```python
NORMAL_PATHS = [
    '/api/products?page={page}&category={cat}',
    '/api/users/{id}/orders',
    '/search?q={term}&sort=price',
    '/checkout/payment',
    ...
]
```

This is important because the Isolation Forest baseline must learn what *legitimate* traffic looks like. If normal traffic is too uniform, the model will flag any slightly unusual-but-legitimate request.

---

## Payload Realism

Attack payloads are drawn from real-world sources:

- **SQL Injection**: CSIC 2010 payloads, OWASP cheatsheet, blind/time-based variants
- **XSS**: OWASP XSS filter evasion cheatsheet, Juice Shop challenge URLs
- **JWT**: Actual malformed tokens from the Juice Shop CTF (e.g., `alg:none` bypass)
- **SSRF**: Real AWS/GCP/Azure metadata service URLs
- **Log4Shell**: Actual CVE-2021-44228 JNDI strings

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `ml/train.py` | Calls `generate_dataset()` to get the training DataFrame |
| `ml/train.py` | Calls `parse_csic_2010()` to load real data |
| `app/simulator.py` | Imports `generate_dataset()` for the `full_dataset` simulation scenario |

---

## Adding New Attack Types

To add a new attack category:

1. Add a new payload list constant (e.g., `_GRAPHQL_INJECTION = [...]`)
2. Add a generator function `_gen_graphql_injection(n)` that samples payloads
3. Call it inside `generate_dataset()` and append results to the DataFrame
4. Add the pattern signatures to `feature_extractor.py`
5. Retrain the model

---

## open-appsec Equivalent

open-appsec trains on a **global dataset** aggregated from deployments across thousands of organizations (with anonymization). This gives it far greater coverage than any single synthetic generator. The synthetic approach here is a pragmatic substitute that enables local training without requiring production data.
