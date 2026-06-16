# `dataset_generator.py` — Synthetic Attack Dataset Generator

## Overview

`dataset_generator.py` creates the **labeled training dataset** used to teach the classifier what attacks look like. It synthetically generates realistic HTTP requests across **13 attack categories** plus normal traffic, drawing on three dataset "styles": CSIC 2010-style e-commerce, OWASP Juice Shop CTF patterns, and HTTPParams fuzzing. It also contains `parse_csic_2010()` — the parser for the real CSIC 2010 HTTP archive files in `data/` — and `augment_labeled_samples()` for expanding user-uploaded site-specific data.

---

## Dataset Composition (Synthetic)

These are the default counts produced by `generate_dataset()`:

| Attack Type | Count | Source Style |
|---|---|---|
| Normal traffic | 6,000 | E-commerce + Juice Shop + API patterns |
| SQL Injection | 1,500 | CSIC 2010 payloads + extended variants |
| XSS | 1,500 | OWASP XSS filter evasion + reflected/stored/DOM |
| Path Traversal | 800 | Unix/Windows/encoded traversal sequences |
| Command Injection | 600 | Linux/Windows shell injection |
| Juice Shop SQLi | 600 | OWASP Juice Shop CTF login/search bypass |
| Juice Shop XSS | 600 | Juice Shop iframe/angular template injection |
| IDOR | 500 | Object reference manipulation paths |
| HTTP Param Pollution | 500 | HTTPParams fuzzing dataset |
| NoSQL Injection | 400 | MongoDB operator injection |
| JWT Abuse | 300 | alg:none, tampered claims, RS256→HS256 confusion |
| SSRF | 300 | Cloud metadata, private IPs, non-HTTP protocols |
| XXE | 200 | XML external entity injection |

**Synthetic total: ~13,800 samples** (7,300 malicious + 6,000 benign, then shuffled)

When real CSIC 2010 files are present in `data/`, `train.py` loads them in addition to the synthetic set, bringing the total training corpus to ~110,000+ samples.

---

## Three Dataset Styles

### 1. CSIC 2010 Style (classic web attacks)
Covers SQL Injection (classic, UNION, blind, time-based, stacked), XSS (reflected, stored, DOM, obfuscated), path traversal (Unix/Windows/encoded/null-byte), and command injection. Payloads are drawn from the CSIC 2010 cheatsheet plus OWASP extensions.

### 2. OWASP Juice Shop Patterns
Targets the specific vulnerabilities exposed in Juice Shop CTF challenges: login bypass via `' OR TRUE--`, search injection via `'); SELECT sleep(5);--`, prototype pollution XSS, Angular template injection (`{{7*7}}`), and IDOR paths like `/rest/basket/-1`.

### 3. HTTPParams Fuzzing
Covers parameter pollution (duplicate keys), oversized values (`'A'*8192`), double-encoding (`%252527`), unicode normalization tricks, array injection (`id[]=`), and content-type confusion (`{$where: 1==1}`).

---

## CSIC 2010 Parser

`parse_csic_2010(filepath, label, attack_type)` handles the real CSIC 2010 HTTP archive files placed in `data/`. It supports two on-disk formats automatically:

**Wrapped format** (files in this repo's `data/` directory):
```
Start - Id: 1
class: Valid

GET /tienda1/index.jsp HTTP/1.1
Host: localhost
...

End - Id: 1
```

**Raw HTTP format** (blocks separated by blank lines):
```
GET /tienda1/publico/anadir.jsp HTTP/1.1
Host: localhost
...

POST /tienda1/publico/pagar.jsp HTTP/1.1
...
```

The parser extracts `method`, `url`, `headers`, and `body` into the standard request dict, assigns `label` and `attack_type`, and skips blocks that don't contain a valid HTTP request line.

---

## Labeled-Sample Augmentation

`augment_labeled_samples(samples, variants_per_sample=5)` expands user-uploaded site-specific labeled requests into synthetic variants. Called by `POST /ml/upload_labeled`.

Each input sample generates `variants_per_sample` additional samples using one of four transformations chosen at random:

| Transform | Description |
|---|---|
| URL encoding | Percent-encode (or double-encode) special chars in the query string |
| Case randomization | Randomly upper/lower-case SQL/XSS keywords (`UnIoN SeLeCt`) |
| Parameter reordering | Shuffle `key=value` pairs joined by `&` |
| Comment padding | Insert SQL comment markers (`/**/`) or spaces into the payload |

For malicious samples (`label=1`), 30% of variants also get a scanner User-Agent (sqlmap, Nikto, etc.). The original samples are preserved alongside their variants.

---

## Request Dict Schema

Every generated request uses this schema — shared by `train.py`, `simulator.py`, `waf_engine.analyze()`, and `feature_extractor.extract_features()`:

```python
{
    'method':      'POST',
    'url':         '/api/login',
    'headers':     {'Content-Type': 'application/json', 'User-Agent': '...'},
    'body':        '{"username":{"$ne":null},"password":{"$ne":null}}',
    'ip':          '203.0.113.42',
    'label':       1,                    # 0 = normal, 1 = attack
    'attack_type': 'nosql_injection'
}
```

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `ml/train.py` | Calls `generate_dataset()` for synthetic data; `parse_csic_2010()` for real CSIC files; `augment_labeled_samples()` is called by `app/main.py` directly |
| `app/main.py` | Imports `augment_labeled_samples` to expand uploaded data before writing to `data/custom_labeled.jsonl` |
| `app/simulator.py` | Imports `generate_dataset()` for the `full_dataset` simulation scenario |

---

## Adding New Attack Types

1. Add a new payload list constant (e.g., `GRAPHQL_PAYLOADS = [...]`)
2. Write a generator function `_gen_graphql() -> Dict` that samples from it
3. Add an entry to `generators` inside `generate_dataset()` with a sample count
4. Add matching detection patterns to `ml/feature_extractor.py`
5. Retrain via `python -m ml.train` or `POST /ml/retrain`

---

## open-appsec Equivalent

open-appsec trains on a **global dataset** aggregated from deployments across thousands of organizations (with anonymization). This gives it far greater real-world coverage than any single synthetic generator. The synthetic approach here is a pragmatic substitute that enables local training without requiring production traffic, while the `augment_labeled_samples` + `POST /ml/upload_labeled` workflow provides a path to fold in site-specific real requests.
