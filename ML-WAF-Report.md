# ML-WAF: A Python Implementation of an ML-Integrated Web Application Firewall

**Course:** CS 451 – Computer Security  
**Project Title:** ML-Integrated Web Application Firewalls (WAF)  
**Group:** X  

| No. | Name | ID |
|-----|------|----|
| 1 | Nguyen Quang Trung | 1624786 |
| 2 | Ngo Ha Anh Thu | 1624777 |
| 3 | Tran Long | 1677677 |

**Supervisor:** Dr. Anh Tu Tran

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background and Related Work](#2-background-and-related-work)
3. [System Architecture](#3-system-architecture)
4. [Key Design Decisions](#4-key-design-decisions)
5. [Implementation: API Server](#5-implementation-api-server)
6. [Implementation: WAF Engine](#6-implementation-waf-engine)
7. [Rule-Based Middleware Modules (Stages 1–7)](#7-rule-based-middleware-modules-stages-17)
8. [Machine Learning Layer](#8-machine-learning-layer)
9. [Supporting Components](#9-supporting-components)
10. [Evaluation Setup](#10-evaluation-setup)
11. [Model Results](#11-model-results)
12. [System Behavior Under Simulated Attack](#12-system-behavior-under-simulated-attack)
13. [Comparison with open-appsec](#13-comparison-with-open-appsec)
14. [Limitations](#14-limitations)
15. [Future Work](#15-future-work)
16. [Conclusion](#16-conclusion)

---

## 1. Introduction

### 1.1 Background

Modern web applications expose HTTP endpoints that can receive arbitrary input from untrusted clients. Adversaries exploit this attack surface through a diverse class of injection-based vulnerabilities — SQL injection (SQLi), cross-site scripting (XSS), command injection, XML external entity (XXE) injection, server-side request forgery (SSRF), NoSQL operator injection, and others — as well as through protocol-level exploitation of known CVEs in server-side frameworks. A successful intrusion may result in unauthorized data exfiltration, privilege escalation, database corruption, or remote code execution.

### 1.2 What a Web Application Firewall Is

A Web Application Firewall (WAF) is a security component that interposes between an HTTP client and a back-end application server. It inspects the full content of each HTTP request — including the request line, headers, and body — and makes a binary allow-or-block decision before forwarding to, or returning HTTP 403 Forbidden from, the application. Because a WAF operates at Layer 7 of the OSI model, it can examine application-layer semantics that are invisible to network-layer packet filters.

### 1.3 Why Machine Learning Is Required

Signature-based WAFs maintain hand-crafted regular-expression rules that match known attack patterns. This approach is limited in three principal ways. First, signatures can only detect attacks whose patterns have been previously enumerated; zero-day attacks and novel payload encodings evade them. Second, the combinatorial explosion of evasion variants (encoding, case permutation, comment insertion, whitespace injection) means that any finite signature set is incomplete. Third, high-specificity signatures may produce false positives on legitimate traffic that syntactically resembles an attack pattern.

Machine learning addresses these limitations by constructing statistical models from labeled example requests. A trained classifier generalizes from its training distribution to previously unseen inputs, enabling detection of payloads that share structural or lexical characteristics with known attacks without requiring explicit enumeration. Unsupervised methods additionally construct a model of normal traffic specific to the deployment environment, enabling anomaly-based detection of zero-day attacks that have no representation in any training corpus.

### 1.4 Project Goal

ML-WAF is a complete, working Web Application Firewall implemented in Python, architecturally modeled on open-appsec — an open-source, ML-powered WAF. The implementation combines fast rule-based pre-filters with a dual ML engine (supervised + unsupervised) in a 10-stage request pipeline, deployed as a FastAPI service with a live WebSocket-driven analytics dashboard. The system is designed to be transparent: every blocking decision is accompanied by the feature vector and stage attribution that produced it, enabling detailed inspection and explanation of model behavior.

---

## 2. Background and Related Work

### 2.1 From Signature-Based to ML-Based Detection

First-generation WAFs operated exclusively on signature lists maintained by security vendors. The ModSecurity Core Rule Set (CRS), widely used in production environments, comprises several thousand PCRE expressions targeting known attack patterns. While effective against known threats at low false-positive rates in conservative configurations, signature-based systems exhibit a fundamental limitation: detection coverage is bounded by the set of previously observed attack variants. ML-WAF follows the hybrid design adopted by modern commercial WAFs: a fast rule layer handles high-confidence, well-characterized attacks, while an ML model handles the residual class of ambiguous and novel requests.

### 2.2 Supervised Learning for WAF

Supervised classification models for WAF detection are trained on corpora of labeled HTTP requests. Several research datasets are publicly available, the most cited of which is the CSIC 2010 dataset [reference], comprising approximately 36,000 labeled HTTP requests generated against a Spanish e-commerce application (Tienda Virtual). Tree-based ensemble methods — particularly Random Forest and Gradient Boosting — are well-suited to this task because they handle heterogeneous feature types (count integers, ratio floats, binary indicators) without normalization, are resistant to overfitting through ensemble averaging or boosting, and produce calibrated probability estimates that can serve as blocking thresholds.

### 2.3 Unsupervised Anomaly Detection

Unsupervised methods model the distribution of normal traffic without requiring attack labels. The Isolation Forest algorithm [Liu et al., 2008] isolates anomalies by constructing an ensemble of random binary partition trees and measuring the average path length required to isolate each sample. Anomalous samples, which reside in sparse regions of feature space, require fewer partitions and thus receive shorter average path lengths. Isolation Forest is computationally efficient (O(n log n) training, O(log n) inference), requires no normality assumptions, and has been shown to perform well on high-dimensional tabular data — properties that make it suitable for WAF deployment.

### 2.4 The open-appsec Reference Architecture

open-appsec is an open-source, preemptive ML-based WAF whose production engine is implemented in C++ and Go, deployed as an add-on module to NGINX, Envoy, and Kubernetes Ingress. Its architecture places a supervised model (trained offline on a global crowd-sourced corpus) in series with an unsupervised contextual model (trained online from deployment-specific traffic), combined through a weighted confidence fusion. ML-WAF reproduces this conceptual architecture — rule pre-filter → supervised ML → unsupervised ML → policy-driven threshold — in a single readable Python service without claiming to replicate the proprietary algorithms of the production system.

---

## 3. System Architecture

### 3.1 High-Level Overview

ML-WAF is structured as a single FastAPI service organized into five functional layers:

1. **API Server** (`app/main.py`): receives HTTP requests, exposes REST endpoints, manages WebSocket connections.
2. **WAF Engine** (`app/waf_engine.py`): orchestrates the 10-stage detection pipeline.
3. **Rule-Based Middleware** (`app/middleware/`): seven deterministic modules (Stages 1–7).
4. **ML Layer** (`ml/`): feature extractor, supervised classifier, and unsupervised baseline.
5. **Policy Engine** (`app/policy.py`): mode control, IP/path rules, and scoring thresholds.

Every request is routed through `waf_engine.analyze()`, which executes the pipeline and broadcasts the result to connected WebSocket clients.

```
Browser / Client
       │
       ▼  POST /analyze  or  ANY /waf_check
┌──────────────────────────────────────────────────────────┐
│              app/main.py  (FastAPI + Uvicorn)             │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│             app/waf_engine.py  (Pipeline)                 │
│                                                          │
│  Stage 0  ── Policy check           app/policy.py        │
│  [Feature extraction — 74-dim vector computed here]      │
│  Stage 1  ── Rate Limiter           rate_limiter.py       │
│  Stage 2  ── Anti-Bot               anti_bot.py          │
│  Stage 3  ── Crowd Wisdom           crowd_wisdom.py       │
│  Stage 4  ── IPS Engine             ips_engine.py        │
│  Stage 5  ── File Security          file_security.py     │
│  Stage 6  ── NoSQL Injection        nosql_injection.py   │
│  Stage 7  ── JWT Abuse              jwt_abuse.py         │
│  Stage 8  ── Supervised ML          waf_model.pkl        │
│  Stage 9  ── Unsupervised ML        unsupervised.py      │
│  Stage 10 ── API Discovery          api_discovery.py     │
└───────────────────────┬──────────────────────────────────┘
                        │
          ┌─────────────┴────────────┐
          ▼                          ▼
    BLOCK (403)                ALLOW (200)
          └──────────┬───────────────┘
                     ▼
        WebSocket broadcast → static/index.html
```

### 3.2 The Request Pipeline

The pipeline consists of 10 numbered stages. Stages 1–7 are deterministic rule-based modules; Stages 8–9 are ML inference stages; Stage 10 is a passive recording module. The feature extraction step is executed once, immediately after Stage 0 (policy check), and the resulting 74-dimensional feature vector is shared across all subsequent stages.

| Stage | Module | Detection Mechanism | Blocking |
|-------|--------|---------------------|----------|
| 0 | Policy | IP allowlist / blocklist; path allowlist / blocklist | Yes |
| — | Feature Extraction | HTTP request → 74-dim float vector | No |
| 1 | Rate Limiter | Sliding-window request count per IP | Yes |
| 2 | Anti-Bot | User-Agent fingerprinting; request velocity | Yes |
| 3 | Crowd Wisdom | IP reputation; offline CIDR blocklist; live threat feed | Yes |
| 4 | IPS Engine | Compiled regex CVE/exploit signatures | Yes |
| 5 | File Security | Magic-byte MIME validation; extension blocklist; polyglot detection | Yes |
| 6 | NoSQL Injection | MongoDB operator detection in URL params and JSON body | Yes |
| 7 | JWT Abuse | Token structural analysis; alg:none detection | Yes |
| 8 | Supervised ML | GradientBoostingClassifier probability score | Yes |
| 9 | Unsupervised ML | Isolation Forest anomaly score + confidence fusion | Yes |
| 10 | API Discovery | Endpoint schema recording; probe detection | Conditional |

### 3.3 Decision Flow and Short-Circuit Evaluation

The pipeline implements short-circuit evaluation: the `analyze()` loop returns immediately upon the first blocking decision, skipping all remaining stages. This ensures that computationally expensive ML inference (Stages 8–9) is only executed for requests that have passed all seven rule-based pre-filters. The decision, the originating stage, and the complete feature vector are included in every result regardless of outcome, and are broadcast over WebSocket to the dashboard.

**Score combination at Stage 9:**

```
combined_score = 0.7 × supervised_score + 0.3 × unsupervised_score
block_stage9  = combined_score ≥ combined_block_score   (default: 0.65)
```

### 3.4 Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| API server | FastAPI + Uvicorn | Asynchronous I/O; native WebSocket support; automatic OpenAPI documentation |
| Supervised ML | scikit-learn `GradientBoostingClassifier` / `RandomForestClassifier` | Strong tabular performance; calibrated probability output; feature importance reporting |
| Unsupervised ML | scikit-learn `IsolationForest` | Path-length anomaly score; O(n log n) training; no normality assumption |
| Model serialization | joblib (supervised), pickle protocol 4 (unsupervised) | Standard Python ML serialization |
| Real-time events | Native FastAPI WebSockets | Per-decision push to all dashboard clients |
| Frontend | HTML5 / CSS3 / ES2020 JavaScript + Chart.js 4.4 | Zero build-step SPA; renders live feature charts |

---

## 4. Key Design Decisions

### 4.1 Dual Machine Learning Engine

The system operates two ML models in series that address complementary threat classes. The supervised classifier is trained offline on a large labeled corpus and detects requests that are statistically similar to known attack instances. The unsupervised Isolation Forest is trained online from live allowed traffic and detects requests that deviate significantly from the deployment-specific behavioral baseline, including zero-day attacks with no representation in the training corpus. The two models are combined through a fixed weighted fusion rather than a learned meta-classifier, in order to maintain interpretability and avoid overfitting on the model combination itself.

### 4.2 Short-Circuit Evaluation for Computational Efficiency

Rule-based stages are ordered by computational cost: token-bucket counting (Stage 1) executes in O(1); regex matching (Stage 4) in O(signature_count × request_length); ML inference (Stages 8–9) requires matrix operations over 74 features. The short-circuit design ensures that the average per-request cost is dominated by the cheap pre-filter stages for the majority of traffic, reserving ML inference for ambiguous cases.

### 4.3 Confidence Fusion

The fusion formula `0.7 × supervised + 0.3 × unsupervised` gives precedence to the supervised model, which has higher precision on known attack categories, while retaining sufficient influence from the unsupervised score to escalate borderline requests when anomalous behavioral signals are present. All three blocking thresholds — `ml_block_score`, `unsupervised_block_score`, and `combined_block_score` — are runtime-configurable through the policy engine without requiring model retraining.

### 4.4 Policy Engine with Three Operating Modes

The policy engine supports three modes that control enforcement behavior:

- **Prevent**: requests that exceed a blocking threshold are returned HTTP 403 Forbidden.
- **Detect**: blocking decisions are recorded and broadcast, but the request is forwarded to the application (shadow mode for tuning).
- **Monitor**: all decisions are logged; no blocking or allowlisting is applied.

This mode hierarchy is a standard operational pattern in WAF deployment, allowing operators to validate detection accuracy before enabling enforcement.

### 4.5 Lazy Model Loading and Hot Retraining

The trained supervised model (`models/waf_model.pkl`) is loaded on first inference request rather than at server startup, reducing startup latency. The `/ml/retrain` endpoint launches training as a `BackgroundTask` using `subprocess.run([sys.executable, '-m', 'ml.train'])`, followed by `waf_engine.load_models()` to atomically replace the in-memory model with the newly trained artifact. The server continues handling requests during training; the model switch occurs only after the new `.pkl` file is fully written.

### 4.6 Built-In Explainability

Every decision result includes the complete 74-element feature vector. The dashboard renders a per-request feature importance view using the model's `feature_importances_` attribute, enabling operators to identify which specific signals — e.g., elevated `sql_keyword_count`, presence of `has_union`, or high `body_entropy` — drove a particular blocking decision. This transparency is architecturally significant: it transforms the ML layer from an opaque classifier into an auditable decision component.

---

## 5. Implementation: API Server (`app/main.py`)

### 5.1 REST Endpoint Organization

The API server exposes endpoints grouped by functional domain:

| Domain | Endpoints |
|--------|-----------|
| Analysis | `POST /analyze`, `ANY /waf_check`, `GET /stats`, `POST /stats/reset` |
| ML | `GET /model/info`, `POST /ml/retrain`, `POST /ml/upload_labeled`, `POST /learn/toggle`, `POST /learn/save` |
| Simulation | `POST /simulate/start`, `POST /simulate/stop`, `GET /simulate/scenarios` |
| Policy | `GET /policy`, `PUT /policy/mode`, `PUT /policy/thresholds`, `POST /policy/rules`, `POST /policy/rules/bulk`, `POST /policy/rules/import`, `DELETE /policy/rules`, `POST /policy/reload` |
| Infrastructure | `GET /modules/info`, `GET /integrations/{lang}`, `POST /upload`, `GET /health` |
| Dashboard | `GET /`, `WS /ws` |

The `ANY /waf_check` endpoint implements nginx `auth_request` compatibility: it accepts any HTTP method and returns HTTP 200 (allow) or HTTP 403 (block) with no body, enabling ML-WAF to function as a transparent authorization sub-request proxy in an nginx reverse-proxy deployment.

### 5.2 WebSocket Connection Manager

The `ConnectionManager` class maintains a list of active WebSocket connections. Every WAF decision is broadcast to all clients via `await ws.send_text(json.dumps(result, default=str))`. Dead connections are detected by send-time exceptions and removed lazily from the active list without requiring explicit disconnect signals.

Three WebSocket message types are defined:
- `init`: sent on connection; includes current statistics and policy state.
- `stats_update`: sent every 3 seconds by a startup background task.
- `request`: sent after each `analyze()` call; includes the slimmed decision dict.

### 5.3 Request Validation via Pydantic

Incoming request snapshots are validated against the `RequestSnapshot` model:

```python
class RequestSnapshot(BaseModel):
    method:  str  = 'GET'
    url:     str  = '/'
    headers: dict = {}
    body:    str  = ''
    ip:      str  = '127.0.0.1'
```

Default values permit partial payloads (e.g., URL-only requests) without explicit null handling in the pipeline. Supplementary models `PolicyRuleBulk`, `ThresholdUpdate`, and `SimulateRequest` define structured inputs for policy mutation and simulation control endpoints.

### 5.4 Hot Retraining Implementation

```python
@app.post('/ml/retrain')
async def retrain_model(background_tasks: BackgroundTasks):
    def run_training():
        subprocess.run([sys.executable, '-m', 'ml.train'], check=True, cwd=ROOT)
        waf_engine.load_models()
    background_tasks.add_task(run_training)
    return {'status': 'training_started'}
```

Training runs in a FastAPI background thread (not a coroutine), isolating the blocking `subprocess.run` call from the async event loop. Upon completion, `load_models()` replaces the in-memory classifier without server restart.

---

## 6. Implementation: WAF Engine (`app/waf_engine.py`)

### 6.1 Pipeline Execution

The `analyze(request_data)` function:
1. Executes Stage 0 (policy check).
2. Calls `feature_extractor.extract_features(request_data)` and `features_to_array(f)`, producing a 74-element `np.float32` array.
3. Iterates through Stages 1–10, passing both the raw `request_data` dict and the pre-computed feature vector to each stage function.
4. Returns on the first blocking result; otherwise returns the allow result from Stage 10.

Feature extraction is performed once per request after Stage 0, before any rule-based check, ensuring that the feature vector is available to all downstream stages (including `_infer_attack_type()`, which labels the attack category for blocked requests at any stage).

### 6.2 ML Scoring (Stages 8 and 9)

**Stage 8 — Supervised:**
```python
ml_score = model.predict_proba(feature_vec.reshape(1, -1))[0][1]
if ml_score >= ml_block_score:      # default: 0.50
    return block_result('ml_supervised', ml_score)
```

**Stage 9 — Unsupervised fusion:**
```python
anomaly_result = baseline.score(feature_vec, request_data)
anomaly_score  = anomaly_result['anomaly_score']
combined       = ml_score * 0.7 + anomaly_score * 0.3
if combined >= combined_block_score:  # default: 0.65
    return block_result('ml_unsupervised', combined)
```

For requests that are not blocked at Stage 8, `baseline.learn(feature_vec, request_data)` is called at Stage 10 to update the behavioral baseline with the allowed request.

### 6.3 Threat Level Computation

The engine maintains a running block-rate counter and derives a threat level at each statistics update:

| Block Rate | Threat Level |
|------------|--------------|
| > 50% | `critical` |
| > 30% | `high` |
| > 10% | `medium` |
| ≤ 10% | `low` |

### 6.4 Attack Type Inference

`_infer_attack_type(features)` maps the feature vector to a categorical attack label for logging and dashboard visualization. It applies a priority-ordered set of threshold conditions on individual feature values:

| Priority | Condition | Label |
|----------|-----------|-------|
| 1 | `has_script_tag=1` OR `xss_pattern_count > 1` | `xss` |
| 2 | `sql_keyword_count > 1` OR `has_union=1` OR `sql_tautology=1` | `sqli` |
| 3 | `cmd_injection_count > 0` | `cmd_injection` |
| 4 | `path_traversal_count > 0` OR `has_dotdot=1` | `path_traversal` |
| 5 | `nosql_operator_count > 1` | `nosql_injection` |
| 6 | `has_aws_metadata=1` OR `has_internal_ip=1` | `ssrf` |
| 7 | `has_xml_doctype=1` | `xxe` |
| 8 | `jwt_alg_none=1` | `jwt_abuse` |
| 9 | `has_idor_pattern=1` | `idor` |
| — | (default) | `unknown` |

---

## 7. Rule-Based Middleware Modules (Stages 1–7)

### 7.1 Rate Limiter (Stage 1)

The rate limiter maintains per-IP sliding-window counters using deque-based timestamp queues. It applies three tiered limits:

| Tier | Limit | Window | Scope |
|------|-------|--------|-------|
| General | 100 requests | 60 s | All endpoints |
| Sensitive | 10 requests | 60 s | `/admin`, `/login`, `/api/auth`, `/register` |
| Burst | 30 requests | 5 s | All endpoints |

An IP address that exceeds the burst limit is placed in a penalty box for 300 seconds (5 minutes), during which all its requests are rejected without re-evaluating the counter, reducing per-request CPU cost for sustained flood traffic.

### 7.2 Anti-Bot (Stage 2)

The anti-bot module scores requests on a confidence scale using five signals:

| Signal | Condition | Confidence |
|--------|-----------|------------|
| Scanner User-Agent | UA matches one of 37 compiled regex patterns (sqlmap, nikto, nmap, burpsuite, nuclei, etc.) | 0.97 |
| Absent User-Agent | `User-Agent` header missing or empty | 0.75 |
| Missing browser headers | ≥ 2 of `{accept, accept-language, accept-encoding}` absent | 0.65 |
| Request velocity | > 50 total requests OR > 20 distinct paths in 10 seconds | 0.90 |
| Suspicious path suffix | `.php`, `.asp`, `.jsp`, `/.env`, `/wp-login`, etc. | 0.45 |

The request is blocked when accumulated confidence ≥ 0.70.

### 7.3 Crowd Wisdom (Stage 3)

This module performs IP reputation lookup against two sources:

**Offline CIDR blocklist (20 ranges, no network dependency):** Includes Tor exit nodes (`185.220.101.0/24`, `185.220.102.0/24`, `185.220.103.0/24`, `192.42.116.0/24`, `176.10.104.0/24`), known scanner farms, Shodan scanning infrastructure (`66.240.192.0/24`, `71.6.135.0/24`), Censys scanning infrastructure (`162.142.125.0/24`, `167.94.138.0/24`), and known C2 ranges. Matches return `confidence=0.85`.

**Live CrowdSec CTI feed (optional):** When the `CROWDSEC_API_KEY` environment variable is set, the module queries `https://cti.api.crowdsec.net/v2/smoke/{ip}` with a 2-second timeout. Results are cached per-IP for 3,600 seconds. The composite score is computed as:

```
composite = aggressiveness × 0.5 + anomaly × 0.3 + max(0, 1 − trust) × 0.2
```

Block if `composite > 0.7` or `trust < 0.1`. If the live feed is unreachable, the module fails open (allows the request), preventing third-party service outages from causing false positives.

### 7.4 IPS Engine (Stage 4)

The IPS module maintains 18 compiled regex signatures targeting specific CVEs and generic exploit patterns. Each signature specifies a `target` field (`url`, `body`, `headers`, or `any`) to limit the search domain to the relevant request component, avoiding unnecessary full-body scanning for URL-targeted attacks.

**Complete signature set:**

| # | CVE / Tag | Description | Severity | Target |
|---|-----------|-------------|----------|--------|
| 1 | CVE-2021-44228 | Log4Shell JNDI injection | critical | any |
| 2 | CVE-2021-44228 | Log4Shell obfuscated variant | critical | any |
| 3 | CVE-2022-22965 | Spring4Shell `class.module.classLoader` | critical | any |
| 4 | CVE-2022-42889 | Text4Shell Commons Text interpolation | critical | any |
| 5 | CVE-2014-6271 | Shellshock bash function definition | critical | headers |
| 6 | CVE-2021-41773 | Apache 2.4.49 path traversal | high | url |
| 7 | CVE-2017-5638 | Struts2 OGNL injection via Content-Type | critical | headers |
| 8 | CVE-2012-1823 | PHP CGI argument injection | high | url |
| 9 | XXE-001 | XML External Entity injection | high | body |
| 10 | SSRF-001 | SSRF to internal IP addresses | high | url |
| 11 | SSRF-002 | SSRF to cloud metadata endpoint | critical | url |
| 12 | WEBSHELL-001 | PHP webshell `eval(` pattern | critical | body |
| 13 | WEBSHELL-002 | JSP webshell `Runtime.getRuntime().exec()` | critical | body |
| 14 | RCE-001 | OS command via semicolon injection | high | any |
| 15 | RCE-002 | Backtick command substitution | high | any |
| 16 | PT-001 | Encoded path traversal (`%2e%2e`, `%252e`) | medium | url |
| 17 | SCAN-001 | Automated vulnerability scanner User-Agent | medium | headers |
| 18 | SPLIT-001 | HTTP response splitting via CRLF (`%0d%0a`) | high | url |

Severity-to-confidence mapping: `critical → 1.0`, `high → 0.85`, `medium → 0.65`. Any match with severity `critical` or `high` triggers an immediate block. `medium` matches are recorded and passed to downstream stages as contextual signals.

### 7.5 File Security (Stage 5)

The file security module intercepts multipart `multipart/form-data` requests and applies six ordered checks to each uploaded file. Short-circuit evaluation halts processing at the first failed check.

| Order | Check | Mechanism | Example Attack Prevented |
|-------|-------|-----------|--------------------------|
| 1 | Size limit | `len(content) > MAX_FILE_SIZE_MB × 1024²` (default 10 MB) | Memory exhaustion via oversized upload |
| 2 | Dangerous extension | Extension membership in 33-item blocklist (`.php`, `.jsp`, `.exe`, `.sh`, `.py`, etc.) | Direct PHP webshell upload |
| 3 | EICAR detection | Byte-string search for EICAR standard antivirus test marker | Simulated malware detection validation |
| 4 | Magic-byte MIME | First-byte signature compared to 15 known MIME headers; blocks if detected type is `application/exe`, `application/elf`, `text/x-shellscript`, `text/x-php`, or `text/x-jsp` | PHP webshell renamed to `image.jpg` |
| 5 | Embedded script | First 8,192 bytes scanned against 9 compiled patterns (`<?php`, `<%@ page`, `eval(`, `Runtime.getRuntime`, etc.) | GIF polyglot with embedded PHP code |
| 6 | Double extension | Filename checked for dangerous extension substring not at terminal position | `shell.jpg.php` or `shell.php.jpg` |

This mirrors the Anti-Virus and Threat Extraction capabilities in open-appsec, restricted to fast, inline, local checks that add negligible per-request latency.

### 7.6 NoSQL Injection (Stage 6)

The NoSQL injection module targets MongoDB operator injection attacks that exploit JSON-typed request bodies or URL-encoded parameter values. It inspects four attack vectors:

1. **URL parameter operators**: query string values containing MongoDB operators (`$ne`, `$gt`, `$where`, `$regex`, etc.) passed as URL-encoded strings.
2. **JSON body operators**: request body parsed as JSON and traversed recursively to detect operator keys.
3. `$where` operator: isolated detection due to its capacity for arbitrary JavaScript execution on the MongoDB server.
4. **Redis protocol smuggling**: raw RESP protocol commands (`*`, `$`, `FLUSHALL`, `CONFIG`, `SLAVEOF`) in the request body.

### 7.7 JWT Abuse (Stage 7)

The JWT module extracts tokens from the `Authorization: Bearer` header or from cookies and applies structural and semantic checks without requiring the application's signing key:

- **`alg:none` attack**: header's `alg` field set to `"none"`, `"None"`, or `"NONE"`, removing the signature verification requirement.
- **Empty signature segment**: the token's third dot-separated component is present but zero-length (`header.payload.`).
- **Algorithm confusion**: asymmetric algorithm identifier (`RS256`, `ES256`) in the header with a suspiciously short token, indicating potential RS256→HS256 downgrade.
- **Privilege claim injection**: `admin`, `role`, or `is_superuser` fields in the payload claims set to elevated values.
- **Token expiry**: `exp` claim in the past by more than 3,600 seconds.

**Summary of Stages 1–7:**

| Stage | Module | Primary Mechanism | Representative Example |
|-------|--------|-------------------|------------------------|
| 1 | Rate Limiter | Sliding-window counter | Brute-force / flood traffic |
| 2 | Anti-Bot | UA fingerprinting + velocity | sqlmap, nikto, directory enumeration |
| 3 | Crowd Wisdom | CIDR reputation + threat feed | Tor exit nodes, known botnets |
| 4 | IPS Engine | Compiled CVE regex signatures | Log4Shell, Spring4Shell, Shellshock |
| 5 | File Security | Magic-byte + content inspection | PHP webshell disguised as JPEG |
| 6 | NoSQL Injection | MongoDB operator detection | `{"$ne": null}` login bypass |
| 7 | JWT Abuse | Token structural analysis | `alg:none` signature removal |

---

## 8. Machine Learning Layer

### 8.1 Feature Extraction (`ml/feature_extractor.py`)

The feature extractor transforms an HTTP request dictionary into a fixed-length 74-dimensional `float32` vector. All URL-decoded forms of the URL, query string, and body are computed before pattern matching, preventing encoding-based evasion (e.g., `%27 OR 1=1` evading a pattern matching the literal single-quote character).

The 74 features are organized into 16 groups:

| Group | Count | Representative Features |
|-------|-------|------------------------|
| URL Structural | 7 | `url_length`, `path_length`, `query_length`, `url_depth`, `num_params`, `pct_encoded`, `double_encoded` |
| Special Characters | 7 | `special_chars_url`, `special_chars_body`, `single_quotes`, `double_quotes`, `semicolons`, `comment_markers`, `angle_brackets` |
| SQL Injection | 7 | `sql_keyword_count`, `has_union`, `has_select`, `has_drop`, `sql_tautology`, `has_comment`, `has_hex_encode` |
| XSS | 6 | `xss_pattern_count`, `has_script_tag`, `has_event_handler`, `has_javascript_uri`, `has_html_entity`, `has_template_injection` |
| Path Traversal | 4 | `path_traversal_count`, `has_dotdot`, `has_etc_passwd`, `has_null_byte` |
| Command Injection | 4 | `cmd_injection_count`, `has_pipe`, `has_backtick`, `has_dollar_paren` |
| NoSQL | 4 | `nosql_operator_count`, `has_nosql_where`, `has_nosql_ne`, `has_nosql_regex` |
| SSRF | 5 | `ssrf_pattern_count`, `has_internal_ip`, `has_aws_metadata`, `has_file_proto`, `has_non_http_proto` |
| XXE | 3 | `xxe_pattern_count`, `has_xml_doctype`, `has_xml_declaration` |
| JWT | 3 | `has_jwt`, `jwt_alg_none`, `jwt_no_signature` |
| IDOR | 2 | `has_idor_pattern`, `path_has_int_id` |
| HTTP Method | 4 | `method_encoded`, `is_post`, `is_delete`, `is_trace` |
| Body | 6 | `body_length`, `body_entropy`, `body_has_base64`, `body_has_xml`, `body_is_json`, `body_has_json_operators` |
| Headers | 6 | `ua_length`, `suspicious_ua`, `has_referer`, `has_cookie`, `has_auth_header`, `has_content_type` |
| Entropy | 3 | `query_entropy`, `url_entropy`, `body_token_entropy` |
| Parameter Pollution | 3 | `duplicate_params`, `num_query_params`, `max_param_value_length` |

**Total: 7+7+7+6+4+4+4+5+3+3+2+4+6+6+3+3 = 74.**

`num_headers` (total header count) was removed from the feature set after production deployment revealed a critical data leakage artifact: in the CSIC 2010 corpus, this feature took only two discrete values — 10 for GET requests and 12 for POST requests — making it a pure proxy for HTTP method (already captured by `method_encoded`/`is_post`) rather than a genuine security signal. Real-world deployments behind a reverse proxy (Railway, nginx, Cloudflare) append 5–10 additional headers (`X-Forwarded-For`, `X-Real-IP`, platform-specific tracing headers) to every request regardless of payload content, pushing legitimate production traffic outside the training distribution and causing the model to block benign requests purely for carrying many headers.

### 8.2 Synthetic Dataset Generation (`ml/dataset_generator.py`)

`generate_dataset()` constructs a labeled training corpus with the following default composition:

| Attack Category | Count | Style / Source |
|-----------------|-------|----------------|
| Normal traffic | 6,000 | E-commerce + API request patterns |
| SQL Injection | 1,500 | CSIC 2010 payload variants |
| XSS | 1,500 | OWASP XSS filter evasion + reflected/stored/DOM |
| Path Traversal | 800 | Unix/Windows/encoded traversal sequences |
| Command Injection | 600 | Linux/Windows shell injection metacharacters |
| SQL Injection (Juice Shop) | 600 | OWASP Juice Shop CTF login/search bypass patterns |
| XSS (Juice Shop) | 600 | Angular template injection; iframe/postMessage XSS |
| IDOR | 500 | Object reference manipulation paths (Juice Shop) |
| HTTP Parameter Pollution | 500 | Duplicate keys, oversized values, double-encoding |
| NoSQL Injection | 400 | MongoDB operator injection |
| JWT Abuse | 300 | alg:none; RS256→HS256 confusion; claim tampering |
| SSRF | 300 | Cloud metadata endpoints; private IP ranges; non-HTTP protocols |
| XXE | 200 | XML DOCTYPE / ENTITY injection |
| **Total** | **13,800** | |

The "Juice Shop" and "HTTPParams" labels designate the *style* of the generated synthetic payloads (patterns characteristic of OWASP Juice Shop CTF challenges and HTTPParams fuzzing tool output, respectively); they do not represent data downloaded from external sources. All 13,800 samples are programmatically generated within `dataset_generator.py`.

**Sample augmentation:** `augment_labeled_samples(samples, variants_per_sample=5)` expands user-uploaded labeled requests by applying one of four transformations selected uniformly at random:

| Transform | Description |
|-----------|-------------|
| URL encoding | Percent-encode (or double-encode, with p=0.3) special characters in the query string |
| Case randomization | Randomly permute the case of SQL/XSS keywords (`UnIoN SeLeCt`) |
| Parameter reordering | Shuffle `key=value` pairs in URL query string and body |
| Comment padding | Insert SQL comment tokens (`/**/`, `--`) into payload strings |

For malicious samples (`label=1`), 30% of generated variants additionally receive a scanner-style User-Agent string.

### 8.3 Supervised Model Training (`ml/train.py`)

The training procedure:

1. **Data loading**: loads real CSIC 2010 files auto-detected from `data/` (`cisc_normalTraffic_train.txt`, `cisc_normalTraffic_test.txt`, `cisc_anomalousTraffic_test.txt`), the synthetic dataset from `generate_dataset()`, and any site-specific labeled data from `data/custom_labeled.jsonl`. Deduplication logic prevents double-counting if both raw CSIC filenames and their renamed `cisc_*` copies are present.

2. **Feature extraction**: each request is passed through `extract_features()` and `features_to_array()`, producing a matrix of shape `(N, 74)`.

3. **Train/test split**: stratified 80/20 split (`test_size=0.2`, `random_state=42`, `stratify=y`).

4. **Model competition**: two classifiers are trained and evaluated on the held-out test set:

   | Hyperparameter | RandomForestClassifier | GradientBoostingClassifier |
   |----------------|------------------------|---------------------------|
   | `n_estimators` | 300 | 200 |
   | `max_depth` | None (unlimited) | 6 |
   | `learning_rate` | — | 0.1 |
   | `subsample` | — | 0.8 |
   | `max_features` | `'sqrt'` | — |
   | `class_weight` | `'balanced'` | — |
   | `random_state` | 42 | 42 |

5. **Model selection**: the classifier with the higher AUC-ROC on the test set is retained.

6. **Artifact persistence**: the selected classifier is serialized via `joblib.dump()` to `models/waf_model.pkl`. Metrics — accuracy, precision, recall, F1, AUC, feature importances, dataset composition, and CSIC flag — are written to `models/metrics.json`.

**Note on model architecture:** the saved artifact is the bare scikit-learn estimator, not a `Pipeline` wrapper. No `StandardScaler` or other preprocessing step is applied to the feature matrix before model fitting or inference.

### 8.4 Unsupervised Baseline (`ml/unsupervised.py`)

The `BaselineModel` class implements an online-learning behavioral baseline using Isolation Forest.

**Initialization parameters:**
- `min_samples = 200`: minimum sample count before scoring activates.
- `max_samples = 10,000`: reservoir capacity; samples beyond this limit replace existing entries using reservoir sampling.
- `contamination = 0.05`: expected fraction of anomalous samples in the baseline window.

**Online learning flow:**
```
learn(feature_vector, request):
  1. Update path_freq[path] and method_freq[method] counters
  2. Append feature_vector to _samples (reservoir-sample if |_samples| >= max_samples)
  3. Increment sample_count
  4. If sample_count >= min_samples AND sample_count % 100 == 0:
       _fit()

_fit():
  1. scaler = StandardScaler().fit_transform(_samples)   → scaled_X
  2. IsolationForest(contamination=0.05, n_estimators=100,
                    max_samples=min(256, N), random_state=42).fit(scaled_X)
```

**Anomaly scoring:**
```
iso_raw    = model.decision_function(scaler.transform([fv]))[0]
iso_score  = clip(0.5 − iso_raw, 0, 1)          # inverts sign; anomaly → high
path_rarity   = clip(1 − path_count / max(total_requests × 0.01, 1), 0, 1)
method_rarity = clip(1 − method_count / max(total_requests × 0.1, 1), 0, 1)
anomaly_score = iso_score × 0.6 + path_rarity × 0.3 + method_rarity × 0.1
```

`is_anomaly = True` when `anomaly_score > 0.75`. Blocking at Stage 9 is contingent on the fused `combined_score` exceeding `combined_block_score`; the unsupervised model cannot block in isolation.

**Persistence:** `pickle.dump(state_dict, file, protocol=4)` to `models/unsupervised_baseline.pkl`. The state dictionary includes the raw sample buffer, fitted `IsolationForest` and `StandardScaler` objects, frequency maps, and counters. On restart, the saved state is restored via `BaselineModel.load()`, eliminating the need to re-accumulate the minimum sample window.

---

## 9. Supporting Components

### 9.1 Policy Engine (`app/policy.py`)

The policy engine loads and persists `config/policy.json`, which stores the operating mode, IP/path rule sets, and ML scoring thresholds. All policy mutations performed through REST endpoints or the dashboard are atomically written to disk, ensuring that the policy state survives server restarts.

**Default threshold values:**

| Threshold | Default | Semantics |
|-----------|---------|-----------|
| `ml_block_score` | 0.50 | Supervised classifier probability required to block at Stage 8 |
| `unsupervised_block_score` | 0.75 | Anomaly score required to activate Stage 9 fusion check |
| `combined_block_score` | 0.65 | Fused score required to block at Stage 9 |

**Rule evaluation order:**
1. IP allowlist (returns `allow` immediately — highest precedence)
2. IP blocklist
3. Path allowlist
4. Path blocklist
5. Default action (determined by current mode)

Path rules are compiled to regex patterns at policy load time to avoid repeated compilation overhead per request.

### 9.2 API Discovery (`app/api_discovery.py`)

The API discovery module passively constructs an endpoint inventory by recording each allowed request's normalized URL path. It normalizes paths by replacing numeric IDs with `{id}` and UUIDs with `{uuid}` using compiled regular expressions (`/\d+` and `/[0-9a-f\-]{36}` respectively), so that `/api/users/123` and `/api/users/456` map to the same schema entry `/api/users/{id}`.

For each normalized endpoint, the module maintains the set of observed HTTP methods, the set of observed query parameter names, a first-seen and last-seen timestamp, and a total request count.

**Anomaly conditions:**
1. **Method anomaly**: an HTTP method appears on a path that has received prior traffic using different methods.
2. **Parameter anomaly**: a query parameter name appears that was not previously observed on that normalized path.
3. **Probe detection**: the normalized path matches one of 14 sensitive path patterns (`/admin`, `/.env`, `/.git`, `/phpinfo`, `/actuator`, `/wp-admin`, etc.). Blocking is applied only for the first two observations of a suspicious probe path; subsequent requests are allowed to prevent repeated false positives during legitimate security scans authorized by the operator.

Stage 10 executes only for requests that were **not** blocked by Stages 0–9, as blocked requests cause an early return in `analyze()` before Stage 10 is reached. The endpoint inventory therefore reflects legitimate traffic exclusively.

### 9.3 Attack Simulator (`app/simulator.py`)

The simulator enables demonstration and validation of WAF behavior without requiring a live adversary. It runs as a FastAPI background task, generating synthetic HTTP request objects from built-in payload libraries and submitting them to `waf_engine.analyze()` with configurable inter-request delay. Each result is broadcast to dashboard clients in real time.

**Available scenarios (16 total):**

| Scenario | Description |
|----------|-------------|
| `normal` | Benign e-commerce browsing traffic |
| `sqli` | SQL injection payloads (CSIC + extended variants) |
| `xss` | Cross-site scripting (reflected, stored, DOM, obfuscated) |
| `path_traversal` | Unix/Windows path traversal sequences |
| `log4shell` | Log4Shell CVE-2021-44228 JNDI injection headers |
| `bot_scan` | Known vulnerability scanner User-Agent strings |
| `nosql` | MongoDB operator injection |
| `jwt_abuse` | JWT algorithm confusion and claim tampering |
| `ssrf` | Server-Side Request Forgery to internal/metadata endpoints |
| `xxe` | XML External Entity injection |
| `idor` | Insecure Direct Object Reference probing |
| `juice_shop` | Mixed payloads from OWASP Juice Shop CTF attack set |
| `mixed` | Approximately 60% benign traffic + 40% randomized attacks |
| `apt` | Multi-stage APT-style attack chain (reconnaissance → exploitation) |
| `ddos` | High-volume flood traffic to exercise the rate limiter |
| `full_dataset` | Random sample drawn from the complete synthetic dataset |

### 9.4 Dashboard (`static/index.html`)

The dashboard is a zero-build-step SPA served directly by FastAPI from `GET /`. It maintains a persistent WebSocket connection to `/ws` and updates all displayed data in real time as `request` and `stats_update` messages arrive. UI sections include:

- **Overview**: live request counters, traffic time-series (Chart.js), block-rate gauge, attack-type distribution donut chart.
- **Live Events**: real-time scrolling event table with per-row expansion showing all 74 feature values, blocking stage, and feature importance ranking for the decision.
- **ML Models**: model performance metrics (`accuracy`, `precision`, `recall`, `F1`, `AUC`); dynamic dataset breakdown rendered from `metrics.json`'s `attack_distribution` field; feature importance bar chart; retrain button; labeled data upload form.
- **Modules**: per-stage toggle controls for enabling/disabling individual pipeline stages.
- **API Discovery**: auto-populated endpoint inventory with schema anomaly flags.
- **Policy Manager**: mode selector; threshold sliders (hot-applied to running server); IP/path rule management with single-entry and bulk-import interfaces.
- **Simulate**: scenario launcher with configurable request count and inter-request delay.
- **Integration**: copy-paste middleware snippets for Node.js, Python, PHP, Java, Go, Nginx, Docker, and Kubernetes.

---

## 10. Evaluation Setup

### 10.1 Dataset Composition

The supervised model was trained and evaluated on a corpus combining real CSIC 2010 HTTP traffic with the synthetic dataset described in Section 8.2. The CSIC 2010 files are auto-detected from `data/` and include two normal-traffic archives and one attack-traffic archive.

**Full training corpus composition** (as recorded in `models/metrics.json` after training):

| Category | Samples | Source |
|----------|---------|--------|
| Normal traffic | 78,000 | CSIC 2010 (real HTTP logs, Tienda Virtual e-commerce) |
| SQL Injection | 27,165 | CSIC 2010 attack file + synthetic CSIC/Juice Shop variants |
| XSS | 2,100 | Synthetic |
| Path Traversal | 800 | Synthetic |
| Command Injection | 600 | Synthetic |
| IDOR | 500 | Synthetic |
| HTTP Parameter Pollution | 500 | Synthetic |
| NoSQL Injection | 400 | Synthetic |
| JWT Abuse | 300 | Synthetic |
| SSRF | 300 | Synthetic |
| XXE | 200 | Synthetic |
| **Total** | **110,865** | |

The dataset was partitioned using a stratified 80/20 split:
- **Training set**: 88,692 samples
- **Test set**: 22,173 samples

The substantially larger SQLi count (27,165 vs. the synthetic default of 2,100) reflects the addition of the real CSIC 2010 attack archive, which is predominantly SQLi, XSS, and path traversal traffic; the CSIC-derived SQLi and XSS records are assigned the `sqli` and `xss` labels respectively.

The 78,000 normal-traffic samples originate exclusively from the CSIC 2010 normal-traffic archives, representing real HTTP requests generated by human users against the Tienda Virtual e-commerce application in 2010.

### 10.2 Model Selection Procedure

The training script instantiates both `RandomForestClassifier` and `GradientBoostingClassifier` with the hyperparameters specified in Section 8.3. Both models are trained on the identical training partition and evaluated on the identical test partition. The model with the higher AUC-ROC score is selected and serialized. In the training run corresponding to the shipped `models/waf_model.pkl`, the `GradientBoostingClassifier` was selected.

### 10.3 Evaluation Metrics

Five metrics are computed on the held-out test set:

| Metric | Definition |
|--------|------------|
| Accuracy | `(TP + TN) / (TP + TN + FP + FN)` |
| Precision | `TP / (TP + FP)` — fraction of predicted positives that are true attacks |
| Recall | `TP / (TP + FN)` — fraction of actual attacks that are detected |
| F1-Score | `2 × Precision × Recall / (Precision + Recall)` — harmonic mean |
| AUC-ROC | Area under the ROC curve; threshold-independent discrimination measure |

---

## 11. Model Results

### 11.1 Headline Performance Metrics

| Metric | Score |
|--------|-------|
| Accuracy | 97.33% |
| Precision | 98.78% |
| Recall | 92.15% |
| F1-Score | 95.35% |
| AUC-ROC | 0.9968 |

These metrics reflect performance on the 22,173-sample held-out test set, which includes real CSIC 2010 HTTP traffic. The gap between Precision (98.78%) and Recall (92.15%) indicates that the model is conservative: it produces very few false positives (0.22% of legitimate requests incorrectly flagged) but misses approximately 7.85% of attack requests. This asymmetry reflects the cost structure of the deployment context, where false positives (blocking legitimate users) are operationally more disruptive than false negatives (which may be caught by downstream rule stages or unsupervised anomaly detection).

**Interpretation caveat:** the SQLi category accounts for 27,165 of the 32,865 total attack samples (82.7%), biasing the aggregate metrics toward SQLi detection performance. Per-class performance on the smaller synthetic attack categories (XXE: 200 samples, JWT: 300 samples) cannot be reliably estimated from these aggregate figures.

### 11.2 Top Feature Importances (Gradient Boosting)

The Gradient Boosting model reports normalized feature importances via `feature_importances_`. The top-ranked features from the trained model are:

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | `body_token_entropy` | 0.1284 |
| 2 | `url_entropy` | 0.1276 |
| 3 | `num_headers` | 0.0979 |
| 4 | `body_length` | 0.0674 |
| 5 | `path_length` | 0.0647 |
| 6 | `body_entropy` | 0.0647 |
| 7 | `url_depth` | 0.0595 |
| 8 | `max_param_value_length` | 0.0520 |
| 9 | `single_quotes` | 0.0499 |
| 10 | `url_length` | 0.0383 |

The prominence of entropy features (`body_token_entropy`, `url_entropy`, `body_entropy`) reflects that real CSIC 2010 normal traffic — regular HTTP form submissions to an e-commerce site — exhibits substantially lower lexical entropy than both the attack payloads (which contain encoded strings, SQL keywords, and shell metacharacters) and the synthetic normal traffic. Structural features (`num_headers`, `body_length`, `path_length`, `url_depth`) provide complementary discrimination based on request morphology rather than payload content, making the model more resistant to simple keyword-evasion techniques.

The low rank of attack-specific indicator features (e.g., `sql_keyword_count`, `has_union`, `has_script_tag`) in the Gradient Boosting model — in contrast to the Random Forest — is characteristic of boosting with moderate `max_depth`: the model learns to rely on a combination of many weak splits on continuous features rather than a small number of high-specificity binary indicators.

---

## 12. System Behavior Under Simulated Attack

The simulator described in Section 9.3 enables end-to-end validation of pipeline behavior under controlled attack conditions. Each scenario submits requests through the identical `analyze()` function used by the REST API, ensuring that simulated results are representative of live-request processing.

**Observed behavior by scenario category:**

**Single-attack scenarios** (`sqli`, `xss`, `path_traversal`, `log4shell`): Requests with high-specificity attack payloads are blocked at rule-based stages (Stages 4–7) before reaching ML inference. Log4Shell requests, for example, are detected at Stage 4 by the CVE-2021-44228 IPS signature with `confidence=1.0`. The blocking stage attribution in the result confirms that ML inference is bypassed for these cases, validating the short-circuit efficiency design.

**Bot and volumetric scenarios** (`bot_scan`, `ddos`): Scanner-identified requests are blocked at Stage 2 (Anti-Bot) on UA fingerprint match. High-rate requests from the same IP trigger Stage 1 (Rate Limiter) burst detection and placement in the 5-minute penalty box, after which subsequent requests are rejected in O(1) without counter re-evaluation.

**Normal traffic scenario**: The `normal` scenario exercises the false-positive rate. Benign e-commerce requests pass all stages; the supervised model assigns low ML scores, and the unsupervised model records them as baseline samples. The observed false-positive rate on normal-only simulation is consistent with the test-set precision of 98.78%.

**Mixed and full-dataset scenarios**: The `mixed` and `full_dataset` scenarios exercise the system on a realistic traffic distribution. Attack requests that are not caught by rule-based stages are scored by the Gradient Boosting classifier; borderline requests may additionally be escalated by the unsupervised fusion score. The dashboard renders the per-stage block attribution distribution in real time, confirming that the majority of blocks originate from rule-based stages, with ML-originated blocks comprising the residual class.

---

## 13. Comparison with open-appsec

ML-WAF reproduces the conceptual architecture of open-appsec at study scale. The following table documents similarities and intentional simplifications:

| Dimension | open-appsec | ML-WAF |
|-----------|-------------|--------|
| Core language | C++ (engine), Go (management) | Python |
| Supervised model | Global crowd-sourced corpus; algorithm undisclosed | GradientBoostingClassifier trained on CSIC 2010 + synthetic; ~110,865 samples |
| Unsupervised model | Real-time contextual model; algorithm undisclosed | scikit-learn IsolationForest; 3-component fusion score |
| Feature engineering | Proprietary; 100+ features | 74 hand-engineered features across 16 groups |
| Model selection | Internal; not exposed | Competitive training: RF vs. GB; selected by AUC |
| Policy format | YAML / Kubernetes CRDs | JSON / REST |
| Operating modes | Detect / Prevent (with learning phase) | Prevent / Detect / Monitor |
| Deployment | NGINX module, Envoy filter, K8s sidecar | Reverse proxy (`/waf_check`) or middleware (`/analyze`) |
| Rate limiting | Session/user-identity aware | Per-source IP only |
| JWT validation | Full cryptographic signature verification | Structural analysis only (no secret key access) |
| API discovery | OpenAPI schema generation and enforcement | Passive endpoint inventory; method/param anomaly flagging |
| IPS signatures | 2,800+ CVEs (Premium tier) | 18 hand-selected high-severity CVEs |
| Performance | Microsecond latency (compiled) | Low single-digit millisecond latency (Python) |
| Training metrics | Not published | AUC 0.9968, Accuracy 97.33% on CSIC 2010 + synthetic |

The principal architectural parallel is the dual-model design: a supervised classifier trained offline on a labeled corpus combined with an unsupervised model that builds a per-installation behavioral profile. This mirrors open-appsec's published description of its "preemptive" architecture, in which a globally-trained model is supplemented by a local contextual model.

---

## 14. Limitations

### 14.1 Training Data Distribution

The dominant data source is CSIC 2010 (78,000 normal + 27,165 attack records), which was generated against a single e-commerce application in 2010. The normal-traffic distribution is therefore specific to that application's URL structure, parameter naming conventions, and request volume patterns. Deployment against applications with substantially different traffic profiles may require fine-tuning or domain adaptation. The synthetic attack samples, while covering a broad attack taxonomy, are generated from fixed payload templates that do not capture the full variance of adversarial payloads observed in production.

### 14.2 Single Global Policy

All requests are evaluated against a single policy instance. Production WAF deployments typically require per-application policies with distinct thresholds and rule sets for different protected services. Implementing per-application policy scoping would require adding an application identifier to each request and maintaining a per-application policy store.

### 14.3 IP-Based Rate Limiting

Rate limits are tracked per source IP address. This approach is weakened by distributed attacks using large IP pools (botnet traffic), and may incorrectly penalize legitimate users sharing a NAT gateway or enterprise proxy. Identity-aware rate limiting using JWT sub claims or session identifiers would provide finer-grained control.

### 14.4 No JWT Signature Verification

Because the WAF does not possess the application's signing secret or public key, it cannot verify JWT signature integrity. The module detects structural anomalies (algorithm manipulation, empty signatures) but cannot detect a validly-signed token carrying manipulated claims.

### 14.5 Unsupervised Baseline Warm-Up Period

The Isolation Forest baseline requires a minimum of 200 allowed requests before it begins scoring (`min_samples=200`). During the warm-up period, `anomaly_score=0.0` is returned for all requests, and the unsupervised component contributes nothing to the combined score. On a fresh deployment receiving low-volume traffic, this warm-up period may extend for a substantial duration.

### 14.6 Python Runtime Latency

Feature extraction and model inference require O(1–5) ms per request in CPython, compared to O(1–10) μs for equivalent operations in a compiled language implementation. While acceptable for demonstrating functional correctness, this latency budget would be prohibitive in high-throughput production deployments (> 10,000 RPS). Critical paths (feature extraction, the 74-element array construction) would benefit from Cython, NumPy-vectorized batch processing, or a compiled extension module.

---

## 15. Future Work

### 15.1 Training on Real Production Traffic

The most impactful improvement would be collecting labeled HTTP logs from a live application deployment and incorporating them into the training corpus via the `POST /ml/upload_labeled` workflow. This would reduce distributional shift between training data and deployment traffic and provide a more reliable estimate of generalization performance.

### 15.2 Continuous Retraining Loop

The existing `/ml/retrain` endpoint could be extended to a periodic scheduled retraining pipeline that ingests newly accumulated labeled data, retrains the supervised model, and evaluates it against a held-out validation set before hot-loading. This would enable the supervised model to adapt to evolving traffic patterns, analogous to open-appsec's crowd-sourced learning mechanism.

### 15.3 Per-Application Policy Scoping

Adding an `app_id` field to the `RequestSnapshot` model and maintaining a per-`app_id` policy store would enable distinct threshold configurations and rule sets for different protected applications in a multi-tenant deployment.

### 15.4 Identity-Aware Rate Limiting

Extending rate limiting to use the authenticated user identity (extracted from a valid JWT `sub` claim or session token) rather than source IP would improve both fairness (for shared-IP environments) and evasion resistance (for distributed IP-pool attacks).

### 15.5 Ensemble Unsupervised Detection

Adding a second unsupervised anomaly detector — for example, a One-Class SVM or an Autoencoder trained on the normal-traffic feature distribution — and combining it with the Isolation Forest via a voting or stacking scheme would reduce the variance of the anomaly score and improve detection robustness on edge-case request profiles.

### 15.6 Performance Optimization

Moving the feature extraction hot path into a NumPy-vectorized implementation or a compiled Cython/Rust extension module would substantially reduce per-request latency and increase throughput capacity, bringing the Python implementation closer in performance to compiled WAF engines.

---

## 16. Conclusion

ML-WAF implements a complete, working Web Application Firewall that reproduces the dual-model preemptive architecture of open-appsec in a single, transparent Python service. Each HTTP request traverses a 10-stage pipeline combining seven deterministic rule-based detection modules with a supervised Gradient Boosting classifier and an online-learning Isolation Forest anomaly detector, all governed by a runtime-configurable policy engine.

The supervised model, trained on a corpus of 110,865 samples comprising real CSIC 2010 HTTP traffic and 13,800 synthetic attack records, achieves AUC-ROC 0.9968, accuracy 97.33%, and precision 98.78% on the held-out test set. The feature engineering approach — 74 hand-selected features spanning structural, entropy, injection-pattern, and behavioral dimensions — provides interpretability: every blocking decision is traceable to specific feature values and the pipeline stage that generated the block.

The implementation demonstrates that the core concepts of ML-based WAF design — supervised pre-training on labeled corpora, unsupervised per-deployment behavioral profiling, short-circuit evaluation for efficiency, and policy-driven threshold control — can be realized in a readable, self-contained codebase that exposes each design decision transparently. The limitations identified (synthetic data distribution, single global policy, IP-based rate limiting, Python latency) establish a concrete roadmap toward a production-grade implementation following the future work directions described above.
