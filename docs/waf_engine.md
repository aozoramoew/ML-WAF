# `waf_engine.py` — Core ML Pipeline Orchestrator

## Overview

`waf_engine.py` is the **heart of ML-WAF**. Every HTTP request that the system evaluates flows through this file. It implements a **10-stage sequential pipeline** where each stage acts as a gatekeeper — if any stage decides to block a request, the pipeline short-circuits and no further stages run.

This mirrors the open-appsec "context engine" architecture, where rule-based engines run before the ML model to catch high-confidence known attacks cheaply, saving the expensive model inference for ambiguous cases.

---

## Pipeline Architecture

```
app/main.py  (POST /analyze  or  ANY /waf_check)
    │
    ▼
waf_engine.analyze(request_data)
    │
    ├─ Stage 0: policy.check_request()   — IP/path allow/blocklists (short-circuits to ALLOW or BLOCK)
    │
    ├─ Feature extraction (runs here, before any blocking stage)
    │   extract_features(request_data) → feature_dict + feature_arr
    │   Used by: ML stages, _infer_attack_type() for every blocking stage below
    │
    ├─ Stage 1: rate_limiter.check()     — Token-bucket IP rate limiting
    ├─ Stage 2: anti_bot.check()         — User-Agent bot fingerprinting
    ├─ Stage 3: crowd_wisdom.check()     — IP reputation (async)
    ├─ Stage 4: ips_engine.check()       — CVE/exploit signature matching
    ├─ Stage 5: file_security.check()    — Magic-byte + EICAR detection
    ├─ Stage 6: nosql_injection.check()  — MongoDB operator injection
    ├─ Stage 7: jwt_abuse.check()        — JWT tampering + alg:none
    │
    ├─ Stage 8: Supervised ML
    │   model.predict_proba(feature_arr) → ml_score
    │   Block if ml_score >= policy.get_thresholds()['ml_block_score']
    │
    ├─ Stage 9: Unsupervised ML (Isolation Forest)
    │   baseline.score(feature_vec) → anomaly_score
    │   If anomaly_score >= unsupervised_block_score:
    │     combined = 0.7*ml_score + 0.3*anomaly_score
    │     Block if combined >= combined_block_score
    │
    └─ Stage 10: api_discovery.record()  — Passive endpoint mapping (non-blocking)
         If allowed: baseline.learn(feature_vec) — online unsupervised learning
```

---

## Key Design Decisions

### Feature Extraction Before Stage 1

Feature extraction (`extract_features`) runs **immediately after the policy check**, before any rule-based blocking stage. This serves two purposes:

1. When any early stage (IPS, rate limiter, etc.) blocks a request, `_infer_attack_type(features)` uses the already-computed feature vector to produce a specific attack type label (`sqli`, `xss`, `cmd_injection`, etc.) rather than a generic `ips_match`.
2. The full feature dict is included in every response, powering the "Why was this blocked?" explanation in the dashboard modal.

### Threshold-Driven ML Decisions

All three ML decision thresholds are read from the policy at decision time — they are **not hardcoded**:

```python
ml_block_score          = policy.get_thresholds().get('ml_block_score', 0.90)
unsupervised_block_score = policy.get_thresholds().get('unsupervised_block_score', 0.75)
combined_block_score     = policy.get_thresholds().get('combined_block_score', 0.85)
```

Default values in `config/policy.json` are `0.50 / 0.75 / 0.65`. Adjust via `PUT /policy/thresholds` or the dashboard Policy tab sliders. A test (`test_ml_block_score_threshold_is_honored`) verifies that changing these values changes the decision.

### Confidence Fusion (Stage 9)

The unsupervised model does not block independently — it only tips the decision when its anomaly score exceeds `unsupervised_block_score` **and** the fused score exceeds `combined_block_score`:

```
combined_score = 0.7 × ml_score + 0.3 × anomaly_score
block = combined_score >= combined_block_score
```

This mirrors open-appsec's two-phase confidence scoring: supervised is the primary signal (trained on global patterns), unsupervised adds environment-specific context.

### Policy Modes

The `_finalize()` function respects the current policy mode:

- **`prevent`** — `decision: BLOCK`, stats incremented as blocked.
- **`detect` / `monitor`** — `decision: ALLOW`, `would_block: true` added to result. Attack counts still increment so the dashboard shows what *would* have been blocked.

### Rule-Based Fallback

When `models/waf_model.pkl` hasn't been trained yet, Stage 8 falls back to `_rule_based_check(features)` — a simple threshold check on `sql_keyword_count`, `xss_pattern_count`, etc. This allows the server to run (with reduced accuracy) before training.

---

## Two Entry Points

### `POST /analyze` — Full JSON response

Returns a detailed dict with `decision`, `confidence`, `attack_type`, `blocked_by`, `modules` (per-stage results), `features`, `ml_score`, and `unsupervised_score`. Always returns HTTP 200 regardless of the WAF decision — the caller must check the `decision` field.

### `ANY /waf_check` — Status-code-only response

Purpose-built for nginx `auth_request` (and similar proxy auth gates). Returns:
- **HTTP 200** — request is allowed
- **HTTP 403** — request is blocked

Reads the original request from forwarded headers (`X-Original-URI`, `X-Original-Method`, `X-Real-IP`). This is the recommended reverse-proxy integration pattern — see `docs/integration_guide.md`.

---

## Exported Interface

| Function | Purpose |
|---|---|
| `analyze(request_data)` | Main async entry point. Returns full decision dict. |
| `get_stats()` | Aggregate counters: total, blocked, allowed, by attack type, by module. |
| `get_metrics()` | Training metrics from `models/metrics.json`. |
| `reset_stats()` | Zeroes all counters. |
| `load_models()` | Hot-reloads `waf_model.pkl` from disk after retraining. |
| `set_learning(bool)` | Enables/disables unsupervised baseline online learning. |
| `is_learning()` | Returns current learning state. |
| `is_model_loaded()` | Returns True if the ML model is in memory. |

---

## Statistics Tracked

```python
_stats = {
    'total': 0,
    'blocked': 0,
    'allowed': 0,
    'attack_counts': {},   # {attack_type: count}
    'blocked_by': {},      # {pipeline_stage: count}
    'req_history': [],     # [{t: timestamp, blocked: bool}] — last 300 entries
}
```

`get_stats()` adds derived fields: `block_rate`, `threat_level`, `model_loaded`, `learning_enabled`, and the unsupervised baseline stats.

`threat_level` is derived from block rate:
- `< 10%` → `low`
- `10–30%` → `medium`
- `30–50%` → `high`
- `> 50%` → `critical`

In detect/monitor mode, `would_block` events still increment `attack_counts` and `blocked_by`, so the dashboard shows realistic threat data even when not actively blocking.

---

## open-appsec Equivalent

In open-appsec, this role is performed by the **"Nano Agent"** — a C++ library that runs inside the protected process and evaluates each request. The architecture is identical: a rule-based pre-filter followed by ML model inference, with a confidence fusion step combining supervised and unsupervised scores. The key difference is that open-appsec's model runs as a shared library in-process for sub-millisecond latency, while this implementation runs as an async Python function within FastAPI (~1–5ms per request).
