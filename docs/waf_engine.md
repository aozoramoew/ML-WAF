# `waf_engine.py` — Core ML Pipeline Orchestrator

## Overview

`waf_engine.py` is the **heart of ML-WAF**. Every HTTP request that the system evaluates flows through this file. It implements a **10-stage sequential pipeline** where each stage acts as a gatekeeper — if any stage decides to block a request, the pipeline short-circuits and no further stages run.

This mirrors the open-appsec "context engine" architecture, where contextual rule engines run before the ML model to catch high-confidence known attacks cheaply, saving the expensive model inference for ambiguous cases.

---

## How It Fits Into the System

```
app/main.py
    │
    │  calls
    ▼
waf_engine.analyze(request_data)
    │
    ├─ Stage 1: rate_limiter.check(ip)
    ├─ Stage 2: anti_bot.check(user_agent)
    ├─ Stage 3: crowd_wisdom.check(ip)
    ├─ Stage 4: ips_engine.check(url, headers, body)
    ├─ Stage 5: file_security.check(headers, body)
    ├─ Stage 6: nosql_injection.check(url, body)
    ├─ Stage 7: jwt_abuse.check(headers)
    ├─ Stage 8: ML Supervised (feature_extractor → Random Forest)
    ├─ Stage 9: ML Unsupervised (Isolation Forest)
    └─ Stage 10: api_discovery.record() [non-blocking, always runs]
```

The final result is broadcast as a JSON message via WebSocket to all connected dashboard clients.

---

## Key Design Decisions

### Lazy Model Loading

The Random Forest model (`models/waf_model.pkl`) is loaded once on first request, not at import time. This avoids slowing down server startup and allows the retrain-and-reload flow to work without restart.

```python
def get_model():
    global _model
    if _model is None:
        _load_model()
    return _model
```

### Short-Circuit Evaluation

The pipeline iterates through stages and returns immediately on the first `block=True`. This is critical for performance — cheap signature checks run first, and the expensive ML inference only runs when all rule-based checks pass.

```python
for stage_name, stage_fn in PIPELINE:
    result = await stage_fn(request_data)
    if result.get('block'):
        decision = 'BLOCK'
        blocked_by = stage_name
        break
```

### Confidence Fusion

When the ML model scores a request, the final block decision is made by combining:
- `ml_score` — probability from the supervised Random Forest (0–1)
- `unsupervised_score` — anomaly score from Isolation Forest (0–1)
- Thresholds from `policy.get_thresholds()`

```
final_score = 0.7 * ml_score + 0.3 * unsupervised_score
block = final_score >= combined_block_score threshold
```

This is equivalent to open-appsec's weighted confidence fusion between its supervised and unsupervised models.

### Feature Inclusion in Result

Every WAF decision includes the raw feature vector that was computed for the request. This powers the **"Why was this blocked?" explanation** in the dashboard modal.

---

## Exported Interface

| Function | Purpose |
|---|---|
| `analyze(request_data)` | Main async entry point. Returns full decision dict. |
| `get_stats()` | Returns aggregate counters (total, blocked, allowed, by-attack-type, by-module). |
| `get_metrics()` | Returns training metrics from `models/metrics.json`. |
| `reset_stats()` | Zeroes all counters. |
| `load_models()` | Hot-reloads the `.pkl` model from disk after retraining. |
| `set_learning(bool)` | Enables/disables unsupervised baseline learning. |

---

## open-appsec Equivalent

In open-appsec, this role is performed by the **"Nano Agent"** — a C++ library that runs inside the protected process and evaluates each request. The architecture is the same: a rule-based pre-filter followed by ML model inference. The key difference is that open-appsec's model runs as a shared library in-process, while this implementation runs as an async Python function within FastAPI.

---

## Statistics Tracked

```python
_stats = {
    'total': 0,
    'blocked': 0,
    'allowed': 0,
    'attack_counts': {},   # per attack type
    'blocked_by': {},      # per pipeline stage
    'threat_level': 'low'
}
```

`threat_level` is derived dynamically from the block rate:
- `< 10%` → `low`
- `10–30%` → `medium`
- `30–60%` → `high`
- `> 60%` → `critical`
