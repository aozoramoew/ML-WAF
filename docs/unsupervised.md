# `unsupervised.py` — Isolation Forest Behavioral Baseline

## Overview

`unsupervised.py` implements the **second ML model** in the dual-engine architecture. Unlike the supervised Random Forest (which was trained offline on labeled attacks), the Isolation Forest learns what **normal traffic for your specific application** looks like — in real time, from live requests that the pipeline allowed through.

This enables detection of **zero-day attacks**: requests that don't match any known attack signature but still deviate significantly from the established behavioral baseline.

---

## Why Two Models?

| Supervised Model | Unsupervised Model |
|---|---|
| Trained offline on labeled data | Trains online from live allowed traffic |
| Knows about known attack types | Detects *anything* anomalous |
| High precision on known attacks | Can catch zero-days |
| Fixed until retrained | Continuously adapts |
| Answers: "Is this like known attacks?" | Answers: "Is this unusual for this app?" |

The final fusion in `waf_engine.py`:
```
combined_score = 0.7 × supervised_score + 0.3 × anomaly_score
```

The 70/30 weighting favours the supervised model (higher precision) while allowing the unsupervised model to escalate borderline cases.

---

## Isolation Forest Algorithm

An **Isolation Forest** detects anomalies by asking: how many random binary splits does it take to isolate this data point?

- **Normal points** are clustered together → need many splits to isolate → long path → low anomaly score
- **Anomalous points** are in sparse regions → isolated quickly → short path → high anomaly score

Key properties that make it ideal for WAF use:
- **O(n log n)** training, **O(log n)** inference — very fast
- No normality assumption — works on any feature distribution
- Scale invariant — uses feature thresholds, not distances (though a `StandardScaler` is applied before fitting for numerical stability)

---

## Online Learning Flow

The `BaselineModel` singleton accumulates samples via `learn(feature_vector, request)`, called for every request that the pipeline **allows through**:

```
1. learn(feature_vector, request) called
   ├─ Update path_freq and method_freq maps
   ├─ Append feature_vector to _samples (reservoir sampling after max_samples=10,000)
   └─ If sample_count >= min_samples AND sample_count % 100 == 0: _fit()

2. _fit()
   ├─ StandardScaler.fit_transform(_samples)
   └─ IsolationForest(contamination=0.05, n_estimators=100).fit(scaled)

3. score(feature_vector, request) → anomaly_score (0–1)
   ├─ Isolation Forest decision_function → iso_score (0=normal, 1=anomaly)
   ├─ path_rarity (how rarely this URL path appears in baseline traffic)
   ├─ method_rarity (how rarely this HTTP method appears)
   └─ Fused: iso_score×0.6 + path_rarity×0.3 + method_rarity×0.1
```

Activation threshold: **200 samples** (`min_samples`). Before that, `score()` always returns `anomaly_score=0.0` and the unsupervised stage has no effect.

---

## Anomaly Score Interpretation

| `anomaly_score` | Meaning |
|---|---|
| 0.0–0.3 | Normal — well within the learned baseline |
| 0.3–0.6 | Slightly unusual — may be a new-but-legitimate path |
| 0.6–0.75 | Suspicious — boosted in the confidence fusion |
| > 0.75 | `is_anomaly=True` — if combined score also exceeds threshold, will block |

The internal `is_anomaly` flag is set at `anomaly_score > 0.75`, but blocking only occurs when the **fused** `combined_score >= combined_block_score` (from `policy.get_thresholds()`). The unsupervised model never blocks alone.

---

## Persistence

The baseline is saved to `models/unsupervised_baseline.pkl` by calling `save_baseline()` (triggered by `POST /learn/save` from the dashboard). The saved state includes:

- All collected feature vectors (`_samples`)
- Fitted `IsolationForest` + `StandardScaler` objects
- `path_freq` and `method_freq` dictionaries
- Total request count and sample count

On server restart, `get_baseline()` calls `BaselineModel.load()` which restores this full state, so no re-learning from scratch is needed.

---

## Stats Exposed to Dashboard

`get_stats()` returns:

```python
{
    'active': True,              # False until 200 samples collected
    'samples_collected': 847,
    'min_samples_needed': 200,
    'progress_pct': 100.0,       # capped at 100
    'top_paths': [('/api/products', 312), ...],  # top 10 most-seen paths
    'method_distribution': {'GET': 620, 'POST': 227},
    'sklearn_available': True,
}
```

The dashboard shows a progress bar during the initial learning phase (0→200 samples) and a green "Active" badge once the baseline is operational.

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `app/waf_engine.py` | Stage 9: calls `baseline.score(features, request)` for anomaly scoring; calls `baseline.learn(features, request)` for every allowed request |
| `app/main.py` | `POST /learn/toggle` calls `waf_engine.set_learning(bool)`; `POST /learn/save` persists the baseline to `models/unsupervised_baseline.pkl` |
| `ml/feature_extractor.py` | The same 75-dim feature vector used by the supervised model is also fed to the Isolation Forest |
| `static/index.html` | Displays `unsupervised_score`, `path_rarity`, and `method_rarity` in the event detail modal |
| `models/unsupervised_baseline.pkl` | On-disk serialized baseline state (pickle format, protocol 4) |

---

## open-appsec Equivalent

This module directly mirrors open-appsec's **"Confidence Engine"** component — an unsupervised model that builds a per-installation behavioral profile. open-appsec's implementation uses a combination of Isolation Forest and One-Class SVM, with automatic ensemble selection based on baseline size. This implementation uses only Isolation Forest for simplicity, but the conceptual architecture is identical:

> "The system automatically builds a model of what constitutes normal behavior for the specific application it is protecting, allowing it to detect novel attacks that have never been seen before." — open-appsec documentation
