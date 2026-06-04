# `unsupervised.py` — Isolation Forest Behavioral Baseline

## Overview

`unsupervised.py` implements the **second ML model** in the dual-engine architecture. Unlike the supervised Random Forest (which was trained offline on labeled attacks), the Isolation Forest learns what **normal traffic for your specific application** looks like — in real time, from live requests.

This enables detection of **zero-day attacks**: requests that look structurally unlike any known attack but still deviate significantly from the established baseline.

---

## Why Two Models?

| Supervised Model | Unsupervised Model |
|---|---|
| Trained offline on labeled data | Trains online from live traffic |
| Knows about known attack types | Detects *anything* anomalous |
| High precision on known attacks | Can catch zero-days |
| Fixed after training | Continuously adapts |
| Answers: "Is this like known attacks?" | Answers: "Is this unusual for this app?" |

The final decision combines both scores:
```
combined = 0.7 × supervised_score + 0.3 × unsupervised_score
```

The 70/30 weighting favours the supervised model (higher precision) while still allowing the unsupervised model to escalate borderline cases.

---

## Isolation Forest Algorithm

An **Isolation Forest** detects anomalies by asking: how many random binary splits does it take to isolate this data point?

- **Normal points** are clustered together → need many splits to isolate → high `path_length` → low anomaly score
- **Anomalous points** are in sparse regions → few splits needed to isolate → short `path_length` → high anomaly score

```
anomaly_score(x) = 2^(- E[path_length(x)] / c(n))
```

Where `c(n)` is the expected path length for a random sample of size `n`.

Key properties that make it ideal for WAF use:
- **O(n log n)** training, **O(log n)** inference — very fast
- **No normality assumption** — works on any feature distribution
- **Scale invariant** — path length is structure-based, not distance-based

---

## Online Learning Architecture

The baseline is not trained once — it **accumulates samples continuously** from live traffic:

```
1. Request arrives
2. waf_engine.analyze() calls baseline.update(feature_vector) [if learning enabled]
3. feature_vector added to rolling buffer (max 10,000 samples)
4. If buffer size >= min_samples_needed (200): refit Isolation Forest
5. Mark baseline as 'active' — anomaly scoring now enabled
```

### Why 200 Samples?

200 is the minimum to get a statistically meaningful baseline without overfitting to a tiny sample. In practice, you'd want 1,000–5,000 samples for a production deployment.

### Refit Frequency

The Isolation Forest is refitted **every 100 new samples** (configurable). This balances freshness against the CPU cost of retraining.

---

## Scoring

```python
def score(feature_vector: np.ndarray) -> float:
    """
    Returns anomaly score in [0, 1].
    0 = completely normal
    1 = highly anomalous
    """
    if not self.active:
        return 0.0
    raw = self.model.decision_function([feature_vector])[0]
    # Isolation Forest returns negative for anomalies
    # Normalise to [0,1] where 1 = most anomalous
    return float(np.clip(-raw, 0, 1))
```

The `decision_function` returns negative values for anomalies. We negate and clip to [0,1] for interpretability.

---

## Persistence

The baseline is saved periodically to `models/baseline.pkl`:

```python
def save_baseline():
    joblib.dump(baseline, 'models/baseline.pkl')
```

This means the WAF doesn't need to re-learn from scratch after a server restart. The dashboard's **ML Models** tab exposes a "Save Baseline" button that triggers `POST /learn/save`.

---

## Stats and Progress

```python
{
    'samples_collected': 847,
    'min_samples_needed': 200,
    'active': True,
    'progress_pct': 100.0,
    'last_refit': 1717420000.0
}
```

The dashboard renders a progress bar during the initial learning phase (0–200 samples) and shows "✅ Active" once the baseline is operational.

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `app/waf_engine.py` | Stage 9: calls `baseline.score(features)` and `baseline.update(features)` |
| `app/main.py` | `POST /learn/toggle` calls `set_learning()`, `POST /learn/save` calls `save_baseline()` |
| `ml/feature_extractor.py` | The same 75-dim feature vector used by the supervised model is also fed to the Isolation Forest |
| `static/index.html` | Displays `unsupervised_score` in the event detail modal |

---

## open-appsec Equivalent

This module directly mirrors open-appsec's **"Confidence Engine"** component — an unsupervised model that builds a per-installation behavioral profile. open-appsec's implementation uses a combination of Isolation Forest and One-Class SVM, with automatic ensemble selection based on baseline size. This implementation uses only Isolation Forest for simplicity, but the conceptual architecture is identical:

> "The system automatically builds a model of what constitutes normal behavior for the specific application it is protecting, allowing it to detect novel attacks that have never been seen before." — open-appsec documentation
