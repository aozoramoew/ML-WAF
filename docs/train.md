# `train.py` — Model Training Pipeline

## Overview

`train.py` is the **offline training script** that produces the `models/waf_model.pkl` file consumed by the live WAF engine. It combines real CSIC 2010 data (if available) with a diverse range of datasets (OWASP Juice Shop, HTTPParams, NoSQL/JWT/SSRF/XXE/IDOR datasets) and a massive mix of **normal, benign user traffic**. It extracts feature vectors from every sample and trains a Random Forest classifier. Mixing in actual normal requests ensures the model accurately identifies legitimate traffic and lets it pass through without false positives.

Run it once before starting the server, or trigger it remotely via `POST /ml/retrain`.

---

## Training Pipeline

```
1. Discover and fuse data sources
   ├─ Real CSIC 2010 data (if available in data/)
   ├─ OWASP Juice Shop payloads (XSS, auth bypass, SSRF)
   ├─ HTTPParams fuzzing dataset (parameter pollution)
   ├─ NoSQL/JWT/SSRF/XXE/IDOR synthetic datasets
   └─ **Normal Traffic**: Actual user requests, benign simulated traffic, and known-good e-commerce patterns (mixed in heavily to ensure the ML detects actual requests and lets them pass through)

2. Load and merge all requests into a unified list of dicts
   [{method, url, headers, body, label, attack_type}, ...]

3. Feature extraction
   For each request → feature_extractor.extract_features() → 75-dim vector

4. Train/test split (80/20, stratified by class)

5. Model training
   ├─ Primary: RandomForestClassifier (n_estimators=300)
   └─ Comparison: GradientBoostingClassifier (optional, slower)

6. Evaluation
   ├─ Accuracy, Precision, Recall, F1
   ├─ ROC-AUC score
   ├─ Classification report by attack type
   └─ Confusion matrix

7. Persist
   ├─ models/waf_model.pkl  (sklearn Pipeline: scaler + classifier)
   └─ models/metrics.json   (all metrics + feature importances + names)
```

---

## Model Architecture

The saved model is a **scikit-learn Pipeline**:

```python
Pipeline([
    ('scaler', StandardScaler()),
    ('clf', RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42,
    ))
])
```

### Why Random Forest?

| Property | Relevance |
|---|---|
| **Handles mixed features** | Some features are counts (integers), some are ratios (0–1), some are binary flags. RF handles this without needing careful normalization. |
| **Built-in feature importance** | We get `feature_importances_` for free, powering the dashboard's importance chart. |
| **Fast inference** | A 300-tree forest can score one request in ~1ms. |
| **Resistant to overfitting** | With 300 trees and `min_samples_leaf=2`, the model generalises well even on imbalanced datasets. |
| **`class_weight='balanced'`** | Automatically upweights minority classes — critical because attack samples are often fewer than normal traffic. |

### Why StandardScaler?

Even though Random Forests are scale-invariant (they use thresholds, not distances), the scaler is included for two reasons:
1. The same Pipeline object can be swapped for SVM or Logistic Regression without changing the downstream code.
2. The scaler normalises features for potential future ensemble with the Isolation Forest (which is distance-based and *is* sensitive to scale).

---

## Evaluation Outputs

After training, the script prints:

```
[Metrics] Test Set Results:
  Accuracy:  99.8%
  Precision: 99.9%
  Recall:    99.7%
  F1-Score:  99.8%
  AUC-ROC:   1.0000

[Report] Per-class:
  normal          precision=1.00 recall=1.00 f1=1.00
  sqli            precision=1.00 recall=1.00 f1=1.00
  xss             precision=0.99 recall=1.00 f1=0.99
  ...
```

> **Note on 100% metrics**: The synthetic dataset is generated with deterministic patterns, so the model memorises them perfectly. Real-world performance on live traffic will be lower — typically 95–99% precision depending on threshold tuning. The CSIC 2010 real data provides a more realistic benchmark.

---

## Metrics JSON Schema

```json
{
  "model_name": "RandomForestClassifier",
  "accuracy": 0.998,
  "precision": 0.999,
  "recall": 0.997,
  "f1": 0.998,
  "auc": 1.0,
  "n_train": 11040,
  "n_test": 2760,
  "n_features": 75,
  "feature_names": ["url_length", "url_entropy", ...],
  "feature_importances": {
    "url_entropy": 0.124,
    "sql_keyword_count": 0.089,
    ...
  },
  "attack_type_distribution": {"sqli": 2100, "xss": 1800, ...},
  "used_real_csic": true
}
```

This file is served by `GET /model/info` and rendered in the dashboard's ML Models tab.

---

## How to Run

```bash
# Minimal (synthetic data only):
python -m ml.train

# With real CSIC 2010 dataset:
python -m ml.train \
  --csic-normal data/normalTrafficTraining.txt \
  --csic-attack data/anomalousTrafficTest.txt

# Trigger from dashboard (runs in FastAPI background task):
POST /ml/retrain
```

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `ml/feature_extractor.py` | Provides `extract_features()` and `features_to_array()` |
| `ml/dataset_generator.py` | Provides `generate_dataset()` and `parse_csic_2010()` |
| `app/waf_engine.py` | Loads the trained `models/waf_model.pkl` at startup |
| `app/main.py` | Triggers `subprocess.run([sys.executable, '-m', 'ml.train'])` via `/ml/retrain` |

---

## open-appsec Equivalent

open-appsec trains its supervised model centrally on aggregated traffic from all deployments (crowd-sourced learning). The model is distributed as a binary update. This implementation trains locally. To replicate the crowd-sourced model, you would:
1. Collect request logs from the live `/analyze` endpoint
2. Label them (human review or user feedback)
3. Merge with the existing training set
4. Re-run `ml.train`

The `POST /ml/retrain` endpoint enables this loop without downtime.
