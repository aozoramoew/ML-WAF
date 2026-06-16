# `train.py` — Model Training Pipeline

## Overview

`train.py` is the **offline training script** that produces the `models/waf_model.pkl` file consumed by the live WAF engine. It automatically discovers CSIC 2010 files in `data/`, combines them with a multi-source synthetic dataset, extracts feature vectors from every sample, and trains a binary classifier (benign vs. malicious). The best model between Random Forest and Gradient Boosting is selected by AUC and saved.

Run it once before starting the server, or trigger it remotely via `POST /ml/retrain`.

---

## Data Sources

| Source | How it's loaded |
|---|---|
| **CSIC 2010 normal** (`data/cisc_normalTraffic_train.txt`, `data/cisc_normalTraffic_test.txt`) | Auto-detected in `data/`; also accepts `--csic-normal` CLI flag |
| **CSIC 2010 attack** (`data/cisc_anomalousTraffic_test.txt`) | Auto-detected in `data/`; also accepts `--csic-attack` CLI flag |
| **Synthetic dataset** | Always generated via `dataset_generator.generate_dataset()` |
| **Custom labeled data** | `data/custom_labeled.jsonl` — loaded via `POST /ml/upload_labeled` |

Real CSIC 2010 files are preferred over synthetic-only training. When both a raw CSIC file (e.g., `normalTrafficTraining.txt`) and its `cisc_`-prefixed copy exist, only one is used to avoid double-counting.

---

## Training Pipeline

```
1. Auto-discover CSIC 2010 files in data/
   (falls back to synthetic-only if none found)

2. Load and merge all requests into a unified list of dicts
   [{method, url, headers, body, label, attack_type}, ...]
   Sources merged in order:
     a. CSIC 2010 normal traffic  (label=0)
     b. CSIC 2010 attack traffic  (label=1, attack_type='sqli')
     c. Synthetic multi-category dataset
     d. Custom uploaded labeled data (data/custom_labeled.jsonl)

3. Feature extraction
   For each request → feature_extractor.extract_features() → 75-dim float32 vector

4. Train/test split (80/20, stratified by label)

5. Model selection — both trained in parallel:
   ├─ RandomForestClassifier (n_estimators=300, class_weight='balanced')
   └─ GradientBoostingClassifier (n_estimators=200, max_depth=6, lr=0.1)
   Best model chosen by AUC-ROC on the test split.

6. Evaluation (printed + saved)
   ├─ Accuracy, Precision, Recall, F1
   ├─ ROC-AUC score
   └─ Classification report (per-class)

7. Persist
   ├─ models/waf_model.pkl   (winning classifier via joblib)
   └─ models/metrics.json    (metrics + feature importances + data stats)
```

---

## Model Architecture

The saved model is a **bare scikit-learn estimator** (not a Pipeline) — either `RandomForestClassifier` or `GradientBoostingClassifier`, whichever achieved the higher AUC on the test split. With the CSIC 2010 data included, Gradient Boosting typically wins.

### Why no StandardScaler?

Random Forest and Gradient Boosting are **tree-based** and scale-invariant — they split on thresholds, not distances, so scaling provides no benefit. No scaler is used.

### Model hyperparameters

**Random Forest** (baseline):
```python
RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    max_features='sqrt',
    class_weight='balanced',
    n_jobs=-1,
    random_state=42,
)
```

**Gradient Boosting** (typically wins with real CSIC data):
```python
GradientBoostingClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    random_state=42,
)
```

`class_weight='balanced'` in Random Forest automatically upweights minority classes (attacks), which is critical when real CSIC normal traffic outnumbers attack traffic.

---

## Realistic Metrics (with CSIC 2010 data)

When trained on the full dataset (real CSIC + synthetic), representative results:

```
Best model: Gradient Boosting  (AUC=0.9968)
  Accuracy : 97.33%
  Precision: 98.78%
  Recall   : 92.15%
  F1-Score : 95.35%
  AUC-ROC  : 0.9968
```

`models/metrics.json` records `used_real_csic: true` when CSIC files were included, and `custom_samples` with the count from `data/custom_labeled.jsonl`.

> **Previous AUC=1.0 / 99.96% metrics were synthetic-only overfit.** Training on real CSIC data where normal and attack patterns genuinely overlap produces the realistic ~97% accuracy figures above. This is the correct benchmark to present.

---

## Metrics JSON Schema

```json
{
  "model_name": "Gradient Boosting",
  "accuracy": 0.9733,
  "precision": 0.9878,
  "recall": 0.9215,
  "f1": 0.9535,
  "auc": 0.9968,
  "n_train": 88692,
  "n_test": 22174,
  "n_features": 75,
  "feature_names": ["url_length", "path_length", ...],
  "feature_importances": {
    "sql_keyword_count": 0.089,
    "url_entropy": 0.072,
    ...
  },
  "attack_distribution": {"normal": 6000, "sqli": 2100, ...},
  "used_real_csic": true,
  "custom_samples": 0
}
```

This file is served by `GET /model/info` and rendered in the dashboard's **ML Models** tab.

---

## How to Run

```bash
# Auto-detects CSIC files in data/ (recommended):
python -m ml.train

# Explicit file paths:
python -m ml.train \
  --csic-normal data/cisc_normalTraffic_train.txt \
  --csic-attack data/cisc_anomalousTraffic_test.txt

# Trigger remotely from dashboard or API (background task):
POST /ml/retrain
```

CSIC files currently in `data/`:
- `data/cisc_normalTraffic_train.txt`
- `data/cisc_normalTraffic_test.txt`
- `data/cisc_anomalousTraffic_test.txt`

These are auto-detected; no CLI flags needed for a standard run.

---

## Custom Labeled Data Upload

Site-specific labeled requests can be uploaded via `POST /ml/upload_labeled` (JSON/CSV/JSONL). They are:

1. Validated (must have `label` field = 0 or 1)
2. Augmented by `dataset_generator.augment_labeled_samples()` into 5× variants per sample
3. Appended to `data/custom_labeled.jsonl`
4. Loaded by `load_custom_labeled_data()` on the next `ml.train` run

The `metrics.json` key `custom_samples` records how many were included.

---

## Interaction with Other Files

| File | Relationship |
|---|---|
| `ml/feature_extractor.py` | Provides `extract_features()` and `features_to_array()` |
| `ml/dataset_generator.py` | Provides `generate_dataset()`, `parse_csic_2010()`, `augment_labeled_samples()` |
| `app/waf_engine.py` | Loads the trained `models/waf_model.pkl` at startup (lazy) |
| `app/main.py` | Triggers `subprocess.run([sys.executable, '-m', 'ml.train'])` via `POST /ml/retrain` |
| `data/custom_labeled.jsonl` | Site-specific labeled data, written by `POST /ml/upload_labeled` |

---

## open-appsec Equivalent

open-appsec trains its supervised model centrally on aggregated traffic from all deployments (crowd-sourced learning). The model is distributed as a binary update. This implementation trains locally. To replicate the crowd-sourced model, you would:

1. Collect request logs from the live `/analyze` endpoint
2. Label them (human review or user feedback)
3. Upload via `POST /ml/upload_labeled`
4. Trigger `POST /ml/retrain`

The `POST /ml/retrain` endpoint enables this loop without downtime.
