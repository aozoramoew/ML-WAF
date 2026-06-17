"""
ML-WAF Training Script — trains on CSIC 2010 (if available) + synthetic data.

Usage:
    python -m ml.train
    python -m ml.train --csic-normal data/normalTrafficTraining.txt \\
                       --csic-attack data/anomalousTrafficTest.txt

CSIC 2010 download: http://www.isi.csic.es/dataset/
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from typing import Optional

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, precision_recall_fscore_support,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Ensure project root is on path when run from any directory
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from ml.feature_extractor import extract_features, features_to_array, FEATURE_NAMES
from ml.dataset_generator import generate_dataset, parse_csic_2010

MODEL_DIR = ROOT / 'models'
DATA_DIR  = ROOT / 'data'
MODEL_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_custom_labeled_data() -> list:
    """Load site-specific labeled requests uploaded via /ml/upload_labeled, if any."""
    custom_path = DATA_DIR / 'custom_labeled.jsonl'
    if not custom_path.exists():
        return []

    requests = []
    with open(custom_path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            requests.append(json.loads(line))

    print(f"  [Custom] Loaded {len(requests)} requests from {custom_path}")
    return requests


def load_all_data(csic_normal: list, csic_attack: list) -> list:
    """Combine real CSIC 2010 data with synthetic data and any uploaded custom data."""
    all_requests = []

    # 1. Real CSIC 2010 normal traffic
    for path in csic_normal:
        all_requests.extend(parse_csic_2010(path, label=0, attack_type='normal'))

    # 2. Real CSIC 2010 attack traffic
    for path in csic_attack:
        all_requests.extend(parse_csic_2010(path, label=1, attack_type='sqli'))

    # 3. Always add synthetic data (more diversity of attack types)
    syn_df = generate_dataset()
    all_requests.extend(syn_df.to_dict('records'))

    # 4. Site-specific labeled data uploaded via /ml/upload_labeled
    all_requests.extend(load_custom_labeled_data())

    print(f"\n[Data] Total samples loaded: {len(all_requests)}")
    return all_requests


def build_feature_matrix(requests: list):
    X, y, types = [], [], []
    errors = 0
    for i, req in enumerate(requests):
        try:
            f = extract_features(req)
            X.append(features_to_array(f))
            y.append(int(req.get('label', 0)))
            types.append(req.get('attack_type', 'unknown'))
        except Exception as e:
            errors += 1
        if (i + 1) % 2000 == 0:
            print(f"  Features: {i+1}/{len(requests)} processed...")
    if errors:
        print(f"  Warning: {errors} requests skipped due to errors.")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32), types


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

def train_models(X_train, X_test, y_train, y_test):
    """Train Random Forest + Gradient Boosting, return best model."""

    candidates = {
        'Random Forest': RandomForestClassifier(
            n_estimators=300, max_depth=12, min_samples_split=10,
            min_samples_leaf=5, max_features='sqrt',
            n_jobs=-1, random_state=42, class_weight='balanced',
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.1,
            min_samples_leaf=5, subsample=0.8, random_state=42,
        ),
    }

    results = {}
    for name, clf in candidates.items():
        print(f"\n[Train] {name}...")
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]
        train_acc = float(clf.score(X_train, y_train))

        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
        acc = float((y_pred == y_test).mean())
        auc = roc_auc_score(y_test, y_prob)

        print(f"  Train Accuracy : {train_acc:.4f}  (vs. Test below — large gap = overfitting)")
        print(f"  Accuracy : {acc:.4f}")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall   : {rec:.4f}")
        print(f"  F1-Score : {f1:.4f}")
        print(f"  AUC-ROC  : {auc:.4f}")
        print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

        results[name] = dict(
            clf=clf, accuracy=acc, precision=float(prec),
            recall=float(rec), f1=float(f1), auc=float(auc),
        )

    best_name = max(results, key=lambda k: results[k]['auc'])
    print(f"\n[Train] Best model: {best_name}  (AUC={results[best_name]['auc']:.4f})")
    return results, best_name


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='ML-WAF model trainer')
    parser.add_argument('--csic-normal', default=None,
                        help='Path to CSIC 2010 normalTrafficTraining.txt')
    parser.add_argument('--csic-attack', default=None,
                        help='Path to CSIC 2010 anomalousTrafficTest.txt')
    args = parser.parse_args()

    # Auto-detect CSIC files from data/ dir if not specified
    NORMAL_CANDIDATES = [
        'normalTrafficTraining.txt', 'normalTrafficTest.txt',
        'cisc_normalTraffic_train.txt', 'cisc_normalTraffic_test.txt',
    ]
    ATTACK_CANDIDATES = [
        'anomalousTrafficTest.txt', 'cisc_anomalousTraffic_test.txt',
    ]

    if args.csic_normal:
        csic_normal = [args.csic_normal]
    else:
        csic_normal = [str(DATA_DIR / f) for f in NORMAL_CANDIDATES if (DATA_DIR / f).exists()]
        # cisc_normalTraffic_*.txt are renamed copies of normalTrafficTraining/Test.txt —
        # include only one copy of each to avoid double-counting.
        if str(DATA_DIR / 'normalTrafficTraining.txt') in csic_normal \
                and str(DATA_DIR / 'cisc_normalTraffic_train.txt') in csic_normal:
            csic_normal.remove(str(DATA_DIR / 'cisc_normalTraffic_train.txt'))
        if str(DATA_DIR / 'normalTrafficTest.txt') in csic_normal \
                and str(DATA_DIR / 'cisc_normalTraffic_test.txt') in csic_normal:
            csic_normal.remove(str(DATA_DIR / 'cisc_normalTraffic_test.txt'))

    if args.csic_attack:
        csic_attack = [args.csic_attack]
    else:
        csic_attack = [str(DATA_DIR / f) for f in ATTACK_CANDIDATES if (DATA_DIR / f).exists()]
        # Avoid double-counting the same dataset in both raw and wrapped form
        if str(DATA_DIR / 'anomalousTrafficTest.txt') in csic_attack \
                and str(DATA_DIR / 'cisc_anomalousTraffic_test.txt') in csic_attack:
            csic_attack.remove(str(DATA_DIR / 'cisc_anomalousTraffic_test.txt'))

    print("=" * 65)
    print("  ML-WAF — Model Training")
    print("=" * 65)
    if csic_normal or csic_attack:
        print(f"  CSIC Normal : {csic_normal}")
        print(f"  CSIC Attack : {csic_attack}")
    else:
        print("  No CSIC 2010 files found — using synthetic data only.")
        print("  To use real data, place files in the data/ directory:")
        print("    data/normalTrafficTraining.txt")
        print("    data/anomalousTrafficTest.txt")

    # ── Load data ──────────────────────────────────────────────────
    requests = load_all_data(csic_normal, csic_attack)

    print("\n[Features] Extracting feature vectors...")
    X, y, attack_types = build_feature_matrix(requests)

    # Class distribution
    unique, counts = np.unique(y, return_counts=True)
    print("\n[Data] Class distribution:")
    for cls, cnt in zip(unique, counts):
        label = 'Benign' if cls == 0 else 'Malicious'
        print(f"  {label}: {cnt:,}  ({cnt/len(y)*100:.1f}%)")

    # ── Split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"\n[Split] Train: {len(X_train):,}  Test: {len(X_test):,}")

    # ── Train ──────────────────────────────────────────────────────
    results, best_name = train_models(X_train, X_test, y_train, y_test)
    best = results[best_name]
    model = best['clf']

    # ── Save model ─────────────────────────────────────────────────
    model_path = MODEL_DIR / 'waf_model.pkl'
    joblib.dump(model, model_path)
    print(f"\n[Save] Model → {model_path}")

    # ── Feature importances ────────────────────────────────────────
    fi = {}
    if hasattr(model, 'feature_importances_'):
        pairs = sorted(
            zip(FEATURE_NAMES, model.feature_importances_.tolist()),
            key=lambda x: x[1], reverse=True,
        )
        fi = {k: round(v, 6) for k, v in pairs}

    # ── Save metrics ───────────────────────────────────────────────
    # Attack type distribution across the full dataset (train + test)
    attack_dist: dict = {}
    for t in attack_types:
        attack_dist[t] = attack_dist.get(t, 0) + 1

    metrics = {
        'model_name': best_name,
        'accuracy': round(best['accuracy'], 4),
        'precision': round(best['precision'], 4),
        'recall': round(best['recall'], 4),
        'f1': round(best['f1'], 4),
        'auc': round(best['auc'], 4),
        'n_features': len(FEATURE_NAMES),
        'feature_names': FEATURE_NAMES,
        'feature_importances': fi,
        'n_train': int(len(X_train)),
        'n_test': int(len(X_test)),
        'attack_distribution': attack_dist,
        'used_real_csic': bool(csic_normal or csic_attack),
        'custom_samples': len(load_custom_labeled_data()),
    }

    metrics_path = MODEL_DIR / 'metrics.json'
    with open(metrics_path, 'w') as fh:
        json.dump(metrics, fh, indent=2)
    print(f"[Save] Metrics → {metrics_path}")

    print("\n" + "=" * 65)
    print("  Training complete!")
    print("=" * 65)
    print(f"  Model     : {best_name}")
    print(f"  Accuracy  : {best['accuracy']*100:.2f}%")
    print(f"  Precision : {best['precision']*100:.2f}%")
    print(f"  Recall    : {best['recall']*100:.2f}%")
    print(f"  F1-Score  : {best['f1']*100:.2f}%")
    print(f"  AUC-ROC   : {best['auc']:.4f}")
    print(f"\n  Start the server: uvicorn app.main:app --reload --port 8000")
    print("=" * 65)


if __name__ == '__main__':
    main()
