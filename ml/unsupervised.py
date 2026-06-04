"""
ML-WAF Unsupervised Baseline Model

Learns normal traffic patterns per-environment in real time.
Uses Isolation Forest + URL path clustering to flag anomalies
that the supervised model hasn't seen before.

This replicates the open-appsec "unsupervised model" concept:
  - Trains on observed normal traffic
  - Scores new requests against the learned baseline
  - Higher score = more anomalous = more likely to be an attack
"""

import json
import pickle
import hashlib
import numpy as np
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, Optional

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


ROOT = Path(__file__).parent.parent
MODEL_PATH = ROOT / 'models' / 'unsupervised_baseline.pkl'


class BaselineModel:
    """
    Per-environment baseline model that learns normal traffic patterns.

    Phase 1 (learning): Collects feature vectors from allowed requests.
    Phase 2 (detection): Scores new requests against the learned baseline.
    """

    def __init__(
        self,
        min_samples: int = 200,          # Minimum samples before activating
        contamination: float = 0.05,     # Expected fraction of anomalies
        max_samples: int = 10_000,       # Cap on stored samples
        confidence_weight: float = 0.3,  # Weight in final fusion score
    ):
        self.min_samples = min_samples
        self.contamination = contamination
        self.max_samples = max_samples
        self.confidence_weight = confidence_weight

        self._samples: list = []
        self._model: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._fitted = False
        self._sample_count = 0

        # URL frequency map for path-based anomaly detection
        self._path_freq: Dict[str, int] = defaultdict(int)
        self._total_requests = 0

        # Method frequency
        self._method_freq: Dict[str, int] = defaultdict(int)

    @property
    def is_active(self) -> bool:
        """Returns True if we have enough data to make predictions."""
        return self._fitted and self._sample_count >= self.min_samples

    @property
    def sample_count(self) -> int:
        return self._sample_count

    def learn(self, feature_vector: np.ndarray, request: Dict[str, Any]) -> None:
        """
        Add a normal request to the baseline.
        Auto-retrains every 100 new samples once min_samples is reached.
        """
        url = str(request.get('url', ''))
        path = url.split('?', 1)[0]
        method = str(request.get('method', 'GET')).upper()

        self._path_freq[path] += 1
        self._method_freq[method] += 1
        self._total_requests += 1

        # Store feature vector (cap at max_samples using reservoir sampling)
        if len(self._samples) < self.max_samples:
            self._samples.append(feature_vector.copy())
        else:
            # Reservoir sampling — replace random element
            idx = np.random.randint(0, self._sample_count)
            if idx < self.max_samples:
                self._samples[idx] = feature_vector.copy()

        self._sample_count += 1

        # Auto-retrain trigger
        if (self._sample_count >= self.min_samples and
                self._sample_count % 100 == 0):
            self._fit()

    def _fit(self) -> None:
        """(Re)fit the Isolation Forest on collected samples."""
        if not SKLEARN_AVAILABLE or len(self._samples) < self.min_samples:
            return

        X = np.array(self._samples, dtype=np.float32)

        # Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Isolation Forest
        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            max_samples=min(256, len(X)),
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._fitted = True

    def score(self, feature_vector: np.ndarray, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score a request against the baseline.

        Returns:
            {
                'anomaly_score': float (0-1, higher = more anomalous),
                'is_anomaly': bool,
                'path_rarity': float,
                'method_rarity': float,
                'active': bool,
            }
        """
        result = {
            'anomaly_score': 0.0,
            'is_anomaly': False,
            'path_rarity': 0.0,
            'method_rarity': 0.0,
            'active': self.is_active,
            'samples_collected': self._sample_count,
        }

        if not self.is_active:
            return result

        # ── Isolation Forest score ────────────────────────────────────
        if self._scaler and self._model:
            try:
                X = feature_vector.reshape(1, -1)
                X_scaled = self._scaler.transform(X)
                # decision_function: negative = anomaly, positive = normal
                raw_score = float(self._model.decision_function(X_scaled)[0])
                # Convert to 0-1 scale (0=normal, 1=anomaly)
                iso_score = max(0.0, min(1.0, 0.5 - raw_score))
            except Exception:
                iso_score = 0.0
        else:
            iso_score = 0.0

        # ── Path rarity score ─────────────────────────────────────────
        url = str(request.get('url', ''))
        path = url.split('?', 1)[0]
        method = str(request.get('method', 'GET')).upper()

        if self._total_requests > 0:
            path_count = self._path_freq.get(path, 0)
            path_rarity = max(0.0, 1.0 - (path_count / max(self._total_requests * 0.01, 1)))
        else:
            path_rarity = 0.0

        if self._total_requests > 0:
            method_count = self._method_freq.get(method, 0)
            method_rarity = max(0.0, 1.0 - (method_count / max(self._total_requests * 0.1, 1)))
        else:
            method_rarity = 0.0

        result['path_rarity'] = round(path_rarity, 4)
        result['method_rarity'] = round(method_rarity, 4)

        # ── Fuse scores ───────────────────────────────────────────────
        # Weighted combination: mostly isolation forest, boost by path rarity
        anomaly_score = (
            iso_score * 0.6 +
            path_rarity * 0.3 +
            method_rarity * 0.1
        )
        anomaly_score = round(min(1.0, anomaly_score), 4)

        result['anomaly_score'] = anomaly_score
        result['is_anomaly'] = anomaly_score > 0.75

        return result

    def save(self, path: Optional[Path] = None) -> None:
        """Serialize model to disk."""
        save_path = path or MODEL_PATH
        save_path.parent.mkdir(exist_ok=True)
        state = {
            'samples': self._samples,
            'model': self._model,
            'scaler': self._scaler,
            'fitted': self._fitted,
            'sample_count': self._sample_count,
            'path_freq': dict(self._path_freq),
            'method_freq': dict(self._method_freq),
            'total_requests': self._total_requests,
            'config': {
                'min_samples': self.min_samples,
                'contamination': self.contamination,
                'max_samples': self.max_samples,
                'confidence_weight': self.confidence_weight,
            }
        }
        with open(save_path, 'wb') as f:
            pickle.dump(state, f, protocol=4)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> 'BaselineModel':
        """Deserialize model from disk."""
        load_path = path or MODEL_PATH
        if not load_path.exists():
            return cls()

        try:
            with open(load_path, 'rb') as f:
                state = pickle.load(f)

            config = state.get('config', {})
            obj = cls(
                min_samples=config.get('min_samples', 200),
                contamination=config.get('contamination', 0.05),
                max_samples=config.get('max_samples', 10_000),
                confidence_weight=config.get('confidence_weight', 0.3),
            )
            obj._samples = state.get('samples', [])
            obj._model = state.get('model')
            obj._scaler = state.get('scaler')
            obj._fitted = state.get('fitted', False)
            obj._sample_count = state.get('sample_count', 0)
            obj._path_freq = defaultdict(int, state.get('path_freq', {}))
            obj._method_freq = defaultdict(int, state.get('method_freq', {}))
            obj._total_requests = state.get('total_requests', 0)
            return obj
        except Exception as e:
            print(f'[Unsupervised] Failed to load baseline model: {e}')
            return cls()

    def get_stats(self) -> Dict:
        """Return current model statistics for the dashboard."""
        return {
            'active': self.is_active,
            'samples_collected': self._sample_count,
            'min_samples_needed': self.min_samples,
            'progress_pct': round(min(100, self._sample_count / self.min_samples * 100), 1),
            'top_paths': sorted(
                self._path_freq.items(), key=lambda x: x[1], reverse=True
            )[:10],
            'method_distribution': dict(self._method_freq),
            'sklearn_available': SKLEARN_AVAILABLE,
        }


# ── Global singleton ──────────────────────────────────────────────────────────
_baseline: Optional[BaselineModel] = None


def get_baseline() -> BaselineModel:
    global _baseline
    if _baseline is None:
        _baseline = BaselineModel.load()
        print(f'[Unsupervised] Baseline loaded — {_baseline.sample_count} samples, '
              f'active={_baseline.is_active}')
    return _baseline


def save_baseline() -> None:
    global _baseline
    if _baseline is not None:
        _baseline.save()
