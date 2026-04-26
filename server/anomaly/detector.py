import logging
import math
from typing import Optional

from server.anomaly.models import (
    AnomalyResult,
    BaselinePoint,
    MetricSnapshot,
    METRICS,
    METRIC_MIN_THRESHOLD,
    _Z_WARN,
)

logger = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest as _IF
    _SKLEARN_AVAILABLE = True
    logger.info("Isolation Forest hazır (scikit-learn mevcut)")
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.info("scikit-learn bulunamadı — sadece istatistiksel tespit aktif")

_IF_MIN_SAMPLES  = 100    # IF eğitimi için minimum örnek sayısı
_IF_MAX_HISTORY  = 2016   # ~7 gün × 24 saat × 12 (5dk/saat)
_IF_SCORE_THRESH = 0.65   # Bu skorun üzeri anomali sayılır


class StatisticalDetector:
    """
    Z-score tabanlı tek boyutlu anomali tespiti.

    Her (entity, metric) çifti için bağımsız çalışır.
    Warm-up tamamlanmamış veya gözlem minimum eşiğin altındaysa atlar.
    """

    def detect(
        self,
        snapshot: MetricSnapshot,
        baselines: dict[str, BaselinePoint],
    ) -> list[AnomalyResult]:
        results = []
        for metric in METRICS:
            bp = baselines.get(metric)
            if bp is None or not bp.is_warmed_up:
                continue
            observed = getattr(snapshot, metric)
            if observed < METRIC_MIN_THRESHOLD.get(metric, 0.0):
                continue
            z = bp.z_score(observed)
            if z >= _Z_WARN:
                results.append(AnomalyResult.from_baseline(bp, observed, z))
        return results


class IsolationForestDetector:
    """
    Çok boyutlu anomali tespiti — tüm metrikler birlikte değerlendirilir.

    Z-score'un kaçırabileceği örüntüleri yakalar:
    tek başına normal olan iki metriğin aynı anda yükselmesi gibi.

    scikit-learn yoksa devre dışı kalır (sistem yine de çalışmaya devam eder).
    """

    def __init__(self) -> None:
        self._models: dict[str, object] = {}
        self._history: dict[str, list[list[float]]] = {}

    def _features(self, snap: MetricSnapshot) -> list[float]:
        return [getattr(snap, m) for m in METRICS]

    def update(self, snapshot: MetricSnapshot) -> None:
        if not _SKLEARN_AVAILABLE:
            return
        eid = snapshot.entity_id
        vec = self._features(snapshot)
        buf = self._history.setdefault(eid, [])
        buf.append(vec)
        if len(buf) > _IF_MAX_HISTORY:
            self._history[eid] = buf[-_IF_MAX_HISTORY:]

    def fit(self, entity_id: str) -> bool:
        if not _SKLEARN_AVAILABLE:
            return False
        history = self._history.get(entity_id, [])
        if len(history) < _IF_MIN_SAMPLES:
            return False
        X = np.array(history, dtype=float)
        self._models[entity_id] = _IF(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        ).fit(X)
        logger.debug(f"IF modeli güncellendi: {entity_id} ({len(history)} örnek)")
        return True

    def anomaly_score(self, snapshot: MetricSnapshot) -> Optional[float]:
        """0.0 = normal, 1.0 = kesinlikle anomali."""
        if not _SKLEARN_AVAILABLE:
            return None
        model = self._models.get(snapshot.entity_id)
        if model is None:
            return None
        vec = np.array([self._features(snapshot)], dtype=float)
        raw = model.decision_function(vec)[0]
        # decision_function: negatif = daha anormal → sigmoid ile 0-1 arasına normalize
        return 1.0 / (1.0 + math.exp(raw * 5))

    def is_anomaly(self, snapshot: MetricSnapshot) -> bool:
        score = self.anomaly_score(snapshot)
        return score is not None and score > _IF_SCORE_THRESH
