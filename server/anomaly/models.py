import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class BaselinePoint:
    """
    Tek bir (entity, metric, hour_bucket) için istatistiksel baseline.

    Welford online algoritması kullanır:
    - O(1) bellek — tüm geçmişi saklamaya gerek yok
    - Sayısal kararlı — çok büyük/küçük değerlerde precision kaybı olmaz
    - Anında güncellenebilir — her yeni sample sonrası mean/variance hazır
    """

    entity_id: str
    metric: str
    hour_bucket: int    # 0-23, saat dilimi bazlı baseline için
    mean: float = 0.0
    m2: float = 0.0     # Welford ikinci moment birikimi
    sample_count: int = 0
    last_updated: Optional[datetime] = None

    @property
    def variance(self) -> float:
        if self.sample_count < 2:
            return 0.0
        return self.m2 / (self.sample_count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(max(self.variance, 0.0))

    @property
    def is_warmed_up(self) -> bool:
        return self.sample_count >= 20

    def update(self, value: float) -> None:
        self.sample_count += 1
        delta = value - self.mean
        self.mean += delta / self.sample_count
        self.m2 += delta * (value - self.mean)
        self.last_updated = datetime.now(timezone.utc)

    def z_score(self, observed: float) -> float:
        s = self.std
        if s < 1e-9:
            return 0.0
        return (observed - self.mean) / s


@dataclass
class MetricSnapshot:
    """Bir entity'nin tek bir zaman penceresindeki ölçüm değerleri."""
    entity_id: str
    window_start: datetime
    fw_block_rate: float       # fw_block olayı / dakika
    conn_rate: float           # toplam ağ olayı / dakika
    unique_dst_ips: float      # benzersiz hedef IP sayısı
    unique_dst_ports: float    # benzersiz hedef port sayısı
    auth_failure_rate: float   # auth hatası / dakika


METRICS: list[str] = [
    "fw_block_rate",
    "conn_rate",
    "unique_dst_ips",
    "unique_dst_ports",
    "auth_failure_rate",
]

# Minimum mutlak değer — bu eşiğin altında false positive üretmemek için alarm yok
METRIC_MIN_THRESHOLD: dict[str, float] = {
    "fw_block_rate":     2.0,
    "conn_rate":         5.0,
    "unique_dst_ips":    5.0,
    "unique_dst_ports":  5.0,
    "auth_failure_rate": 2.0,
}

_Z_WARN     = 2.5
_Z_HIGH     = 3.5
_Z_CRITICAL = 4.5


@dataclass
class AnomalyResult:
    """Tespit edilen tek bir anomali kaydı."""
    result_id: str
    entity_id: str
    metric: str
    observed_value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    severity: str
    confidence: float        # 0.0 – 1.0
    message: str
    detected_at: datetime
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_baseline(cls, bp: BaselinePoint, observed: float, z: float) -> "AnomalyResult":
        if z >= _Z_CRITICAL:
            severity, confidence = "critical", 0.95
        elif z >= _Z_HIGH:
            severity, confidence = "high", 0.80
        else:
            severity, confidence = "warning", 0.60

        msg = (
            f"Anomali tespit: {bp.entity_id} — {bp.metric} = {observed:.2f} "
            f"(baseline {bp.mean:.2f}±{bp.std:.2f}, z={z:.1f}σ)"
        )
        return cls(
            result_id      = str(uuid.uuid4()),
            entity_id      = bp.entity_id,
            metric         = bp.metric,
            observed_value = observed,
            baseline_mean  = bp.mean,
            baseline_std   = bp.std,
            z_score        = z,
            severity       = severity,
            confidence     = confidence,
            message        = msg,
            detected_at    = datetime.now(timezone.utc),
        )
