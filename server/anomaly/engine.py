import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone

from server.anomaly.baseline import BaselineStore
from server.anomaly.collector import MetricsCollector
from server.anomaly.detector import IsolationForestDetector, StatisticalDetector
from server.anomaly.models import AnomalyResult, METRICS
from server.anomaly.store import AnomalyResultStore
from server.database import DatabaseManager
from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)

_INTERVAL_SEC  = int(os.getenv("ANOMALY_INTERVAL_SEC", "300"))   # 5 dakika
_FIT_EVERY     = int(os.getenv("ANOMALY_FIT_EVERY", "288"))      # ~24 saat (288×5dk)


class AnomalyEngine:
    """
    Anomaly detection döngüsünü yöneten ana sınıf.

    Döngü her {_INTERVAL_SEC} saniyede bir çalışır:
      1. MetricsCollector  → son 5dk entity metriklerini topla
      2. BaselineStore     → her (entity, metric, hour) baseline'ı güncelle
      3. StatisticalDetector → Z-score anomali tespiti
      4. IsolationForestDetector → çok boyutlu anomali tespiti (opsiyonel)
      5. AnomalyResultStore → sonuçları DB'ye yaz
    """

    def __init__(self, db_path: str):
        self._collector = MetricsCollector(db_path)
        self._baselines = BaselineStore(db_path)
        self._stat      = StatisticalDetector()
        self._ifd       = IsolationForestDetector()
        self._results   = AnomalyResultStore(db_path)
        self._db        = DatabaseManager(db_path)
        self._cycle_count = 0
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="anomaly-engine")
        logger.info(f"Anomaly detection motoru başlatıldı (interval={_INTERVAL_SEC}s)")

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("Anomaly detection motoru durduruldu.")

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self._cycle)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Anomaly detection döngü hatası: {exc}", exc_info=True)
            await asyncio.sleep(_INTERVAL_SEC)

    def _cycle(self) -> None:
        self._cycle_count += 1
        now  = datetime.now(timezone.utc)
        hour = now.hour

        snapshots = self._collector.collect()
        if not snapshots:
            return

        all_results: list[AnomalyResult] = []

        for snap in snapshots:
            baselines: dict = {}

            # 1. Her metrik için baseline güncelle
            for metric in METRICS:
                observed = getattr(snap, metric)
                bp = self._baselines.get_or_create(snap.entity_id, metric, hour)
                bp.update(observed)
                self._baselines.save(bp)
                baselines[metric] = bp

            # 2. İstatistiksel tespit (Z-score)
            stat_hits = self._stat.detect(snap, baselines)
            all_results.extend(stat_hits)

            # 3. Isolation Forest güncelle
            self._ifd.update(snap)

            # 4. IF anomali skoru — istatistiksel anomalileri zenginleştir
            if stat_hits:
                if_score = self._ifd.anomaly_score(snap)
                if if_score is not None:
                    for r in stat_hits:
                        r.extra["if_score"] = round(if_score, 3)

        # 5. Periodik IF model yenileme (~24 saatte bir)
        if self._cycle_count % _FIT_EVERY == 0:
            entities = {s.entity_id for s in snapshots}
            for eid in entities:
                self._ifd.fit(eid)

        # 6. Sonuçları kaydet ve bildir
        if all_results:
            from server.notifier import notifier
            for r in all_results:
                self._results.save(r)
                notifier.notify_anomaly(r)
                log = NormalizedLog(
                    log_id=str(uuid.uuid4()),
                    raw_id=str(uuid.uuid4()),
                    source_type=LogSourceType.NETGUARD,
                    source_host="netguard-anomaly",
                    timestamp=r.detected_at,
                    severity=r.severity,
                    category=LogCategory.INTRUSION,
                    event_type="anomaly_detected",
                    src_ip=r.entity_id,
                    message=r.message,
                    tags=["anomaly", r.metric],
                )
                self._db.save_normalized_log(log)
            logger.info(
                f"Anomaly cycle #{self._cycle_count}: "
                f"{len(all_results)} anomali / {len(snapshots)} entity"
            )

    # ── Dışarıdan erişilen yardımcı metodlar ─────────────────────────────────

    def get_recent_results(
        self,
        limit: int = 100,
        entity_id: str | None = None,
        severity: str | None = None,
        since_hours: int = 24,
    ) -> list[dict]:
        return self._results.list_recent(
            limit=limit, entity_id=entity_id,
            severity=severity, since_hours=since_hours,
        )

    def get_summary(self, since_hours: int = 24) -> dict:
        return self._results.summary(since_hours=since_hours)

    def get_baselines(self) -> list[dict]:
        return self._baselines.list_entities()

    def get_warmup_status(self, entity_id: str) -> dict:
        return self._baselines.warmup_status(entity_id)
