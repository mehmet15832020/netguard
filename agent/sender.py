"""
NetGuard Agent — Sender

Sadece bir iş yapar: MetricSnapshot'ı server'a HTTP POST ile gönderir.
Bağlantı hatalarını yönetir, retry yapar.

Metrik toplamadan haberi yoktur.
"""

import httpx
import logging
import time

from shared.models import AgentRegistration, MetricSnapshot
from shared.protocol import (
    CONNECTION_TIMEOUT_SEC,
    ENDPOINT_METRICS,
    ENDPOINT_REGISTER,
    MAX_RETRY_ATTEMPTS,
    RETRY_BACKOFF_SEC,
)

logger = logging.getLogger(__name__)


class MetricSender:
    """
    Server ile HTTP iletişimini yönetir.
    Tek bir instance oluşturulur, uygulama boyunca yaşar.
    """

    def __init__(self, server_url: str):
        """
        server_url: Örn. "http://192.168.1.100:8000"
        Sona slash koyma.
        """
        self.server_url = server_url.rstrip("/")
        self._client = httpx.Client(timeout=CONNECTION_TIMEOUT_SEC, verify=False)
        logger.info(f"Sender başlatıldı → {self.server_url}")

    def register(self, registration: AgentRegistration) -> bool:
        """
        Agent ilk başladığında server'a kendini tanıtır.
        Başarılıysa True, başarısızsa False döner.
        """
        url = f"{self.server_url}{ENDPOINT_REGISTER}"
        try:
            response = self._client.post(
                url,
                content=registration.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            logger.info("Agent kaydı başarılı.")
            return True
        except httpx.ConnectError:
            logger.warning(f"Server'a bağlanılamadı: {url}")
            return False
        except httpx.HTTPStatusError as e:
            logger.error(f"Kayıt başarısız — HTTP {e.response.status_code}")
            return False

    def send_snapshot(self, snapshot: MetricSnapshot) -> bool:
        """
        MetricSnapshot'ı server'a gönderir.
        Başarısızlıkta MAX_RETRY_ATTEMPTS kadar tekrar dener.
        """
        url = f"{self.server_url}{ENDPOINT_METRICS}"

        for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
            try:
                response = self._client.post(
                    url,
                    content=snapshot.model_dump_json(),
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.debug(
                    f"Snapshot gönderildi "
                    f"[CPU: {snapshot.cpu.usage_percent:.1f}%  "
                    f"RAM: {snapshot.memory.usage_percent:.1f}%]"
                )
                return True

            except (httpx.ConnectError, httpx.TimeoutException):
                logger.warning(
                    f"Bağlantı hatası (deneme {attempt}/{MAX_RETRY_ATTEMPTS})"
                )
                if attempt < MAX_RETRY_ATTEMPTS:
                    time.sleep(RETRY_BACKOFF_SEC)

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP hatası: {e.response.status_code}")
                return False

        logger.error("Tüm denemeler başarısız. Snapshot düşürüldü.")
        return False

    def close(self):
        """HTTP client'ı kapat. Program sonunda çağrılmalı."""
        self._client.close()