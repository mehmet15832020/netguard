"""
NetGuard Agent — Ana giriş noktası

Collector ve Sender'ı birleştirir.
Yapılandırmayı ortam değişkenlerinden okur.
Ana döngüyü yönetir.
"""



import logging
import os
import platform
import sys
import time

from agent.collector import collect_snapshot, _get_agent_id
from agent.sender import MetricSender
from agent.log_shipper import LogShipper
from shared.models import AgentRegistration
from shared.protocol import DEFAULT_SEND_INTERVAL_SEC
from agent.traffic_collector import traffic_collector
# Log formatı: zaman | seviye | modül | mesaj
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netguard.agent")


def get_config() -> dict:
    """
    Yapılandırmayı ortam değişkenlerinden okur.
    Ortam değişkeni yoksa varsayılan değeri kullanır.

    Kullanım:
        SERVER_URL=http://192.168.1.100:8000 python -m agent.main
    """
    return {
        "server_url":   os.getenv("NETGUARD_SERVER_URL", "http://localhost:8000"),
        "api_key":      os.getenv("NETGUARD_API_KEY", ""),
        "send_interval": int(os.getenv("NETGUARD_SEND_INTERVAL", DEFAULT_SEND_INTERVAL_SEC)),
    }


def main():
    config = get_config()
    logger.info("=" * 50)
    logger.info("NetGuard Agent başlatılıyor...")
    logger.info(f"Server: {config['server_url']}")
    logger.info(f"Gönderim aralığı: {config['send_interval']}s")
    logger.info("=" * 50)

    sender = MetricSender(server_url=config["server_url"])

    log_shipper = LogShipper(
        server_url=config["server_url"],
        api_key=config["api_key"],
    )
    log_shipper.start()

# Traffic collector'ı başlat
    if os.getenv("NETGUARD_ENABLE_TRAFFIC", "true").lower() == "true":
        traffic_collector.start()
        logger.info("Traffic Collector aktif.")
    else:
        logger.info("Traffic Collector devre dışı (NETGUARD_ENABLE_TRAFFIC=false)")

    # Server'a kendini tanıt
    registration = AgentRegistration(
        agent_id=_get_agent_id(),
        hostname=__import__("socket").gethostname(),
        os_name=platform.system(),
        os_version=platform.release(),
        python_version=platform.python_version(),
    )

    if not sender.register(registration):
        logger.warning("Kayıt başarısız — server çalışmıyor olabilir. Metrik göndermeye devam ediliyor.")

    # Ana döngü
    logger.info("Metrik toplama döngüsü başladı.")
    try:
        while True:
            snapshot = collect_snapshot()
            # Traffic summary varsa snapshot'a ekle
            traffic = traffic_collector.get_latest()
            if traffic:
                snapshot.traffic_summary = traffic
            sender.send_snapshot(snapshot)
            time.sleep(config["send_interval"])

    except KeyboardInterrupt:
        logger.info("Agent durduruluyor (Ctrl+C)...")
    finally:
        log_shipper.stop()
        sender.close()
        logger.info("Agent durduruldu.")


if __name__ == "__main__":
    main()