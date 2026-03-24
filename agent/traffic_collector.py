"""
NetGuard Agent — Traffic Collector

TShark/pyshark kullanarak ağ trafiğini yakalar ve analiz eder.
Belirli aralıklarla çalışır, TrafficSummary üretir.

Tasarım kararı: Bu collector diğerlerinden bağımsız çalışır.
collect_snapshot() ile entegre edilir ama ayrı thread'de çalışır.
"""

import logging
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logger.warning("pyshark kurulu değil — traffic collector devre dışı")

from shared.models import ProtocolStats, TrafficSummary

# Kaç saniyede bir trafik yakalama yapılır
CAPTURE_INTERVAL_SEC = 30
# Her yakalamada kaç saniye dinlenir
CAPTURE_DURATION_SEC = 10
# Maksimum kaç paket yakalanır (sistem yükü kontrolü)
MAX_PACKETS = 500


def _get_active_interface() -> str:
    """
    Aktif ağ arayüzünü bul.
    lo (loopback) ve vmnet'leri atla.
    """
    try:
        import psutil
        net_io = psutil.net_io_counters(pernic=True)
        best = None
        best_bytes = 0
        for name, stats in net_io.items():
            if name == "lo" or name.startswith("vmnet") or name.startswith("docker"):
                continue
            total = stats.bytes_sent + stats.bytes_recv
            if total > best_bytes:
                best_bytes = total
                best = name
        return best or "eth0"
    except Exception:
        return "eth0"


def _analyze_packets(packets) -> dict:
    """
    Yakalanan paket listesini analiz eder.
    Protokol dağılımı, IP istatistikleri, şüpheli paket sayısı döner.
    """
    protocol_counts: Counter = Counter()
    protocol_bytes: defaultdict = defaultdict(int)
    src_ips: Counter = Counter()
    dst_ips: Counter = Counter()
    total_bytes = 0
    suspicious = 0

    for pkt in packets:
        try:
            pkt_len = int(pkt.length) if hasattr(pkt, 'length') else 0
            total_bytes += pkt_len

            # Protokol tespiti — en üst katmandan başla
            proto = "OTHER"
            if hasattr(pkt, 'http'):
                proto = "HTTP"
            elif hasattr(pkt, 'dns'):
                proto = "DNS"
            elif hasattr(pkt, 'tls'):
                proto = "TLS/HTTPS"
            elif hasattr(pkt, 'tcp'):
                proto = "TCP"
            elif hasattr(pkt, 'udp'):
                proto = "UDP"
            elif hasattr(pkt, 'icmp'):
                proto = "ICMP"
            elif hasattr(pkt, 'arp'):
                proto = "ARP"

            protocol_counts[proto] += 1
            protocol_bytes[proto] += pkt_len

            # IP adresleri
            if hasattr(pkt, 'ip'):
                src_ips[pkt.ip.src] += 1
                dst_ips[pkt.ip.dst] += 1

            # Basit şüpheli tespiti
            # Port taraması: çok sayıda farklı port erişimi
            if hasattr(pkt, 'tcp'):
                dport = int(pkt.tcp.dstport) if hasattr(pkt.tcp, 'dstport') else 0
                # Bilinen tehlikeli portlara erişim
                if dport in (22, 23, 3389, 445, 1433, 3306):
                    suspicious += 1

        except Exception:
            continue

    return {
        "protocol_counts": protocol_counts,
        "protocol_bytes": protocol_bytes,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "total_bytes": total_bytes,
        "suspicious": suspicious,
    }


def _build_protocol_stats(analysis: dict, total_packets: int) -> list[ProtocolStats]:
    """Protocol istatistiklerini ProtocolStats listesine çevirir."""
    stats = []
    for proto, count in analysis["protocol_counts"].most_common():
        pct = (count / total_packets * 100) if total_packets > 0 else 0
        stats.append(ProtocolStats(
            protocol=proto,
            packet_count=count,
            byte_count=analysis["protocol_bytes"].get(proto, 0),
            percentage=round(pct, 1),
        ))
    return stats


def capture_traffic(interface: str = None, duration: int = CAPTURE_DURATION_SEC) -> TrafficSummary | None:
    """
    Belirtilen arayüzde trafik yakalar ve TrafficSummary döndürür.
    pyshark yoksa veya hata olursa None döner.
    """
    if not PYSHARK_AVAILABLE:
        return None

    if interface is None:
        interface = _get_active_interface()

    start = time.time()
    packets = []

    try:
        logger.debug(f"Trafik yakalama başladı: {interface} ({duration}s)")
        capture = pyshark.LiveCapture(
            interface=interface,
            output_file=None,
        )
        capture.sniff(timeout=duration, packet_count=MAX_PACKETS)
        packets = list(capture._packets)
        capture.close()
    except Exception as e:
        logger.warning(f"Trafik yakalama hatası: {e}")
        return None

    elapsed = time.time() - start
    if not packets:
        logger.debug("Yakalanan paket yok.")
        return None

    analysis = _analyze_packets(packets)
    total_packets = len(packets)

    return TrafficSummary(
        interface=interface,
        duration_sec=round(elapsed, 2),
        total_packets=total_packets,
        total_bytes=analysis["total_bytes"],
        protocols=_build_protocol_stats(analysis, total_packets),
        top_src_ips=[ip for ip, _ in analysis["src_ips"].most_common(5)],
        top_dst_ips=[ip for ip, _ in analysis["dst_ips"].most_common(5)],
        captured_at=datetime.now(timezone.utc),
        suspicious_packet_count=analysis["suspicious"],
    )


class TrafficCollectorThread:
    """
    Arka planda periyodik trafik yakalama yapar.
    En son TrafficSummary'yi thread-safe şekilde saklar.
    """

    def __init__(self):
        self._latest: TrafficSummary | None = None
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._running = False

    def start(self):
        self._running = True
        self._thread.start()
        logger.info("Traffic Collector thread başlatıldı.")

    def stop(self):
        self._running = False

    def get_latest(self) -> TrafficSummary | None:
        with self._lock:
            return self._latest

    def _run(self):
        while self._running:
            try:
                summary = capture_traffic()
                if summary:
                    with self._lock:
                        self._latest = summary
                    logger.info(
                        f"Trafik özeti: {summary.total_packets} paket, "
                        f"{len(summary.protocols)} protokol, "
                        f"{summary.suspicious_packet_count} şüpheli"
                    )
            except Exception as e:
                logger.error(f"Traffic collector hatası: {e}")
            time.sleep(CAPTURE_INTERVAL_SEC)


# Global instance
traffic_collector = TrafficCollectorThread()