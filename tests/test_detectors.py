"""
NetGuard — Saldırı dedektörü testleri

Sistem kaynaklarını (psutil, /proc/net/*) mock'layarak test eder.
"""

import pytest
from collections import namedtuple
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, mock_open

from shared.models import LogCategory


# ------------------------------------------------------------------ #
#  Port Scan Dedektörü
# ------------------------------------------------------------------ #

class TestPortScanDetector:
    """
    Port tarama dedektörü pyshark ile SYN paketlerini dinler.
    Test ortamında sniffer thread'i başlatmadan _history'e doğrudan veri
    enjekte ederek dedektörün karar mantığını test ediyoruz.
    """

    def _make_detector(self, threshold=10, window=60) -> "PortScanDetector":
        """Sniffer başlatmadan dedektör oluştur."""
        from server.detectors.port_scan import PortScanDetector
        with patch.object(PortScanDetector, "_start_sniffer", return_value=None):
            return PortScanDetector(threshold=threshold, window_seconds=window)

    def _inject(self, detector, src_ip: str, ports: list[int], age: float = 0.0):
        """_history'e sahte SYN kayıtları ekle. age=0 → şu an, age>0 → X saniye önce."""
        import time
        now = time.monotonic()
        with detector._lock:
            for port in ports:
                detector._history[src_ip].append((now - age, port))

    def test_no_alert_below_threshold(self):
        detector = self._make_detector(threshold=10)
        self._inject(detector, "1.2.3.4", list(range(5)))
        assert detector.detect() == []

    def test_alert_at_threshold(self):
        detector = self._make_detector(threshold=10)
        self._inject(detector, "1.2.3.4", list(range(10)))
        logs = detector.detect()
        assert len(logs) == 1
        assert logs[0].event_type == "port_scan_attempt"
        assert logs[0].src_ip == "1.2.3.4"

    def test_multiple_ips_tracked_independently(self):
        detector = self._make_detector(threshold=5)
        self._inject(detector, "1.1.1.1", list(range(5)))  # eşikte
        self._inject(detector, "2.2.2.2", list(range(3)))  # eşiğin altında
        logs = detector.detect()
        assert len(logs) == 1
        assert logs[0].src_ip == "1.1.1.1"

    def test_old_entries_outside_window_ignored(self):
        detector = self._make_detector(threshold=5, window=30)
        # 31 saniye önce → pencere dışı
        self._inject(detector, "3.3.3.3", list(range(10)), age=31.0)
        logs = detector.detect()
        assert logs == []

    def test_no_duplicate_alert_same_ip(self):
        detector = self._make_detector(threshold=5)
        self._inject(detector, "4.4.4.4", list(range(5)))
        first  = detector.detect()
        second = detector.detect()
        assert len(first) == 1
        assert len(second) == 0  # Aynı IP için tekrar alarm vermemeli

    def test_log_has_correct_fields(self):
        detector = self._make_detector(threshold=3)
        self._inject(detector, "5.5.5.5", [80, 443, 8080])
        logs = detector.detect()
        assert len(logs) == 1
        log = logs[0]
        assert log.category == LogCategory.NETWORK
        assert log.severity == "warning"
        assert "port_scan" in log.tags
        assert "5.5.5.5" in log.message


# ------------------------------------------------------------------ #
#  ARP Spoof Dedektörü
# ------------------------------------------------------------------ #

ARP_TABLE_NORMAL = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
"""

ARP_TABLE_CHANGED_MAC = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
192.168.1.2      0x1         0x2         11:22:33:44:55:66     *        eth0
"""

ARP_TABLE_DUPLICATE_MAC = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
"""


class TestARPSpoofDetector:
    def test_no_alert_on_first_run(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(ARP_TABLE_NORMAL)

        from server.detectors.arp_spoof import ARPSpoofDetector
        detector = ARPSpoofDetector(arp_path=str(arp_file))
        logs = detector.detect()
        # İlk çalıştırmada bilinen eşleme yok — sadece öğrenir
        assert len(logs) == 0

    def test_alert_on_mac_change(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(ARP_TABLE_NORMAL)

        from server.detectors.arp_spoof import ARPSpoofDetector
        detector = ARPSpoofDetector(arp_path=str(arp_file))
        detector.detect()   # ilk çalıştırma — öğren

        arp_file.write_text(ARP_TABLE_CHANGED_MAC)
        logs = detector.detect()

        assert len(logs) >= 1
        mac_change_logs = [l for l in logs if "spoofing" in l.message.lower() or "değişti" in l.message]
        assert len(mac_change_logs) >= 1
        assert logs[0].event_type == "arp_spoof_attempt"
        assert logs[0].severity == "critical"

    def test_alert_on_duplicate_mac(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(ARP_TABLE_DUPLICATE_MAC)

        from server.detectors.arp_spoof import ARPSpoofDetector
        detector = ARPSpoofDetector(arp_path=str(arp_file))
        logs = detector.detect()

        duplicate_logs = [l for l in logs if "duplicate_mac" in l.tags]
        assert len(duplicate_logs) >= 1
        assert duplicate_logs[0].severity == "critical"

    def test_no_alert_when_table_unchanged(self, tmp_path):
        arp_file = tmp_path / "arp"
        arp_file.write_text(ARP_TABLE_NORMAL)

        from server.detectors.arp_spoof import ARPSpoofDetector
        detector = ARPSpoofDetector(arp_path=str(arp_file))
        detector.detect()   # ilk — öğren
        logs = detector.detect()  # ikinci — değişim yok

        mac_change_logs = [l for l in logs if "spoofing" in l.message.lower() or "değişti" in l.message]
        assert len(mac_change_logs) == 0

    def test_missing_arp_file_returns_empty(self):
        from server.detectors.arp_spoof import ARPSpoofDetector
        detector = ARPSpoofDetector(arp_path="/nonexistent/arp")
        logs = detector.detect()
        assert logs == []


# ------------------------------------------------------------------ #
#  ICMP Flood Dedektörü
# ------------------------------------------------------------------ #

SNMP_CONTENT_LOW = """\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InEchos InEchoReps OutMsgs
Icmp: 1000 0 0 100 0 0 200
"""

SNMP_CONTENT_HIGH = """\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InEchos InEchoReps OutMsgs
Icmp: 31000 0 0 100 0 0 200
"""


class TestICMPFloodDetector:
    def test_no_alert_on_first_call(self, tmp_path):
        snmp_file = tmp_path / "snmp"
        snmp_file.write_text(SNMP_CONTENT_LOW)

        from server.detectors.icmp_flood import ICMPFloodDetector
        detector = ICMPFloodDetector(snmp_path=str(snmp_file), threshold=100)
        logs = detector.detect()
        # İlk çalıştırmada önceki değer yok
        assert len(logs) == 0

    def test_no_alert_below_threshold(self, tmp_path):
        snmp_file = tmp_path / "snmp"
        snmp_file.write_text(SNMP_CONTENT_LOW)

        from server.detectors.icmp_flood import ICMPFloodDetector
        import time
        detector = ICMPFloodDetector(snmp_path=str(snmp_file), threshold=100)
        detector.detect()  # ilk — kaydet

        # Hafif artış (eşik altı)
        snmp_file.write_text(SNMP_CONTENT_LOW.replace("1000", "1050"))
        # 50 paket fark, 1 saniye aralık — 50 pkt/s < 100 eşik

        detector._prev_time -= 1.0  # 1 saniye geçmiş gibi yap
        logs = detector.detect()
        assert len(logs) == 0

    def test_alert_above_threshold(self, tmp_path):
        snmp_file = tmp_path / "snmp"
        snmp_file.write_text(SNMP_CONTENT_LOW)

        from server.detectors.icmp_flood import ICMPFloodDetector
        detector = ICMPFloodDetector(snmp_path=str(snmp_file), threshold=100)
        detector.detect()  # ilk çalıştırma

        # Büyük artış — 30000 paket
        snmp_file.write_text(SNMP_CONTENT_HIGH)
        detector._prev_time -= 1.0  # 1 saniye geçmiş gibi yap
        logs = detector.detect()

        assert len(logs) == 1
        assert logs[0].event_type == "icmp_flood_attempt"
        assert logs[0].severity == "critical"
        assert "icmp_flood" in logs[0].tags

    def test_missing_snmp_file_returns_empty(self):
        from server.detectors.icmp_flood import ICMPFloodDetector
        detector = ICMPFloodDetector(snmp_path="/nonexistent/snmp", threshold=100)
        logs = detector.detect()
        assert logs == []


# ------------------------------------------------------------------ #
#  DNS Anomali Dedektörü
# ------------------------------------------------------------------ #

class TestDNSAnomalyDetector:
    def _make_dns_conn(self, src_ip: str):
        conn = MagicMock()
        conn.laddr = MagicMock(ip=src_ip, port=54321)
        conn.raddr = MagicMock(ip="8.8.8.8", port=53)
        return conn

    def test_no_alert_below_threshold(self):
        from server.detectors.dns_anomaly import DNSAnomalyDetector
        detector = DNSAnomalyDetector(threshold=30)

        conns = [self._make_dns_conn("10.0.0.1") for _ in range(5)]
        with patch("psutil.net_connections", return_value=conns):
            logs = detector.detect()
        assert len(logs) == 0

    def test_alert_at_threshold(self):
        from server.detectors.dns_anomaly import DNSAnomalyDetector
        detector = DNSAnomalyDetector(threshold=10)

        conns = [self._make_dns_conn("10.0.0.1") for _ in range(10)]
        with patch("psutil.net_connections", return_value=conns):
            logs = detector.detect()

        assert len(logs) == 1
        assert logs[0].event_type == "dns_query_burst"
        assert logs[0].src_ip == "10.0.0.1"
        assert logs[0].dst_port == 53

    def test_multiple_sources_tracked(self):
        from server.detectors.dns_anomaly import DNSAnomalyDetector
        detector = DNSAnomalyDetector(threshold=5)

        conns = (
            [self._make_dns_conn("10.0.0.1") for _ in range(5)] +
            [self._make_dns_conn("10.0.0.2") for _ in range(10)]
        )
        with patch("psutil.net_connections", return_value=conns):
            logs = detector.detect()

        assert len(logs) == 2
        ips = {l.src_ip for l in logs}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips


# ------------------------------------------------------------------ #
#  Dedektör Yöneticisi
# ------------------------------------------------------------------ #

class TestDetectorManager:
    def test_run_all_collects_from_all_detectors(self, tmp_path, monkeypatch):
        """Manager tüm dedektörleri çalıştırır ve logları DB'ye yazar."""
        import server.database as db_module
        test_db = db_module.DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)

        import server.detectors.manager as mgr_module
        monkeypatch.setattr(mgr_module, "db", test_db)

        from server.detectors.manager import DetectorManager
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid

        # Her dedektörü 1 log döndürecek şekilde mock'la
        mock_log = NormalizedLog(
            log_id="test", raw_id="raw",
            source_type=LogSourceType.NETGUARD,
            source_host="host",
            timestamp=__import__('datetime').datetime.now(__import__('datetime').timezone.utc),
            severity="warning",
            category=LogCategory.NETWORK,
            event_type="test_event",
            message="test",
        )

        manager = DetectorManager()
        for d in manager._detectors:
            monkeypatch.setattr(d, "detect", lambda log=mock_log: [log])

        logs = manager.run_all()
        assert len(logs) == len(manager._detectors)

    def test_detector_error_does_not_crash_others(self, tmp_path, monkeypatch):
        """Bir dedektör hata verse bile diğerleri çalışmaya devam eder."""
        import server.database as db_module
        test_db = db_module.DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)

        import server.detectors.manager as mgr_module
        monkeypatch.setattr(mgr_module, "db", test_db)

        from server.detectors.manager import DetectorManager
        manager = DetectorManager()

        # İlk dedektör hata fırlatsın
        monkeypatch.setattr(manager._detectors[0], "detect", lambda: (_ for _ in ()).throw(RuntimeError("simulated error")))
        # Diğerleri boş dönsün
        for d in manager._detectors[1:]:
            monkeypatch.setattr(d, "detect", lambda: [])

        # Hata fırlatmamalı
        logs = manager.run_all()
        assert isinstance(logs, list)
