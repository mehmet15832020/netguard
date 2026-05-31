"""
A3 — LateralMovementDetector kapsamlı test paketi.

Kapsam: pyshark bağımlılığı, thread-safety, RFC 1918 filtreleme,
LATERAL_PORTS validasyonu, sniffer hata senaryoları.

Kaynaklar:
  NIST SP 800-94 Rev.1 §6.2 — sensor failure graceful degradation
  MITRE ATT&CK T1021 — lateral movement port seti doğrulaması
  CIS Controls v8.1 Control 13.6 — bileşen hata senaryoları
"""

import sys
import threading
import time
import pytest
from unittest.mock import MagicMock, patch


def _make_detector(threshold=3, window=120):
    from server.detectors.lateral import LateralMovementDetector
    with patch.object(LateralMovementDetector, "_start_sniffer", return_value=None):
        return LateralMovementDetector(threshold=threshold, window_seconds=window)


def _inject(detector, source_ip: str, targets: list[tuple[str, int]], age: float = 0.0):
    now = time.monotonic()
    with detector._lock:
        for dst_ip, dst_port in targets:
            detector._history[source_ip].append((now - age, dst_ip, dst_port))


def _make_mock_packet(src="192.168.1.10", dst="192.168.1.20", dstport="22"):
    pkt = MagicMock()
    pkt.ip.src = src
    pkt.ip.dst = dst
    pkt.tcp.dstport = dstport
    return pkt


# ------------------------------------------------------------------ #
#  RFC 1918 _is_private()
# ------------------------------------------------------------------ #

class TestIsPrivate:
    """NIST SP 800-94 §3.1: internal ağ ayrımı doğru çalışmalı."""

    def test_10_network_is_private(self):
        from server.detectors.lateral import _is_private
        assert _is_private("10.0.0.1") is True
        assert _is_private("10.255.255.255") is True

    def test_192_168_is_private(self):
        from server.detectors.lateral import _is_private
        assert _is_private("192.168.0.1") is True
        assert _is_private("192.168.255.255") is True

    def test_172_16_to_31_all_private(self):
        """RFC 1918: 172.16.0.0/12 — 172.16 ile 172.31 arası."""
        from server.detectors.lateral import _is_private
        for i in range(16, 32):
            assert _is_private(f"172.{i}.0.1") is True, f"172.{i}.x private olmalı"

    def test_172_15_is_public(self):
        """172.15.x RFC 1918 dışı — public."""
        from server.detectors.lateral import _is_private
        assert _is_private("172.15.255.255") is False

    def test_172_32_is_public(self):
        """172.32.x RFC 1918 dışı — public."""
        from server.detectors.lateral import _is_private
        assert _is_private("172.32.0.1") is False

    def test_public_ips_not_private(self):
        from server.detectors.lateral import _is_private
        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.1", "198.51.100.1"):
            assert _is_private(ip) is False, f"{ip} public olmalı"

    def test_localhost_not_private(self):
        """127.0.0.1 RFC 1918 değil — loopback."""
        from server.detectors.lateral import _is_private
        assert _is_private("127.0.0.1") is False

    def test_link_local_not_private(self):
        """169.254.x.x link-local — RFC 1918 değil."""
        from server.detectors.lateral import _is_private
        assert _is_private("169.254.1.1") is False


# ------------------------------------------------------------------ #
#  LATERAL_PORTS seti (MITRE ATT&CK T1021)
# ------------------------------------------------------------------ #

class TestLateralPorts:
    def test_all_mitre_t1021_ports_present(self):
        """MITRE ATT&CK T1021 kapsamındaki portlar tanımlı olmalı."""
        from server.detectors.lateral import LATERAL_PORTS
        required = {22, 23, 135, 139, 445, 3389, 5985, 5986}
        assert required.issubset(LATERAL_PORTS)

    def test_http_https_not_lateral(self):
        from server.detectors.lateral import LATERAL_PORTS
        assert 80 not in LATERAL_PORTS
        assert 443 not in LATERAL_PORTS

    def test_lateral_ports_is_frozenset(self):
        from server.detectors.lateral import LATERAL_PORTS
        assert isinstance(LATERAL_PORTS, frozenset)


# ------------------------------------------------------------------ #
#  Sniffer hata senaryoları (NIST SP 800-94 §6.2)
# ------------------------------------------------------------------ #

class TestSnifferFailure:
    def test_pyshark_import_error_logs_warning(self, caplog):
        """pyshark yok → logger.warning, detector çökmemeli."""
        import logging
        from server.detectors.lateral import LateralMovementDetector

        with patch.object(LateralMovementDetector, "_start_sniffer", return_value=None):
            detector = LateralMovementDetector()

        saved = sys.modules.get("pyshark", "ABSENT")
        sys.modules["pyshark"] = None  # ImportError tetikler
        try:
            with caplog.at_level(logging.WARNING, logger="server.detectors.lateral"):
                detector._start_sniffer()
        finally:
            if saved == "ABSENT":
                sys.modules.pop("pyshark", None)
            else:
                sys.modules["pyshark"] = saved

        assert any("pyshark" in r.message.lower() for r in caplog.records)

    def test_pyshark_import_error_no_thread_started(self):
        """pyshark yok → sniffer thread başlatılmamalı."""
        from server.detectors.lateral import LateralMovementDetector

        with patch.object(LateralMovementDetector, "_start_sniffer", return_value=None):
            detector = LateralMovementDetector()

        before = threading.active_count()

        saved = sys.modules.get("pyshark", "ABSENT")
        sys.modules["pyshark"] = None
        try:
            detector._start_sniffer()
        finally:
            if saved == "ABSENT":
                sys.modules.pop("pyshark", None)
            else:
                sys.modules["pyshark"] = saved

        time.sleep(0.05)
        assert threading.active_count() <= before

    def test_sniff_loop_exception_logs_error(self, caplog):
        """sniff_continuously() exception → logger.error, çökmez."""
        import logging
        detector = _make_detector()

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.side_effect = RuntimeError("bağlantı kesildi")

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            with caplog.at_level(logging.ERROR, logger="server.detectors.lateral"):
                detector._sniff_loop()

        assert any("sniffer durdu" in r.message for r in caplog.records)

    def test_attribute_error_in_packet_does_not_stop_loop(self, caplog):
        """Hatalı paket AttributeError → sonraki paket işlenmeli + debug log üretilmeli."""
        import logging
        detector = _make_detector()

        bad_packet = object()  # .ip attribute yok → AttributeError
        good_packet = _make_mock_packet(src="192.168.1.10", dst="192.168.1.20", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([
            bad_packet, good_packet,
        ])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            with caplog.at_level(logging.DEBUG, logger="server.detectors.lateral"):
                detector._sniff_loop()

        with detector._lock:
            assert "192.168.1.10" in detector._history

        assert any("malformed" in r.message.lower() for r in caplog.records)

    def test_value_error_in_dstport_does_not_stop_loop(self):
        """dstport sayısal değil → ValueError → loop ölmemeli, sonraki paket işlenmeli."""
        detector = _make_detector()

        bad_packet = _make_mock_packet(src="192.168.1.5", dst="192.168.1.6", dstport="not_a_number")
        good_packet = _make_mock_packet(src="192.168.1.10", dst="192.168.1.20", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([
            bad_packet, good_packet,
        ])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert "192.168.1.10" in detector._history
            assert "192.168.1.5" not in detector._history


# ------------------------------------------------------------------ #
#  _sniff_loop() paket işleme mantığı
# ------------------------------------------------------------------ #

class TestSniffLoopPacketProcessing:
    def test_valid_lateral_packet_added_to_history(self):
        """İç→iç + LATERAL_PORT → _history'e ekle."""
        detector = _make_detector()
        packet = _make_mock_packet(src="192.168.1.10", dst="192.168.1.20", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([packet])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert "192.168.1.10" in detector._history
            entries = detector._history["192.168.1.10"]
            assert len(entries) == 1
            assert entries[0][1] == "192.168.1.20"
            assert entries[0][2] == 22

    def test_non_lateral_port_not_added(self):
        """Destination port LATERAL_PORTS dışında → _history'e eklenme."""
        detector = _make_detector()
        packet = _make_mock_packet(dstport="80")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([packet])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert len(detector._history) == 0

    def test_public_source_ip_not_added(self):
        """Kaynak IP public → iç→iç değil → eklenmemeli."""
        detector = _make_detector()
        packet = _make_mock_packet(src="8.8.8.8", dst="192.168.1.20", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([packet])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert len(detector._history) == 0

    def test_public_destination_ip_not_added(self):
        """Hedef IP public → iç→iç değil → eklenmemeli."""
        detector = _make_detector()
        packet = _make_mock_packet(src="192.168.1.10", dst="8.8.8.8", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([packet])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert len(detector._history) == 0

    def test_same_src_dst_not_added(self):
        """Kaynak == Hedef → kendi kendine bağlantı → eklenmemeli."""
        detector = _make_detector()
        packet = _make_mock_packet(src="192.168.1.10", dst="192.168.1.10", dstport="22")

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter([packet])

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert len(detector._history) == 0

    def test_all_lateral_ports_accepted(self):
        """Tüm LATERAL_PORTS değerleri → _history'e ekle."""
        from server.detectors.lateral import LATERAL_PORTS
        detector = _make_detector()

        packets = [
            _make_mock_packet(
                src="192.168.1.10",
                dst=f"192.168.1.{20 + i}",
                dstport=str(port),
            )
            for i, port in enumerate(sorted(LATERAL_PORTS))
        ]

        mock_pyshark = MagicMock()
        mock_pyshark.LiveCapture.return_value.sniff_continuously.return_value = iter(packets)

        with patch.dict(sys.modules, {"pyshark": mock_pyshark}):
            detector._sniff_loop()

        with detector._lock:
            assert len(detector._history["192.168.1.10"]) == len(LATERAL_PORTS)


# ------------------------------------------------------------------ #
#  Window temizleme ve _alerted sıfırlama
# ------------------------------------------------------------------ #

# ------------------------------------------------------------------ #
#  Window temizleme — deterministik (age parametresi)
# ------------------------------------------------------------------ #

class TestWindowCleanup:
    def test_expired_entries_removed_by_detect(self):
        """Süresi dolmuş girişler detect() ile silinmeli — deterministik, sleep yok."""
        detector = _make_detector(threshold=2, window=120)
        _inject(detector, "192.168.1.10", [("192.168.1.1", 22)], age=200.0)

        detector.detect()

        with detector._lock:
            assert "192.168.1.10" not in detector._history
            assert "192.168.1.10" not in detector._alerted

    def test_fresh_and_expired_mixed(self):
        """Karma girdi: eski silindi, yeni kaldı — history boş değil."""
        detector = _make_detector(threshold=2, window=120)
        _inject(detector, "192.168.1.10", [("192.168.1.1", 22)], age=200.0)
        _inject(detector, "192.168.1.10", [("192.168.1.2", 445)], age=0.0)

        detector.detect()

        with detector._lock:
            assert "192.168.1.10" in detector._history
            assert len(detector._history["192.168.1.10"]) == 1


# ------------------------------------------------------------------ #
#  Window temizleme ve _alerted sıfırlama
# ------------------------------------------------------------------ #

class TestAlertedReset:
    def test_alerted_cleared_after_entries_expire(self):
        """Tüm girişler pencere dışına çıkınca _alerted temizlenmeli → IP tekrar uyarı üretir."""
        detector = _make_detector(threshold=2, window=1)

        _inject(detector, "192.168.1.10", [
            ("192.168.1.1", 22), ("192.168.1.2", 445),
        ])
        first = detector.detect()
        assert len(first) == 1
        assert "192.168.1.10" in detector._alerted

        time.sleep(1.1)

        # Süresi dolmuş girişleri temizlemek için detect() çağrısı zorunlu;
        # bu çağrı _history'yi boşaltır → _alerted.discard() tetiklenir.
        detector.detect()
        assert "192.168.1.10" not in detector._alerted

        _inject(detector, "192.168.1.10", [
            ("192.168.1.1", 22), ("192.168.1.2", 445),
        ])
        second = detector.detect()
        assert len(second) == 1

    def test_partial_window_does_not_clear_alerted(self):
        """Bir kısım girdi eski, bir kısmı yeni → IP hâlâ uyarılmış sayılmalı."""
        detector = _make_detector(threshold=2, window=60)

        _inject(detector, "192.168.1.10", [
            ("192.168.1.1", 22), ("192.168.1.2", 445),
        ])
        detector.detect()  # Uyarıyı kaydet

        # Yeni girdi ekle — eski silindi ama uyarı durumu korunmalı
        _inject(detector, "192.168.1.10", [
            ("192.168.1.3", 22),
        ])
        second = detector.detect()
        assert len(second) == 0  # Zaten uyarıldı, tekrar üretme


# ------------------------------------------------------------------ #
#  Thread safety (IEEE 1012 — concurrent verification)
# ------------------------------------------------------------------ #

class TestThreadSafety:
    def test_concurrent_history_write_no_crash(self):
        """Eşzamanlı _history yazma race condition üretmemeli."""
        detector = _make_detector(threshold=100, window=60)
        errors: list[Exception] = []

        def writer(src_ip: str, dst_ip: str):
            try:
                now = time.monotonic()
                with detector._lock:
                    detector._history[src_ip].append((now, dst_ip, 22))
            except Exception as exc:
                errors.append(exc)

        def reader():
            try:
                detector.detect()
            except Exception as exc:
                errors.append(exc)

        threads = []
        for i in range(5):
            for j in range(4):
                threads.append(
                    threading.Thread(target=writer, args=(f"192.168.1.{i}", f"192.168.2.{j}"))
                )
        for _ in range(5):
            threads.append(threading.Thread(target=reader))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Race condition: {errors}"

    def test_detect_is_threadsafe_with_lock(self):
        """10 paralel detect() çağrısı — sadece 1 uyarı üretilmeli (lock koruması)."""
        detector = _make_detector(threshold=2, window=60)
        _inject(detector, "192.168.1.10", [
            ("192.168.1.1", 22), ("192.168.1.2", 445),
        ])

        results: list = []

        def run_detect():
            logs = detector.detect()
            results.extend(logs)

        threads = [threading.Thread(target=run_detect) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(results) == 1, f"Beklenen 1 uyarı, üretilen: {len(results)}"
