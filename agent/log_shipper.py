"""
NetGuard Agent — Log Shipper

/var/log/auth.log'u tails ederek güvenlik olaylarını NetGuard sunucusuna gönderir.
Ayrıca psutil.net_connections() ile şüpheli bağlantıları periyodik olarak raporlar.
Position file ile restart'ta duplicate önler.
Thread olarak çalışır, ana agent döngüsünden bağımsızdır.
"""

import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import psutil

logger = logging.getLogger(__name__)

AUTH_LOG_PATH  = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
POSITION_FILE  = os.getenv("LOG_POSITION_FILE", "/tmp/netguard_auth_pos")
SHIP_INTERVAL  = 10   # saniye
BATCH_SIZE     = 50   # tek seferde max kaç olay gönderilir
CONN_SCAN_INTERVAL = 60  # saniye — bağlantı taraması aralığı

_RE_FAILED   = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port")
_RE_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port")
_RE_SUDO     = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")

# Bilinen meşru portlar — bunları raporlama
_TRUSTED_DPORTS = frozenset({22, 80, 443, 8000, 8080, 8443, 53, 123, 5140, 2055})
# Şüpheli hedef portlar
_SUSPICIOUS_DPORTS = frozenset({
    4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,    # C2 geleneksel
    1337, 31337,                                          # hacker kültürü
    5900, 5901,                                           # VNC
    3389,                                                 # RDP
    23, 2323,                                             # Telnet
    21,                                                   # FTP
    6379, 27017, 5432, 3306,                             # Veritabanı portları
})


def _parse_line(line: str) -> Optional[dict]:
    """Tek bir auth.log satırını parse eder. Tanınamazsa None döner."""
    if m := _RE_FAILED.search(line):
        return {
            "event_action": "ssh_failure",
            "severity":   "warning",
            "username":   m.group(1),
            "source_ip":  m.group(2),
            "message":    f"Başarısız SSH girişi: kullanıcı={m.group(1)} kaynak={m.group(2)}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    if m := _RE_ACCEPTED.search(line):
        return {
            "event_action": "ssh_success",
            "severity":   "info",
            "username":   m.group(1),
            "source_ip":  m.group(2),
            "message":    f"Başarılı SSH girişi: kullanıcı={m.group(1)} kaynak={m.group(2)}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    if m := _RE_SUDO.search(line):
        return {
            "event_action": "sudo_usage",
            "severity":   "info",
            "username":   m.group(1),
            "source_ip":  None,
            "message":    f"Sudo kullanımı: kullanıcı={m.group(1)} komut={m.group(2).strip()}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_position() -> int:
    try:
        return int(Path(POSITION_FILE).read_text().strip())
    except Exception:
        return 0


def _write_position(pos: int) -> None:
    try:
        Path(POSITION_FILE).write_text(str(pos))
    except Exception:
        pass


def _collect_suspicious_connections() -> list[dict]:
    """
    psutil.net_connections() ile aktif TCP bağlantıları tarar.
    Şüpheli portlara (C2 portları, DB portları, VNC, RDP vb.) yapılan
    ESTABLISHED bağlantıları raporlar.
    """
    events = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    local_ip = socket.gethostbyname(socket.gethostname())
    now = _now_iso()

    for conn in conns:
        if conn.status != "ESTABLISHED":
            continue
        if not conn.raddr:
            continue

        remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0

        if remote_ip in ("127.0.0.1", "::1", local_ip):
            continue

        is_suspicious_port = remote_port in _SUSPICIOUS_DPORTS
        is_high_ephemeral = remote_port >= 49152

        if not is_suspicious_port and not is_high_ephemeral:
            continue
        if remote_port in _TRUSTED_DPORTS:
            continue

        severity = "critical" if is_suspicious_port else "warning"
        proc_name = ""
        try:
            if conn.pid:
                proc_name = psutil.Process(conn.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        events.append({
            "event_action": "suspicious_outbound_connection",
            "severity": severity,
            "username": None,
            "source_ip": local_ip,
            "message": (
                f"Şüpheli bağlantı: {local_ip}:{local_port} → {remote_ip}:{remote_port}"
                + (f" [{proc_name}]" if proc_name else "")
            ),
            "raw_data": f"pid={conn.pid} proc={proc_name} raddr={remote_ip}:{remote_port}",
            "occurred_at": now,
        })

    return events


def _collect_new_events() -> list[dict]:
    """auth.log'u son okunan pozisyondan itibaren okur, olayları döner."""
    log_path = Path(AUTH_LOG_PATH)
    if not log_path.exists():
        return []

    pos = _read_position()
    current_size = log_path.stat().st_size

    if current_size < pos:
        pos = 0

    events = []
    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(pos)
            for line in f:
                ev = _parse_line(line)
                if ev:
                    events.append(ev)
            new_pos = f.tell()
        _write_position(new_pos)
    except PermissionError:
        logger.warning(f"auth.log okunamıyor — izin hatası: {AUTH_LOG_PATH}")
    except Exception as e:
        logger.warning(f"auth.log okuma hatası: {e}")

    return events


class LogShipper:
    """Auth.log'u periyodik olarak okuyup sunucuya gönderir."""

    def __init__(self, server_url: str, api_key: str):
        self._server_url = server_url.rstrip("/")
        self._api_key    = api_key
        self._hostname   = socket.gethostname()
        self._client     = httpx.Client(timeout=10, verify=False)
        self._thread     = threading.Thread(target=self._loop, daemon=True)
        self._stop       = threading.Event()

    def start(self) -> None:
        if not self._api_key:
            logger.warning("NETGUARD_API_KEY tanımlı değil — log shipper devre dışı")
            return
        if not Path(AUTH_LOG_PATH).exists():
            logger.warning(f"auth.log bulunamadı ({AUTH_LOG_PATH}) — auth log izleme devre dışı")
        self._thread.start()
        logger.info("Log Shipper başlatıldı.")

    def stop(self) -> None:
        self._stop.set()
        self._client.close()

    def _loop(self) -> None:
        _last_conn_scan = 0.0
        while not self._stop.is_set():
            try:
                events = _collect_new_events()
                if events:
                    self._ship(events)
            except Exception as e:
                logger.warning(f"Log Shipper döngü hatası: {e}")

            now = time.time()
            if now - _last_conn_scan >= CONN_SCAN_INTERVAL:
                try:
                    conn_events = _collect_suspicious_connections()
                    if conn_events:
                        self._ship(conn_events)
                except Exception as e:
                    logger.warning(f"Bağlantı taraması hatası: {e}")
                _last_conn_scan = now

            self._stop.wait(SHIP_INTERVAL)

    def _ship(self, events: list[dict]) -> None:
        url = f"{self._server_url}/api/v1/agents/security-events"
        for i in range(0, len(events), BATCH_SIZE):
            batch = events[i:i + BATCH_SIZE]
            try:
                resp = self._client.post(
                    url,
                    json={"hostname": self._hostname, "events": batch},
                    headers={"X-API-Key": self._api_key},
                )
                resp.raise_for_status()
                logger.info(f"Log Shipper: {len(batch)} olay gönderildi.")
            except Exception as e:
                logger.warning(f"Log Shipper gönderim hatası: {e}")
