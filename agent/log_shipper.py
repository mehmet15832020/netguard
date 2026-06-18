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

from agent.tls_config import resolve_client_cert, resolve_tls_verify

logger = logging.getLogger(__name__)

AUTH_LOG_PATH  = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
# M1 — Reboot-safe position file (Filebeat registry pattern — Elastic/Filebeat docs)
_DEFAULT_POS_DIR = os.getenv("LOG_POSITION_DIR", "/var/lib/netguard")
POSITION_FILE  = os.getenv("LOG_POSITION_FILE", os.path.join(_DEFAULT_POS_DIR, "auth_pos"))
SHIP_INTERVAL  = 10   # saniye
BATCH_SIZE     = 50   # tek seferde max kaç olay gönderilir
CONN_SCAN_INTERVAL = 60  # saniye — bağlantı taraması aralığı
SUSPICIOUS_CONN_THRESHOLD = int(os.getenv("SUSPICIOUS_CONN_THRESHOLD", "5"))

_RE_FAILED   = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port")
_RE_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port")
_RE_SUDO     = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
_RE_PAM_AUTH_FAILURE = re.compile(
    r"PAM:?\s+[Aa]uthentication failure.*?(?:for user|user=)\s*(\S+?)(?:\s+from\s+([\d.]+))?(?:\s|$)"
)
_RE_PAM_UNIX = re.compile(
    r"pam_unix\(\S+:auth\):\s+authentication failure;.*?user=(\S+)"
)
# M2 — su kullanıcı değiştirme başarısız (MITRE ATT&CK T1548.003)
_RE_SU_FAIL = re.compile(
    r"su:\s+FAILED\s+SU\s+\(to\s+(\S+)\)\s+(\S+)\s+on"
)
_RE_PAM_SU_FAIL = re.compile(
    r"pam_unix\(su(?:-l)?:auth\):\s+authentication failure;.*\buser=(\S+)"
)

# M3/M4 — _TRUSTED_DPORTS kaldırıldı; 443/80 dahil tüm dış bağlantılar raporlanır.
# CrowdStrike 2025: saldırıların %71'i HTTPS C2 (443/80) — filtrelemek kör nokta yaratır.
# Şüpheli hedef portlar — bunlar için severity critical
_SUSPICIOUS_DPORTS = frozenset({
    4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999,    # C2 geleneksel
    1337, 31337,                                          # hacker kültürü
    5900, 5901,                                           # VNC
    3389,                                                 # RDP
    23, 2323,                                             # Telnet
    21,                                                   # FTP
    6379, 27017, 5432, 3306,                             # Veritabanı portları
})
# Düşük öncelikli bilinen servis portları — info severity
_COMMON_DPORTS = frozenset({53, 123, 5140, 2055, 22, 8000})


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
    if m := _RE_PAM_AUTH_FAILURE.search(line):
        username = m.group(1).rstrip(";")
        source_ip = m.group(2) if m.lastindex and m.lastindex >= 2 else None
        return {
            "event_action": "pam_auth_failure",
            "severity":   "warning",
            "username":   username,
            "source_ip":  source_ip,
            "message":    (
                f"PAM kimlik doğrulama hatası: kullanıcı={username}"
                + (f" kaynak={source_ip}" if source_ip else "")
            ),
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    # M2 — su kullanıcı değiştirme başarısız (önce kontrol edilmeli — _RE_PAM_UNIX daha genel)
    if m := _RE_PAM_SU_FAIL.search(line):
        username = m.group(1)
        return {
            "event_action": "su_failure",
            "severity":   "warning",
            "username":   username,
            "source_ip":  None,
            "message":    f"PAM su kimlik doğrulama başarısız: kullanıcı={username}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    if m := _RE_PAM_UNIX.search(line):
        username = m.group(1)
        return {
            "event_action": "pam_auth_failure",
            "severity":   "warning",
            "username":   username,
            "source_ip":  None,
            "message":    f"PAM kimlik doğrulama hatası: kullanıcı={username}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    # M2 — "su: FAILED SU (to root) user on pts/0"
    if m := _RE_SU_FAIL.search(line):
        target_user = m.group(1)
        actor = m.group(2)
        return {
            "event_action": "su_failure",
            "severity":   "warning",
            "username":   actor,
            "source_ip":  None,
            "message":    f"su başarısız: {actor} → {target_user}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_position_dir() -> None:
    try:
        Path(POSITION_FILE).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _read_position() -> int:
    try:
        return int(Path(POSITION_FILE).read_text().strip())
    except Exception:
        return 0


def _write_position(pos: int) -> None:
    _ensure_position_dir()
    try:
        Path(POSITION_FILE).write_text(str(pos))
    except Exception:
        pass


def _collect_suspicious_connections() -> list[dict]:
    """
    psutil.net_connections() ile aktif TCP bağlantıları tarar.

    Bilinen kötü portlara (C2/VNC/RDP/DB) yapılan bağlantılar doğrudan raporlanır.
    Yüksek ephemeral portlara giden bağlantılar ise SUSPICIOUS_CONN_THRESHOLD
    kadar farklı hedefe ulaşıldığında raporlanır — tek bağlantı FP'yi önler.
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    local_ip = socket.gethostbyname(socket.gethostname())
    now = _now_iso()

    known_bad_events: list[dict] = []
    ephemeral_remotes: set[str] = set()

    for conn in conns:
        if conn.status != "ESTABLISHED":
            continue
        if not conn.raddr:
            continue

        remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0

        if remote_ip in ("127.0.0.1", "::1", local_ip):
            continue

        proc_name = ""
        try:
            if conn.pid:
                proc_name = psutil.Process(conn.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if remote_port in _SUSPICIOUS_DPORTS:
            known_bad_events.append({
                "event_action": "suspicious_outbound_connection",
                "severity": "critical",
                "username": None,
                "source_ip": local_ip,
                "message": (
                    f"Şüpheli bağlantı: {local_ip}:{local_port} → {remote_ip}:{remote_port}"
                    + (f" [{proc_name}]" if proc_name else "")
                ),
                "raw_data": f"pid={conn.pid} proc={proc_name} raddr={remote_ip}:{remote_port}",
                "occurred_at": now,
            })
        elif remote_port not in _COMMON_DPORTS:
            # M3/M4 — 443 dahil tüm yüksek port bağlantıları raporla; eşik bazlı FP kontrolü
            ephemeral_remotes.add(f"{remote_ip}:{remote_port}")

    events = list(known_bad_events)

    if len(ephemeral_remotes) >= SUSPICIOUS_CONN_THRESHOLD:
        events.append({
            "event_action": "suspicious_outbound_connection",
            "severity": "warning",
            "username": None,
            "source_ip": local_ip,
            "message": (
                f"Yüksek sayıda ephemeral bağlantı: {local_ip} → "
                f"{len(ephemeral_remotes)} farklı hedef (eşik: {SUSPICIOUS_CONN_THRESHOLD})"
            ),
            "raw_data": f"ephemeral_count={len(ephemeral_remotes)}",
            "occurred_at": now,
        })

    return events


def _collect_listening_ports() -> list[dict]:
    """M5 — LISTEN durumundaki portları process adıyla raporlar.

    Yeni backdoor listener tespiti için: collector.py'daki count-only yaklaşımının aksine
    hangi port + hangi process listesi döner. (MITRE ATT&CK T1571; CIS Controls v8 §4.5)
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return []

    events = []
    now = _now_iso()
    for conn in conns:
        if conn.status != "LISTEN":
            continue
        if not conn.laddr:
            continue
        port = conn.laddr.port
        proto = "tcp6" if ":" in conn.laddr.ip else "tcp"
        proc_name = ""
        try:
            if conn.pid:
                proc_name = psutil.Process(conn.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        events.append({
            "event_action": "listening_port",
            "severity": "info",
            "username": None,
            "source_ip": None,
            "message": f"Dinleyen port: {port}/{proto} [{proc_name}]",
            "raw_data": f"pid={conn.pid} proc={proc_name} port={port} proto={proto}",
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
        self._client     = httpx.Client(
            timeout=10, verify=resolve_tls_verify(), cert=resolve_client_cert(),
        )
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
        _last_port_scan = 0.0
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

            # M5 — Listening port snapshot (5 dakikada bir; günde 288 snapshot)
            if now - _last_port_scan >= 300:
                try:
                    port_events = _collect_listening_ports()
                    if port_events:
                        self._ship(port_events)
                except Exception as e:
                    logger.warning(f"Port taraması hatası: {e}")
                _last_port_scan = now

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
