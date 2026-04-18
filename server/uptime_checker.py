"""
NetGuard — Uptime / Service Checker

Her kayıtlı cihaz için:
  - ICMP ping    (asyncio subprocess)
  - TCP port     (asyncio.open_connection)
  - HTTP/HTTPS   (httpx async)

Sonuçlar service_checks tablosuna kaydedilir ve security_events'e yazılır.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 5.0   # saniye
_TCP_TIMEOUT  = 3.0
_PING_TIMEOUT = 3.0
_PING_COUNT   = 3


async def ping(host: str, count: int = _PING_COUNT, timeout: float = _PING_TIMEOUT) -> dict:
    """
    ICMP ping — asyncio subprocess ile platform-bağımsız.
    Döndürür: {reachable, rtt_ms, packet_loss_pct, error}
    """
    cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), host]
    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        elapsed = (time.monotonic() - start) * 1000  # ms

        output = stdout.decode(errors="replace")
        reachable = proc.returncode == 0

        # "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.123 ms" satırından avg al
        rtt_ms: Optional[float] = None
        for line in output.splitlines():
            if "rtt" in line and "avg" in line:
                try:
                    rtt_ms = float(line.split("=")[1].strip().split("/")[1])
                except (IndexError, ValueError):
                    pass
            # "X packets transmitted, Y received" — paket kayıp hesabı
        loss_pct = 0.0
        for line in output.splitlines():
            if "packet loss" in line:
                try:
                    loss_pct = float(line.split("%")[0].split()[-1])
                except (IndexError, ValueError):
                    pass

        return {
            "reachable": reachable,
            "rtt_ms": rtt_ms if rtt_ms is not None else (elapsed / count if reachable else None),
            "packet_loss_pct": loss_pct,
            "error": "" if reachable else "ping timeout/unreachable",
        }
    except asyncio.TimeoutError:
        return {"reachable": False, "rtt_ms": None, "packet_loss_pct": 100.0, "error": "timeout"}
    except Exception as exc:
        return {"reachable": False, "rtt_ms": None, "packet_loss_pct": 100.0, "error": str(exc)}


async def tcp_check(host: str, port: int, timeout: float = _TCP_TIMEOUT) -> dict:
    """
    TCP port erişilebilirlik testi.
    Döndürür: {reachable, rtt_ms, error}
    """
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        rtt_ms = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"reachable": True, "rtt_ms": round(rtt_ms, 2), "error": ""}
    except asyncio.TimeoutError:
        return {"reachable": False, "rtt_ms": None, "error": "timeout"}
    except ConnectionRefusedError:
        return {"reachable": False, "rtt_ms": None, "error": "connection refused"}
    except Exception as exc:
        return {"reachable": False, "rtt_ms": None, "error": str(exc)}


async def http_check(url: str, timeout: float = _HTTP_TIMEOUT) -> dict:
    """
    HTTP/HTTPS GET isteği ile servis kontrolü.
    Döndürür: {reachable, status_code, rtt_ms, error}
    """
    try:
        import httpx
    except ImportError:
        return {"reachable": False, "status_code": None, "rtt_ms": None, "error": "httpx kurulu değil"}

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
        rtt_ms = round((time.monotonic() - start) * 1000, 2)
        ok = resp.status_code < 500
        return {
            "reachable": ok,
            "status_code": resp.status_code,
            "rtt_ms": rtt_ms,
            "error": "" if ok else f"HTTP {resp.status_code}",
        }
    except httpx.TimeoutException:
        return {"reachable": False, "status_code": None, "rtt_ms": None, "error": "timeout"}
    except Exception as exc:
        return {"reachable": False, "status_code": None, "rtt_ms": None, "error": str(exc)}


async def check_device(device_id: str, ip: str) -> list[dict]:
    """
    Bir cihazı ping + yaygın TCP portlarla kontrol eder.
    Döndürür: [{"check_type", "target", "port", "status", "rtt_ms", "details"}, ...]
    """
    results = []

    # ICMP ping
    pr = await ping(ip)
    results.append({
        "device_id": device_id,
        "check_type": "icmp",
        "target": ip,
        "port": None,
        "status": "up" if pr["reachable"] else "down",
        "rtt_ms": pr["rtt_ms"],
        "details": pr,
    })

    # Yaygın TCP portlar (sadece cihaz ping'e cevap veriyorsa)
    if pr["reachable"]:
        common_ports = [22, 80, 443, 161]
        tcp_tasks = [tcp_check(ip, p) for p in common_ports]
        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
        for port, tr in zip(common_ports, tcp_results):
            if isinstance(tr, Exception):
                tr = {"reachable": False, "rtt_ms": None, "error": str(tr)}
            results.append({
                "device_id": device_id,
                "check_type": "tcp",
                "target": ip,
                "port": port,
                "status": "up" if tr["reachable"] else "down",
                "rtt_ms": tr["rtt_ms"],
                "details": tr,
            })

    return results


class UptimeChecker:
    """Kayıtlı cihazları periyodik olarak kontrol eden servis."""

    def __init__(self):
        self._prev_status: dict[str, str] = {}  # device_id → "up"/"down"

    async def run_once(self) -> list[dict]:
        """Tüm cihazları bir kez kontrol eder, sonuçları kaydeder."""
        from server.database import db

        devices = db.get_devices()
        if not devices:
            return []

        # Her cihaz için IP belirle (agent: ip, snmp: ip/host)
        tasks = []
        device_refs = []
        for dev in devices:
            ip = dev.get("ip") or dev.get("device_id")
            if not ip or not _looks_like_ip(ip):
                continue
            tasks.append(check_device(dev["device_id"], ip))
            device_refs.append(dev)

        if not tasks:
            return []

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        flat: list[dict] = []

        for dev, results in zip(device_refs, all_results):
            if isinstance(results, Exception):
                logger.warning(f"Uptime check hatası ({dev['device_id']}): {results}")
                continue

            # DB'ye kaydet
            for r in results:
                try:
                    db.save_service_check(
                        device_id=r["device_id"],
                        check_type=r["check_type"],
                        target=r["target"],
                        port=r["port"],
                        status=r["status"],
                        rtt_ms=r["rtt_ms"],
                        details=str(r["details"]),
                    )
                except Exception as exc:
                    logger.error(f"service_check DB hatası: {exc}")

            # ICMP sonucundan device status güncelle
            icmp = next((r for r in results if r["check_type"] == "icmp"), None)
            if icmp:
                new_status = icmp["status"]
                old_status = self._prev_status.get(dev["device_id"])
                if old_status is not None and old_status != new_status:
                    logger.warning(
                        f"Cihaz durum değişimi: {dev['device_id']} {old_status} → {new_status}"
                    )
                    _emit_status_event(dev, new_status)
                self._prev_status[dev["device_id"]] = new_status
                try:
                    db.update_device_status(dev["device_id"], new_status)
                except Exception as exc:
                    logger.error(f"Device status güncelleme hatası: {exc}")

            flat.extend(results)

        return flat


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _emit_status_event(dev: dict, new_status: str):
    """Cihaz up/down değişimini security_events'e yazar."""
    try:
        import uuid
        from datetime import datetime, timezone
        from server.database import db
        from shared.models import SecurityEvent, SecurityEventType

        etype = SecurityEventType.DEVICE_DOWN if new_status == "down" else SecurityEventType.DEVICE_UP
        severity = "warning" if new_status == "down" else "info"
        name = dev.get("name") or dev.get("device_id", "unknown")
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            agent_id=dev.get("device_id", "unknown"),
            hostname=name,
            event_type=etype,
            severity=severity,
            source_ip=dev.get("ip"),
            message=f"Cihaz durumu değişti: {name} → {new_status}",
            raw_data=str(dev),
            occurred_at=datetime.now(timezone.utc),
        )
        db.save_security_event(event)
    except Exception as exc:
        logger.error(f"Status event yazma hatası: {exc}")


uptime_checker = UptimeChecker()
