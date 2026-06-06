"""
NetGuard — Sensor sağlık metrikleri (C4).

CIS Control 13.1: Sürekli ağ izleme kapasitesinin doğrulanması.
Zeek stats.log paket kaybı, Suricata EVE kernel_drops, psutil arayüz sayaçları.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psutil

logger = logging.getLogger(__name__)

ZEEK_STATS_LOG           = Path(os.getenv("ZEEK_STATS_LOG",    "/zeek-logs/stats.log"))
SURICATA_EVE_LOG         = Path(os.getenv("SURICATA_EVE_LOG",  "/var/log/suricata/eve.json"))
SENSOR_DROP_WARN_THRESH  = float(os.getenv("SENSOR_DROP_WARN_THRESHOLD",  "0.05"))
SENSOR_DROP_CRIT_THRESH  = float(os.getenv("SENSOR_DROP_CRIT_THRESHOLD",  "0.15"))

_IFACE_SKIP = frozenset({"lo"})


def _status(drop_rate: float) -> str:
    if drop_rate >= SENSOR_DROP_CRIT_THRESH:
        return "critical"
    if drop_rate >= SENSOR_DROP_WARN_THRESH:
        return "warning"
    return "ok"


def _parse_zeek_ts(ts_str: str) -> Optional[str]:
    try:
        return datetime.fromtimestamp(float(ts_str), tz=timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        return ts_str


def _read_zeek_tsv_headers(stats_path: Path) -> list[str]:
    try:
        with stats_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#fields"):
                    return line.split("\t")[1:]
    except Exception:
        pass
    return []


def get_zeek_stats(stats_path: Path = ZEEK_STATS_LOG) -> dict:
    result: dict = {
        "name": "zeek",
        "status": "unknown",
        "pkts_proc": None,
        "drop_rate": None,
        "bytes_recv": None,
        "last_updated": None,
        "error": None,
    }

    try:
        if not stats_path.exists():
            result["error"] = "stats.log bulunamadı"
            return result

        last_line = None
        with stats_path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw and not raw.startswith("#"):
                    last_line = raw

        if not last_line:
            result["error"] = "stats.log veri içermiyor"
            return result

        try:
            data = json.loads(last_line)
            pkts_proc    = int(data.get("pkts_proc", 0))
            drop_rate    = float(data.get("pkt_drop_rate", 0.0))
            bytes_recv   = int(data.get("bytes_recv", 0))
            last_updated = _parse_zeek_ts(str(data["ts"])) if "ts" in data else None
        except (json.JSONDecodeError, ValueError):
            headers = _read_zeek_tsv_headers(stats_path)
            parts   = last_line.split("\t")

            def _col(name: str, default: str = "0") -> str:
                try:
                    return parts[headers.index(name)]
                except (ValueError, IndexError):
                    return default

            pkts_proc    = int(float(_col("pkts_proc")))
            drop_rate    = float(_col("pkt_drop_rate"))
            bytes_recv   = int(float(_col("bytes_recv")))
            ts_val       = _col("ts", "0")
            last_updated = _parse_zeek_ts(ts_val) if ts_val != "0" else None

        result.update({
            "status":       _status(drop_rate),
            "pkts_proc":    pkts_proc,
            "drop_rate":    round(drop_rate, 4),
            "bytes_recv":   bytes_recv,
            "last_updated": last_updated,
        })

    except Exception as exc:
        logger.warning("Zeek stats.log okunamadı: %s", exc)
        result["status"] = "unknown"
        result["error"]  = str(exc)

    return result


def get_suricata_stats(eve_path: Path = SURICATA_EVE_LOG) -> dict:
    result: dict = {
        "name": "suricata",
        "status": "unknown",
        "kernel_packets": None,
        "kernel_drops": None,
        "drop_rate": None,
        "decoder_packets": None,
        "last_updated": None,
        "error": None,
    }

    try:
        if not eve_path.exists():
            result["error"] = "eve.json bulunamadı"
            return result

        file_size  = eve_path.stat().st_size
        read_from  = max(0, file_size - 512 * 1024)
        last_stats = None

        with eve_path.open("r", encoding="utf-8", errors="replace") as fh:
            if read_from > 0:
                fh.seek(read_from)
                fh.readline()
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    if obj.get("event_type") == "stats":
                        last_stats = obj
                except json.JSONDecodeError:
                    continue

        if not last_stats:
            result["error"] = "stats event bulunamadı"
            return result

        stats_block = last_stats.get("stats", {})
        capture     = stats_block.get("capture", {})
        decoder     = stats_block.get("decoder", {})

        kernel_packets = int(capture.get("kernel_packets", 0))
        kernel_drops   = int(capture.get("kernel_drops",   0))
        total          = kernel_packets + kernel_drops
        drop_rate      = (kernel_drops / total) if total > 0 else 0.0

        result.update({
            "status":          _status(drop_rate),
            "kernel_packets":  kernel_packets,
            "kernel_drops":    kernel_drops,
            "drop_rate":       round(drop_rate, 4),
            "decoder_packets": int(decoder.get("pkts", 0)),
            "last_updated":    last_stats.get("timestamp"),
        })

    except Exception as exc:
        logger.warning("Suricata EVE stats okunamadı: %s", exc)
        result["status"] = "unknown"
        result["error"]  = str(exc)

    return result


def get_interface_stats() -> list[dict]:
    results = []
    try:
        counters = psutil.net_io_counters(pernic=True)
        for iface, s in counters.items():
            if iface in _IFACE_SKIP or iface.startswith(("veth", "docker", "br-")):
                continue
            total     = s.packets_recv + s.dropin
            drop_rate = (s.dropin / total) if total > 0 else 0.0
            results.append({
                "interface":   iface,
                "status":      _status(drop_rate),
                "packets_recv": s.packets_recv,
                "dropin":      s.dropin,
                "dropout":     s.dropout,
                "drop_rate":   round(drop_rate, 4),
                "bytes_recv":  s.bytes_recv,
                "bytes_sent":  s.bytes_sent,
            })
    except Exception as exc:
        logger.warning("Arayüz istatistikleri alınamadı: %s", exc)
    return results


def get_all_sensor_health() -> dict:
    zeek      = get_zeek_stats()
    suricata  = get_suricata_stats()
    ifaces    = get_interface_stats()

    statuses = [s["status"] for s in (zeek, suricata) if s["status"] != "unknown"]
    if "critical" in statuses:
        overall = "critical"
    elif "warning" in statuses:
        overall = "warning"
    elif statuses:
        overall = "ok"
    else:
        overall = "unknown"

    return {
        "overall":    overall,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "sensors": {
            "zeek":     zeek,
            "suricata": suricata,
        },
        "interfaces": ifaces,
        "thresholds": {
            "warn":     SENSOR_DROP_WARN_THRESH,
            "critical": SENSOR_DROP_CRIT_THRESH,
        },
    }
