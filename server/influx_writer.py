"""
NetGuard — InfluxDB Writer

MetricSnapshot'ları InfluxDB'ye yazar.
Line Protocol formatı kullanır — InfluxDB'nin native formatı.

Tasarım: Storage katmanından bağımsız.
RAM cache hâlâ çalışır, InfluxDB kalıcı katman olarak eklenir.
"""

import logging
import os
import re
from datetime import datetime, timezone

_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from shared.models import MetricSnapshot
from server.snmp_collector import SNMPDeviceInfo

logger = logging.getLogger(__name__)


class InfluxWriter:
    """
    InfluxDB'ye veri yazar.
    Her MetricSnapshot için birden fazla measurement yazar:
    - cpu_metrics
    - memory_metrics
    - disk_metrics
    - network_metrics
    """

    def __init__(self):
        self._url = os.getenv("INFLUXDB_URL", "http://localhost:8086")
        self._token = os.getenv("INFLUXDB_TOKEN", "")
        self._org = os.getenv("INFLUXDB_ORG", "netguard")
        self._bucket = os.getenv("INFLUXDB_BUCKET", "metrics")
        self._client = None
        self._write_api = None
        self._enabled = bool(self._token)

        if not self._enabled:
            logger.warning("INFLUXDB_TOKEN tanımlı değil — InfluxDB devre dışı")

    def connect(self):
        """InfluxDB bağlantısını kur."""
        if not self._enabled:
            return
        try:
            self._client = InfluxDBClient(
                url=self._url,
                token=self._token,
                org=self._org,
            )
            self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
            health = self._client.health()
            logger.info(f"InfluxDB bağlantısı kuruldu: {self._url} ({health.status})")
        except Exception as e:
            logger.error(f"InfluxDB bağlantı hatası: {e}")
            self._enabled = False

    def write_snapshot(self, snapshot: MetricSnapshot) -> bool:
        """
        Snapshot'ı InfluxDB'ye yazar.
        Başarılıysa True, hata olursa False döner.
        """
        if not self._enabled or not self._write_api:
            return False

        try:
            points = []
            ts = snapshot.collected_at

            # CPU metrikleri
            points.append(
                Point("cpu_metrics")
                .tag("agent_id", snapshot.agent_id)
                .tag("hostname", snapshot.hostname)
                .field("usage_percent", snapshot.cpu.usage_percent)
                .field("core_count", snapshot.cpu.core_count)
                .field("load_avg_1m", snapshot.cpu.load_avg_1m)
                .time(ts, WritePrecision.S)
            )

            # RAM metrikleri
            mem = snapshot.memory
            ram_pct = (mem.used_bytes / mem.total_bytes * 100) if mem.total_bytes > 0 else 0
            points.append(
                Point("memory_metrics")
                .tag("agent_id", snapshot.agent_id)
                .tag("hostname", snapshot.hostname)
                .field("used_bytes", mem.used_bytes)
                .field("total_bytes", mem.total_bytes)
                .field("available_bytes", mem.available_bytes)
                .field("usage_percent", round(ram_pct, 2))
                .time(ts, WritePrecision.S)
            )

            # Disk metrikleri
            for disk in snapshot.disks:
                points.append(
                    Point("disk_metrics")
                    .tag("agent_id", snapshot.agent_id)
                    .tag("hostname", snapshot.hostname)
                    .tag("mount_point", disk.mount_point)
                    .field("used_bytes", disk.used_bytes)
                    .field("free_bytes", disk.free_bytes)
                    .field("usage_percent", disk.usage_percent)
                    .time(ts, WritePrecision.S)
                )

            # Network metrikleri
            for iface in snapshot.network_interfaces:
                points.append(
                    Point("network_metrics")
                    .tag("agent_id", snapshot.agent_id)
                    .tag("hostname", snapshot.hostname)
                    .tag("interface", iface.interface_name)
                    .field("bytes_sent", iface.bytes_sent)
                    .field("bytes_recv", iface.bytes_recv)
                    .field("packets_sent", iface.packets_sent)
                    .field("packets_recv", iface.packets_recv)
                    .field("errors_in", iface.errors_in)
                    .field("errors_out", iface.errors_out)
                    .time(ts, WritePrecision.S)
                )

            # Bant genişliği metrikleri
            if snapshot.network_snapshot:
                for bw in snapshot.network_snapshot.bandwidth:
                    points.append(
                        Point("bandwidth_metrics")
                        .tag("agent_id", snapshot.agent_id)
                        .tag("hostname", snapshot.hostname)
                        .tag("interface", bw.interface_name)
                        .field("bytes_sent_per_sec", bw.bytes_sent_per_sec)
                        .field("bytes_recv_per_sec", bw.bytes_recv_per_sec)
                        .time(ts, WritePrecision.S)
                    )

                # Bağlantı istatistikleri
                conn = snapshot.network_snapshot.connections
                points.append(
                    Point("connection_metrics")
                    .tag("agent_id", snapshot.agent_id)
                    .tag("hostname", snapshot.hostname)
                    .field("total", conn.total)
                    .field("established", conn.established)
                    .field("time_wait", conn.time_wait)
                    .field("listen", conn.listen)
                    .time(ts, WritePrecision.S)
                )

            self._write_api.write(
                bucket=self._bucket,
                org=self._org,
                record=points,
            )
            logger.debug(f"InfluxDB'ye {len(points)} point yazıldı: {snapshot.hostname}")
            return True

        except Exception as e:
            logger.error(f"InfluxDB yazma hatası: {e}")
            return False

    def write_snmp(self, info: SNMPDeviceInfo) -> bool:
        """
        SNMP cihaz verisini InfluxDB'ye yazar.
        Sistem OID'leri için tek point, her arayüz için ayrı point üretir.
        Erişilemeyen cihazlar için hiçbir şey yazmaz.
        """
        if not self._enabled or not self._write_api:
            return False
        if not info.reachable:
            return False

        try:
            now = datetime.now(timezone.utc)
            points = []

            # Sistem düzeyinde point
            points.append(
                Point("snmp_device")
                .tag("host", info.host)
                .tag("sys_name", info.sys_name or info.host)
                .field("uptime_ticks", info.uptime_ticks)
                .field("interface_count", len(info.interfaces))
                .time(now, WritePrecision.S)
            )

            # Arayüz başına point
            for iface in info.interfaces:
                points.append(
                    Point("snmp_interface")
                    .tag("host", info.host)
                    .tag("sys_name", info.sys_name or info.host)
                    .tag("if_index", iface.index)
                    .tag("if_name", iface.name)
                    .field("oper_status", iface.oper_status)
                    .field("hc_in_octets", iface.hc_in_octets)
                    .field("hc_out_octets", iface.hc_out_octets)
                    .field("in_errors", iface.in_errors)
                    .field("out_errors", iface.out_errors)
                    .field("in_discards", iface.in_discards)
                    .field("bandwidth_in_bps", iface.bandwidth_in_bps)
                    .field("bandwidth_out_bps", iface.bandwidth_out_bps)
                    .time(now, WritePrecision.S)
                )

            self._write_api.write(bucket=self._bucket, org=self._org, record=points)
            logger.debug(f"SNMP InfluxDB'ye yazıldı: {info.host} ({len(info.interfaces)} arayüz)")
            return True
        except Exception as e:
            logger.error(f"SNMP InfluxDB yazma hatası: {e}")
            return False

    _RANGES: dict[str, tuple[str, str]] = {
        "1h":  ("1m",  "-1h"),
        "6h":  ("5m",  "-6h"),
        "24h": ("15m", "-24h"),
        "7d":  ("1h",  "-7d"),
    }

    def query_agent_metrics(self, agent_id: str, range: str = "1h") -> dict | None:
        """
        InfluxDB'den agent metrik geçmişini çeker.
        Döner: {cpu, memory, net_in, net_out} her biri [{t, v}] listesi.
        InfluxDB yoksa None döner.
        """
        if not self._enabled:
            return None
        if not _AGENT_ID_RE.match(agent_id):
            return None

        window, start = self._RANGES.get(range, ("1m", "-1h"))
        bucket = self._bucket

        try:
            client = InfluxDBClient(url=self._url, token=self._token, org=self._org)
            qa = client.query_api()

            def run(measurement: str, field: str) -> list[dict]:
                flux = (
                    f'from(bucket: "{bucket}")'
                    f' |> range(start: {start})'
                    f' |> filter(fn: (r) => r._measurement == "{measurement}")'
                    f' |> filter(fn: (r) => r["agent_id"] == "{agent_id}")'
                    f' |> filter(fn: (r) => r._field == "{field}")'
                    f' |> aggregateWindow(every: {window}, fn: mean, createEmpty: false)'
                    f' |> keep(columns: ["_time", "_value"])'
                )
                tables = qa.query(flux)
                return [
                    {"t": rec.get_time().isoformat(), "v": round(rec.get_value() or 0, 2)}
                    for table in tables for rec in table.records
                ]

            result = {
                "cpu":     run("cpu_metrics",       "usage_percent"),
                "memory":  run("memory_metrics",    "usage_percent"),
                "net_in":  run("bandwidth_metrics", "bytes_recv_per_sec"),
                "net_out": run("bandwidth_metrics", "bytes_sent_per_sec"),
            }
            client.close()
            return result
        except Exception as e:
            logger.error(f"InfluxDB sorgu hatası: {e}")
            return None

    def close(self):
        """Bağlantıyı kapat."""
        if self._client:
            self._client.close()


# Global instance
influx_writer = InfluxWriter()