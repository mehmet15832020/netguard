"""
NetGuard Agent — Collector

Sadece bir iş yapar: psutil kullanarak sistem metriklerini okur
ve MetricSnapshot nesnesi döndürür.

Server'dan haberi yoktur. Ağdan haberi yoktur.
"""

import platform
import socket
import uuid
import psutil

from datetime import datetime, timezone
from shared.models import (
    AgentStatus,
    CPUMetrics,
    DiskMetrics,
    MemoryMetrics,
    MetricSnapshot,
    NetworkInterfaceMetrics,
)
from shared.protocol import MAX_DISK_ENTRIES, MAX_INTERFACE_ENTRIES


def _get_agent_id() -> str:
    """
    Makineye özgü tekrarlanabilir ID üretir.
    Her çalıştırmada aynı ID döner — UUID random değil, MAC bazlı.
    """
    return str(uuid.UUID(int=uuid.getnode()))


def _collect_cpu() -> CPUMetrics:
    """CPU metriklerini toplar."""
    load_avg = psutil.getloadavg()
    return CPUMetrics(
        usage_percent=psutil.cpu_percent(interval=1),
        core_count=psutil.cpu_count(logical=False) or 1,
        load_avg_1m=round(load_avg[0], 2),
    )


def _collect_memory() -> MemoryMetrics:
    """RAM metriklerini toplar."""
    mem = psutil.virtual_memory()
    return MemoryMetrics(
        total_bytes=mem.total,
        used_bytes=mem.used,
        available_bytes=mem.available,
    )


def _collect_disks() -> list[DiskMetrics]:
    """
    Tüm fiziksel disk bölümlerini toplar.
    Sanal/geçici dosya sistemlerini atlar (tmpfs, devfs vb.)
    """
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disks.append(DiskMetrics(
                mount_point=partition.mountpoint,
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                usage_percent=usage.percent,
            ))
        except PermissionError:
            # Bazı mount point'lere erişim izni olmayabilir, geç
            continue

    return disks[:MAX_DISK_ENTRIES]


def _collect_network() -> list[NetworkInterfaceMetrics]:
    """
    Tüm ağ arayüzlerinin istatistiklerini toplar.
    Loopback (lo) arayüzünü dahil eder — monitoring için faydalı.
    """
    interfaces = []
    net_io = psutil.net_io_counters(pernic=True)

    for name, stats in net_io.items():
        interfaces.append(NetworkInterfaceMetrics(
            interface_name=name,
            bytes_sent=stats.bytes_sent,
            bytes_recv=stats.bytes_recv,
            packets_sent=stats.packets_sent,
            packets_recv=stats.packets_recv,
            errors_in=stats.errin,
            errors_out=stats.errout,
        ))

    return interfaces[:MAX_INTERFACE_ENTRIES]


def collect_snapshot() -> MetricSnapshot:
    """
    Tek entry point. Tüm metrikleri toplar, MetricSnapshot döndürür.
    Herhangi bir alt toplama başarısız olursa status DEGRADED olur.
    """
    status = AgentStatus.ONLINE
    
    cpu = _collect_cpu()
    memory = _collect_memory()

    try:
        disks = _collect_disks()
    except Exception:
        disks = []
        status = AgentStatus.DEGRADED

    try:
        network = _collect_network()
    except Exception:
        network = []
        status = AgentStatus.DEGRADED

    return MetricSnapshot(
        agent_id=_get_agent_id(),
        hostname=socket.gethostname(),
        collected_at=datetime.now(timezone.utc),
        status=status,
        cpu=cpu,
        memory=memory,
        disks=disks,
        network_interfaces=network,
    )