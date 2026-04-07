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

import time


from shared.models import (
    AgentStatus,
    CPUMetrics,
    DiskMetrics,
    MemoryMetrics,
    MetricSnapshot,
    NetworkBandwidth,
    NetworkInterfaceMetrics,
    NetworkSnapshot,
    ConnectionStats,
    ProcessInfo,
    ProcessSnapshot,
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


# Atlanacak dosya sistemi tipleri — bunlar sanal/read-only sistemler
_SKIP_FSTYPES = frozenset({
    "squashfs",  # snap paketleri
    "tmpfs",     # geçici bellek dosya sistemi
    "devtmpfs",  # cihaz dosyaları
    "overlay",   # Docker katmanları
    "nsfs",      # namespace dosya sistemi
})


def _collect_disks() -> list[DiskMetrics]:
    """
    Fiziksel disk bölümlerini toplar.
    Sanal/read-only dosya sistemlerini filtreler.
    """
    disks = []
    for partition in psutil.disk_partitions(all=False):
        # Sanal dosya sistemlerini atla
        if partition.fstype in _SKIP_FSTYPES:
            continue
        # Snap mount noktalarını atla
        if partition.mountpoint.startswith("/snap/"):
            continue

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


# Önceki ölçüm — hız hesabı için saklanır
_prev_net_io: dict = {}
_prev_net_time: float = 0.0


def _collect_bandwidth() -> list[NetworkBandwidth]:
    """
    Önceki ölçümle karşılaştırarak anlık bant genişliği hesaplar.
    İlk çağrıda boş liste döner — referans nokta yok.
    """
    global _prev_net_io, _prev_net_time

    now = time.time()
    current = psutil.net_io_counters(pernic=True)

    if not _prev_net_io:
        # İlk ölçüm — referans kaydet, sonuç yok
        _prev_net_io = {k: v for k, v in current.items()}
        _prev_net_time = now
        return []

    elapsed = now - _prev_net_time
    if elapsed < 0.1:
        return []

    bandwidth = []
    for name, stats in current.items():
        if name not in _prev_net_io:
            continue
        prev = _prev_net_io[name]
        bandwidth.append(NetworkBandwidth(
            interface_name=name,
            bytes_sent_per_sec=max(0, (stats.bytes_sent - prev.bytes_sent) / elapsed),
            bytes_recv_per_sec=max(0, (stats.bytes_recv - prev.bytes_recv) / elapsed),
            packets_sent_per_sec=max(0, (stats.packets_sent - prev.packets_sent) / elapsed),
            packets_recv_per_sec=max(0, (stats.packets_recv - prev.packets_recv) / elapsed),
        ))

    _prev_net_io = {k: v for k, v in current.items()}
    _prev_net_time = now

    return bandwidth[:MAX_INTERFACE_ENTRIES]


def _collect_connections() -> ConnectionStats:
    """Aktif TCP bağlantı istatistiklerini toplar."""
    try:
        conns = psutil.net_connections(kind="inet")
        stats = {"ESTABLISHED": 0, "TIME_WAIT": 0, "LISTEN": 0}
        for c in conns:
            if c.status in stats:
                stats[c.status] += 1
        return ConnectionStats(
            total=len(conns),
            established=stats["ESTABLISHED"],
            time_wait=stats["TIME_WAIT"],
            listen=stats["LISTEN"],
        )
    except psutil.AccessDenied:
        return ConnectionStats(total=0, established=0, time_wait=0, listen=0)

def _collect_processes() -> ProcessSnapshot:
    """
    Sistemdeki process listesini toplar.
    CPU ve RAM'e göre ilk 10'ar process döndürür.
    """
    processes = []

    for proc in psutil.process_iter([
        'pid', 'name', 'cpu_percent', 'memory_percent',
        'memory_info', 'status', 'username'
    ]):
        try:
            info = proc.info
            processes.append(ProcessInfo(
                pid=info['pid'],
                name=info['name'] or 'unknown',
                cpu_percent=round(info['cpu_percent'] or 0.0, 2),
                memory_percent=round(info['memory_percent'] or 0.0, 2),
                memory_rss_bytes=info['memory_info'].rss if info['memory_info'] else 0,
                status=info['status'] or 'unknown',
                username=info['username'] or '',
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Durum sayıları
    running = sum(1 for p in processes if p.status == 'running')
    sleeping = sum(1 for p in processes if p.status == 'sleeping')

    # En çok CPU kullanan 10 process
    top_cpu = sorted(processes, key=lambda p: p.cpu_percent, reverse=True)[:10]

    # En çok RAM kullanan 10 process
    top_mem = sorted(processes, key=lambda p: p.memory_percent, reverse=True)[:10]

    return ProcessSnapshot(
        total_processes=len(processes),
        running=running,
        sleeping=sleeping,
        top_cpu=top_cpu,
        top_memory=top_mem,
        captured_at=datetime.now(timezone.utc),
    )

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

    try:
        bandwidth = _collect_bandwidth()
        connections = _collect_connections()
        network_snapshot = NetworkSnapshot(
            bandwidth=bandwidth,
            connections=connections,
            captured_at=datetime.now(timezone.utc),
        )
    except Exception:
        network_snapshot = None
        status = AgentStatus.DEGRADED


    try:
        process_snapshot = _collect_processes()
    except Exception:
        process_snapshot = None
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
        network_snapshot=network_snapshot,
        process_snapshot=process_snapshot,
    )

    return MetricSnapshot(
        agent_id=_get_agent_id(),
        hostname=socket.gethostname(),
        collected_at=datetime.now(timezone.utc),
        status=status,
        cpu=cpu,
        memory=memory,
        disks=disks,
        network_interfaces=network,
        network_snapshot=network_snapshot,
    )