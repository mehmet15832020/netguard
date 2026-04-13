"""
NetGuard shared data models.

Agent ile server arasındaki veri sözleşmesi (contract) burada tanımlanır.
Her iki taraf da bu modelleri import eder — hiçbir zaman kopyalanmaz.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, computed_field




class AgentStatus(str, Enum):
    """Agent'ın o anki durumu."""
    ONLINE = "online"
    DEGRADED = "degraded"   # Çalışıyor ama bazı metrikler alınamıyor
    OFFLINE = "offline"


class CPUMetrics(BaseModel):
    """CPU kullanım metrikleri."""
    usage_percent: float = Field(ge=0.0, le=100.0, description="Toplam CPU kullanımı %")
    core_count: int = Field(ge=1, description="Fiziksel çekirdek sayısı")
    load_avg_1m: float = Field(ge=0.0, description="1 dakikalık yük ortalaması")


class MemoryMetrics(BaseModel):
    """RAM kullanım metrikleri."""
    total_bytes: int = Field(ge=0, description="Toplam RAM (byte)")
    used_bytes: int = Field(ge=0, description="Kullanılan RAM (byte)")
    available_bytes: int = Field(ge=0, description="Kullanılabilir RAM (byte)")

    @computed_field
    @property
    def usage_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return round((self.used_bytes / self.total_bytes) * 100, 2)


class DiskMetrics(BaseModel):
    """Disk kullanım metrikleri."""
    mount_point: str = Field(description="Bağlama noktası, örn: '/'")
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)
    usage_percent: float = Field(ge=0.0, le=100.0)


class NetworkInterfaceMetrics(BaseModel):
    """Tek bir ağ arayüzünün metrikleri."""
    interface_name: str = Field(description="Arayüz adı, örn: 'eth0'")
    bytes_sent: int = Field(ge=0, description="Gönderilen toplam byte")
    bytes_recv: int = Field(ge=0, description="Alınan toplam byte")
    packets_sent: int = Field(ge=0)
    packets_recv: int = Field(ge=0)
    errors_in: int = Field(ge=0, description="Giriş hata sayısı")
    errors_out: int = Field(ge=0, description="Çıkış hata sayısı")


class NetworkBandwidth(BaseModel):
    """
    İki snapshot arasında hesaplanan anlık bant genişliği.
    Agent tarafında hesaplanır, server'a gönderilir.
    """
    interface_name: str
    bytes_sent_per_sec: float = Field(ge=0.0, description="Gönderim hızı (byte/s)")
    bytes_recv_per_sec: float = Field(ge=0.0, description="Alım hızı (byte/s)")
    packets_sent_per_sec: float = Field(ge=0.0)
    packets_recv_per_sec: float = Field(ge=0.0)

    @property
    def mbps_sent(self) -> float:
        return round(self.bytes_sent_per_sec / 1_000_000, 3)

    @property
    def mbps_recv(self) -> float:
        return round(self.bytes_recv_per_sec / 1_000_000, 3)

class ConnectionStats(BaseModel):
    """Aktif ağ bağlantı istatistikleri."""
    total: int = Field(ge=0, description="Toplam bağlantı sayısı")
    established: int = Field(ge=0, description="Kurulu bağlantılar")
    time_wait: int = Field(ge=0, description="TIME_WAIT durumundaki bağlantılar")
    listen: int = Field(ge=0, description="Dinlenen portlar")

class NetworkSnapshot(BaseModel):
    """
    Ağ durumunun tam görüntüsü.
    MetricSnapshot'a gömülü olarak gönderilir.
    """
    bandwidth: list[NetworkBandwidth] = Field(default_factory=list)
    connections: ConnectionStats
    captured_at: datetime
class ProtocolStats(BaseModel):
    """Tek bir protokolün trafik istatistikleri."""
    protocol: str = Field(description="Protokol adı: TCP, UDP, DNS, HTTP...")
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)
class TrafficSummary(BaseModel):
    """
    Belirli bir zaman aralığında yakalanan trafiğin özeti.
    Agent tarafından üretilir, server'a gönderilir.
    """
    interface: str = Field(description="Hangi arayüzde yakalandı")
    duration_sec: float = Field(ge=0.0, description="Yakalama süresi")
    total_packets: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    protocols: list[ProtocolStats] = Field(default_factory=list)
    top_src_ips: list[str] = Field(default_factory=list, description="En çok trafik üreten kaynak IP'ler")
    top_dst_ips: list[str] = Field(default_factory=list, description="En çok trafik alan hedef IP'ler")
    captured_at: datetime
    suspicious_packet_count: int = Field(default=0, ge=0)
class ProcessInfo(BaseModel):
    """Tek bir process'in anlık bilgisi."""
    pid: int
    name: str
    cpu_percent: float = Field(ge=0.0)
    memory_percent: float = Field(ge=0.0, le=100.0)
    memory_rss_bytes: int = Field(ge=0)
    status: str
    username: str = ""


class ProcessSnapshot(BaseModel):
    """Sistemdeki process listesinin özeti."""
    total_processes: int = Field(ge=0)
    running: int = Field(ge=0)
    sleeping: int = Field(ge=0)
    top_cpu: list[ProcessInfo] = Field(default_factory=list)
    top_memory: list[ProcessInfo] = Field(default_factory=list)
    captured_at: datetime

class MetricSnapshot(BaseModel):
    """
    Agent'ın tek bir anda topladığı tüm metrikler.
    Server'a gönderilen temel veri birimi budur.
    """
    agent_id: str = Field(description="Agent'ın benzersiz kimliği")
    hostname: str = Field(description="Makinenin hostname'i")
    collected_at: datetime = Field(description="Metriğin toplandığı zaman (UTC)")
    status: AgentStatus = Field(default=AgentStatus.ONLINE)

    cpu: CPUMetrics
    memory: MemoryMetrics
    disks: list[DiskMetrics] = Field(default_factory=list)
    network_interfaces: list[NetworkInterfaceMetrics] = Field(default_factory=list)
    network_snapshot: Optional[NetworkSnapshot] = None
    process_snapshot: Optional[ProcessSnapshot] = None
    traffic_summary: Optional[TrafficSummary] = None
    model_config = {"ser_json_timedelta": "iso8601"}


class AgentRegistration(BaseModel):
    """
    Agent ilk başladığında server'a kendini tanıtır.
    Bu mesaj bir kez gönderilir.
    """
    agent_id: str
    hostname: str
    os_name: str = Field(description="İşletim sistemi, örn: 'Linux'")
    os_version: str = Field(description="OS sürümü")
    python_version: str
    netguard_version: str = Field(default="0.1.0")
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SecurityEventType(str, Enum):
    """Güvenlik olayının türü."""
    BRUTE_FORCE      = "brute_force"       # Çok sayıda başarısız login
    SSH_FAILURE      = "ssh_failure"       # Tek başarısız SSH girişi
    SSH_SUCCESS      = "ssh_success"       # Başarılı SSH girişi
    SUDO_USAGE       = "sudo_usage"        # sudo komutu kullanımı
    PORT_OPENED      = "port_opened"       # Yeni port açıldı
    PORT_CLOSED      = "port_closed"       # Port kapandı
    CHECKSUM_CHANGED = "checksum_changed"  # Kritik dosya değişti


class SecurityEvent(BaseModel):
    """Tek bir güvenlik olayı kaydı."""
    event_id: str = Field(description="Benzersiz olay ID")
    agent_id: str
    hostname: str
    event_type: SecurityEventType
    severity: str = Field(description="info | warning | critical")
    source_ip: Optional[str] = None
    username: Optional[str] = None
    message: str
    raw_data: Optional[str] = None        # Ham log satırı veya JSON
    occurred_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LogSourceType(str, Enum):
    """Log kaynağının tipi."""
    SURICATA  = "suricata"   # Suricata IDS/IPS
    ZEEK      = "zeek"       # Zeek network monitor
    WAZUH     = "wazuh"      # Wazuh HIDS
    SYSLOG    = "syslog"     # Genel syslog
    AUTH_LOG  = "auth_log"   # /var/log/auth.log
    NETGUARD  = "netguard"   # NetGuard internal


class LogCategory(str, Enum):
    """Olayın genel kategorisi."""
    AUTHENTICATION = "authentication"  # Giriş/çıkış olayları
    NETWORK        = "network"         # Ağ trafiği olayları
    INTRUSION      = "intrusion"       # Saldırı tespiti
    SYSTEM         = "system"          # Sistem olayları
    UNKNOWN        = "unknown"


class RawLog(BaseModel):
    """
    Kaynaktan gelen ham log — işlenmeden önce saklanır.
    İki DB katmanının 'ham' tarafı budur.
    """
    raw_id: str = Field(description="Benzersiz ham log ID")
    source_type: Optional[LogSourceType] = None
    source_host: str = Field(description="Logu gönderen host/IP")
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_content: str = Field(description="Ham log satırı veya JSON içerik")
    normalized: bool = Field(default=False, description="Normalize edildi mi")
    normalized_log_id: Optional[str] = None


class NormalizedLog(BaseModel):
    """
    Ortak formata dönüştürülmüş log kaydı.
    Kaynak ne olursa olsun aynı alanlar dolu — korelasyon bu sayede çalışır.
    """
    log_id: str = Field(description="Benzersiz normalize log ID")
    raw_id: str = Field(description="Kaynak ham log ID")
    source_type: LogSourceType
    source_host: str
    timestamp: datetime = Field(description="Olayın gerçekleştiği zaman (UTC)")
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = Field(description="info | warning | critical")
    category: LogCategory
    event_type: str = Field(description="Spesifik olay tipi, örn: ssh_failure")
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    message: str = Field(description="İnsan okunabilir normalize edilmiş mesaj")
    tags: list[str] = Field(default_factory=list, description="Ek etiketler")
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelatedEvent(BaseModel):
    """
    Birden fazla normalize log olayının korelasyonu sonucu üretilen olay.
    Örnek: 5 dakikada 10 SSH hatası → tek bir brute_force_detected eventi.
    """
    corr_id: str = Field(description="Benzersiz korelasyon ID")
    rule_id: str = Field(description="Tetikleyen kural ID")
    rule_name: str
    event_type: str = Field(description="Korelasyon olay tipi, örn: brute_force_detected")
    severity: str = Field(description="info | warning | critical")
    group_value: str = Field(description="Gruplanma değeri, örn: kaynak IP")
    matched_count: int = Field(ge=1, description="Zaman penceresindeki eşleşen log sayısı")
    window_seconds: int = Field(description="Kural zaman penceresi (saniye)")
    first_seen: datetime = Field(description="Penceredeki ilk olayın zamanı")
    last_seen: datetime = Field(description="Penceredeki son olayın zamanı")
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AlertSeverity(str, Enum):
    """Alert öncelik seviyesi."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert durumu."""
    ACTIVE = "active"       # Hâlâ devam ediyor
    RESOLVED = "resolved"   # Çözüldü


class Alert(BaseModel):
    """Tek bir alert kaydı."""
    alert_id: str = Field(description="Benzersiz alert ID")
    agent_id: str
    hostname: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    metric: str = Field(description="Hangi metrik tetikledi, örn: 'cpu'")
    message: str = Field(description="İnsan okunabilir açıklama")
    value: float = Field(description="Tetikleyen değer")
    threshold: float = Field(description="Aşılan eşik")
    triggered_at: datetime
    resolved_at: Optional[datetime] = None







