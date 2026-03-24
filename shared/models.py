"""
NetGuard shared data models.

Agent ile server arasındaki veri sözleşmesi (contract) burada tanımlanır.
Her iki taraf da bu modelleri import eder — hiçbir zaman kopyalanmaz.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field




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





