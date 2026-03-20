"""
NetGuard shared data models.

Agent ile server arasındaki veri sözleşmesi (contract) burada tanımlanır.
Her iki taraf da bu modelleri import eder — hiçbir zaman kopyalanmaz.
"""

from datetime import datetime
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

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


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
    registered_at: datetime = Field(default_factory=datetime.utcnow)