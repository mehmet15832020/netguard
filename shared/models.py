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


class ActiveConnection(BaseModel):
    """Tek bir aktif TCP/UDP bağlantısının anlık bilgisi."""
    laddr: Optional[str] = Field(None, description="Yerel adres:port")
    raddr: Optional[str] = Field(None, description="Uzak adres:port")
    status: str = Field(description="ESTABLISHED | CLOSE_WAIT vb.")
    pid: Optional[int] = None


class ListeningPort(BaseModel):
    """Dinleyen (LISTEN) tek bir port kaydı."""
    port: int
    ip: str = Field(description="Bağlı olduğu yerel adres")
    pid: Optional[int] = None


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
    active_connections: list[ActiveConnection] = Field(
        default_factory=list,
        description="ESTABLISHED/CLOSE_WAIT TCP bağlantıları (C2 tespiti için)",
    )
    listening_ports: list[ListeningPort] = Field(
        default_factory=list,
        description="LISTEN durumundaki portlar (backdoor tespiti için)",
    )
    dns_stats: dict = Field(
        default_factory=dict,
        description="systemd-resolved DNS istatistikleri (M6)",
    )
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
    PORT_SCAN        = "port_scan_attempt" # Port tarama girişimi
    ARP_SPOOF        = "arp_spoof"         # ARP spoofing
    ICMP_FLOOD       = "icmp_flood"        # ICMP flood
    DNS_ANOMALY      = "dns_anomaly"       # DNS anomalisi
    DEVICE_DOWN      = "device_down"       # Cihaz erişilemiyor
    DEVICE_UP        = "device_up"         # Cihaz tekrar erişilebilir
    SNMP_TRAP        = "snmp_trap"         # SNMP TRAP alındı
    WIN_LOGON_SUCCESS      = "windows_logon_success"       # 4624
    WIN_LOGON_FAILURE      = "windows_logon_failure"       # 4625
    WIN_EXPLICIT_LOGON     = "windows_explicit_logon"      # 4648 (pass-the-hash göstergesi)
    WIN_PROCESS_CREATE     = "windows_process_create"      # 4688
    WIN_USER_CREATED       = "windows_user_created"        # 4720
    WIN_GROUP_MEMBER_ADDED = "windows_group_member_added"  # 4732
    WIN_KERBEROS_TGT       = "windows_kerberos_tgt"        # 4768
    WIN_KERBEROS_SERVICE   = "windows_kerberos_service"    # 4769
    WIN_SYSMON_PROCESS     = "windows_sysmon_process"      # Sysmon EID 1
    WIN_SYSMON_NETWORK     = "windows_sysmon_network"      # Sysmon EID 3
    WIN_SYSMON_PROC_ACCESS = "windows_sysmon_proc_access"  # Sysmon EID 10 (mimikatz)
    WIN_SYSMON_DNS         = "windows_sysmon_dns"          # Sysmon EID 22
    WIN_SERVICE_INSTALLED     = "windows_service_installed"      # EID 7045
    WIN_SERVICE_START_CHANGED = "windows_service_start_changed" # EID 7040
    WIN_SERVICE_CRASHED       = "windows_service_crashed"       # EID 7034
    WIN_SPECIAL_PRIV          = "windows_special_priv"          # EID 4672
    WIN_TASK_CREATED          = "windows_task_created"          # EID 4698
    WIN_TASK_UPDATED          = "windows_task_updated"          # EID 4702
    WIN_ACCOUNT_LOCKOUT       = "windows_account_lockout"       # EID 4740
    WIN_KERBEROS_PREAUTH_FAIL = "windows_kerberos_preauth_fail" # EID 4771
    WIN_NTLM_AUTH             = "windows_ntlm_auth"             # EID 4776
    WIN_SHARE_ACCESS          = "windows_share_access"          # EID 5140
    WIN_LOG_CLEARED           = "windows_log_cleared"           # EID 1102
    WIN_COMPUTER_ACCOUNT      = "windows_computer_account_changed"  # EID 4741
    WIN_LOGON_PROC_REG        = "windows_logon_process_registered"  # EID 4614
    WIN_TOKEN_PRIV_ADJ        = "windows_token_privilege_adjusted"  # EID 4703
    WIN_PS_MODULE             = "windows_powershell_module"      # EID 4103
    WIN_PS_SCRIPTBLOCK        = "windows_powershell_scriptblock" # EID 4104
    WIN_APPLOCKER_BLOCKED     = "windows_applocker_blocked"      # EID 8004
    WIN_SYSMON_DRIVER_LOAD    = "windows_sysmon_driver_load"     # Sysmon 6
    WIN_SYSMON_IMAGE_LOAD     = "windows_sysmon_image_load"      # Sysmon 7
    WIN_SYSMON_REMOTE_THREAD  = "windows_sysmon_remote_thread"   # Sysmon 8
    WIN_SYSMON_RAW_ACCESS     = "windows_sysmon_raw_access"      # Sysmon 9
    WIN_SYSMON_FILE_CREATE    = "windows_sysmon_file_create"     # Sysmon 11
    WIN_SYSMON_REGISTRY       = "windows_sysmon_registry"        # Sysmon 13
    WIN_SYSMON_ADS            = "windows_sysmon_ads"             # Sysmon 15
    WIN_SYSMON_PIPE_CREATED   = "windows_sysmon_pipe_created"    # Sysmon 17
    WIN_SYSMON_PIPE_CONNECTED = "windows_sysmon_pipe_connected"  # Sysmon 18
    WIN_SYSMON_WMI_EVENT      = "windows_sysmon_wmi_event"       # Sysmon 19
    WIN_SYSMON_WMI_BINDING    = "windows_sysmon_wmi_binding"     # Sysmon 21
    WIN_SYSMON_PROCESS_TAMPER = "windows_sysmon_process_tamper"  # Sysmon 25
    WIN_LATERAL_LOGON         = "windows_lateral_logon"          # Lateral movement logon
    LATERAL_MOVEMENT  = "lateral_movement"                 # İç ağdan iç ağa tarama
    SUSPICIOUS_CONN   = "suspicious_outbound_connection"   # Şüpheli dış bağlantı
    C2_BEACONING      = "c2_beaconing"                     # C2 beacon tespiti (MITRE T1071)


class SecurityEvent(BaseModel):
    """Tek bir güvenlik olayı kaydı."""
    event_id: str = Field(description="Benzersiz olay ID")
    agent_id: str
    hostname: str
    event_action: SecurityEventType
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
    WINDOWS   = "windows"   # Windows EVTX / Sysmon (doğrudan yükleme)
    SYSLOG    = "syslog"     # Genel syslog
    AUTH_LOG  = "auth_log"   # /var/log/auth.log
    NETGUARD  = "netguard"   # NetGuard internal
    PFSENSE   = "pfsense"    # pfSense filterlog
    OPNSENSE  = "opnsense"   # OPNsense filterlog[pid]
    CISCO_ASA = "cisco_asa"  # Cisco ASA %ASA-
    FORTIGATE = "fortigate"  # FortiGate type=traffic
    VYOS      = "vyos"       # VyOS iptables/nftables kernel log
    NGINX     = "nginx"      # nginx access/error log
    APACHE    = "apache"     # Apache access/error log
    NETFLOW      = "netflow"      # NetFlow v5/v9/IPFIX (v10) UDP akış verisi
    SFLOW        = "sflow"        # sFlow v5 sampled flow (RFC 3176)
    OPENCANARY   = "opencanary"   # Thinkst OpenCanary honeypot
    M365         = "m365"         # Microsoft 365 audit (Office 365 Management API)
    GWORKSPACE   = "gworkspace"   # Google Workspace Admin Reports API
    DHCP         = "dhcp"         # ISC dhcpd / Kea / FortiGate DHCP lease syslog (F1, marka bağımsız)
    DNS_RESOLVER = "dns_resolver" # Unbound / dnsmasq / FortiGate DNS filter syslog (F2, marka bağımsız)
    CISCO_IOS    = "cisco_ios"    # Cisco IOS/NX-OS router/switch BGP+LINK syslog (G1)
    JUNIPER      = "juniper"      # Juniper Junos RPD BGP + SNMP_TRAP_LINK (G1)
    MIKROTIK     = "mikrotik"     # MikroTik RouterOS interface syslog (G1)


class LogCategory(str, Enum):
    """Olayın genel kategorisi."""
    AUTHENTICATION = "authentication"  # Giriş/çıkış olayları
    NETWORK        = "network"         # Ağ trafiği olayları
    INTRUSION      = "intrusion"       # Saldırı tespiti
    SYSTEM         = "system"          # Sistem olayları
    UNKNOWN        = "unknown"


class ParseStatus(str, Enum):
    """Ham logun işlenme durumu."""
    PENDING = "pending"    # Henüz işlenmedi
    SUCCESS = "success"    # Başarıyla normalize edildi
    FAILED  = "failed"     # Parse edilemedi, normalize logı yok


class RawLog(BaseModel):
    """
    Kaynaktan gelen ham log — işlenmeden önce saklanır.
    İki DB katmanının 'ham' tarafı budur.
    """
    raw_id: str = Field(description="Benzersiz ham log ID")
    source_type: Optional[LogSourceType] = None
    observer_hostname: str = Field(description="Logu gönderen host/IP")
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_content: str = Field(description="Ham log satırı veya JSON içerik")
    parse_status: ParseStatus = Field(default=ParseStatus.PENDING, description="İşlenme durumu")
    normalized_log_id: Optional[str] = None


class NormalizedLog(BaseModel):
    """
    Ortak formata dönüştürülmüş log kaydı.
    Kaynak ne olursa olsun aynı alanlar dolu — korelasyon bu sayede çalışır.
    """
    log_id: str = Field(description="Benzersiz normalize log ID")
    raw_id: str = Field(description="Kaynak ham log ID")
    source_type: LogSourceType
    observer_hostname: str
    timestamp: datetime = Field(description="Olayın gerçekleştiği zaman (UTC)")
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = Field(description="info | warning | critical")
    event_category: LogCategory
    event_action: str = Field(description="Spesifik olay tipi, örn: ssh_failure")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_hostname: Optional[str] = None
    destination_hostname: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    network_protocol: Optional[str] = None
    username: Optional[str] = None
    message: str = Field(description="İnsan okunabilir normalize edilmiş mesaj")
    tags: list[str] = Field(default_factory=list, description="Ek etiketler")
    extra: dict = Field(default_factory=dict, description="Kaynağa özgü ek alanlar")
    network_bytes: Optional[int] = None
    community_id: Optional[str] = None
    processed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorrelatedEvent(BaseModel):
    """
    Birden fazla normalize log olayının korelasyonu sonucu üretilen olay.
    Örnek: 5 dakikada 10 SSH hatası → tek bir brute_force_detected eventi.
    """
    corr_id: str = Field(description="Benzersiz korelasyon ID")
    rule_id: str = Field(description="Tetikleyen kural ID")
    rule_name: str
    event_action: str = Field(description="Korelasyon olay tipi, örn: brute_force_detected")
    severity: str = Field(description="info | warning | critical")
    group_value: str = Field(description="Gruplanma değeri, örn: kaynak IP")
    group_by_field: str = Field(default="source_ip", description="Korelasyon gruplama kolonu, örn: source_ip | observer_hostname")
    matched_count: int = Field(ge=1, description="Zaman penceresindeki eşleşen log sayısı")
    window_seconds: int = Field(description="Kural zaman penceresi (saniye)")
    first_seen: datetime = Field(description="Penceredeki ilk olayın zamanı")
    last_seen: datetime = Field(description="Penceredeki son olayın zamanı")
    message: str
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK teknik ID'leri, örn: T1110.001")
    mitre_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK taktik adları, örn: credential_access")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentStatus(str, Enum):
    """Incident'ın mevcut durumu."""
    OPEN          = "open"
    INVESTIGATING = "investigating"
    RESOLVED      = "resolved"


class Incident(BaseModel):
    """Tek bir güvenlik incident kaydı."""
    incident_id:     str = Field(description="Benzersiz incident ID")
    title:           str
    description:     str = ""
    severity:        str = Field(description="info | warning | critical")
    status:          IncidentStatus = IncidentStatus.OPEN
    assigned_to:     Optional[str] = None
    source_event_id: Optional[str] = None
    source_type:     Optional[str] = None
    created_by:      str
    notes:           str = ""
    rule_id:         Optional[str] = None
    group_value:     Optional[str] = None
    group_by_field:  str = "source_ip"
    priority_score:  int = 0
    closure_note:    str = ""
    created_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at:      datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at:     Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None


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







