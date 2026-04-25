"""
NetGuard — Compliance Raporu Motoru
PCI DSS v4.0 ve ISO 27001:2022 kontrollerini NetGuard yetenekleriyle otomatik eşleştirir.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Veri modelleri
# ---------------------------------------------------------------------------

@dataclass
class ComplianceControl:
    control_id: str          # PCI-10.2.1 veya ISO-A.8.15
    title: str
    description: str
    framework: str           # "PCI DSS v4.0" | "ISO 27001:2022"
    category: str
    netguard_features: list[str]   # Bu kontrolü karşılayan NetGuard özellikleri
    check_fn: Optional[str] = None # DB'den kontrol edilecek metrik adı


@dataclass
class ControlResult:
    control_id: str
    title: str
    framework: str
    category: str
    status: str              # "compliant" | "partial" | "gap"
    score: int               # 0-100
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PCI DSS v4.0 kontrolleri (temel gereksinimler)
# ---------------------------------------------------------------------------

PCI_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="PCI-1.3",
        title="Ağ Erişim Kontrolü",
        description="Ağ güvenlik kontrollerini kur ve sürdür",
        framework="PCI DSS v4.0",
        category="Ağ Güvenliği",
        netguard_features=["device_discovery", "topology", "snmp_monitoring"],
        check_fn="device_count",
    ),
    ComplianceControl(
        control_id="PCI-2.2",
        title="Sistem Sertleştirme",
        description="Tüm sistem bileşenleri için güvenlik yapılandırma standartları",
        framework="PCI DSS v4.0",
        category="Sistem Güvenliği",
        netguard_features=["security_events", "log_monitoring"],
        check_fn="security_event_count",
    ),
    ComplianceControl(
        control_id="PCI-6.4",
        title="Web Uygulama Güvenliği",
        description="Web uygulamalarını saldırılara karşı koru",
        framework="PCI DSS v4.0",
        category="Uygulama Güvenliği",
        netguard_features=["web_log_parser", "correlation_rules"],
        check_fn="web_log_count",
    ),
    ComplianceControl(
        control_id="PCI-7.2",
        title="Erişim Kontrol Sistemi",
        description="Sistem bileşenlerine erişimi iş gereksinimiyle sınırla",
        framework="PCI DSS v4.0",
        category="Erişim Yönetimi",
        netguard_features=["auth_log_monitoring", "brute_force_detection"],
        check_fn="auth_event_count",
    ),
    ComplianceControl(
        control_id="PCI-8.3",
        title="Kullanıcı Kimlik Doğrulama",
        description="Tüm kullanıcılar için güçlü kimlik doğrulama",
        framework="PCI DSS v4.0",
        category="Kimlik Yönetimi",
        netguard_features=["brute_force_detection", "ssh_monitoring", "windows_logon"],
        check_fn="brute_force_event_count",
    ),
    ComplianceControl(
        control_id="PCI-10.2",
        title="Denetim Günlükleri — Kritik Olaylar",
        description="Tüm bireysel kullanıcı erişimlerini ve kritik olayları kaydet",
        framework="PCI DSS v4.0",
        category="Log Yönetimi",
        netguard_features=["audit_log", "security_events", "normalized_logs"],
        check_fn="audit_log_count",
    ),
    ComplianceControl(
        control_id="PCI-10.3",
        title="Denetim Günlükleri — Bütünlük",
        description="Denetim günlüklerini değişiklik ve imhadan koru",
        framework="PCI DSS v4.0",
        category="Log Yönetimi",
        netguard_features=["audit_log", "retention_policy"],
        check_fn="audit_log_count",
    ),
    ComplianceControl(
        control_id="PCI-10.4",
        title="Anormallik ve Tehdit Tespiti",
        description="Anormallikleri ve şüpheli etkinlikleri tespit et",
        framework="PCI DSS v4.0",
        category="İzleme",
        netguard_features=["correlation_engine", "attack_chain", "sigma_rules"],
        check_fn="correlated_event_count",
    ),
    ComplianceControl(
        control_id="PCI-10.7",
        title="Güvenlik İhlali Tespiti",
        description="Kritik kontrol sistemlerindeki hataları tespit et ve raporla",
        framework="PCI DSS v4.0",
        category="İzleme",
        netguard_features=["alerts", "incidents", "notifier"],
        check_fn="active_alert_count",
    ),
    ComplianceControl(
        control_id="PCI-11.5",
        title="Ağ İzinsiz Giriş Tespiti",
        description="Ağdaki yetkisiz erişimleri ve şüpheli etkinlikleri tespit et",
        framework="PCI DSS v4.0",
        category="Saldırı Tespiti",
        netguard_features=["netflow", "correlation_rules", "firewall_parser"],
        check_fn="netflow_log_count",
    ),
    ComplianceControl(
        control_id="PCI-12.10",
        title="Olay Müdahale Planı",
        description="Güvenlik ihlallerine yanıt vermek için plan hazırla ve uygula",
        framework="PCI DSS v4.0",
        category="Olay Müdahalesi",
        netguard_features=["incidents", "incident_assignment", "audit_log"],
        check_fn="incident_count",
    ),
]

# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A kontrolleri
# ---------------------------------------------------------------------------

ISO_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="ISO-A.5.23",
        title="Bulut Hizmetleri Güvenliği",
        description="Bulut hizmetlerinin edinimi, kullanımı ve yönetimi için süreçler",
        framework="ISO 27001:2022",
        category="Organizasyonel Kontroller",
        netguard_features=["device_monitoring", "snmp_monitoring"],
        check_fn="device_count",
    ),
    ComplianceControl(
        control_id="ISO-A.6.8",
        title="Bilgi Güvenliği Olay Raporlama",
        description="Çalışanların bilgi güvenliği olaylarını raporlama mekanizması",
        framework="ISO 27001:2022",
        category="İnsan Kaynakları Güvenliği",
        netguard_features=["incidents", "security_events"],
        check_fn="incident_count",
    ),
    ComplianceControl(
        control_id="ISO-A.7.4",
        title="Fiziksel Güvenlik İzleme",
        description="Tesislerin yetkisiz fiziksel erişime karşı sürekli izlenmesi",
        framework="ISO 27001:2022",
        category="Fiziksel Kontroller",
        netguard_features=["device_discovery", "network_monitoring"],
        check_fn="device_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.2",
        title="Ayrıcalıklı Erişim Hakları",
        description="Ayrıcalıklı erişim haklarının tahsisi ve yönetimi",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["sudo_monitoring", "privilege_escalation_detection"],
        check_fn="sudo_event_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.5",
        title="Güvenli Kimlik Doğrulama",
        description="Güvenli kimlik doğrulama teknolojileri ve prosedürleri",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["brute_force_detection", "ssh_monitoring", "windows_logon"],
        check_fn="brute_force_event_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.7",
        title="Zararlı Yazılım Koruması",
        description="Zararlı yazılımlara karşı koruma",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["sigma_rules", "process_monitoring", "windows_events"],
        check_fn="windows_process_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.8",
        title="Teknik Açıklık Yönetimi",
        description="Teknik açıklıkların zamanında tespiti ve yönetimi",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["threat_intel", "correlation_rules"],
        check_fn="threat_intel_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.15",
        title="Log Kayıt",
        description="Etkinliklerin, istisnaların ve güvenlik olaylarının kaydedilmesi",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["normalized_logs", "audit_log", "security_events"],
        check_fn="normalized_log_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.16",
        title="İzleme Faaliyetleri",
        description="Ağ, sistem ve uygulama davranışının izlenmesi",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["snmp_monitoring", "netflow", "correlation_engine"],
        check_fn="correlated_event_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.20",
        title="Ağ Güvenliği",
        description="Ağların ve ağ cihazlarının güvenliği",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["topology", "snmp_monitoring", "device_discovery"],
        check_fn="device_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.22",
        title="Web Filtreleme",
        description="Zararlı içeriklere erişimi yönet",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["firewall_parser", "web_log_parser"],
        check_fn="firewall_log_count",
    ),
    ComplianceControl(
        control_id="ISO-A.5.26",
        title="Bilgi Güvenliği Olaylarına Müdahale",
        description="Bilgi güvenliği olaylarına uygun şekilde müdahale edilmesi",
        framework="ISO 27001:2022",
        category="Organizasyonel Kontroller",
        netguard_features=["incidents", "attack_chain", "notifier"],
        check_fn="incident_count",
    ),
    ComplianceControl(
        control_id="ISO-A.8.12",
        title="Veri Sızıntısı Önleme",
        description="Yetkisiz bilgi ifşasını tespit etmek ve önlemek için önlemler",
        framework="ISO 27001:2022",
        category="Teknolojik Kontroller",
        netguard_features=["netflow", "correlation_rules", "exfiltration_detection"],
        check_fn="netflow_log_count",
    ),
]

ALL_CONTROLS = PCI_CONTROLS + ISO_CONTROLS


# ---------------------------------------------------------------------------
# Coverage hesaplama
# ---------------------------------------------------------------------------

def _score_control(control: ComplianceControl, metrics: dict) -> ControlResult:
    """Bir kontrolün mevcut veriye göre uyumluluk skorunu hesaplar."""
    check = control.check_fn
    value = metrics.get(check, 0) if check else 0

    features_active = [f for f in control.netguard_features if metrics.get(f"feature_{f}", False)]

    if check and value > 0:
        if value >= 10:
            status, score = "compliant", 100
        else:
            status, score = "partial", 50
    elif features_active:
        status, score = "partial", 40
    else:
        status, score = "gap", 0

    evidence: list[str] = []
    recommendations: list[str] = []

    if check == "audit_log_count" and value > 0:
        evidence.append(f"Denetim günlüğünde {value} kayıt mevcut")
    if check == "correlated_event_count" and value > 0:
        evidence.append(f"Korelasyon motoru {value} olay tespit etti")
    if check == "incident_count" and value > 0:
        evidence.append(f"{value} olay kaydı mevcut")
    if check == "brute_force_event_count" and value > 0:
        evidence.append(f"Kaba kuvvet saldırısı tespiti aktif ({value} olay)")
    if check == "normalized_log_count" and value > 0:
        evidence.append(f"{value} normalize log kaydı mevcut")
    if check == "device_count" and value > 0:
        evidence.append(f"{value} ağ cihazı izleniyor")
    if check == "active_alert_count" and value > 0:
        evidence.append(f"{value} aktif alarm mevcut")
    if check == "netflow_log_count" and value > 0:
        evidence.append(f"NetFlow analizi aktif ({value} akış kaydı)")

    if status == "gap":
        recommendations.append(f"NetGuard özelliklerini etkinleştir: {', '.join(control.netguard_features[:3])}")
    if status == "partial":
        recommendations.append("Veri toplanıyor ancak daha fazla telemetri gerekli")

    return ControlResult(
        control_id=control.control_id,
        title=control.title,
        framework=control.framework,
        category=control.category,
        status=status,
        score=score,
        evidence=evidence,
        recommendations=recommendations,
    )


def evaluate_compliance(db, framework: Optional[str] = None) -> dict:
    """
    Veritabanındaki mevcut verilere göre uyumluluk durumunu değerlendirir.

    framework: "PCI DSS v4.0" | "ISO 27001:2022" | None (ikisi de)
    """
    metrics = _collect_metrics(db)

    controls = ALL_CONTROLS
    if framework:
        controls = [c for c in controls if c.framework == framework]

    results = [_score_control(c, metrics) for c in controls]

    compliant = [r for r in results if r.status == "compliant"]
    partial   = [r for r in results if r.status == "partial"]
    gaps      = [r for r in results if r.status == "gap"]

    overall_score = round(sum(r.score for r in results) / len(results)) if results else 0

    by_framework: dict[str, dict] = {}
    for r in results:
        fw = r.framework
        if fw not in by_framework:
            by_framework[fw] = {"compliant": 0, "partial": 0, "gap": 0, "total": 0, "score": 0}
        by_framework[fw][r.status] += 1
        by_framework[fw]["total"] += 1
        by_framework[fw]["score"] += r.score

    for fw in by_framework:
        total = by_framework[fw]["total"]
        by_framework[fw]["score"] = round(by_framework[fw]["score"] / total) if total else 0

    return {
        "overall_score":  overall_score,
        "total_controls": len(results),
        "compliant":      len(compliant),
        "partial":        len(partial),
        "gaps":           len(gaps),
        "by_framework":   by_framework,
        "controls":       [
            {
                "control_id":      r.control_id,
                "title":           r.title,
                "framework":       r.framework,
                "category":        r.category,
                "status":          r.status,
                "score":           r.score,
                "evidence":        r.evidence,
                "recommendations": r.recommendations,
            }
            for r in results
        ],
    }


def _collect_metrics(db) -> dict:
    """DB'den mevcut veri metriklerini toplar."""
    metrics: dict = {}

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        metrics["audit_log_count"] = row[0] if row else 0
    except Exception:
        metrics["audit_log_count"] = 0

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM correlated_events").fetchone()
        metrics["correlated_event_count"] = row[0] if row else 0
    except Exception:
        metrics["correlated_event_count"] = 0

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM incidents").fetchone()
        metrics["incident_count"] = row[0] if row else 0
    except Exception:
        metrics["incident_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type IN ('brute_force','windows_logon_failure')"
        ).fetchone()
        metrics["brute_force_event_count"] = row[0] if row else 0
    except Exception:
        metrics["brute_force_event_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'sudo_usage'"
        ).fetchone()
        metrics["sudo_event_count"] = row[0] if row else 0
    except Exception:
        metrics["sudo_event_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type = 'windows_process_create'"
        ).fetchone()
        metrics["windows_process_count"] = row[0] if row else 0
    except Exception:
        metrics["windows_process_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_type LIKE 'ssh_%' OR event_type LIKE 'windows_logon%'"
        ).fetchone()
        metrics["auth_event_count"] = row[0] if row else 0
    except Exception:
        metrics["auth_event_count"] = 0

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM normalized_logs").fetchone()
        metrics["normalized_log_count"] = row[0] if row else 0
    except Exception:
        metrics["normalized_log_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM normalized_logs WHERE source_type = 'netflow'"
        ).fetchone()
        metrics["netflow_log_count"] = row[0] if row else 0
    except Exception:
        metrics["netflow_log_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM normalized_logs WHERE source_type IN ('pfsense','cisco_asa','fortigate')"
        ).fetchone()
        metrics["firewall_log_count"] = row[0] if row else 0
    except Exception:
        metrics["firewall_log_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM normalized_logs WHERE source_type IN ('nginx','apache')"
        ).fetchone()
        metrics["web_log_count"] = row[0] if row else 0
    except Exception:
        metrics["web_log_count"] = 0

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM devices").fetchone()
        metrics["device_count"] = row[0] if row else 0
    except Exception:
        metrics["device_count"] = 0

    try:
        row = db._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'active'"
        ).fetchone()
        metrics["active_alert_count"] = row[0] if row else 0
    except Exception:
        metrics["active_alert_count"] = 0

    try:
        row = db._conn.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()
        metrics["threat_intel_count"] = row[0] if row else 0
    except Exception:
        metrics["threat_intel_count"] = 0

    return metrics
