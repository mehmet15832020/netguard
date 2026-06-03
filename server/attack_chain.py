"""
NetGuard — Multi-Stage Attack Chain Detector

Standart SIEM ürünlerinin yaptığının ötesine geçer: tek bir eşik kuralı
tetiklemek yerine, aynı kaynaktan gelen FARKLI saldırı aşamalarını zamanla
takip eder ve bir kill chain örüntüsü tespit ettiğinde yüksek öncelikli
alert üretir.

Kill Chain Aşamaları (Lockheed Martin / MITRE ATT&CK):
  RECON       → port_scan, dns_anomaly            (Keşif)
  WEAPONIZE   → windows_brute_force, ssh_failure  (Silahlanma / Erişim Denemeleri)
  ACCESS      → ssh_success, windows_logon_success (İlk Erişim)
  EXECUTE     → windows_process_create, sudo_abuse (Komut Çalıştırma)
  LATERAL     → lateral_movement, windows_lateral  (Yanal Hareket)

Tetikleme:
  2 farklı aşama / 30 dakika → PARTIAL_ATTACK_CHAIN (warning)
  3+ farklı aşama / 30 dakika → FULL_ATTACK_CHAIN (critical)

Her IP için aşama kaydı bellekte tutulur; 30 dakika geçmişe düşen
kayıtlar otomatik temizlenir.
"""

import ipaddress
import logging
import os
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Per-IP lock prevents TOCTOU race between is_ip_blocked() check and block_ip() call.
_block_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
_block_locks_meta = threading.Lock()


def _get_block_lock(ip: str) -> threading.Lock:
    with _block_locks_meta:
        return _block_locks[ip]


def _load_protected_networks() -> list:
    nets = [
        # IPv4 RFC1918 + loopback + link-local
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        # IPv6 loopback, ULA, link-local
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]
    for cidr in os.getenv("PROTECTED_CIDRS", "").split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("PROTECTED_CIDRS geçersiz CIDR atlandı: %s", cidr)
    return nets


_PROTECTED_NETWORKS = _load_protected_networks()

CHAIN_WINDOW_SEC = 1800   # 30 dakika
PARTIAL_THRESHOLD = 2     # uyarı eşiği
FULL_THRESHOLD    = 3     # kritik eşiği

STAGE_MAP: dict[str, str] = {
    # event_action → stage adı
    # Raw log event types
    "port_scan":                 "recon",
    "dns_anomaly":               "recon",
    "ssh_failure":               "weaponize",
    "windows_logon_failure":     "weaponize",
    "windows_brute_force":       "weaponize",
    "brute_force":               "weaponize",
    "ssh_success":               "access",
    "windows_logon_success":     "access",
    "windows_lateral_movement":  "lateral",   # MITRE ATT&CK: Lateral Movement taktiği (T1550/T1569)
    "windows_process_create":    "execute",
    "sudo_abuse":                "execute",
    "lateral_movement":          "lateral",
    "windows_lateral":           "lateral",
    # Correlated event output types (sigma rule output)
    "ssh_brute_force":           "weaponize",
    "windows_pass_the_hash":     "weaponize",
    "port_scan_detected":        "recon",
    "arp_attack":                "recon",
    "ssh_lateral":               "lateral",
    "anomaly_detected":              "recon",
    "asset_anomaly_detected":        "recon",
    "web_scan_detected":             "recon",
    "multi_source_attack_detected":  "recon",
    # Sigma kural slug prefix'leri (title → slug → _detected dönüşümü)
    "arp_spoof":             "recon",     # ARP Spoofing Burst
    "zeek_port":             "recon",     # Zeek Port Scan Notice
    "ssh_target":            "weaponize", # SSH Targeted Attack
    "dns_c2":                "lateral",   # DNS C2 High Frequency (C2 kanal)
    "dns_tunnel":            "lateral",   # DNS Tunneling
    "dns_query":             "recon",     # DNS Query Burst
    "ftp_exfil":             "lateral",   # FTP Exfiltration Burst
    "web_auth":              "weaponize", # Web Auth Brute Force
    "icmp_flood":            "recon",     # ICMP Flood
    "c2_beaconing":          "lateral",   # C2 Beaconing (IAT analysis — MITRE TA0011 T1071)
    "firewall_beacon":       "recon",     # Firewall Beaconing (C2 beaconing)
    "firewall_ddos":         "recon",     # Firewall DDoS Flood
    "network_connection_fl": "recon",     # Network Connection Flood
    "anomaly_cluster":       "recon",     # Anomaly Cluster Multi-Source
    "coordinated":           "recon",     # Coordinated Multi-Source Attack
    "tls_suspicious":        "recon",     # TLS Suspicious JA3
    "tls_suspicious_ja4s":  "lateral",   # JA4S server fingerprint → TA0011 C&C T1071.001
    "ssl_self":              "recon",     # SSL Self-Signed Certificate Burst
    "ssl_cert":              "recon",     # SSL Certificate Invalid
    "command_injection":     "execute",   # Command Injection
    "path_traversal":        "execute",   # Path Traversal
    "xss":                   "execute",   # XSS Attempt
    "sql_injection":         "execute",   # SQL Injection
    # Suricata IDS
    "suricata_alert":        "recon",     # IDS uyarısı (varsayılan recon; burst korelasyon lateral'e taşır)
    "suricata_anomaly":      "recon",     # Protocol anomaly
    "suricata_alert_burst":  "lateral",   # Suricata Alert Burst (sigma korelasyon çıktısı)
    "suricata_lateral":      "lateral",   # Lateral movement burst (dst_ip gruplama)
    # Suricata G7 — HTTP/TLS/SSH anomaly (MITRE T1071 / T1587.003 / T1110)
    "suricata_http_anomaly": "recon",     # T1595 — scanner UA = active scanning / recon
    "suricata_tls_anomaly":  "lateral",   # T1071 — C2 over TLS / self-signed / old version
    "suricata_ssh_anomaly":  "weaponize", # T1110 — SSH brute-force tool (erisim denemesi)
    # NetFlow D1 — büyük akış / şüpheli port / tünel (MITRE T1048 / T1071 / T1572)
    "netflow_large_flow":    "lateral",   # T1048 — exfil over alt protocol (büyük tek akış)
    "netflow_suspicious_por":"lateral",   # T1071 — C2/lateral suspicious port akışı
    "netflow_tunneled":      "lateral",   # T1572 — GRE/ESP/IPv6-in-IPv4 protocol tunneling
    # NetFlow Sigma korelasyon çıktı slug prefix'leri
    "netflow_large_flow_exf":"lateral",   # NetFlow Large Flow Exfiltration Burst (T1048)
    "netflow_tunnel_protoco":"lateral",   # NetFlow Tunnel Protocol Burst (T1572)
    # Windows / Sysmon (U2 + N1)
    "windows_explicit_logon":         "weaponize",  # 4648 — pass-the-hash göstergesi
    "windows_user_created":           "execute",    # 4720 — persistence (yeni hesap)
    "windows_group_member_added":     "execute",    # 4728/4732 — privilege escalation
    "windows_kerberos_tgt":           "weaponize",  # 4768 — credential access / AS-REP roasting
    "windows_kerberos_service":       "lateral",    # 4769 — Kerberoasting / lateral movement
    "windows_sysmon_proc_access":     "execute",    # Sysmon EID10 — credential dumping (mimikatz)
    "windows_sysmon_network":         "lateral",    # Sysmon EID3 — C2 / lateral connection
    "windows_sysmon_process":         "execute",    # Sysmon EID1 — suspicious execution
    "windows_sysmon_dns":             "recon",      # Sysmon EID22 — DNS C2 / recon
    # N1 — yeni EID'ler
    "windows_special_priv":           "execute",    # 4672 — SeDebugPrivilege → credential dump
    "windows_task_created":           "execute",    # 4698 — scheduled task persistence T1053.005
    "windows_task_updated":           "execute",    # 4702 — scheduled task güncelleme
    "windows_account_lockout":        "weaponize",  # 4740 — password spray / brute-force
    "windows_kerberos_preauth_fail":  "weaponize",  # 4771 — AS-REP roasting T1558.004
    "windows_ntlm_auth":              "weaponize",  # 4776 — NTLM PtH hazırlık T1550.002
    "windows_share_access":           "lateral",    # 5140 — admin share erişim T1021.002
    "windows_log_cleared":            "execute",    # 1102 — iz silme T1070.001
    "windows_sysmon_driver_load":     "execute",    # Sysmon EID6 — BYOVD T1068
    "windows_sysmon_image_load":      "execute",    # Sysmon EID7 — DLL injection T1055
    "windows_sysmon_file_create":     "execute",    # Sysmon EID11 — dropper T1105
    "windows_sysmon_registry":        "execute",    # Sysmon EID13 — persistence T1547.001
    # N1 genişletme — yeni 17 EID
    "windows_lateral_logon":            "lateral",    # 4624 network type=3 — lateral movement T1550.002
    "windows_computer_account_changed": "execute",    # 4741 — persistence T1098.002
    "windows_logon_process_registered": "execute",    # 4614 — LSA hijack T1556
    "windows_token_privilege_adjusted": "execute",    # 4703 — token manipulation T1134
    "windows_powershell_module":        "execute",    # 4103 — PowerShell execution T1059.001
    "windows_powershell_scriptblock":   "execute",    # 4104 — PowerShell ScriptBlock T1059.001
    "windows_service_installed":        "execute",    # 7045 — persistence T1543.003
    "windows_service_crashed":          "execute",    # 7034 — defense evasion T1562.001
    "windows_service_start_changed":    "execute",    # 7040 — persistence T1547.001
    "windows_applocker_blocked":        "execute",    # 8004 — defense evasion T1562.001
    "windows_sysmon_remote_thread":     "execute",    # Sysmon 8 — process injection T1055
    "windows_sysmon_raw_access":        "execute",    # Sysmon 9 — data collection T1005
    "windows_sysmon_ads":               "execute",    # Sysmon 15 — hide artifacts T1564.004
    "windows_sysmon_pipe_created":      "lateral",    # Sysmon 17 — LOLBin injection T1218
    "windows_sysmon_pipe_connected":    "lateral",    # Sysmon 18 — LOLBin injection T1218
    "windows_sysmon_wmi_event":         "lateral",    # Sysmon 19 — WMI persistence T1047
    "windows_sysmon_wmi_binding":       "lateral",    # Sysmon 21 — WMI binding T1047
    "windows_sysmon_process_tamper":    "execute",    # Sysmon 25 — process tampering T1070
    # Zeek weird.log (N2)
    "zeek_weird_unknown_protocol":       "lateral",   # T1071 C2 tunnel
    "zeek_weird_bad_http_request":       "execute",   # T1190 exploit
    "zeek_weird_tcp_evasion":            "recon",     # T1089 IDS evasion
    "zeek_weird_tcp_manipulation":       "recon",     # TCP state manipulation
    "zeek_weird_syn_anomaly":            "recon",     # T1499 SYN state violation
    "zeek_weird_tcp_anomaly":            "recon",     # TCP state violation
    "zeek_weird_dns_anomaly":            "recon",     # T1071.004 DNS anomaly
    "zeek_weird_http_anomaly":           "recon",     # T1071.001 HTTP evasion
    "zeek_weird_protocol_corruption":    "recon",     # T1089 protocol abuse
    "zeek_weird_protocol_evasion":       "recon",     # T1071 evasion
    # Zeek dpd.log (N2)
    "zeek_dpd_ssl_failure":              "lateral",   # T1071.001 non-TLS on 443
    "zeek_dpd_http_failure":             "lateral",   # T1071.001 non-HTTP on 443
    "zeek_dpd_dns_failure":              "lateral",   # T1071.004 DNS tunnel
    "zeek_dpd_ssh_failure":              "weaponize", # T1021.006 SSH evasion
    # Zeek files.log (N2)
    "zeek_file_inbound":                 "execute",   # T1105 file download
    "zeek_file_inbound_suspicious":      "execute",   # T1566/T1105 malicious download
    "zeek_file_outbound":                "lateral",   # T1048 data exfiltration
    "zeek_file_outbound_suspicious":     "lateral",   # T1048.001 exfil
    # ── Zeek rdp.log ──────────────────────────────────────────────────────────
    "zeek_rdp_success":              "access",      # T1021.001 başarılı RDP
    "zeek_rdp_failure":              "weaponize",   # T1021.001 brute-force
    "zeek_rdp_no_cert":              "lateral",     # T1021.001 C2 tünel
    "zeek_rdp_suspicious_client":    "lateral",     # T1021.001 saldırı aracı
    # ── Zeek kerberos.log ─────────────────────────────────────────────────────
    "zeek_kerberos_tgs_rc4":         "weaponize",   # T1558.003 Kerberoasting
    "zeek_kerberos_as_nopreauth":    "weaponize",   # T1558.004 AS-REP Roasting
    "zeek_kerberos_golden_ticket":   "execute",     # T1558.001 Golden Ticket
    "zeek_kerberos_rc4_downgrade":   "lateral",     # T1558 RC4 downgrade
    "zeek_kerberos_failure":         "weaponize",   # T1110 brute-force
    # ── Zeek smb_files.log ────────────────────────────────────────────────────
    "zeek_smb_admin_share":          "lateral",     # T1021.002 admin share
    "zeek_smb_suspicious_file":      "lateral",     # T1570 lateral tool transfer
    "zeek_smb_delete":               "execute",     # T1070.001 cover tracks
    "zeek_smb_recon":                "recon",       # T1018 domain recon
    "zeek_smb_write":                "lateral",     # T1021.002 file write
    "zeek_smb_rename":               "execute",     # T1070 file manipulation
    "zeek_smb_open":                 "recon",       # file access
    "zeek_smb_operation":            "recon",       # generic SMB
    # ── Zeek dce_rpc.log ──────────────────────────────────────────────────────
    "zeek_dce_rpc_dcsync":           "execute",     # T1003.006 DCSync
    "zeek_dce_rpc_psexec":           "execute",     # T1569.002 PsExec
    "zeek_dce_rpc_wmi":              "execute",     # T1047 WMI execution
    "zeek_dce_rpc_task":             "execute",     # T1053.005 Task Scheduler
    "zeek_dce_rpc_registry":         "execute",     # T1112 registry modification
    "zeek_dce_rpc_samr_enum":        "recon",       # T1087 account discovery
    "zeek_dce_rpc_policy":           "recon",       # T1082 system discovery
    "zeek_dce_rpc_operation":        "recon",       # generic DCE-RPC
    # ── sFlow v5 (N6) — sampled flow (RFC 3176 / T1048 / T1572) ─────────────
    "sflow_flow":             "recon",      # normal akış örnekleme
    "sflow_large_flow":       "lateral",    # T1048 büyük veri exfil
    "sflow_tunneled":         "lateral",    # T1572 protokol tüneli
    "sflow_suspicious_port":  "weaponize",  # şüpheli port akışı
    # ── OpenCanary honeypot ───────────────────────────────────────────────────
    "honeypot_ssh":     "weaponize",   # T1110.001 SSH credential brute-force
    "honeypot_ftp":     "recon",       # T1046 FTP service enumeration
    "honeypot_http":    "recon",       # T1595 web active scanning
    "honeypot_smb":     "lateral",     # T1021.002 SMB lateral movement attempt
    "honeypot_mysql":   "lateral",     # T1190 DB exploit / T1110 brute-force
    "honeypot_mssql":   "lateral",     # T1190 MSSQL exploit
    "honeypot_snmp":    "recon",       # T1046 network scan / T1201 SNMP recon
    "honeypot_rdp":     "lateral",     # T1021.001 RDP lateral movement
    "honeypot_redis":   "lateral",     # T1190 Redis exploit
    "honeypot_tftp":    "recon",       # T1046 TFTP recon
    "honeypot_ntp":     "recon",       # T1046 NTP scanning
    "honeypot_telnet":  "weaponize",   # T1021 Telnet brute-force
    # ── Microsoft 365 cloud audit (N8 — BEC T1114/T1098/T1530) ───────────────
    "m365_inbox_rule":         "lateral",    # T1114.003 email forwarding rule
    "m365_mailbox_permission": "lateral",    # T1098 mailbox full-access grant
    "m365_delegate_access":    "lateral",    # T1098 delegate access grant
    "m365_mail_access":        "lateral",    # T1114 email collection (MailItemsAccessed)
    "m365_bulk_download":      "lateral",    # T1530 data from cloud storage
    "m365_role_assignment":    "weaponize",  # T1098.003 additional cloud roles
    "m365_login_failure":      "recon",      # T1110 brute force
    # ── Google Workspace cloud audit (N8 — BEC T1110/T1114/T1098/T1078/T1530) ─
    "gws_login_failure":    "recon",      # T1110 brute force
    "gws_suspicious_login": "weaponize",  # T1078 valid accounts abuse
    "gws_gmail_rule":       "lateral",    # T1114.003 Gmail forwarding/filter rule
    "gws_admin_privilege":  "weaponize",  # T1098 account manipulation
    "gws_bulk_download":    "lateral",    # T1530 data from cloud storage
}

# Longest-prefix-first sıralama — belirsiz prefix eşleşmelerinde daha uzun (özgül) prefix kazanır.
# Endüstri standardı: routing table longest-match, Suricata rule priority aynı prensibi kullanır.
_STAGE_MAP_BY_LEN: list[tuple[str, str]] = sorted(
    STAGE_MAP.items(), key=lambda x: len(x[0]), reverse=True
)

STAGE_LABELS = {
    "recon":      "Keşif",
    "weaponize":  "Erişim Denemeleri",
    "access":     "İlk Erişim",
    "execute":    "Komut Çalıştırma",
    "lateral":    "Yanal Hareket",
}


def _resolve_stage(event_action: str) -> Optional[str]:
    # Exact match önce — en kesin eşleşme
    if event_action in STAGE_MAP:
        return STAGE_MAP[event_action]
    # Prefix fallback — raw event_action'lar için (örn. "port_scan_attempt" → "port_scan")
    # Uzun prefix kısa prefix'e göre önceliklidir (longest-match)
    for prefix, stage in _STAGE_MAP_BY_LEN:
        if event_action.startswith(prefix):
            return stage
    return None


class AttackChainTracker:
    """
    Thread-safe. Her source_ip için aşama → zaman damgaları listesi tutar.
    Periyodik temizlik için _purge() çağrısı dahilidir.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {source_ip: {stage: [datetime, ...]}}
        self._chains: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))

    def record(self, source_ip: str, event_action: str, occurred_at: Optional[datetime] = None) -> Optional[dict]:
        """
        Yeni bir event kaydeder. Zincir tamamlanmışsa tetikleme dict'i döner,
        aksi hâlde None döner.

        Dönüş örneği:
          {
            "chain_type": "FULL_ATTACK_CHAIN",
            "severity":   "critical",
            "source_ip":     "10.0.0.5",
            "stages":     ["recon", "weaponize", "access"],
            "stage_labels": ["Keşif", "Erişim Denemeleri", "İlk Erişim"],
            "message":    "...",
            "event_action": "full_attack_chain_detected",
          }
        """
        if not source_ip or source_ip in ("-", "None", "none"):
            return None

        stage = _resolve_stage(event_action)
        if not stage:
            return None

        now = occurred_at or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)

        trigger: Optional[dict] = None

        with self._lock:
            bucket = self._chains[source_ip]
            bucket[stage].append(now)

            # Pencere dışı kayıtları temizle
            for s in list(bucket.keys()):
                bucket[s] = [t for t in bucket[s] if t >= cutoff]
                if not bucket[s]:
                    del bucket[s]

            active_stages = list(bucket.keys())
            stage_count = len(active_stages)

            if stage_count >= FULL_THRESHOLD:
                trigger = self._build_trigger(source_ip, active_stages, "FULL_ATTACK_CHAIN", "critical")
            elif stage_count >= PARTIAL_THRESHOLD:
                trigger = self._build_trigger(source_ip, active_stages, "PARTIAL_ATTACK_CHAIN", "warning")

        # Lock dışında I/O — in-memory state ile tutarlı (lock içinde güncellendi)
        try:
            from server.database import db
            db.save_chain_stage(source_ip, stage, now)
        except Exception as exc:
            logger.debug(f"Chain stage DB kaydedilemedi [{source_ip}/{stage}]: {exc}")

        return trigger

    def _build_trigger(self, source_ip: str, stages: list[str], chain_type: str, severity: str) -> dict:
        labels = [STAGE_LABELS.get(s, s) for s in stages]
        chain_str = " → ".join(labels)
        level = "TAM" if chain_type == "FULL_ATTACK_CHAIN" else "KISMİ"
        return {
            "chain_type":   chain_type,
            "severity":     severity,
            "source_ip":       source_ip,
            "stages":       stages,
            "stage_labels": labels,
            "event_action":   chain_type.lower() + "_detected",
            "message":      (
                f"{level} SALDIRI ZİNCİRİ — {source_ip}: "
                f"{chain_str} "
                f"({len(stages)} aşama / {CHAIN_WINDOW_SEC // 60} dakika)"
            ),
        }

    def get_chains(self) -> dict:
        """Aktif zincirlerin anlık görüntüsü (UI / API için)."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)
        result = {}
        with self._lock:
            for ip, bucket in self._chains.items():
                active = {s: len([t for t in ts if t >= cutoff])
                          for s, ts in bucket.items()
                          if any(t >= cutoff for t in ts)}
                if active:
                    result[ip] = active
        return result

    def purge(self) -> None:
        """Süresi geçmiş kayıtları temizler. Periyodik çağrılabilir."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)
        with self._lock:
            for ip in list(self._chains.keys()):
                bucket = self._chains[ip]
                for s in list(bucket.keys()):
                    bucket[s] = [t for t in bucket[s] if t >= cutoff]
                    if not bucket[s]:
                        del bucket[s]
                if not bucket:
                    del self._chains[ip]
        try:
            from server.database import db
            db.purge_old_chain_stages(CHAIN_WINDOW_SEC)
        except Exception as exc:
            logger.debug(f"Chain state DB temizlenemedi: {exc}")

    def restore_from_db(self) -> None:
        """Sunucu başlangıcında DB'den aktif chain state'i yükle."""
        try:
            from server.database import db
            stages = db.get_active_chain_stages(CHAIN_WINDOW_SEC)
            with self._lock:
                self._chains = defaultdict(lambda: defaultdict(list))
                for source_ip, stage_dict in stages.items():
                    for stage, timestamps in stage_dict.items():
                        self._chains[source_ip][stage] = list(timestamps)
            count = len(self._chains)
            if count:
                logger.info(f"Attack chain restore: {count} aktif IP DB'den yüklendi")
        except Exception as exc:
            logger.warning(f"Attack chain DB restore başarısız: {exc}")


def _auto_block_full_chain(trigger: dict) -> None:
    if os.getenv("AUTO_BLOCK_ON_FULL_CHAIN", "0") != "1":
        return
    if trigger.get("chain_type") != "FULL_ATTACK_CHAIN":
        return
    source_ip = trigger.get("source_ip", "")
    if not source_ip:
        return
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        logger.warning("AUTO_BLOCK: geçersiz IP [%s]", source_ip)
        return
    if any(addr in net for net in _PROTECTED_NETWORKS):
        logger.info("AUTO_BLOCK atlandı (korumalı ağ): %s", source_ip)
        return

    min_severity = os.getenv("BLOCK_MIN_SEVERITY", "high")
    severity = trigger.get("severity", "info")
    _sev_order = {"info": 1, "warning": 2, "high": 3, "critical": 4}
    if _sev_order.get(severity, 0) < _sev_order.get(min_severity, 3):
        logger.info("AUTO_BLOCK atlandı (severity %s < %s): %s", severity, min_severity, source_ip)
        return

    ip_lock = _get_block_lock(source_ip)
    with ip_lock:
        try:
            from server.fp_manager import fp_manager
            from server.database import db
            if fp_manager.is_suppressed(event_action="full_attack_chain_detected", source_ip=source_ip, tenant_id="default"):
                logger.info("AUTO_BLOCK atlandı (FP kuralı): %s", source_ip)
                try:
                    db.save_audit_event(
                        actor="system/kill_chain",
                        action="auto_block_skipped_fp",
                        resource=f"ip:{source_ip}",
                        detail="FP kuralı tetiklendi — FULL_ATTACK_CHAIN otomatik bloklama atlandı",
                        ip_address=source_ip,
                    )
                except Exception:
                    pass
                return
            if db.is_ip_blocked(source_ip, tenant_id="default"):
                logger.debug("AUTO_BLOCK atlandı (zaten bloklu): %s", source_ip)
                return
            from server.active_response import active_response_manager
            stages = ", ".join(trigger.get("stages") or ["unknown"])
            result = active_response_manager.block_ip(
                source_ip,
                f"Otomatik bloklama: FULL_ATTACK_CHAIN ({stages})",
                "system/kill_chain",
                tenant_id="default",
            )
            if result.get("success"):
                logger.info("AUTO_BLOCK başarılı [%s] provider=%s", source_ip, result.get("provider"))
            else:
                logger.error("AUTO_BLOCK provider başarısız [%s]: %s", source_ip, result.get("error"))
        except Exception as exc:
            logger.error("AUTO_BLOCK_ON_FULL_CHAIN hata [%s]: %s", source_ip, exc, exc_info=True)


def chain_trigger_to_correlated_event(trigger: dict, db_save: bool = True):
    """
    AttackChainTracker'dan gelen tetikleme dict'ini CorrelatedEvent'e dönüştürür
    ve isteğe bağlı olarak DB'ye kaydeder.
    """
    from shared.models import CorrelatedEvent
    now = datetime.now(timezone.utc)
    event = CorrelatedEvent(
        corr_id        = str(uuid.uuid4()),
        rule_id        = trigger["chain_type"].lower(),
        rule_name      = trigger["chain_type"].replace("_", " ").title(),
        event_action     = trigger["event_action"],
        severity       = trigger["severity"],
        group_value    = trigger["source_ip"],
        group_by_field = "source_ip",
        matched_count  = len(trigger["stages"]),
        window_seconds = CHAIN_WINDOW_SEC,
        first_seen     = now,
        last_seen      = now,
        message        = trigger["message"],
    )
    if db_save:
        try:
            from server.database import db
            db.save_correlated_event(event)
        except Exception as exc:
            logger.warning(f"Attack chain event kaydedilemedi: {exc}")
    _auto_block_full_chain(trigger)
    return event


# Global singleton
attack_chain_tracker = AttackChainTracker()
