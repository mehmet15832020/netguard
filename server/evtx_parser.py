"""
NetGuard — EVTX Dosya Parser

Windows .evtx formatındaki olay günlüğü dosyalarını parse eder.
Forensik analiz ve offline inceleme için kullanılır.

Desteklenen event ID'ler:
  Windows Security: 4624, 4625, 4648, 4672, 4688, 4698, 4702, 4720,
                    4728, 4732, 4740, 4768, 4769, 4771, 4776, 5140, 1102
  Sysmon:           1, 3, 6, 7, 10, 11, 13, 22

Gereksinim: python-evtx (pip install python-evtx)
"""

import ipaddress
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# event_action → (default_severity)  — dinamik override mümkün
_EID_MAP: dict[int, tuple[str, str]] = {
    # Windows Security Events
    4624:  ("windows_logon_success",        "info"),
    4625:  ("windows_logon_failure",        "warning"),
    4648:  ("windows_explicit_logon",       "warning"),
    4672:  ("windows_special_priv",         "warning"),
    4688:  ("windows_process_create",       "info"),
    4698:  ("windows_task_created",         "warning"),
    4702:  ("windows_task_updated",         "warning"),
    4720:  ("windows_user_created",         "warning"),
    4728:  ("windows_group_member_added",   "warning"),
    4732:  ("windows_group_member_added",   "warning"),
    4740:  ("windows_account_lockout",      "warning"),
    4768:  ("windows_kerberos_tgt",         "info"),
    4769:  ("windows_kerberos_service",     "info"),
    4771:  ("windows_kerberos_preauth_fail","warning"),
    4776:  ("windows_ntlm_auth",            "info"),
    5140:  ("windows_share_access",         "info"),
    1102:  ("windows_log_cleared",          "critical"),
    # Sysmon Events
    1:     ("windows_sysmon_process",       "info"),
    3:     ("windows_sysmon_network",       "info"),
    6:     ("windows_sysmon_driver_load",   "warning"),
    7:     ("windows_sysmon_image_load",    "info"),
    10:    ("windows_sysmon_proc_access",   "warning"),
    11:    ("windows_sysmon_file_create",   "info"),
    13:    ("windows_sysmon_registry",      "info"),
    22:    ("windows_sysmon_dns",           "info"),
}

_LOGON_TYPES = {
    "2":  "interactive",
    "3":  "network",
    "4":  "batch",
    "5":  "service",
    "7":  "unlock",
    "8":  "network_cleartext",
    "10": "remote_interactive",
    "11": "cached_interactive",
}

# Sysmon: süreç adlarına göre şüphe sınıflandırması
_LOLBAS: frozenset[str] = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "installutil.exe", "schtasks.exe",
    "at.exe", "wmic.exe", "forfiles.exe", "pcalua.exe",
    "net.exe", "net1.exe", "sc.exe", "reg.exe", "tasklist.exe",
    "whoami.exe", "nltest.exe", "systeminfo.exe",
})

_KNOWN_MALWARE_PROC: frozenset[str] = frozenset({
    "mimikatz.exe", "procdump.exe", "wce.exe", "fgdump.exe",
    "pwdump.exe", "gsecdump.exe", "lsadump.exe", "sekurlsa.exe",
})

_KERBEROS_WEAK_ENC: frozenset[str] = frozenset({
    "0x17", "0x18", "23", "24",   # RC4 — Kerberoasting indicator
    "0x1", "0x3", "1", "3",       # DES-CBC-CRC / DES-CBC-MD5 — legacy weak
})


def _xml_text(root: ET.Element, path: str) -> str:
    el = root.find(path, {"": _NS})
    return (el.text or "").strip() if el is not None else ""


def _get_data(root: ET.Element, name: str) -> str:
    for el in root.findall(".//{%s}Data" % _NS):
        if el.get("Name") == name:
            return (el.text or "").strip()
    return ""


def _clean_ip(val: str) -> Optional[str]:
    if not val or val in ("-", "::1", "127.0.0.1", "0.0.0.0", "::", "::"):
        return None
    try:
        addr = ipaddress.ip_address(val)
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return None
    except ValueError:
        return None
    return val


def _parse_record_xml(xml_str: str) -> Optional[dict]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    try:
        eid_str = _xml_text(root, "./{%s}System/{%s}EventID" % (_NS, _NS))
        if not eid_str:
            return None
        eid = int(eid_str)
    except (ValueError, TypeError):
        return None

    if eid not in _EID_MAP:
        return None

    event_action, _ = _EID_MAP[eid]
    el_time  = root.find(".//{%s}TimeCreated" % _NS)
    occurred_at = el_time.get("SystemTime", "") if el_time is not None else ""
    if not occurred_at:
        occurred_at = datetime.now(timezone.utc).isoformat()
    computer = _xml_text(root, "./{%s}System/{%s}Computer" % (_NS, _NS))

    # ── Windows Security Events ───────────────────────────────────────────────

    if eid == 4625:
        username  = _get_data(root, "TargetUserName")
        source_ip = _clean_ip(_get_data(root, "IpAddress"))
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          username,
            "source_ip":         source_ip,
            "observer_hostname": computer,
            "message":           f"Windows logon failure: user={username}",
            "raw_data":          xml_str[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4624:
        username    = _get_data(root, "TargetUserName")
        source_ip   = _clean_ip(_get_data(root, "IpAddress"))
        logon_type  = _get_data(root, "LogonType")
        logon_label = _LOGON_TYPES.get(logon_type, logon_type)
        if logon_label in ("service", "batch"):
            return None
        return {
            "event_action":      event_action,
            "severity":          "info",
            "username":          username,
            "source_ip":         source_ip,
            "observer_hostname": computer,
            "message":           f"Windows logon success: user={username} type={logon_label}",
            "raw_data":          xml_str[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4648:
        subj_user = _get_data(root, "SubjectUserName")
        tgt_user  = _get_data(root, "AccountName")
        server    = _get_data(root, "ServerName")
        process   = _get_data(root, "ProcessName")
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          subj_user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Explicit logon: {subj_user} → {tgt_user}@{server} via {process}",
            "raw_data":          f"EID=4648 subj={subj_user} tgt={tgt_user} server={server}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4688:
        subject_user = _get_data(root, "SubjectUserName")
        process_name = _get_data(root, "NewProcessName")
        cmdline      = _get_data(root, "CommandLine")
        proc_lower   = (process_name.split("\\")[-1] if process_name else "").lower()
        severity     = "critical" if proc_lower in _KNOWN_MALWARE_PROC else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          subject_user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Process created: {process_name}",
            "raw_data":          f"EID=4688 user={subject_user} process={process_name} cmd={cmdline}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4720:
        new_user = _get_data(root, "TargetUserName")
        creator  = _get_data(root, "SubjectUserName")
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          creator,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"User account created: {new_user} by {creator}",
            "raw_data":          f"EID=4720 new_user={new_user} creator={creator}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4732:
        member = _get_data(root, "MemberName")
        group  = _get_data(root, "TargetUserName")
        actor  = _get_data(root, "SubjectUserName")
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          actor,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Group member added: {member} → group={group} by {actor}",
            "raw_data":          f"EID=4732 member={member} group={group} actor={actor}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4768:
        user      = _get_data(root, "TargetUserName")
        domain    = _get_data(root, "TargetDomainName")
        src_ip    = _clean_ip(_get_data(root, "IpAddress"))
        status    = _get_data(root, "Status")
        enc_type  = _get_data(root, "TicketEncryptionType")
        pre_auth  = _get_data(root, "PreAuthType")
        downgrade = enc_type in _KERBEROS_WEAK_ENC
        failure   = status not in ("0x0", "")
        as_rep_roast = (pre_auth == "0" and downgrade)
        if as_rep_roast:
            severity = "critical"
        elif failure or downgrade:
            severity = "warning"
        else:
            severity = "info"
        msg = f"Kerberos TGT: {user}@{domain} status={status} enc={enc_type}"
        if as_rep_roast:
            msg += " [AS_REP_ROAST]"
        elif downgrade:
            msg += " [WEAK_ENCRYPTION]"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         src_ip,
            "observer_hostname": computer,
            "message":           msg,
            "raw_data":          f"EID=4768 user={user} domain={domain} status={status} enc={enc_type} preauth={pre_auth}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4769:
        user      = _get_data(root, "TargetUserName")
        service   = _get_data(root, "ServiceName")
        src_ip    = _clean_ip(_get_data(root, "IpAddress"))
        enc_type  = _get_data(root, "TicketEncryptionType")
        kerberoast = enc_type in _KERBEROS_WEAK_ENC
        severity   = "warning" if kerberoast else "info"
        msg = f"Kerberos ST: {user} → {service} enc={enc_type}"
        if kerberoast:
            msg += " [KERBEROAST]"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         src_ip,
            "observer_hostname": computer,
            "message":           msg,
            "raw_data":          f"EID=4769 user={user} service={service} enc={enc_type}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4672:
        user   = _get_data(root, "SubjectUserName")
        privs  = _get_data(root, "PrivilegeList")
        # SeDebugPrivilege → credential dumping, process injection
        high_risk = any(p in privs for p in ("SeDebugPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"))
        severity  = "critical" if high_risk else "warning"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Special privileges assigned: user={user} privs={privs[:120]}",
            "raw_data":          f"EID=4672 user={user} privs={privs}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid in (4698, 4702):
        actor     = _get_data(root, "SubjectUserName")
        task_name = _get_data(root, "TaskName")
        label     = "created" if eid == 4698 else "updated"
        non_std   = not any(task_name.startswith(p) for p in (
            r"\Microsoft\Windows", r"\Microsoft\Office", r"\Microsoft\Edge"
        ))
        severity  = "warning" if non_std else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          actor,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Scheduled task {label}: {task_name} by {actor}",
            "raw_data":          f"EID={eid} actor={actor} task={task_name}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid in (4728, 4732):
        member = _get_data(root, "MemberName")
        group  = _get_data(root, "TargetUserName")
        actor  = _get_data(root, "SubjectUserName")
        # Admin/Domain Admins eklemesi yüksek risk
        high_risk = any(g in group.lower() for g in ("admin", "domain admins", "enterprise admins"))
        severity  = "critical" if high_risk else "warning"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          actor,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Group member added: {member} → {group} by {actor}",
            "raw_data":          f"EID={eid} member={member} group={group} actor={actor}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4740:
        locked_user = _get_data(root, "TargetUserName")
        caller      = _get_data(root, "SubjectUserName")
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          locked_user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Account locked out: {locked_user} (caller={caller})",
            "raw_data":          f"EID=4740 locked={locked_user} caller={caller}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4771:
        user   = _get_data(root, "TargetUserName")
        src_ip = _clean_ip(_get_data(root, "IpAddress"))
        status = _get_data(root, "Status")
        return {
            "event_action":      event_action,
            "severity":          "warning",
            "username":          user,
            "source_ip":         src_ip,
            "observer_hostname": computer,
            "message":           f"Kerberos pre-auth failed: {user} status={status}",
            "raw_data":          f"EID=4771 user={user} src={src_ip} status={status}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 4776:
        user       = _get_data(root, "TargetUserName")
        workstation = _get_data(root, "Workstation")
        status     = _get_data(root, "Status")
        failure    = status not in ("0x0", "")
        severity   = "warning" if failure else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"NTLM auth {'failed' if failure else 'success'}: user={user} from={workstation}",
            "raw_data":          f"EID=4776 user={user} workstation={workstation} status={status}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 5140:
        user       = _get_data(root, "SubjectUserName")
        share      = _get_data(root, "ShareName")
        src_ip     = _clean_ip(_get_data(root, "IpAddress"))
        admin_share = any(s in share.upper() for s in (r"ADMIN$", r"C$", r"IPC$"))
        severity   = "warning" if admin_share else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         src_ip,
            "observer_hostname": computer,
            "message":           f"Network share accessed: {share} by {user} from {src_ip}",
            "raw_data":          f"EID=5140 user={user} share={share} src={src_ip}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 1102:
        user = _get_data(root, "SubjectUserName")
        return {
            "event_action":      event_action,
            "severity":          "critical",
            "username":          user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Security audit log cleared by {user}",
            "raw_data":          f"EID=1102 user={user}"[:500],
            "occurred_at":       occurred_at,
        }

    # ── Sysmon Events ─────────────────────────────────────────────────────────

    if eid == 1:
        image      = _get_data(root, "Image")
        cmdline    = _get_data(root, "CommandLine")
        parent     = _get_data(root, "ParentImage")
        user       = _get_data(root, "User")
        hashes     = _get_data(root, "Hashes")
        proc_name  = (image.split("\\")[-1] if image else "").lower()
        parent_name = (parent.split("\\")[-1] if parent else "").lower()
        is_malware = proc_name in _KNOWN_MALWARE_PROC
        is_suspicious = proc_name in _LOLBAS and parent_name not in (
            "explorer.exe", "powershell.exe", "pwsh.exe", "cmd.exe"
        )
        severity = "critical" if is_malware else ("warning" if is_suspicious else "info")
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Sysmon process: {image or '?'} cmd={cmdline[:80] if cmdline else ''}",
            "raw_data":          f"EID=1 image={image} parent={parent} cmd={cmdline} hashes={hashes}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 3:
        image    = _get_data(root, "Image")
        src_ip   = _clean_ip(_get_data(root, "SourceIp"))
        dst_ip   = _clean_ip(_get_data(root, "DestinationIp"))
        dst_port_str = _get_data(root, "DestinationPort")
        try:
            dst_port = int(dst_port_str)
            if not (0 <= dst_port <= 65535):
                dst_port = None
        except (ValueError, TypeError):
            dst_port = None
        proto    = (_get_data(root, "Protocol") or "tcp").lower()
        user     = _get_data(root, "User")
        proc_name = (image.split("\\")[-1] if image else "").lower()
        severity = "warning" if proc_name in _LOLBAS else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          user,
            "source_ip":         src_ip,
            "destination_ip":    dst_ip,
            "destination_port":  dst_port,
            "network_protocol":  proto,
            "observer_hostname": computer,
            "message":           f"Sysmon network: {image or '?'} → {dst_ip}:{dst_port}",
            "raw_data":          f"EID=3 image={image} dst={dst_ip}:{dst_port}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 10:
        src_image = _get_data(root, "SourceImage")
        tgt_image = _get_data(root, "TargetImage")
        access    = _get_data(root, "GrantedAccess")
        tgt_name  = (tgt_image.split("\\")[-1] if tgt_image else "").lower()
        # Mimikatz/credential dumping targets lsass.exe
        severity  = "critical" if tgt_name == "lsass.exe" else "warning"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Sysmon proc access: {src_image or '?'} → {tgt_image or '?'} [{access}]",
            "raw_data":          f"EID=10 src={src_image} tgt={tgt_image} access={access}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 22:
        proc    = _get_data(root, "Image")
        query   = _get_data(root, "QueryName")
        status  = _get_data(root, "QueryStatus")
        results = _get_data(root, "QueryResults")
        proc_name = (proc.split("\\")[-1] if proc else "").lower()
        severity  = "warning" if proc_name in _LOLBAS else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Sysmon DNS: {query} from {proc or '?'} status={status}",
            "raw_data":          f"EID=22 proc={proc} query={query} status={status} results={results}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 6:
        driver  = _get_data(root, "ImageLoaded")
        hashes  = _get_data(root, "Hashes")
        signed  = _get_data(root, "Signed").lower()
        sig_ok  = signed == "true"
        severity = "info" if sig_ok else "critical"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Driver loaded: {driver} signed={signed}",
            "raw_data":          f"EID=6 driver={driver} hashes={hashes} signed={signed}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 7:
        proc    = _get_data(root, "Image")
        image   = _get_data(root, "ImageLoaded")
        hashes  = _get_data(root, "Hashes")
        signed  = _get_data(root, "Signed").lower()
        # System32 dışından yüklenen imzasız DLL şüpheli
        non_sys = "system32" not in image.lower() and "syswow64" not in image.lower()
        unsigned = signed != "true"
        severity = "warning" if (non_sys and unsigned) else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Image loaded: {image} by {proc or '?'} signed={signed}",
            "raw_data":          f"EID=7 proc={proc} image={image} hashes={hashes} signed={signed}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 11:
        proc     = _get_data(root, "Image")
        target   = _get_data(root, "TargetFilename")
        proc_name = (proc.split("\\")[-1] if proc else "").lower()
        # Geçici/kullanıcı dizinlerine yürütülebilir dosya bırakma
        suspicious_path = any(p in target.lower() for p in (
            r"\temp\\", r"\appdata\local\temp", r"\users\public\\", r"\programdata\\"
        ))
        suspicious_ext = target.lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"))
        severity = "warning" if (suspicious_path and suspicious_ext) else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"File created: {target} by {proc or '?'}",
            "raw_data":          f"EID=11 proc={proc} target={target}"[:500],
            "occurred_at":       occurred_at,
        }

    if eid == 13:
        proc   = _get_data(root, "Image")
        target = _get_data(root, "TargetObject")
        detail = _get_data(root, "Details")
        # Run/RunOnce ve Winlogon → persistence
        persistence_keys = (
            r"currentversion\run", r"currentversion\runonce",
            r"winlogon", r"userinit", r"shell",
        )
        is_persist = any(k in target.lower() for k in persistence_keys)
        severity   = "warning" if is_persist else "info"
        return {
            "event_action":      event_action,
            "severity":          severity,
            "username":          None,
            "source_ip":         None,
            "observer_hostname": computer,
            "message":           f"Registry value set: {target} by {proc or '?'}",
            "raw_data":          f"EID=13 proc={proc} key={target} val={detail}"[:500],
            "occurred_at":       occurred_at,
        }

    return None


def parse_evtx_bytes(data: bytes) -> list[dict]:
    """
    .evtx dosya içeriğini (bytes) parse eder.
    Her tanınan event için dict döner.
    """
    try:
        from Evtx.Evtx import FileHeader
        from Evtx.Views import evtx_file_xml_view
    except ImportError:
        logger.error("python-evtx kurulu değil: pip install python-evtx")
        return []

    results: list[dict] = []
    try:
        fh = FileHeader(data, 0x0)
        for xml_str, _ in evtx_file_xml_view(fh):
            parsed = _parse_record_xml(xml_str)
            if parsed:
                results.append(parsed)
    except Exception as exc:
        logger.warning("EVTX parse hatası: %s", exc)
    return results


def parse_evtx_xml_strings(xml_strings: list[str]) -> list[dict]:
    """XML string listesinden parse eder (test ve mock için)."""
    results = []
    for xml_str in xml_strings:
        parsed = _parse_record_xml(xml_str)
        if parsed:
            results.append(parsed)
    return results
