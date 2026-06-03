"""Zeek N5 parser testleri: rdp.log, kerberos.log, smb_files.log, dce_rpc.log"""
import pytest
from server.parsers.zeek import parse_rdp, parse_kerberos, parse_smb_files, parse_dce_rpc

_TS = 1700000000.0


def _rdp(**kw):
    base = {
        "ts": _TS, "id.orig_h": "10.0.0.5", "id.orig_p": 54321,
        "id.resp_h": "192.168.1.10", "id.resp_p": 3389,
        "result": "encrypted", "cert_count": 1, "client_build": 19045,
        "client_name": "CORP-PC", "security_protocol": "HYBRID",
    }
    base.update(kw)
    return base


def _krb(**kw):
    base = {
        "ts": _TS, "id.orig_h": "10.0.0.5", "id.orig_p": 49152,
        "id.resp_h": "192.168.1.1", "id.resp_p": 88,
        "request_type": "TGS", "client": "jdoe/CORP",
        "service": "http/webserver.corp", "success": True,
        "cipher": "aes256-cts-hmac-sha1-96", "error_msg": "",
        "forwardable": False, "renewable": False,
        "from": _TS, "till": _TS + 36000,
    }
    base.update(kw)
    return base


def _smb(**kw):
    base = {
        "ts": _TS, "id.orig_h": "10.0.0.5", "id.orig_p": 54321,
        "id.resp_h": "192.168.1.10", "id.resp_p": 445,
        "action": "SMB::FILE_OPEN", "path": r"\\server\share",
        "name": "document.docx", "size": 1024,
    }
    base.update(kw)
    return base


def _dce(**kw):
    base = {
        "ts": _TS, "id.orig_h": "10.0.0.5", "id.orig_p": 49152,
        "id.resp_h": "192.168.1.1", "id.resp_p": 135,
        "endpoint": "lsarpc", "operation": "LsarQueryInformationPolicy",
        "named_pipe": r"\lsarpc", "rtt": 5.2,
    }
    base.update(kw)
    return base


# ─────────────────────────────────────────────────── parse_rdp ────

class TestParseRdp:

    def test_success_parsed(self):
        r = parse_rdp(_rdp())
        assert r is not None
        assert r.event_action == "zeek_rdp_success"
        assert r.severity == "info"

    def test_no_cert_critical(self):
        r = parse_rdp(_rdp(result="ssl", cert_count=0))
        assert r is not None
        assert r.event_action == "zeek_rdp_no_cert"
        assert r.severity == "critical"

    def test_failure_warning(self):
        r = parse_rdp(_rdp(result="", cert_count=1))
        assert r is not None
        assert r.event_action == "zeek_rdp_failure"
        assert r.severity == "warning"

    def test_suspicious_client_critical(self):
        r = parse_rdp(_rdp(client_name="hydra-rdp-scanner"))
        assert r is not None
        assert r.event_action == "zeek_rdp_suspicious_client"
        assert r.severity == "critical"

    def test_no_cert_in_message(self):
        r = parse_rdp(_rdp(result="ssl", cert_count=0))
        assert "[NO_CERT]" in r.message

    def test_source_dest_populated(self):
        r = parse_rdp(_rdp())
        assert r.source_ip == "10.0.0.5"
        assert r.destination_ip == "192.168.1.10"
        assert r.destination_port == 3389

    def test_tags_include_zeek_rdp(self):
        r = parse_rdp(_rdp())
        assert "zeek" in r.tags
        assert "rdp" in r.tags

    def test_empty_result_no_cert_not_failure(self):
        r = parse_rdp(_rdp(result="", cert_count=0, security_protocol=""))
        assert r is not None

    def test_extra_contains_cert_count(self):
        r = parse_rdp(_rdp(cert_count=2))
        assert r.extra["cert_count"] == 2

    def test_network_protocol_tcp(self):
        r = parse_rdp(_rdp())
        assert r.network_protocol == "tcp"


# ─────────────────────────────────────────────────── parse_kerberos ────

class TestParseKerberos:

    def test_empty_request_type_returns_none(self):
        assert parse_kerberos(_krb(request_type="")) is None

    def test_dash_request_type_returns_none(self):
        assert parse_kerberos(_krb(request_type="-")) is None

    def test_normal_tgs_info(self):
        r = parse_kerberos(_krb())
        assert r is not None
        assert r.severity == "info"

    def test_kerberoasting_tgs_rc4_high(self):
        r = parse_kerberos(_krb(request_type="TGS", cipher="rc4-hmac", success=True))
        assert r is not None
        assert r.event_action == "zeek_kerberos_tgs_rc4"
        assert r.severity == "high"

    def test_as_rep_roasting_high(self):
        r = parse_kerberos(_krb(
            request_type="AS", success=False,
            error_msg="KDC_ERR_PREAUTH_REQUIRED",
        ))
        assert r is not None
        assert r.event_action == "zeek_kerberos_as_nopreauth"
        assert r.severity == "high"

    def test_golden_ticket_critical(self):
        r = parse_kerberos(_krb(
            forwardable=True, renewable=True,
            till=_TS + 86400 * 10,  # 10 gün
        ))
        assert r is not None
        assert r.event_action == "zeek_kerberos_golden_ticket"
        assert r.severity == "critical"

    def test_rc4_downgrade_warning(self):
        r = parse_kerberos(_krb(request_type="TGS", cipher="rc4-hmac", success=False))
        assert r is not None
        assert r.event_action == "zeek_kerberos_rc4_downgrade"
        assert r.severity == "warning"

    def test_generic_failure_warning(self):
        r = parse_kerberos(_krb(success=False, error_msg="KDC_ERR_C_PRINCIPAL_UNKNOWN"))
        assert r is not None
        assert r.event_action == "zeek_kerberos_failure"
        assert r.severity == "warning"

    def test_kerberoasting_in_tags(self):
        r = parse_kerberos(_krb(request_type="TGS", cipher="rc4-hmac", success=True))
        assert "kerberoasting" in r.tags

    def test_cipher_in_message(self):
        r = parse_kerberos(_krb(cipher="rc4-hmac"))
        assert "rc4-hmac" in r.message

    def test_client_in_message(self):
        r = parse_kerberos(_krb(client="attacker/CORP"))
        assert "attacker" in r.message

    def test_event_category_authentication(self):
        from shared.models import LogCategory
        r = parse_kerberos(_krb())
        assert r.event_category == LogCategory.AUTHENTICATION

    def test_boolean_string_success(self):
        r = parse_kerberos(_krb(success="T"))
        assert r is not None

    def test_boolean_string_failure(self):
        r = parse_kerberos(_krb(success="F", error_msg="KDC_ERR_PREAUTH_REQUIRED",
                                request_type="AS"))
        assert r is not None
        assert r.event_action == "zeek_kerberos_as_nopreauth"


# ─────────────────────────────────────────────────── parse_smb_files ────

class TestParseSmbFiles:

    def test_empty_action_returns_none(self):
        assert parse_smb_files(_smb(action="")) is None

    def test_dash_action_returns_none(self):
        assert parse_smb_files(_smb(action="-")) is None

    def test_no_path_no_name_returns_none(self):
        assert parse_smb_files(_smb(path="", name="", action="SMB::FILE_OPEN")) is None

    def test_admin_share_write_critical(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_WRITE",
            path=r"\\server\ADMIN$\system32",
            name="tool.exe",
        ))
        assert r is not None
        assert r.event_action == "zeek_smb_admin_share"
        assert r.severity == "critical"

    def test_suspicious_file_critical(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_WRITE",
            path=r"\\server\share",
            name="psexec.exe",
        ))
        assert r is not None
        assert r.event_action == "zeek_smb_suspicious_file"
        assert r.severity == "critical"

    def test_file_delete_high(self):
        r = parse_smb_files(_smb(action="SMB::FILE_DELETE"))
        assert r is not None
        assert r.event_action == "zeek_smb_delete"
        assert r.severity == "high"

    def test_sysvol_recon_warning(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_OPEN",
            path=r"\\dc\SYSVOL\corp\Policies",
            name="GPT.INI",
        ))
        assert r is not None
        assert r.event_action == "zeek_smb_recon"
        assert r.severity == "warning"

    def test_normal_open_info(self):
        r = parse_smb_files(_smb(action="SMB::FILE_OPEN"))
        assert r is not None
        assert r.event_action == "zeek_smb_open"
        assert r.severity == "info"

    def test_generic_write_warning(self):
        r = parse_smb_files(_smb(action="SMB::FILE_WRITE"))
        assert r is not None
        assert r.event_action == "zeek_smb_write"
        assert r.severity == "warning"

    def test_admin_share_in_message(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_WRITE",
            path=r"\\server\ADMIN$",
            name="x.exe",
        ))
        assert "[ADMIN_SHARE]" in r.message

    def test_source_dest_populated(self):
        r = parse_smb_files(_smb())
        assert r.source_ip == "10.0.0.5"
        assert r.destination_ip == "192.168.1.10"

    def test_c_dollar_share_critical(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_WRITE",
            path=r"\\server\C$\Windows\Temp",
        ))
        assert r is not None
        assert r.event_action == "zeek_smb_admin_share"

    def test_netlogon_recon(self):
        r = parse_smb_files(_smb(
            action="SMB::FILE_OPEN",
            path=r"\\dc\NETLOGON\scripts",
        ))
        assert r is not None
        assert r.event_action == "zeek_smb_recon"


# ─────────────────────────────────────────────────── parse_dce_rpc ────

class TestParseDceRpc:

    def test_empty_endpoint_returns_none(self):
        assert parse_dce_rpc(_dce(endpoint="")) is None

    def test_empty_operation_returns_none(self):
        assert parse_dce_rpc(_dce(operation="")) is None

    def test_dash_endpoint_returns_none(self):
        assert parse_dce_rpc(_dce(endpoint="-")) is None

    def test_dcsync_critical(self):
        r = parse_dce_rpc(_dce(endpoint="drsuapi", operation="DsGetNCChanges"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_dcsync"
        assert r.severity == "critical"

    def test_psexec_createservice_critical(self):
        r = parse_dce_rpc(_dce(endpoint="svcctl", operation="CreateServiceW"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_psexec"
        assert r.severity == "critical"

    def test_wmi_execmethod_high(self):
        r = parse_dce_rpc(_dce(endpoint="IWbemServices", operation="ExecMethod"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_wmi"
        assert r.severity == "high"

    def test_task_scheduler_high(self):
        r = parse_dce_rpc(_dce(endpoint="atsvc", operation="SchRpcRegisterTask"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_task"
        assert r.severity == "high"

    def test_registry_setvalue_high(self):
        r = parse_dce_rpc(_dce(endpoint="winreg", operation="SetValue"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_registry"
        assert r.severity == "high"

    def test_samr_enum_warning(self):
        r = parse_dce_rpc(_dce(endpoint="samr", operation="SamrEnumerateUserInDomain"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_samr_enum"
        assert r.severity == "warning"

    def test_lsarpc_policy_info(self):
        r = parse_dce_rpc(_dce())  # default is lsarpc
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_policy"
        assert r.severity == "info"

    def test_unknown_operation_info(self):
        r = parse_dce_rpc(_dce(endpoint="unknown", operation="SomeMethod"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_operation"
        assert r.severity == "info"

    def test_message_contains_endpoint_operation(self):
        r = parse_dce_rpc(_dce(endpoint="drsuapi", operation="DsGetNCChanges"))
        assert "drsuapi" in r.message
        assert "DsGetNCChanges" in r.message

    def test_named_pipe_in_message(self):
        r = parse_dce_rpc(_dce(named_pipe=r"\svcctl"))
        assert r"\svcctl" in r.message or "svcctl" in r.message

    def test_case_insensitive_matching(self):
        r = parse_dce_rpc(_dce(endpoint="DRSUAPI", operation="DSGETNCCHANGES"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_dcsync"

    def test_intrusion_category(self):
        from shared.models import LogCategory
        r = parse_dce_rpc(_dce(endpoint="drsuapi", operation="DsGetNCChanges"))
        assert r.event_category == LogCategory.INTRUSION

    def test_startservicew_psexec(self):
        r = parse_dce_rpc(_dce(endpoint="svcctl", operation="StartServiceW"))
        assert r is not None
        assert r.event_action == "zeek_dce_rpc_psexec"


# ─────────────────────────────────── zeek_collector + stage_map ────

class TestCollectorAndStageMap:

    def test_rdp_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "rdp" in _PARSERS

    def test_kerberos_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "kerberos" in _PARSERS

    def test_smb_files_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "smb_files" in _PARSERS

    def test_dce_rpc_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "dce_rpc" in _PARSERS

    def test_stage_map_rdp(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_rdp_no_cert") == "lateral"
        assert STAGE_MAP.get("zeek_rdp_failure") == "weaponize"
        assert STAGE_MAP.get("zeek_rdp_success") == "access"

    def test_stage_map_kerberos(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_kerberos_tgs_rc4") == "weaponize"
        assert STAGE_MAP.get("zeek_kerberos_as_nopreauth") == "weaponize"
        assert STAGE_MAP.get("zeek_kerberos_golden_ticket") == "execute"

    def test_stage_map_smb(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_smb_admin_share") == "lateral"
        assert STAGE_MAP.get("zeek_smb_delete") == "execute"
        assert STAGE_MAP.get("zeek_smb_recon") == "recon"

    def test_stage_map_dce_rpc(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_dce_rpc_dcsync") == "execute"
        assert STAGE_MAP.get("zeek_dce_rpc_psexec") == "execute"
        assert STAGE_MAP.get("zeek_dce_rpc_wmi") == "execute"
        assert STAGE_MAP.get("zeek_dce_rpc_samr_enum") == "recon"
