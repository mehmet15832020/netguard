"""
NetGuard — V1-9 Aktif Yanıt

OPNsense REST API ve VyOS SSH üzerinden IP bloklama/blok kaldırma.
Fallback: OPNsense başarısız → VyOS denenir.

Env değişkenleri:
  OPNSENSE_HOST        — OPNsense IP/hostname (örn: 10.0.30.1)
  OPNSENSE_KEY         — API key
  OPNSENSE_SECRET      — API secret
  OPNSENSE_BLOCK_ALIAS — Firewall alias adı (default: NETGUARD_BLOCK)
  VYOS_HOST            — VyOS IP (örn: 192.168.203.200)
  VYOS_USER            — SSH kullanıcı (default: vyos)
  VYOS_KEY_PATH        — SSH key dosya yolu
  VYOS_FW_NAME         — Firewall name (default: BLOCK-LIST)
"""

import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]")


def _notify_block_failed(ip: str, reason: str, error: str) -> None:
    try:
        from server.notifier import notifier
        subject = f"NetGuard: IP blok başarısız — {ip}"
        body = (
            f"NetGuard IP Bloklama Başarısız\n{'='*40}\n\n"
            f"IP         : {ip}\n"
            f"Sebep      : {reason}\n"
            f"Hata       : {error}\n"
            f"Zaman      : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
            f"{'='*40}\n"
            f"OPNsense ve VyOS her ikisi de başarısız oldu. "
            f"Firewall bağlantısını kontrol edin.\n"
        )
        notifier.email.send_custom(subject, body)
        if notifier.webhook.enabled:
            payload = {
                "event_type": "block_failed",
                "ip": ip,
                "reason": reason,
                "error": error,
            }
            if notifier.webhook.webhook_type == "discord":
                notifier.webhook._post_payload(
                    {
                        "embeds": [{
                            "title": f"NetGuard: IP blok başarısız — {ip}",
                            "description": f"OPNsense ve VyOS her ikisi de başarısız oldu.",
                            "color": 15158332,
                            "fields": [
                                {"name": "IP",    "value": ip,     "inline": True},
                                {"name": "Sebep", "value": reason, "inline": True},
                                {"name": "Hata",  "value": error,  "inline": False},
                            ],
                            "footer": {"text": "NetGuard Active Response"},
                        }]
                    },
                    f"block_failed:{ip}",
                )
            else:
                notifier.webhook._post_payload(
                    {"text": f"NetGuard: IP blok başarısız — {ip}\nHata: {error}", **payload},
                    f"block_failed:{ip}",
                )
    except Exception as exc:
        logger.warning("block_failed bildirim gönderilemedi [%s]: %s", ip, exc)


def _parse_progressive_ttl() -> list[float]:
    """BLOCK_PROGRESSIVE_TTL env'ini ayrıştır. Default: 1,4,24,168 saat."""
    raw = os.getenv("BLOCK_PROGRESSIVE_TTL", "1,4,24,168")
    result = []
    for part in raw.split(","):
        try:
            result.append(float(part.strip()))
        except ValueError:
            pass
    return result if result else [1.0, 4.0, 24.0, 168.0]


def _progressive_ttl(offense_count: int) -> float:
    """offense_count'a göre TTL saatini döndür."""
    ttl_list = _parse_progressive_ttl()
    idx = min(offense_count - 1, len(ttl_list) - 1)
    return ttl_list[idx]


@dataclass
class BlockResult:
    success: bool
    provider: str
    error: str = ""


@dataclass
class UnblockResult:
    success: bool
    provider: str
    error: str = ""


# ────────────────────────────── OPNsense ──────────────────────────────────── #

class OPNsenseProvider:

    def __init__(self) -> None:
        self._host    = os.getenv("OPNSENSE_HOST", "")
        self._key     = os.getenv("OPNSENSE_KEY", "")
        self._secret  = os.getenv("OPNSENSE_SECRET", "")
        self._alias   = os.getenv("OPNSENSE_BLOCK_ALIAS", "NETGUARD_BLOCK")
        self._timeout = 10

    def _base(self) -> str:
        return f"https://{self._host}/api"

    def _auth(self) -> tuple[str, str]:
        return (self._key, self._secret)

    def _ready(self) -> bool:
        return bool(self._host and self._key and self._secret)

    def _apply(self, client) -> None:
        try:
            client.post(f"{self._base()}/firewall/alias/reconfigure", auth=self._auth())
        except Exception as exc:
            logger.debug("OPNsense reconfigure başarısız: %s", exc)

    def block(
        self,
        ip: str,
        destination_port: Optional[int] = None,
        network_protocol: Optional[str] = None,
    ) -> BlockResult:
        if not self._ready():
            return BlockResult(False, "opnsense", "OPNsense credentials eksik")
        try:
            import httpx
            with httpx.Client(verify=False, timeout=self._timeout) as client:
                if destination_port is not None or network_protocol is not None:
                    return self._block_with_rule(client, ip, destination_port, network_protocol)
                r = client.post(
                    f"{self._base()}/firewall/alias/addHost/{self._alias}",
                    auth=self._auth(),
                    json={"address": ip},
                )
                if r.status_code not in (200, 201):
                    return BlockResult(False, "opnsense", f"HTTP {r.status_code}: {r.text[:100]}")
                self._apply(client)
                logger.info("OPNsense block başarılı: %s alias=%s", ip, self._alias)
                return BlockResult(True, "opnsense")
        except Exception as exc:
            return BlockResult(False, "opnsense", str(exc))

    def _block_with_rule(
        self,
        client,
        ip: str,
        port: Optional[int],
        protocol: Optional[str],
    ) -> BlockResult:
        rule = {
            "action":      "block",
            "interface":   "lan",
            "ipprotocol":  "inet",
            "protocol":    protocol or "any",
            "src":         ip,
            "dst":         "any",
            "dstport":     str(port) if port else "any",
            "description": f"NetGuard block {ip}:{port or 'any'}/{protocol or 'any'}",
            "enabled":     "1",
        }
        r = client.post(
            f"{self._base()}/firewall/filter/addRule",
            auth=self._auth(),
            json={"rule": rule},
        )
        if r.status_code not in (200, 201):
            return BlockResult(False, "opnsense", f"Rule API HTTP {r.status_code}: {r.text[:100]}")
        r2 = client.post(f"{self._base()}/firewall/filter/apply", auth=self._auth())
        if r2.status_code not in (200, 201):
            logger.warning("OPNsense rule apply başarısız: %s", r2.status_code)
        logger.info("OPNsense rule block: %s port=%s proto=%s", ip, port, protocol)
        return BlockResult(True, "opnsense")

    def unblock(self, ip: str) -> UnblockResult:
        if not self._ready():
            return UnblockResult(False, "opnsense", "OPNsense credentials eksik")
        try:
            import httpx
            with httpx.Client(verify=False, timeout=self._timeout) as client:
                r = client.post(
                    f"{self._base()}/firewall/alias/delHost/{self._alias}",
                    auth=self._auth(),
                    json={"address": ip},
                )
                if r.status_code not in (200, 201):
                    return UnblockResult(False, "opnsense", f"HTTP {r.status_code}: {r.text[:100]}")
                self._apply(client)
                logger.info("OPNsense unblock başarılı: %s", ip)
                return UnblockResult(True, "opnsense")
        except Exception as exc:
            return UnblockResult(False, "opnsense", str(exc))

    def list_blocked(self) -> list[str]:
        if not self._ready():
            return []
        try:
            import httpx
            with httpx.Client(verify=False, timeout=self._timeout) as client:
                r = client.get(
                    f"{self._base()}/firewall/alias/getAliasUUID/{self._alias}",
                    auth=self._auth(),
                )
                if r.status_code != 200:
                    return []
                alias_uuid = r.json().get("uuid", "")
                if not alias_uuid:
                    return []
                r2 = client.get(
                    f"{self._base()}/firewall/alias/getAlias/{alias_uuid}",
                    auth=self._auth(),
                )
                if r2.status_code != 200:
                    return []
                content = r2.json().get("alias", {}).get("content", {})
                return [v.get("ip", "") for v in content.values() if v.get("ip")]
        except Exception as exc:
            logger.warning("OPNsense list_blocked başarısız: %s", exc)
            return []


# ────────────────────────────── VyOS ─────────────────────────────────────── #

class VyOSProvider:

    def __init__(self) -> None:
        self._host     = os.getenv("VYOS_HOST", "")
        self._user     = os.getenv("VYOS_USER", "vyos")
        self._key_path = os.getenv("VYOS_KEY_PATH", "")
        self._timeout  = 15
        self._fw_name  = os.getenv("VYOS_FW_NAME", "BLOCK-LIST")

    def _ready(self) -> bool:
        return bool(self._host and self._key_path)

    # Per-command wait times (seconds). VyOS rolling 2026 is slow in GNS3.
    _CMD_WAIT: dict[str, float] = {
        "configure": 40,
        "commit":    45,
        "save":      30,
        "exit":      30,
    }
    _DEFAULT_WAIT: float = 20

    def _open_shell(self):
        """Open a Paramiko interactive shell and wait for initial prompt."""
        import paramiko
        import time as _t
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self._host,
            username=self._user,
            key_filename=self._key_path,
            timeout=self._timeout,
        )
        shell = client.invoke_shell(width=220, height=50)

        def wait_prompt(secs: float) -> str:
            buf = b""
            deadline = _t.time() + secs
            while _t.time() < deadline:
                if shell.recv_ready():
                    buf += shell.recv(65535)
                    text = buf.decode("utf-8", errors="replace")
                    if "vyos@vyos:~$" in text or "vyos@vyos#" in text:
                        return text
                _t.sleep(0.05)
            return buf.decode("utf-8", errors="replace")

        wait_prompt(15)  # initial shell prompt
        return client, shell, wait_prompt

    def _exec(self, commands: list[str]) -> tuple[bool, str]:
        """Run a list of VyOS commands in one interactive SSH session."""
        try:
            import paramiko  # noqa: F401 (triggers ImportError if missing)
        except ImportError:
            return False, "paramiko yüklü değil — pip install paramiko"
        try:
            client, shell, wait_prompt = self._open_shell()
            all_output: list[str] = []
            for cmd in commands:
                shell.send(cmd + "\n")
                wait = self._CMD_WAIT.get(cmd, self._DEFAULT_WAIT)
                all_output.append(wait_prompt(wait))
            shell.close()
            client.close()
            full = "\n".join(all_output)
            _FAIL = ("Invalid command", "Set failed", "Commit failed", "Delete failed",
                     "Configuration path", "not valid")
            for phrase in _FAIL:
                if phrase.lower() in full.lower():
                    return False, full.strip()
            return True, full.strip()
        except Exception as exc:
            return False, str(exc)

    def block(
        self,
        ip: str,
        destination_port: Optional[int] = None,
        network_protocol: Optional[str] = None,
    ) -> BlockResult:
        if not self._ready():
            return BlockResult(False, "vyos", "VyOS credentials eksik")
        try:
            import paramiko  # noqa: F401
        except ImportError:
            return BlockResult(False, "vyos", "paramiko yüklü değil — pip install paramiko")
        try:
            client, shell, wait_prompt = self._open_shell()

            # Phase 1: enter configure mode and show existing rules
            shell.send("configure\n")
            wait_prompt(self._CMD_WAIT["configure"])
            shell.send(f"show firewall ipv4 name {self._fw_name}\n")
            show_out = wait_prompt(self._DEFAULT_WAIT)

            # Derive next rule number from existing rules
            nums = re.findall(r"rule (\d+)", show_out)
            rule_num = max((int(n) for n in nums), default=99) + 1

            # Phase 2: apply block rules in the already-open configure session
            set_cmds = [
                f"set firewall ipv4 name {self._fw_name} rule {rule_num} action drop",
                f"set firewall ipv4 name {self._fw_name} rule {rule_num} source address {ip}",
            ]
            if network_protocol and network_protocol != "any":
                set_cmds.append(
                    f"set firewall ipv4 name {self._fw_name} rule {rule_num} protocol {network_protocol}"
                )
            if destination_port:
                set_cmds.append(
                    f"set firewall ipv4 name {self._fw_name} rule {rule_num} destination port {destination_port}"
                )
            set_cmds += ["commit", "save", "exit"]

            all_output = [show_out]
            for cmd in set_cmds:
                shell.send(cmd + "\n")
                wait = self._CMD_WAIT.get(cmd, self._DEFAULT_WAIT)
                all_output.append(wait_prompt(wait))

            shell.close()
            client.close()
            full = "\n".join(all_output)
            _FAIL = ("Invalid command", "Set failed", "Commit failed", "Delete failed",
                     "Configuration path", "not valid")
            for phrase in _FAIL:
                if phrase.lower() in full.lower():
                    return BlockResult(False, "vyos", full.strip())
            logger.info("VyOS block: %s port=%s proto=%s rule=%d", ip, destination_port, network_protocol, rule_num)
            return BlockResult(True, "vyos")
        except Exception as exc:
            return BlockResult(False, "vyos", str(exc))

    def unblock(self, ip: str) -> UnblockResult:
        if not self._ready():
            return UnblockResult(False, "vyos", "VyOS credentials eksik")
        try:
            import paramiko  # noqa: F401
        except ImportError:
            return UnblockResult(False, "vyos", "paramiko yüklü değil — pip install paramiko")
        try:
            client, shell, wait_prompt = self._open_shell()

            # Phase 1: enter configure mode and show existing rules
            shell.send("configure\n")
            wait_prompt(self._CMD_WAIT["configure"])
            shell.send(f"show firewall ipv4 name {self._fw_name}\n")
            show_out = wait_prompt(self._DEFAULT_WAIT)

            # Find the rule number for this IP (strip ANSI before parsing)
            clean = _ANSI_RE.sub("", show_out)
            pattern = re.compile(r"rule (\d+).*?address (\S+)", re.DOTALL)
            rule_num = None
            for m in pattern.finditer(clean):
                if m.group(2) == ip:
                    rule_num = int(m.group(1))
                    break

            if rule_num is None:
                shell.send("exit\n")
                wait_prompt(self._CMD_WAIT["exit"])
                shell.close()
                client.close()
                return UnblockResult(False, "vyos", f"VyOS'ta {ip} kuralı bulunamadı")

            # Phase 2: delete the rule in the already-open configure session
            for cmd in [
                f"delete firewall ipv4 name {self._fw_name} rule {rule_num}",
                "commit", "save", "exit",
            ]:
                shell.send(cmd + "\n")
                wait = self._CMD_WAIT.get(cmd, self._DEFAULT_WAIT)
                wait_prompt(wait)

            shell.close()
            client.close()
            logger.info("VyOS unblock başarılı: %s rule=%d", ip, rule_num)
            return UnblockResult(True, "vyos")
        except Exception as exc:
            return UnblockResult(False, "vyos", str(exc))

    def list_blocked(self) -> list[str]:
        """VyOS BLOCK-LIST grubundaki engelli IP'leri döndür."""
        if not self._ready():
            return []
        try:
            ok, output = self._exec([f"show firewall name {self._fw_name}"])
            if not ok:
                return []
            ips = []
            for line in output.splitlines():
                line = line.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                    ips.append(line)
            return ips
        except Exception as exc:
            logger.warning("VyOS list_blocked başarısız: %s", exc)
            return []


# ────────────────────────────── Manager ──────────────────────────────────── #

class ActiveResponseManager:

    def __init__(self) -> None:
        self._opnsense = OPNsenseProvider()
        self._vyos     = VyOSProvider()

    def block_ip(
        self,
        ip: str,
        reason: str,
        blocked_by: str,
        source_incident_id: Optional[str] = None,
        tenant_id: str = "default",
        ttl_hours: Optional[float] = None,
        destination_port: Optional[int] = None,
        network_protocol: Optional[str] = None,
    ) -> dict:
        from server.database import db
        result = self._opnsense.block(ip, destination_port, network_protocol)
        if not result.success:
            logger.warning("OPNsense block başarısız (%s), VyOS deneniyor", result.error)
            result = self._vyos.block(ip, destination_port, network_protocol)

        if result.success:
            block_id = str(uuid.uuid4())
            offense_count = db.get_offense_count(ip, tenant_id) + 1
            effective_ttl = ttl_hours if ttl_hours is not None else _progressive_ttl(offense_count)
            if destination_port or network_protocol:
                enriched_reason = (
                    f"{reason} [port={destination_port or 'any'} proto={network_protocol or 'any'}]"
                )
            else:
                enriched_reason = reason
            db.block_ip(
                block_id, ip, enriched_reason, blocked_by,
                source_incident_id, result.provider, tenant_id,
                ttl_hours=effective_ttl,
                offense_count=offense_count,
            )
            detail = (
                f"provider={result.provider} reason={enriched_reason} "
                f"offense_count={offense_count} ttl_hours={effective_ttl}"
            )
            db.save_audit_event(
                actor=blocked_by,
                action="ip_blocked",
                resource=f"ip:{ip}",
                detail=detail,
            )
        else:
            logger.error("Tüm aktif yanıt provider'ları başarısız: %s", ip)
            db.save_audit_event(
                actor="system",
                action="ip_block_failed",
                resource=f"ip:{ip}",
                detail=f"firewall error: {result.error}",
            )
            try:
                _notify_block_failed(ip, reason, result.error)
            except Exception as exc:
                logger.warning("block_failed bildirim çağrısı başarısız [%s]: %s", ip, exc)

        return {
            "success":  result.success,
            "provider": result.provider,
            "error":    result.error,
        }

    def unblock_ip(
        self,
        ip: str,
        unblocked_by: str,
        tenant_id: str = "default",
    ) -> dict:
        from server.database import db
        record = db.get_block_by_ip(ip, tenant_id)
        if not record:
            return {"success": False, "provider": "none", "error": "IP bloklu değil"}

        provider = record.get("provider", "opnsense")
        if provider == "opnsense":
            result = self._opnsense.unblock(ip)
        elif provider == "vyos":
            result = self._vyos.unblock(ip)
        else:
            return {"success": False, "provider": provider, "error": f"Bilinmeyen provider: {provider}"}

        phantom = not result.success and "bulunamadı" in (result.error or "")
        if result.success or phantom:
            db.unblock_ip(ip, unblocked_by, tenant_id)
            db.save_audit_event(
                actor=unblocked_by,
                action="ip_unblocked" if result.success else "ip_unblocked_phantom",
                resource=f"ip:{ip}",
                detail=f"provider={provider}" + ("" if result.success else " (firewall rule missing — phantom cleared)"),
            )
        else:
            logger.error("Unblock başarısız: %s — %s", ip, result.error)
            db.save_audit_event(
                actor="system",
                action="ip_unblock_failed",
                resource=f"ip:{ip}",
                detail=f"firewall error: {result.error}",
            )
        return {
            "success":  result.success or phantom,
            "provider": result.provider,
            "error":    result.error,
        }

    def get_active_blocks(self, tenant_id: Optional[str] = None) -> list[dict]:
        from server.database import db
        return db.get_blocked_ips(active_only=True, tenant_id=tenant_id)

    def verify_blocks(self, tenant_id: Optional[str] = None) -> dict:
        from server.database import db
        db_blocks       = {r["ip"] for r in db.get_blocked_ips(active_only=True, tenant_id=tenant_id)}
        opnsense_up     = self._opnsense._ready()
        opnsense_blocks = set(self._opnsense.list_blocked()) if opnsense_up else set()
        vyos_up         = self._vyos._ready()
        vyos_blocks     = set(self._vyos.list_blocked()) if vyos_up else set()
        fw_blocks       = opnsense_blocks | vyos_blocks

        phantom = sorted(db_blocks - fw_blocks)
        orphan  = sorted(fw_blocks - db_blocks)
        synced  = sorted(db_blocks & fw_blocks)

        status = "ok" if not phantom and not orphan else "mismatch"
        return {
            "status":          status,
            "synced":          synced,
            "phantom":         phantom,
            "orphan":          orphan,
            "fw_reachable":    opnsense_up or vyos_up,
            "opnsense_up":     opnsense_up,
            "vyos_up":         vyos_up,
        }

    def expire_blocks(self) -> int:
        """Süresi dolmuş IP bloklarını otomatik kaldır. Unblock edilen sayıyı döndür."""
        from server.database import db
        expired = db.get_expired_blocks()
        count = 0
        for record in expired:
            result = self.unblock_ip(
                record["ip"], "system:auto-expire", record.get("tenant_id", "default")
            )
            if result["success"]:
                count += 1
            else:
                logger.warning(
                    "Auto-expire unblock başarısız: %s — %s",
                    record["ip"], result.get("error"),
                )
        return count


active_response_manager = ActiveResponseManager()
