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

    def block(self, ip: str) -> BlockResult:
        if not self._ready():
            return BlockResult(False, "opnsense", "OPNsense credentials eksik")
        try:
            import httpx
            with httpx.Client(verify=False, timeout=self._timeout) as client:
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

    def _exec(self, commands: list[str]) -> tuple[bool, str]:
        try:
            import paramiko
        except ImportError:
            return False, "paramiko yüklü değil — pip install paramiko"

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self._host,
                username=self._user,
                key_filename=self._key_path,
                timeout=self._timeout,
            )
            cmd = "\n".join(commands)
            _, stdout, stderr = client.exec_command(cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()
            client.close()
            if "Error" in err or "error" in err.lower():
                return False, err.strip()
            return True, out.strip()
        except Exception as exc:
            return False, str(exc)

    def _next_rule_num(self) -> int:
        ok, out = self._exec([f"show firewall name {self._fw_name}"])
        if not ok:
            return 100
        nums = re.findall(r"rule (\d+)", out)
        return max((int(n) for n in nums), default=99) + 1

    def block(self, ip: str) -> BlockResult:
        if not self._ready():
            return BlockResult(False, "vyos", "VyOS credentials eksik")
        rule_num = self._next_rule_num()
        ok, msg = self._exec([
            "configure",
            f"set firewall name {self._fw_name} rule {rule_num} action drop",
            f"set firewall name {self._fw_name} rule {rule_num} source address {ip}",
            "commit",
            "save",
            "exit",
        ])
        if not ok:
            return BlockResult(False, "vyos", msg)
        logger.info("VyOS block başarılı: %s rule=%d", ip, rule_num)
        return BlockResult(True, "vyos")

    def unblock(self, ip: str) -> UnblockResult:
        if not self._ready():
            return UnblockResult(False, "vyos", "VyOS credentials eksik")
        ok, out = self._exec([f"show firewall name {self._fw_name}"])
        if not ok:
            return UnblockResult(False, "vyos", out)
        pattern = re.compile(r"rule (\d+).*?address (\S+)", re.DOTALL)
        rule_num = None
        for m in pattern.finditer(out):
            if m.group(2) == ip:
                rule_num = int(m.group(1))
                break
        if rule_num is None:
            return UnblockResult(False, "vyos", f"VyOS'ta {ip} kuralı bulunamadı")
        ok, msg = self._exec([
            "configure",
            f"delete firewall name {self._fw_name} rule {rule_num}",
            "commit",
            "save",
            "exit",
        ])
        if not ok:
            return UnblockResult(False, "vyos", msg)
        logger.info("VyOS unblock başarılı: %s rule=%d", ip, rule_num)
        return UnblockResult(True, "vyos")


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
    ) -> dict:
        from server.database import db
        result = self._opnsense.block(ip)
        if not result.success:
            logger.warning("OPNsense block başarısız (%s), VyOS deneniyor", result.error)
            result = self._vyos.block(ip)

        if result.success:
            block_id = str(uuid.uuid4())
            offense_count = db.get_offense_count(ip, tenant_id) + 1
            effective_ttl = ttl_hours if ttl_hours is not None else _progressive_ttl(offense_count)
            db.block_ip(
                block_id, ip, reason, blocked_by,
                source_incident_id, result.provider, tenant_id,
                ttl_hours=effective_ttl,
                offense_count=offense_count,
            )
            detail = (
                f"provider={result.provider} reason={reason} "
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

        if result.success:
            db.unblock_ip(ip, unblocked_by, tenant_id)
            db.save_audit_event(
                actor=unblocked_by,
                action="ip_unblocked",
                resource=f"ip:{ip}",
                detail=f"provider={provider}",
            )
        return {
            "success":  result.success,
            "provider": result.provider,
            "error":    result.error,
        }

    def get_active_blocks(self, tenant_id: Optional[str] = None) -> list[dict]:
        from server.database import db
        return db.get_blocked_ips(active_only=True, tenant_id=tenant_id)

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
