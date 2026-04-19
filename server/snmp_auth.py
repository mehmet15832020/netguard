"""
NetGuard — SNMP authentication builder

SNMPv2c ve SNMPv3 için birleşik auth nesnesi üretir.
"""

from typing import Union

try:
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        UsmUserData,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmDESPrivProtocol,
        usmAesCfb128Protocol,
        usmNoPrivProtocol,
        usmNoAuthProtocol,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    CommunityData = None
    UsmUserData = None
    usmHMACMD5AuthProtocol = None
    usmHMACSHAAuthProtocol = None
    usmDESPrivProtocol = None
    usmAesCfb128Protocol = None
    usmNoPrivProtocol = None
    usmNoAuthProtocol = None

_AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol if SNMP_AVAILABLE else None,
    "SHA": usmHMACSHAAuthProtocol if SNMP_AVAILABLE else None,
}

_PRIV_PROTOCOLS = {
    "DES":  usmDESPrivProtocol    if SNMP_AVAILABLE else None,
    "AES":  usmAesCfb128Protocol  if SNMP_AVAILABLE else None,
}


def build_snmp_auth(
    snmp_version: str = "v2c",
    community: str = "public",
    v3_username: str = "",
    v3_auth_protocol: str = "SHA",
    v3_auth_key: str = "",
    v3_priv_protocol: str = "AES",
    v3_priv_key: str = "",
) -> Union["CommunityData", "UsmUserData"]:
    """v2c veya v3 için uygun auth nesnesi döner."""
    if snmp_version == "v3":
        auth_proto = _AUTH_PROTOCOLS.get(v3_auth_protocol.upper(), usmHMACSHAAuthProtocol)
        priv_proto = _PRIV_PROTOCOLS.get(v3_priv_protocol.upper(), usmAesCfb128Protocol)

        if v3_auth_key and v3_priv_key:
            return UsmUserData(
                v3_username,
                authKey=v3_auth_key,
                privKey=v3_priv_key,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        if v3_auth_key:
            return UsmUserData(
                v3_username,
                authKey=v3_auth_key,
                authProtocol=auth_proto,
                privProtocol=usmNoPrivProtocol,
            )
        return UsmUserData(v3_username)

    return CommunityData(community, mpModel=1)


def build_snmp_auth_from_device(device: dict) -> Union["CommunityData", "UsmUserData"]:
    """devices tablosu satırından auth nesnesi üretir."""
    return build_snmp_auth(
        snmp_version=device.get("snmp_version", "v2c") or "v2c",
        community=device.get("snmp_community", "public") or "public",
        v3_username=device.get("snmp_v3_username", "") or "",
        v3_auth_protocol=device.get("snmp_v3_auth_protocol", "SHA") or "SHA",
        v3_auth_key=device.get("snmp_v3_auth_key", "") or "",
        v3_priv_protocol=device.get("snmp_v3_priv_protocol", "AES") or "AES",
        v3_priv_key=device.get("snmp_v3_priv_key", "") or "",
    )
