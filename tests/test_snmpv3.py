"""
Faz 7 — SNMPv3 auth builder ve database migration testleri.
"""

import pytest
from server.snmp_auth import build_snmp_auth, build_snmp_auth_from_device, SNMP_AVAILABLE


class TestBuildSnmpAuth:
    def test_v2c_returns_community_data(self):
        auth = build_snmp_auth(snmp_version="v2c", community="public")
        cls_name = type(auth).__name__
        assert cls_name == "CommunityData"

    def test_v2c_default_version(self):
        auth = build_snmp_auth(community="secret")
        cls_name = type(auth).__name__
        assert cls_name == "CommunityData"

    @pytest.mark.skipif(not SNMP_AVAILABLE, reason="pysnmp kurulu değil")
    def test_v3_auth_priv_returns_usm(self):
        auth = build_snmp_auth(
            snmp_version="v3",
            v3_username="netguard",
            v3_auth_key="authpass123",
            v3_priv_key="privpass123",
        )
        assert type(auth).__name__ == "UsmUserData"

    @pytest.mark.skipif(not SNMP_AVAILABLE, reason="pysnmp kurulu değil")
    def test_v3_auth_only_no_priv(self):
        auth = build_snmp_auth(
            snmp_version="v3",
            v3_username="netguard",
            v3_auth_key="authpass123",
        )
        assert type(auth).__name__ == "UsmUserData"

    @pytest.mark.skipif(not SNMP_AVAILABLE, reason="pysnmp kurulu değil")
    def test_v3_no_auth_no_priv(self):
        auth = build_snmp_auth(
            snmp_version="v3",
            v3_username="netguard",
        )
        assert type(auth).__name__ == "UsmUserData"

    def test_v3_md5_protocol(self):
        auth = build_snmp_auth(
            snmp_version="v3",
            v3_username="u",
            v3_auth_key="authpass",
            v3_priv_key="privpass",
            v3_auth_protocol="MD5",
            v3_priv_protocol="DES",
        )
        assert type(auth).__name__ == "UsmUserData"

    def test_unknown_protocol_falls_back_to_sha_aes(self):
        auth = build_snmp_auth(
            snmp_version="v3",
            v3_username="u",
            v3_auth_key="authpass",
            v3_priv_key="privpass",
            v3_auth_protocol="UNKNOWN",
            v3_priv_protocol="UNKNOWN",
        )
        assert type(auth).__name__ == "UsmUserData"


class TestBuildSnmpAuthFromDevice:
    def test_v2c_device(self):
        device = {"snmp_version": "v2c", "snmp_community": "public"}
        auth = build_snmp_auth_from_device(device)
        assert type(auth).__name__ == "CommunityData"

    def test_missing_version_defaults_v2c(self):
        device = {"snmp_community": "public"}
        auth = build_snmp_auth_from_device(device)
        assert type(auth).__name__ == "CommunityData"

    def test_empty_version_defaults_v2c(self):
        device = {"snmp_version": "", "snmp_community": "public"}
        auth = build_snmp_auth_from_device(device)
        assert type(auth).__name__ == "CommunityData"

    def test_v3_device(self):
        device = {
            "snmp_version": "v3",
            "snmp_v3_username": "admin",
            "snmp_v3_auth_key": "authpass123",
            "snmp_v3_priv_key": "privpass123",
            "snmp_v3_auth_protocol": "SHA",
            "snmp_v3_priv_protocol": "AES",
        }
        auth = build_snmp_auth_from_device(device)
        assert type(auth).__name__ == "UsmUserData"


class TestDatabaseV3Migration:
    def test_v3_columns_exist(self, tmp_db):
        with tmp_db._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        expected = {
            "snmp_v3_username",
            "snmp_v3_auth_protocol",
            "snmp_v3_auth_key",
            "snmp_v3_priv_protocol",
            "snmp_v3_priv_key",
        }
        assert expected.issubset(cols)

    def test_save_device_with_v3(self, tmp_db):
        tmp_db.save_device(
            device_id="router-v3",
            name="Router V3",
            device_type="snmp",
            ip="10.0.0.1",
            snmp_version="v3",
            snmp_v3_username="netguard",
            snmp_v3_auth_key="authpass123",
            snmp_v3_priv_key="privpass123",
        )
        device = tmp_db.get_device("router-v3")
        assert device is not None
        assert device["snmp_version"] == "v3"
        assert device["snmp_v3_username"] == "netguard"
        assert device["snmp_v3_auth_key"] == "authpass123"

    def test_v3_fields_default_empty(self, tmp_db):
        tmp_db.save_device(
            device_id="router-v2c",
            name="Router V2c",
            device_type="snmp",
            ip="10.0.0.2",
        )
        device = tmp_db.get_device("router-v2c")
        assert device["snmp_v3_username"] == ""
        assert device["snmp_v3_auth_key"] == ""
        assert device["snmp_v3_priv_key"] == ""
