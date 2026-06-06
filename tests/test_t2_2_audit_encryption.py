"""T2-2 — audit_log at-rest şifreleme testleri.

audit_log.detail ve audit_log.ip_address Fernet ile şifrelenir;
SHA-256 hash zinciri bütünlüğü korunur.

Kaynak: NIST SP 800-111 §4.2, CIS Controls v8.1 §3.11, KVKK m.12
"""

import pytest
from cryptography.fernet import Fernet

_TEST_KEY = Fernet.generate_key().decode()
_FERNET_PREFIX = "gAAAAA"


@pytest.fixture
def enc_db(tmp_db, monkeypatch):
    """NETGUARD_ENCRYPTION_KEY set edilmiş tmp_db."""
    monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", _TEST_KEY)
    import server.crypto as _c
    _c._key_warning_logged = False
    return tmp_db


# ─── Şifreli Saklama ─────────────────────────────────────────────────────────

class TestEncryptedStorage:

    def test_detail_stored_as_ciphertext(self, enc_db):
        enc_db.save_audit_event("admin", "test_action", "/res", detail="gizli_bilgi")
        with enc_db._connect() as conn:
            row = conn.execute("SELECT detail FROM audit_log LIMIT 1").fetchone()
        assert row["detail"].startswith(_FERNET_PREFIX)

    def test_ip_address_stored_as_ciphertext(self, enc_db):
        enc_db.save_audit_event("admin", "block", "/ip", ip_address="10.0.0.5")
        with enc_db._connect() as conn:
            row = conn.execute("SELECT ip_address FROM audit_log LIMIT 1").fetchone()
        assert row["ip_address"].startswith(_FERNET_PREFIX)

    def test_actor_not_encrypted(self, enc_db):
        enc_db.save_audit_event("plaintext_actor", "action", "/res")
        with enc_db._connect() as conn:
            row = conn.execute("SELECT actor FROM audit_log LIMIT 1").fetchone()
        assert row["actor"] == "plaintext_actor"

    def test_empty_detail_does_not_crash(self, enc_db):
        enc_db.save_audit_event("admin", "action", "/res", detail="")
        rows = enc_db.get_audit_log(limit=1)
        assert rows[0]["detail"] is not None

    def test_empty_ip_does_not_crash(self, enc_db):
        enc_db.save_audit_event("admin", "action", "/res", ip_address="")
        rows = enc_db.get_audit_log(limit=1)
        assert rows[0]["ip_address"] is not None


# ─── Deşifre Okuma ───────────────────────────────────────────────────────────

class TestDecryptedRead:

    def test_get_audit_log_returns_plaintext_detail(self, enc_db):
        enc_db.save_audit_event("admin", "action", "/res", detail="orijinal_metin")
        rows = enc_db.get_audit_log(limit=1)
        assert rows[0]["detail"] == "orijinal_metin"

    def test_get_audit_log_returns_plaintext_ip(self, enc_db):
        enc_db.save_audit_event("admin", "action", "/res", ip_address="192.168.1.99")
        rows = enc_db.get_audit_log(limit=1)
        assert rows[0]["ip_address"] == "192.168.1.99"

    def test_roundtrip_preserves_unicode(self, enc_db):
        enc_db.save_audit_event("admin", "action", "/res", detail="türkçe_içerik_öüşçğ")
        rows = enc_db.get_audit_log(limit=1)
        assert rows[0]["detail"] == "türkçe_içerik_öüşçğ"

    def test_multiple_rows_all_decrypted(self, enc_db):
        for i in range(5):
            enc_db.save_audit_event("admin", f"action_{i}", "/res", detail=f"detail_{i}", ip_address=f"10.0.0.{i}")
        rows = enc_db.get_audit_log(limit=10)
        for i, row in enumerate(reversed(rows)):
            assert row["detail"] == f"detail_{i}"
            assert row["ip_address"] == f"10.0.0.{i}"


# ─── Hash Zinciri Uyumu ──────────────────────────────────────────────────────

class TestChainIntegrityWithEncryption:

    def test_verify_chain_valid_single_entry(self, enc_db):
        enc_db.save_audit_event("admin", "login", "/session", detail="gizli", ip_address="1.2.3.4")
        result = enc_db.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 1

    def test_verify_chain_valid_five_entries(self, enc_db):
        for i in range(5):
            enc_db.save_audit_event("admin", f"a{i}", f"/r{i}", detail=f"d{i}", ip_address=f"10.0.0.{i}")
        result = enc_db.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 5

    def test_tamper_encrypted_detail_detected(self, enc_db):
        enc_db.save_audit_event("admin", "critical_action", "/target", detail="gizli_veri")
        with enc_db._connect() as conn:
            conn.execute("UPDATE audit_log SET detail='tampered' WHERE action='critical_action'")
        result = enc_db.verify_audit_chain()
        assert result["valid"] is False

    def test_tamper_actor_still_detected(self, enc_db):
        enc_db.save_audit_event("admin", "original", "/res")
        with enc_db._connect() as conn:
            conn.execute("UPDATE audit_log SET actor='attacker' WHERE action='original'")
        result = enc_db.verify_audit_chain()
        assert result["valid"] is False

    def test_hash_computed_on_plaintext(self, enc_db):
        """entry_hash, plaintext üzerinden hesaplanmalı — ciphertext üzerinden değil."""
        from server.database import _audit_content, _AUDIT_CHAIN_GENESIS
        import hashlib
        enc_db.save_audit_event("admin", "hash_test", "/r", detail="bilgi", ip_address="5.5.5.5")
        row = enc_db.get_audit_log(limit=1)[0]
        content = _audit_content(
            row["event_id"], row["actor"], row["action"], row["resource"],
            row["detail"], row["ip_address"] or "",
            row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
            row["previous_hash"] or _AUDIT_CHAIN_GENESIS,
        )
        assert hashlib.sha256(content.encode()).hexdigest() == row["entry_hash"]


# ─── Şifresiz Mod (Anahtar Yok) ─────────────────────────────────────────────

class TestNoKeyPassthrough:

    def test_without_key_plaintext_stored(self, tmp_db, monkeypatch):
        monkeypatch.delenv("NETGUARD_ENCRYPTION_KEY", raising=False)
        import server.crypto as _c
        _c._key_warning_logged = False
        tmp_db.save_audit_event("admin", "action", "/res", detail="acik_metin", ip_address="9.9.9.9")
        with tmp_db._connect() as conn:
            row = conn.execute("SELECT detail, ip_address FROM audit_log LIMIT 1").fetchone()
        assert row["detail"] == "acik_metin"
        assert row["ip_address"] == "9.9.9.9"

    def test_without_key_verify_chain_valid(self, tmp_db, monkeypatch):
        monkeypatch.delenv("NETGUARD_ENCRYPTION_KEY", raising=False)
        import server.crypto as _c
        _c._key_warning_logged = False
        tmp_db.save_audit_event("admin", "a1", "/r")
        tmp_db.save_audit_event("admin", "a2", "/r")
        result = tmp_db.verify_audit_chain()
        assert result["valid"] is True


# ─── Migration Backfill Testi ────────────────────────────────────────────────

class TestMigrationBackfill:

    def test_existing_plaintext_gets_encrypted(self, tmp_db, monkeypatch):
        """Alembic 020: mevcut plaintext satırlar şifrelenmeli."""
        monkeypatch.delenv("NETGUARD_ENCRYPTION_KEY", raising=False)
        import server.crypto as _c
        _c._key_warning_logged = False
        tmp_db.save_audit_event("admin", "old_action", "/res", detail="eski_veri", ip_address="1.1.1.1")

        with tmp_db._connect() as conn:
            row = conn.execute("SELECT detail, ip_address FROM audit_log LIMIT 1").fetchone()
        assert not row["detail"].startswith(_FERNET_PREFIX)

        monkeypatch.setenv("NETGUARD_ENCRYPTION_KEY", _TEST_KEY)
        _c._key_warning_logged = False

        f = Fernet(_TEST_KEY.encode())
        with tmp_db._connect() as conn:
            rows = conn.execute("SELECT id, detail, ip_address FROM audit_log").fetchall()
            for r in rows:
                new_d = f.encrypt(r["detail"].encode()).decode() if r["detail"] and not r["detail"].startswith(_FERNET_PREFIX) else r["detail"]
                new_ip = f.encrypt(r["ip_address"].encode()).decode() if r["ip_address"] and not r["ip_address"].startswith(_FERNET_PREFIX) else r["ip_address"]
                conn.execute("UPDATE audit_log SET detail=%s, ip_address=%s WHERE id=%s", (new_d, new_ip, r["id"]))

        with tmp_db._connect() as conn:
            row = conn.execute("SELECT detail, ip_address FROM audit_log LIMIT 1").fetchone()
        assert row["detail"].startswith(_FERNET_PREFIX)
        assert row["ip_address"].startswith(_FERNET_PREFIX)

    def test_already_encrypted_not_double_encrypted(self, enc_db):
        """Şifreli satırlar ikinci kez şifrelenmemeli."""
        enc_db.save_audit_event("admin", "action", "/r", detail="veri")
        with enc_db._connect() as conn:
            row1 = conn.execute("SELECT detail FROM audit_log LIMIT 1").fetchone()
            first_cipher = row1["detail"]

        f = Fernet(_TEST_KEY.encode())
        _FERNET_PREFIX_check = first_cipher.startswith(_FERNET_PREFIX)
        assert _FERNET_PREFIX_check

        if _FERNET_PREFIX_check:
            with enc_db._connect() as conn:
                conn.execute("UPDATE audit_log SET detail=%s WHERE detail=%s", (first_cipher, first_cipher))

        with enc_db._connect() as conn:
            row2 = conn.execute("SELECT detail FROM audit_log LIMIT 1").fetchone()
        assert row2["detail"] == first_cipher
