"""
NetGuard — T2-2 At-rest şifreleme testleri

Birim      : encrypt/decrypt/generate_key
Çapraz     : anahtar yokken fallback davranışı
Entegrasyon: TOTP secret DB'ye şifreli yazılır, okunurken çözülür;
             tam MFA akışı şifreli DB ile çalışır

Kaynak: OWASP Cryptographic Storage CS, NIST SP 800-111, CIS Controls v8.1 §3.11
"""

import os
import pytest
import pyotp
import bcrypt
from unittest.mock import patch
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from server.main import app
from server.auth import create_access_token
from server import crypto

client = TestClient(app)

_VALID_KEY = Fernet.generate_key().decode()


def _auth(username: str = "admin", role: str = "admin") -> dict:
    token = create_access_token(username=username, role=role, tenant_id="default")
    return {"Authorization": f"Bearer {token}"}


def _make_user(tmp_db, username: str = "enc_user") -> None:
    pw_hash = bcrypt.hashpw(b"pass123", bcrypt.gensalt()).decode()
    tmp_db.create_db_user(username, pw_hash, "viewer", "default")


# ─── Birim: encrypt / decrypt ─────────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_encrypt_returns_different_string(self):
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            result = crypto.encrypt("JBSWY3DPEHPK3PXP")
        assert result != "JBSWY3DPEHPK3PXP"

    def test_decrypt_recovers_plaintext(self):
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            ciphertext = crypto.encrypt("JBSWY3DPEHPK3PXP")
            assert crypto.decrypt(ciphertext) == "JBSWY3DPEHPK3PXP"

    def test_encrypt_without_key_returns_plaintext(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop(crypto._KEY_ENV, None)
            result = crypto.encrypt("secret")
        assert result == "secret"

    def test_decrypt_without_key_returns_input(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop(crypto._KEY_ENV, None)
            result = crypto.decrypt("plaintext")
        assert result == "plaintext"

    def test_decrypt_none_returns_none(self):
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            assert crypto.decrypt(None) is None

    def test_decrypt_plaintext_fallback(self):
        """Anahtar varken plaintext değer decrypt edilmeye çalışılırsa olduğu gibi döner."""
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            result = crypto.decrypt("JBSWY3DPEHPK3PXP")
        assert result == "JBSWY3DPEHPK3PXP"

    def test_different_encryptions_of_same_plaintext(self):
        """Fernet her seferinde farklı ciphertext üretir (IV randomness)."""
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            c1 = crypto.encrypt("same_secret")
            c2 = crypto.encrypt("same_secret")
        assert c1 != c2

    def test_generate_key_format(self):
        key = crypto.generate_key()
        assert isinstance(key, str)
        Fernet(key.encode())


# ─── Çapraz: DB encrypt/decrypt entegrasyonu ─────────────────────────────────

class TestDatabaseEncryption:
    def test_totp_secret_stored_encrypted(self, tmp_db):
        """set_user_totp_secret → DB'de plaintext değil ciphertext olmalı."""
        _make_user(tmp_db, "enc_test")
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            tmp_db.set_user_totp_secret("enc_test", "JBSWY3DPEHPK3PXP")

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT totp_secret FROM db_users WHERE username=%s", ("enc_test",)
            ).fetchone()
        raw = row["totp_secret"]
        assert raw != "JBSWY3DPEHPK3PXP", "DB'de plaintext secret saklanmamalı"
        assert raw.startswith("gAAAAA"), "Fernet token gAAAAA ile başlar"

    def test_get_user_totp_decrypts(self, tmp_db):
        """get_user_totp şifreli değeri çözüp döndürmeli."""
        _make_user(tmp_db, "dec_test")
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            tmp_db.set_user_totp_secret("dec_test", "JBSWY3DPEHPK3PXP")
            result = tmp_db.get_user_totp("dec_test")
        assert result["totp_secret"] == "JBSWY3DPEHPK3PXP"

    def test_get_user_totp_no_key_fallback(self, tmp_db):
        """Anahtar yokken plaintext secret okunabilmeli (geçiş dönemi)."""
        _make_user(tmp_db, "nokey_test")
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop(crypto._KEY_ENV, None)
            tmp_db.set_user_totp_secret("nokey_test", "PLAINTEXT_SECRET")
            result = tmp_db.get_user_totp("nokey_test")
        assert result["totp_secret"] == "PLAINTEXT_SECRET"

    def test_missing_user_returns_none(self, tmp_db):
        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            result = tmp_db.get_user_totp("nonexistent_user")
        assert result["totp_secret"] is None
        assert result["totp_enabled"] is False


# ─── Entegrasyon: tam MFA akışı şifreli DB ile ───────────────────────────────

class TestEncryptedTotpFlow:
    def test_setup_confirm_verify_with_encryption(self, tmp_db):
        """TOTP kurulum → doğrulama → login tam akışı şifreli DB ile çalışmalı."""
        _make_user(tmp_db, "flow_user")
        headers = _auth("flow_user", "viewer")

        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            r = client.post("/api/v1/auth/totp-setup", headers=headers)
            assert r.status_code == 200, r.text
            secret = r.json()["secret"]
            assert len(secret) >= 16, "Secret pyotp base32 formatında olmalı"

            code = pyotp.TOTP(secret).now()
            r2 = client.post(
                "/api/v1/auth/totp-confirm",
                json={"code": code},
                headers=headers,
            )
            assert r2.status_code == 200, r2.text

            result = tmp_db.get_user_totp("flow_user")
        assert result["totp_secret"] == secret
        assert result["totp_enabled"] is True

    def test_totp_verify_decrypts_for_validation(self, tmp_db):
        """Şifreli DB'den okunan secret ile TOTP kodu doğrulanabilmeli."""
        _make_user(tmp_db, "verify_user")
        secret = pyotp.random_base32()

        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            tmp_db.set_user_totp_secret("verify_user", secret)
            tmp_db.enable_user_totp("verify_user")
            result = tmp_db.get_user_totp("verify_user")

        totp = pyotp.TOTP(result["totp_secret"])
        assert totp.verify(totp.now(), valid_window=1)

    def test_plaintext_secret_readable_after_migration(self, tmp_db):
        """Şifrelenmiş DB'de eski plaintext kayıt da okunabilmeli (geçiş uyumluluğu)."""
        _make_user(tmp_db, "migrate_user")
        secret = "OLDSECRETBASE32=="

        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO db_users (username, password_hash, role, tenant_id)"
                " VALUES (%s, '__TOTP_ONLY__', %s, %s)",
                ("migrate_user", "viewer", "default"),
            )
            conn.execute(
                "UPDATE db_users SET totp_secret=%s WHERE username=%s",
                (secret, "migrate_user"),
            )

        with patch.dict(os.environ, {crypto._KEY_ENV: _VALID_KEY}):
            result = tmp_db.get_user_totp("migrate_user")

        assert result["totp_secret"] == secret
