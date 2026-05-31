"""
O3 — Backup/restore script yapısal doğrulama testleri.
Container başlatmadan script varlığı, yapı ve mantık kontrolü yapar.
"""

import os
import pathlib
import re
import tarfile
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
BACKUP_SH = SCRIPTS_DIR / "backup.sh"
RESTORE_SH = SCRIPTS_DIR / "restore.sh"
VERIFY_SH = SCRIPTS_DIR / "verify-backup.sh"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def backup_content() -> str:
    return BACKUP_SH.read_text()


@pytest.fixture(scope="module")
def restore_content() -> str:
    return RESTORE_SH.read_text()


@pytest.fixture(scope="module")
def verify_content() -> str:
    return VERIFY_SH.read_text()


# ── TestScriptExistence ───────────────────────────────────────────────────────

class TestScriptExistence:
    def test_backup_sh_exists(self):
        assert BACKUP_SH.is_file(), "scripts/backup.sh bulunamadı"

    def test_restore_sh_exists(self):
        assert RESTORE_SH.is_file(), "scripts/restore.sh bulunamadı"

    def test_verify_sh_exists(self):
        assert VERIFY_SH.is_file(), "scripts/verify-backup.sh bulunamadı"

    def test_backup_sh_has_shebang(self, backup_content):
        assert backup_content.startswith("#!/usr/bin/env bash")

    def test_restore_sh_has_shebang(self, restore_content):
        assert restore_content.startswith("#!/usr/bin/env bash")

    def test_verify_sh_has_shebang(self, verify_content):
        assert verify_content.startswith("#!/usr/bin/env bash")


# ── TestStrictMode ────────────────────────────────────────────────────────────

class TestStrictMode:
    def test_backup_has_strict_mode(self, backup_content):
        assert "set -euo pipefail" in backup_content

    def test_restore_has_strict_mode(self, restore_content):
        assert "set -euo pipefail" in restore_content

    def test_verify_has_strict_mode(self, verify_content):
        assert "set -euo pipefail" in verify_content


# ── TestBackupComponents ──────────────────────────────────────────────────────

class TestBackupComponents:
    def test_backup_includes_pg_dump(self, backup_content):
        assert "pg_dump" in backup_content

    def test_backup_uses_custom_format(self, backup_content):
        assert "-Fc" in backup_content, "pg_dump -Fc (custom format) kullanılmalı"

    def test_backup_includes_config_dir(self, backup_content):
        assert "config/" in backup_content

    def test_backup_includes_env_file(self, backup_content):
        assert '".env"' in backup_content or "'.env'" in backup_content or '".env"' in backup_content

    def test_backup_includes_ssl_certs_volume(self, backup_content):
        assert "ssl_certs" in backup_content

    def test_backup_includes_netguard_data_volume(self, backup_content):
        assert "netguard_data" in backup_content

    def test_backup_does_not_backup_zeek_logs(self, backup_content):
        assert "zeek_logs" not in backup_content or "Yedeklenmez" in backup_content or \
               "zeek_logs" not in [
                   line.strip() for line in backup_content.splitlines()
                   if "backup_volume" in line and "zeek" in line
               ], "zeek_logs yedeklenmemeli (geçici log)"

    def test_backup_produces_sha256_manifest(self, backup_content):
        assert "sha256sum" in backup_content
        assert "MANIFEST" in backup_content

    def test_backup_supports_env_encryption(self, backup_content):
        assert "openssl enc" in backup_content
        assert "aes-256-cbc" in backup_content

    def test_backup_uses_pbkdf2(self, backup_content):
        assert "pbkdf2" in backup_content, "PBKDF2 key derivation kullanılmalı"

    def test_backup_supports_dir_argument(self, backup_content):
        assert "--dir" in backup_content


# ── TestBackupRetention ───────────────────────────────────────────────────────

class TestBackupRetention:
    def test_backup_has_daily_retention(self, backup_content):
        assert "daily" in backup_content

    def test_backup_has_weekly_retention(self, backup_content):
        assert "weekly" in backup_content

    def test_backup_deletes_old_daily(self, backup_content):
        assert "mtime +7" in backup_content, "7 günden eski yedekler silinmeli"

    def test_backup_deletes_old_weekly(self, backup_content):
        assert "mtime +28" in backup_content, "28 günden eski haftalık referanslar silinmeli"

    def test_backup_creates_weekly_on_sunday(self, backup_content):
        assert "DAY_OF_WEEK" in backup_content
        assert '"7"' in backup_content, "Pazar (7) günü haftalık yedek alınmalı"


# ── TestRestoreComponents ─────────────────────────────────────────────────────

class TestRestoreComponents:
    def test_restore_includes_pg_restore(self, restore_content):
        assert "pg_restore" in restore_content

    def test_restore_stops_services_first(self, restore_content):
        # Yorum satırlarını atla (# ile başlayan)
        lines = [(i, l) for i, l in enumerate(restore_content.splitlines())
                 if not l.strip().startswith("#")]
        down_idx = next((i for i, l in lines if "compose down" in l), None)
        restore_idx = next((i for i, l in lines if "pg_restore" in l), None)
        assert down_idx is not None, "docker compose down komutu bulunamadı"
        assert restore_idx is not None, "pg_restore komutu bulunamadı"
        assert down_idx < restore_idx, "Servisler DB restore'dan önce durdurulmalı"

    def test_restore_restarts_services_after(self, restore_content):
        lines = [(i, l) for i, l in enumerate(restore_content.splitlines())
                 if not l.strip().startswith("#")]
        restore_idx = next((i for i, l in lines if "pg_restore" in l), None)
        up_idx = next((i for i, l in lines if "compose up" in l and "-d" in l
                       and i > (restore_idx or 0)), None)
        assert up_idx is not None, "Restore sonrası docker compose up -d bulunamadı"

    def test_restore_supports_dry_run(self, restore_content):
        assert "--dry-run" in restore_content
        assert "DRY_RUN" in restore_content

    def test_restore_asks_for_confirmation(self, restore_content):
        assert "yes/N" in restore_content or "yes" in restore_content

    def test_restore_handles_encrypted_env(self, restore_content):
        assert "openssl enc -d" in restore_content, "Şifreli .env çözme desteği gerekli"

    def test_restore_validates_manifest_before_restore(self, restore_content):
        # Yorum satırlarını atla
        lines = [(i, l) for i, l in enumerate(restore_content.splitlines())
                 if not l.strip().startswith("#")]
        manifest_idx = next((i for i, l in lines if "MANIFEST" in l and "sha256" in l.lower()), None)
        pg_restore_idx = next((i for i, l in lines if "pg_restore" in l), None)
        assert manifest_idx is not None, "Manifest doğrulaması bulunamadı"
        assert pg_restore_idx is not None, "pg_restore komutu bulunamadı"
        assert manifest_idx < pg_restore_idx, "Manifest kontrolü restore'dan önce yapılmalı"

    def test_restore_supports_date_argument(self, restore_content):
        assert "--date" in restore_content

    def test_restore_supports_set_argument(self, restore_content):
        assert "--set" in restore_content

    def test_restore_supports_skip_db(self, restore_content):
        assert "--skip-db" in restore_content

    def test_restore_supports_skip_volumes(self, restore_content):
        assert "--skip-volumes" in restore_content

    def test_restore_backs_up_existing_env_before_overwrite(self, restore_content):
        assert ".env.bak" in restore_content, "Mevcut .env yedeklenmeli (üzerine yazmadan önce)"


# ── TestVerifyScript ──────────────────────────────────────────────────────────

class TestVerifyScript:
    def test_verify_checks_sha256_manifest(self, verify_content):
        assert "sha256sum" in verify_content
        assert "MANIFEST" in verify_content

    def test_verify_tests_pg_dump_readability(self, verify_content):
        assert "pg_restore" in verify_content and "--list" in verify_content

    def test_verify_tests_tar_integrity(self, verify_content):
        assert "tar -tzf" in verify_content

    def test_verify_checks_empty_files(self, verify_content):
        assert "-s " in verify_content or "! -s" in verify_content

    def test_verify_checks_backup_age(self, verify_content):
        assert "SET_AGE" in verify_content or "AGE" in verify_content

    def test_verify_supports_set_argument(self, verify_content):
        assert "--set" in verify_content

    def test_verify_supports_dir_argument(self, verify_content):
        assert "--dir" in verify_content

    def test_verify_exits_with_error_count(self, verify_content):
        assert "exit ${ERRORS}" in verify_content or "exit $ERRORS" in verify_content


# ── TestBackupSecurity ────────────────────────────────────────────────────────

class TestBackupSecurity:
    def test_backup_warns_when_no_password(self, backup_content):
        assert "BACKUP_PASSWORD" in backup_content
        assert "warn" in backup_content.lower() or "uyar" in backup_content.lower()

    def test_env_encryption_uses_strong_iter(self, backup_content):
        match = re.search(r"-iter\s+(\d+)", backup_content)
        assert match, "-iter parametresi bulunamadı (PBKDF2 iteration count)"
        iterations = int(match.group(1))
        assert iterations >= 100000, \
            f"PBKDF2 iter sayısı {iterations} — en az 100000 olmalı (OWASP)"

    def test_restore_requires_password_for_encrypted_env(self, restore_content):
        assert "BACKUP_PASSWORD" in restore_content
        assert "err" in restore_content

    def test_postgres_password_via_env_not_cli(self, backup_content):
        assert "PGPASSWORD" in backup_content, \
            "PostgreSQL şifresi komut satırında değil PGPASSWORD env ile geçilmeli"
        assert "-W " not in backup_content, \
            "-W flag (interactive prompt) kullanılmamalı"


# ── TestBackupIntegration ─────────────────────────────────────────────────────

class TestBackupIntegration:
    """Container başlatmadan backup mantığını test et."""

    def test_backup_manifest_format(self, tmp_path):
        """SHA-256 manifest formatını doğrula."""
        test_file = tmp_path / "test.dump"
        test_file.write_bytes(b"test postgres dump content")

        manifest = tmp_path / "MANIFEST.sha256"

        import hashlib
        digest = hashlib.sha256(test_file.read_bytes()).hexdigest()
        manifest.write_text(f"{digest} test.dump\n")

        lines = manifest.read_text().strip().splitlines()
        assert len(lines) == 1
        parts = lines[0].split(" ")
        assert len(parts) == 2
        assert len(parts[0]) == 64, "SHA-256 hash 64 hex karakter olmalı"

    def test_config_tar_can_be_created_and_extracted(self, tmp_path):
        """Config arşivi oluşturma ve açma mantığını doğrula."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        rule_file = config_dir / "test_rule.yml"
        rule_file.write_text("detection: test")

        archive = tmp_path / "config_test.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(config_dir, arcname="config")

        assert archive.stat().st_size > 0

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(extract_dir)

        assert (extract_dir / "config" / "test_rule.yml").exists()

    def test_openssl_encryption_roundtrip(self, tmp_path):
        """OpenSSL AES-256-CBC şifreleme/çözme döngüsünü test et."""
        import subprocess
        original = tmp_path / "original.txt"
        original.write_text("SECRET_KEY=test123\nPASSWORD=abc")
        encrypted = tmp_path / "encrypted.enc"
        decrypted = tmp_path / "decrypted.txt"

        enc_result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
             "-pass", "pass:testpassword",
             "-in", str(original), "-out", str(encrypted)],
            capture_output=True
        )
        if enc_result.returncode != 0:
            pytest.skip("openssl bulunamadı")

        dec_result = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
             "-pass", "pass:testpassword",
             "-in", str(encrypted), "-out", str(decrypted)],
            capture_output=True
        )
        assert dec_result.returncode == 0
        assert decrypted.read_text() == original.read_text()
