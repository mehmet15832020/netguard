"""
NetGuard — At-rest şifreleme yardımcı modülü

Fernet (AES-128-CBC + HMAC-SHA256) ile simetrik şifreleme.
Anahtar NETGUARD_ENCRYPTION_KEY env değişkeninden okunur.

Anahtar tanımlı değilse: şifreleme atlanır, plaintext saklanır (WARNING log).
Tanımlıysa: tüm yeni yazımlar şifreli, okumalar otomatik çözülür.

Geçiş dönemi uyumluluğu: decrypt() InvalidToken alırsa plaintext olarak döner
(migration öncesi kayıtlar için).

Kaynak: OWASP Cryptographic Storage CS, NIST SP 800-111, CIS Controls v8.1 §3.11
"""

import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_KEY_ENV = "NETGUARD_ENCRYPTION_KEY"


def _get_fernet() -> Fernet | None:
    raw = os.environ.get(_KEY_ENV)
    if not raw:
        return None
    try:
        return Fernet(raw.strip().encode())
    except Exception as exc:
        logger.error("NETGUARD_ENCRYPTION_KEY geçersiz format: %s", exc)
        return None


def encrypt(plaintext: str) -> str:
    """Plaintext string'i şifrele. Anahtar yoksa plaintext döner."""
    f = _get_fernet()
    if f is None:
        logger.warning(
            "%s tanımlı değil — hassas veri şifresiz saklanıyor", _KEY_ENV
        )
        return plaintext
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str | None) -> str | None:
    """Şifreli string'i çöz. Anahtar yoksa veya plaintext ise olduğu gibi döner."""
    if ciphertext is None:
        return None
    f = _get_fernet()
    if f is None:
        return ciphertext
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return ciphertext


def generate_key() -> str:
    """Yeni Fernet anahtarı üret — tek seferlik kurulum için."""
    return Fernet.generate_key().decode()
