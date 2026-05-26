"""
NetGuard — At-rest şifreleme yardımcı modülü

Fernet (AES-128-CBC + HMAC-SHA256) ile simetrik şifreleme.
Anahtar NETGUARD_ENCRYPTION_KEY env değişkeninden okunur.

Anahtar tanımlı değilse: şifreleme atlanır, plaintext saklanır (WARNING log, startup'ta bir kez).
Tanımlıysa: tüm yeni yazımlar şifreli, okumalar otomatik çözülür.

Geçiş dönemi uyumluluğu: decrypt() InvalidToken alırsa ve değer Fernet token
formatında değilse (gAAAAA ile başlamıyorsa) plaintext olarak döner.
Fernet formatındaki bir değer InvalidToken atıyorsa → anahtar yanlış demektir,
bu durumda hata loglanır ve exception yükseltilir (MFA kilitlenmesini açıkça gösterir).

Kaynak: OWASP Cryptographic Storage CS, NIST SP 800-111, CIS Controls v8.1 §3.11
"""

import logging
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_KEY_ENV = "NETGUARD_ENCRYPTION_KEY"
_FERNET_PREFIX = "gAAAAA"
_key_warning_logged = False


@lru_cache(maxsize=8)
def _get_fernet(raw_key: str) -> Fernet:
    return Fernet(raw_key.encode())


def _fernet() -> Fernet | None:
    global _key_warning_logged
    raw = os.environ.get(_KEY_ENV, "").strip()
    if not raw:
        if not _key_warning_logged:
            logger.warning(
                "%s tanımlı değil — hassas veri (TOTP secret) şifresiz saklanıyor. "
                "Üretim ortamında 'python -c \"from server.crypto import generate_key; "
                "print(generate_key())\"' ile anahtar oluşturun.",
                _KEY_ENV,
            )
            _key_warning_logged = True
        return None
    try:
        return _get_fernet(raw)
    except Exception as exc:
        logger.error("%s geçersiz format: %s", _KEY_ENV, exc)
        return None


def encrypt(plaintext: str) -> str:
    """Plaintext string'i şifrele. Anahtar yoksa plaintext döner."""
    f = _fernet()
    if f is None:
        return plaintext
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str | None) -> str | None:
    """Şifreli string'i çöz.

    Davranış:
    - None → None
    - Anahtar yoksa → ciphertext olduğu gibi döner
    - Fernet formatında değil (eski plaintext kayıt) → olduğu gibi döner
    - Fernet formatında ama InvalidToken → HATA: anahtar yanlış, exception yükseltilir
    """
    if ciphertext is None:
        return None
    f = _fernet()
    if f is None:
        return ciphertext

    is_fernet_token = ciphertext.startswith(_FERNET_PREFIX)

    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        if is_fernet_token:
            logger.error(
                "TOTP secret çözülemedi — %s yanlış olabilir veya değiştirilmiş. "
                "Kullanıcı MFA doğrulaması başarısız olacak.",
                _KEY_ENV,
            )
            raise
        return ciphertext
    except Exception as exc:
        logger.error("decrypt() beklenmeyen hata: %s", exc)
        raise


def generate_key() -> str:
    """Yeni Fernet anahtarı üret — tek seferlik kurulum için.

    Kullanım:
        python -c "from server.crypto import generate_key; print(generate_key())"
    Üretilen değeri NETGUARD_ENCRYPTION_KEY env değişkenine atayın.
    """
    return Fernet.generate_key().decode()
