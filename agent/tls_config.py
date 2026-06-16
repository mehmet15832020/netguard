"""
NetGuard Agent — TLS doğrulama yapılandırması

httpx.Client(verify=...) parametresi için ortam değişkenlerinden değer üretir.
Windows agent'taki (windows_log_shipper.py) desenle aynı mantık, Linux tarafı için.

Öncelik:
  1. NETGUARD_CA_BUNDLE set edilmişse → o CA dosyasıyla doğrula (özel/self-signed CA)
  2. Yoksa NETGUARD_VERIFY_TLS (default "true") → "false" yapılırsa doğrulama kapanır,
     ama bu durum logger.warning ile açıkça uyarılır (sessiz güvenlik açığı olmasın).
"""

import logging
import os

logger = logging.getLogger(__name__)


def resolve_tls_verify() -> bool | str:
    """httpx.Client(verify=...) için kullanılacak değeri döndürür."""
    ca_bundle = os.getenv("NETGUARD_CA_BUNDLE")
    if ca_bundle:
        return ca_bundle

    verify_enabled = os.getenv("NETGUARD_VERIFY_TLS", "true").lower() != "false"
    if not verify_enabled:
        logger.warning(
            "NETGUARD_VERIFY_TLS=false — sunucu TLS sertifikası doğrulanmıyor, "
            "MITM riski. Production'da kullanılmamalı."
        )
    return verify_enabled


def resolve_client_cert() -> tuple[str, str] | None:
    """
    httpx.Client(cert=...) için (cert_path, key_path) döndürür — A3 mTLS.
    NETGUARD_CLIENT_CERT/NETGUARD_CLIENT_KEY tanımlı değilse None döner;
    bu durumda agent mTLS sunmaz, server (AGENT_MTLS_REQUIRED=false ise)
    API-key-only doğrulamaya düşer.
    """
    cert_path = os.getenv("NETGUARD_CLIENT_CERT")
    key_path = os.getenv("NETGUARD_CLIENT_KEY")
    if not cert_path or not key_path:
        return None
    return (cert_path, key_path)
