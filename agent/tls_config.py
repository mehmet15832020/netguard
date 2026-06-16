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
