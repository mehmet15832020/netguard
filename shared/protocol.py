"""
NetGuard iletişim protokolü sabitleri.

Agent ile server arasındaki URL'ler, zaman aşımları ve
versiyon bilgisi burada merkezi olarak tanımlanır.
Bir URL değişirse sadece burası güncellenir.
"""

# API versiyonu — breaking change olduğunda artırılır
API_VERSION = "v1"

# Agent → Server endpoint'leri
ENDPOINT_REGISTER = f"/api/{API_VERSION}/agents/register"
ENDPOINT_METRICS = f"/api/{API_VERSION}/agents/metrics"
ENDPOINT_HEALTH = f"/api/{API_VERSION}/health"

# Agent davranış sabitleri
DEFAULT_COLLECT_INTERVAL_SEC = 10   # Her kaç saniyede metrik toplanır
DEFAULT_SEND_INTERVAL_SEC = 10      # Her kaç saniyede server'a gönderilir
CONNECTION_TIMEOUT_SEC = 5          # Server'a bağlantı zaman aşımı
MAX_RETRY_ATTEMPTS = 3              # Başarısız gönderimde kaç kez tekrar dene
RETRY_BACKOFF_SEC = 2               # Tekrar denemeler arasındaki bekleme

# Veri boyutu limitleri
MAX_DISK_ENTRIES = 20               # Bir snapshot'ta maksimum disk sayısı
MAX_INTERFACE_ENTRIES = 10          # Bir snapshot'ta maksimum ağ arayüzü sayısı