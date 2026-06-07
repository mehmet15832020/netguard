"""
NetGuard — AI Alert Explainer (F4)

Correlated event'leri Groq API (Llama 3.3 70B) ile analiz eder.
24 saatlik DB cache, tenant isolation, rate limit'ler route katmanında.

Prompt injection koruması: kullanıcı verisi instruction string'ine
eklenmez — JSON context bloğuna izole edilir.
"""

import json
import logging
import os
import socket

logger = logging.getLogger(__name__)

_GROQ_KEY          = os.getenv("GROQ_API_KEY", "")
_GROQ_MODEL        = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
_MAX_OUTPUT_TOKENS = 1200
_GROQ_TIMEOUT      = 30.0
_GROQ_HOST         = "api.groq.com"
_GROQ_FALLBACK_IP  = "172.64.149.20"


def _ensure_groq_resolvable() -> None:
    """
    api.groq.com sistüm DNS ile çözümlenemiyorsa /etc/hosts'a fallback IP ekler.
    Cloudflare anycast (172.64.x.x) çok nadiren değişir; üretimde DoH ile doğrulama önerilir.
    """
    try:
        socket.getaddrinfo(_GROQ_HOST, 443, proto=socket.IPPROTO_TCP)
        return
    except OSError:
        pass

    try:
        hosts_path = "/etc/hosts"
        with open(hosts_path) as f:
            if _GROQ_HOST in f.read():
                return
        with open(hosts_path, "a") as f:
            f.write(f"\n{_GROQ_FALLBACK_IP} {_GROQ_HOST}\n")
        logger.warning(f"DNS çözümlenemedi; /etc/hosts'a {_GROQ_FALLBACK_IP} {_GROQ_HOST} eklendi")
    except OSError as e:
        logger.error(f"/etc/hosts güncellenemedi: {e}")

_SYSTEM_PROMPT = """\
Sen NetGuard ağ güvenlik izleme platformu için kıdemli bir SOC analistisin.
SANS Incident Handler's Handbook, NIST SP 800-61 ve endüstri SOC playbook standartlarına
göre tetiklenen alerti Türkçe olarak analiz et.

Yanıtını TAM OLARAK şu altı bölümde yaz (başlıkları değiştirme):

**Triage Kararı**
İlk satır: `🔴 ESKALASYONa AL` / `🟡 İZLE` / `🟢 KAPAT` — hangisi uygunsa.
İkinci satır: Güven seviyesi: Yüksek / Orta / Düşük — ve kısa gerekçe (1 cümle).
Üçüncü satır: Aciliyet: "X dakika/saat içinde müdahale gerekli" veya "Rutin izleme yeterli".

**Ne Oldu**
5W1H formatında: Kim (kaynak IP/sistem), Ne (event_action, tetiklenme sayısı),
Nerede (hedef IP/port/protokol), Ne Zaman (zaman dilimi, süre), Nasıl (saldırı vektörü),
Neden (muhtemel amaç). Somut sayılar ve değerler kullan.

**Log Korelasyonu**
Sağlanan log kayıtlarını kronolojik sırayla analiz et. Her log grubundan ne çıkarıyorsun?
Zaman damgaları arasındaki boşluklar, tekrarlanan IP'ler, port pattern'leri ve
anormal davranış işaretlerini belirt. Loglar arası ilişki varsa bağla.
Log yoksa: "Eşleşen log kaydı mevcut değil — kural tetiklendi ancak ham log korelasyonu yapılamıyor."

**Risk Değerlendirmesi**
Yanlış pozitif olasılığı ve gerekçesi (1-2 cümle).
Gerçek tehdit ise: etkilenebilecek sistemler, potansiyel lateral movement yönü,
veri sızıntısı riski, iş etkisi. Kill chain'deki konum (SANS Kill Chain / MITRE aşaması).

**MITRE ATT&CK**
Her teknik: `TechniqueID — Teknik Adı`: Bu alert bağlamında ne anlama geliyor (1-2 cümle).
Mapping yoksa: "MITRE eşleşmesi tanımlanmamış."

**Müdahale Adımları**
Öncelik sırasına göre 5-7 madde. Her madde somut ve araç/komut belirten:
- Hangi NetGuard sayfasında ne bakılacak (ör. "Kill Chain Timeline'da bu IP'yi filtrele")
- Hangi firewall/switch üzerinde hangi kuralı kontrol et
- Yanlış pozitif kapama kriteri (ne görürsen kapat)
- Escalation eşiği (ne görürsen eskalasyon yap, kime)
- Blok/karantina önerisi varsa: NetGuard Aktif Yanıt üzerinden veya manuel

Kurallar:
- Yalnızca Türkçe yaz. Teknik terimler (MITRE ID, protokol, log alanı adları) İngilizce kalabilir.
- Bağlamı yorumla, tekrar etme. Analist için katma değer üret.
- Gereksiz giriş cümlesi yazma, direkt bölümlerle başla.
- Maksimum 700 kelime.
"""


def _build_user_message(event_data: dict, recent_logs: list[dict]) -> str:
    logs_summary = []
    for log in recent_logs[:5]:
        entry = {k: log[k] for k in (
            "timestamp", "source_ip", "destination_ip", "source_port",
            "destination_port", "network_protocol", "event_action",
            "event_category", "severity", "message",
        ) if log.get(k) is not None}
        logs_summary.append(entry)

    context = {
        "alert": {
            "rule_id":         event_data.get("rule_id"),
            "rule_name":       event_data.get("rule_name"),
            "severity":        event_data.get("severity"),
            "event_action":    event_data.get("event_action"),
            "group_value":     event_data.get("group_value"),
            "matched_count":   event_data.get("matched_count"),
            "window_seconds":  event_data.get("window_seconds"),
            "first_seen":      str(event_data.get("first_seen", "")),
            "last_seen":       str(event_data.get("last_seen", "")),
            "message":         event_data.get("message"),
            "mitre_techniques": event_data.get("mitre_techniques", []),
            "mitre_tactics":    event_data.get("mitre_tactics", []),
        },
        "recent_matching_logs": logs_summary,
    }
    return (
        "Analyze this security alert and explain it to the analyst:\n\n"
        f"```json\n{json.dumps(context, indent=2, default=str)}\n```"
    )


def explain_event(
    event_data: dict,
    recent_logs: list[dict],
    db,
    tenant_id: str,
    corr_id: str,
) -> dict:
    """
    Correlated event için AI açıklaması üretir veya cache'den döner.

    event_data: CorrelatedEvent.model_dump() çıktısı
    recent_logs: son eşleşen normalized_logs (dict listesi)
    db: DatabaseManager instance
    """
    cached = db.get_alert_explanation(corr_id, tenant_id)
    if cached is not None:
        return cached

    if not _GROQ_KEY:
        raise RuntimeError("GROQ_API_KEY tanımlı değil")

    _ensure_groq_resolvable()

    try:
        from groq import Groq
        client = Groq(api_key=_GROQ_KEY, timeout=_GROQ_TIMEOUT, max_retries=1)
        user_msg = _build_user_message(event_data, recent_logs)
        response = client.chat.completions.create(
            model=_GROQ_MODEL,
            max_tokens=_MAX_OUTPUT_TOKENS,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
        )
    except Exception as exc:
        logger.error(f"Groq API hatası: {exc}")
        raise RuntimeError(f"AI açıklama üretilemedi: {exc}") from exc

    explanation   = response.choices[0].message.content
    input_tokens  = response.usage.prompt_tokens
    output_tokens = response.usage.completion_tokens

    db.save_alert_explanation(
        corr_id=corr_id,
        tenant_id=tenant_id,
        explanation=explanation,
        model=_GROQ_MODEL,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

    return {
        "explanation":    explanation,
        "model":          _GROQ_MODEL,
        "input_tokens":   input_tokens,
        "output_tokens":  output_tokens,
        "created_at":     None,
        "cached":         False,
    }
