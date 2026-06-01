"""
NetGuard — AI Alert Explainer (F4)

Correlated event'leri Claude API ile analiz eder.
24 saatlik DB cache, tenant isolation, rate limit'ler route katmanında.

Prompt injection koruması: kullanıcı verisi instruction string'ine
eklenmez — JSON context bloğuna izole edilir.
"""

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
_ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
_MAX_OUTPUT_TOKENS = 600

_SYSTEM_PROMPT = """\
You are a security analyst assistant for NetGuard, a network security monitoring platform.
Your task is to explain a security alert in clear, concise language for a network security analyst.

Structure your response in exactly these four sections (use the exact headers):
**What Happened**
One or two sentences: what the detection rule observed.

**Why It Matters**
One or two sentences: security relevance, attack stage, and potential impact.

**MITRE ATT&CK**
If techniques are present, name each one and what it means in this context (one line each).
If empty, write "No MITRE mapping."

**Recommended Actions**
Three to five bullet points: concrete next steps for the analyst.

Rules:
- Be direct and factual. No fluff.
- Do not repeat information verbatim from the context.
- Use security terminology appropriate for a mid-level SOC analyst.
- Write in English regardless of input language.
- Maximum 400 words total.
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

    if not _ANTHROPIC_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY tanımlı değil")

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=_ANTHROPIC_KEY)
        user_msg = _build_user_message(event_data, recent_logs)
        response = client.messages.create(
            model=_ANTHROPIC_MODEL,
            max_tokens=_MAX_OUTPUT_TOKENS,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as exc:
        logger.error(f"Claude API hatası: {exc}")
        raise RuntimeError(f"AI açıklama üretilemedi: {exc}") from exc

    explanation   = response.content[0].text
    input_tokens  = response.usage.input_tokens
    output_tokens = response.usage.output_tokens

    db.save_alert_explanation(
        corr_id=corr_id,
        tenant_id=tenant_id,
        explanation=explanation,
        model=_ANTHROPIC_MODEL,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

    return {
        "explanation":    explanation,
        "model":          _ANTHROPIC_MODEL,
        "input_tokens":   input_tokens,
        "output_tokens":  output_tokens,
        "created_at":     None,
        "cached":         False,
    }
