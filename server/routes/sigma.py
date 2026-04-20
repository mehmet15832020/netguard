"""
NetGuard Server — SIGMA Kural Yönetim Endpoint'leri

GET    /api/v1/sigma/rules              → Yüklü SIGMA kurallarını listele
GET    /api/v1/sigma/rules/{rule_id}    → Kural YAML içeriğini getir
POST   /api/v1/sigma/rules              → Yeni SIGMA kuralı yükle (YAML body)
DELETE /api/v1/sigma/rules/{rule_id}    → SIGMA kuralını sil
POST   /api/v1/sigma/rules/validate     → Kural geçerliliğini test et (kaydetmeden)
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server.auth import User, get_current_user, require_admin
from server.correlator import correlator, SIGMA_RULES_DIR
from server.sigma_parser import parse_sigma_file, sigma_to_correlation_rule

logger = logging.getLogger(__name__)
router = APIRouter()

SIGMA_DIR = Path(SIGMA_RULES_DIR)


def _rule_path(rule_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in rule_id)
    return SIGMA_DIR / f"{safe}.yml"


def _list_sigma_files() -> list[Path]:
    if not SIGMA_DIR.exists():
        return []
    return sorted(SIGMA_DIR.glob("**/*.y*ml"))


class SigmaRuleUpload(BaseModel):
    yaml_content: str


@router.get("/sigma/rules")
def list_sigma_rules(_: User = Depends(get_current_user)):
    """Yüklü SIGMA kurallarını metadata ile listele."""
    results = []
    for path in _list_sigma_files():
        sigma = parse_sigma_file(path)
        if sigma is None:
            continue
        results.append({
            "rule_id":       sigma.rule_id,
            "title":         sigma.title,
            "status":        sigma.status,
            "description":   sigma.description,
            "level":         sigma.level,
            "tags":          sigma.tags,
            "falsepositives": sigma.falsepositives,
            "enabled":       sigma.enabled,
            "filename":      path.name,
        })
    return {"count": len(results), "rules": results}


@router.get("/sigma/rules/{rule_id}")
def get_sigma_rule(rule_id: str, _: User = Depends(get_current_user)):
    """Bir SIGMA kuralının ham YAML içeriğini döndür."""
    path = _rule_path(rule_id)
    if not path.exists():
        # Farklı dosya adıyla da ara
        for f in _list_sigma_files():
            sigma = parse_sigma_file(f)
            if sigma and sigma.rule_id == rule_id:
                return {"rule_id": rule_id, "filename": f.name, "yaml_content": f.read_text(encoding="utf-8")}
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    return {"rule_id": rule_id, "filename": path.name, "yaml_content": path.read_text(encoding="utf-8")}


@router.post("/sigma/rules/validate")
def validate_sigma_rule(body: SigmaRuleUpload, _: User = Depends(get_current_user)):
    """SIGMA kuralını kaydetmeden geçerlilik kontrolü yap."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as tmp:
        tmp.write(body.yaml_content)
        tmp_path = tmp.name

    try:
        sigma = parse_sigma_file(Path(tmp_path))
        if sigma is None:
            raise HTTPException(status_code=422, detail="SIGMA kuralı geçersiz — log'ları kontrol edin")
        rule = sigma_to_correlation_rule(sigma)
        return {
            "valid": True,
            "rule_id":           rule.rule_id,
            "name":              rule.name,
            "match_event_type":  rule.match_event_type,
            "group_by":          rule.group_by,
            "window_seconds":    rule.window_seconds,
            "threshold":         rule.threshold,
            "severity":          rule.severity,
            "output_event_type": rule.output_event_type,
        }
    finally:
        os.unlink(tmp_path)


@router.post("/sigma/rules")
def upload_sigma_rule(body: SigmaRuleUpload, _: User = Depends(require_admin)):
    """Yeni SIGMA kuralı yükle ve korelasyon motorunu yeniden yükle."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as tmp:
        tmp.write(body.yaml_content)
        tmp_path = tmp.name

    try:
        sigma = parse_sigma_file(Path(tmp_path))
        if sigma is None:
            raise HTTPException(status_code=422, detail="SIGMA kuralı geçersiz")
        sigma_to_correlation_rule(sigma)  # dönüşüm hatası yoksa devam et
    finally:
        os.unlink(tmp_path)

    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    dest = _rule_path(sigma.rule_id)
    dest.write_text(body.yaml_content, encoding="utf-8")

    loaded = correlator.load_rules()
    logger.info(f"SIGMA kural yüklendi: {sigma.rule_id} → {dest.name}")
    return {"saved": sigma.rule_id, "filename": dest.name, "total_rules": loaded}


@router.delete("/sigma/rules/{rule_id}")
def delete_sigma_rule(rule_id: str, _: User = Depends(require_admin)):
    """SIGMA kuralını sil ve motoru yeniden yükle."""
    path = _rule_path(rule_id)
    if not path.exists():
        for f in _list_sigma_files():
            sigma = parse_sigma_file(f)
            if sigma and sigma.rule_id == rule_id:
                path = f
                break
        else:
            raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")

    path.unlink()
    loaded = correlator.load_rules()
    logger.info(f"SIGMA kural silindi: {rule_id}")
    return {"deleted": rule_id, "total_rules": loaded}
