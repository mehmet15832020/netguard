"""
NetGuard Server — SIGMA Kural Yönetim Endpoint'leri (V2 / pySigma)

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
from sigma.collection import SigmaCollection as _SC
from sigma.correlations import SigmaCorrelationRule

from server.auth import User, get_current_user, require_admin
from server.correlator import correlator, SIGMA_RULES_V2_DIR

logger = logging.getLogger(__name__)
router = APIRouter()

SIGMA_DIR = Path(SIGMA_RULES_V2_DIR)


def _rule_path(rule_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "_-" else "_" for c in rule_id)
    return SIGMA_DIR / f"{safe}.yml"


def _list_sigma_files() -> list[Path]:
    if not SIGMA_DIR.exists():
        return []
    return sorted(SIGMA_DIR.glob("**/*.y*ml"))


def _parse_v2_rule(path: Path) -> dict | None:
    """V2 pySigma dosyasını oku ve metadata döndür (son kural öncelikli)."""
    try:
        text = path.read_text(encoding="utf-8")
        collection = _SC.from_yaml(text)
        for rule in reversed(list(collection)):
            rule_id = str(rule.id) if rule.id else path.stem
            title   = str(rule.title) if rule.title else path.stem
            level   = rule.level.name.lower() if rule.level else "medium"
            tags    = [str(t) for t in (rule.tags or [])]
            fps     = [str(f) for f in (rule.falsepositives or [])]
            desc    = str(rule.description) if getattr(rule, "description", None) else ""
            status  = str(rule.status) if getattr(rule, "status", None) else "unknown"
            return {
                "rule_id":        rule_id,
                "title":          title,
                "status":         status,
                "description":    desc,
                "level":          level,
                "tags":           tags,
                "falsepositives": fps,
                "enabled":        True,
                "filename":       path.name,
            }
    except Exception:
        return None
    return None


class SigmaRuleUpload(BaseModel):
    yaml_content: str


@router.get("/sigma/rules")
def list_sigma_rules(_: User = Depends(get_current_user)):
    """Yüklü SIGMA V2 kurallarını metadata ile listele."""
    results = []
    for path in _list_sigma_files():
        meta = _parse_v2_rule(path)
        if meta is None:
            continue
        results.append(meta)
    return {"count": len(results), "rules": results}


@router.get("/sigma/rules/{rule_id}")
def get_sigma_rule(rule_id: str, _: User = Depends(get_current_user)):
    """Bir SIGMA V2 kuralının ham YAML içeriğini döndür."""
    path = _rule_path(rule_id)
    if path.exists():
        return {"rule_id": rule_id, "filename": path.name, "yaml_content": path.read_text(encoding="utf-8")}

    for f in _list_sigma_files():
        meta = _parse_v2_rule(f)
        if meta and meta["rule_id"] == rule_id:
            return {"rule_id": rule_id, "filename": f.name, "yaml_content": f.read_text(encoding="utf-8")}

    raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")


@router.post("/sigma/rules/validate")
def validate_sigma_rule(body: SigmaRuleUpload, _: User = Depends(get_current_user)):
    """SIGMA V2 kuralını kaydetmeden pySigma ile geçerlilik kontrolü yap."""
    try:
        collection = _SC.from_yaml(body.yaml_content)
        rules = list(collection)
        if not rules:
            raise HTTPException(status_code=422, detail="Kural bulunamadı")
        r = rules[-1]
        rule_id = str(r.id) if r.id else "unknown"
        title   = str(r.title) if r.title else ""
        level   = r.level.name.lower() if r.level else "medium"
        is_corr = isinstance(r, SigmaCorrelationRule)
        return {
            "valid":    True,
            "rule_id":  rule_id,
            "title":    title,
            "level":    level,
            "is_correlation": is_corr,
            "rule_count": len(rules),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Geçersiz Sigma YAML: {e}")


@router.post("/sigma/rules")
def upload_sigma_rule(body: SigmaRuleUpload, _: User = Depends(require_admin)):
    """Yeni SIGMA V2 kuralı yükle ve korelasyon motorunu yeniden yükle."""
    try:
        collection = _SC.from_yaml(body.yaml_content)
        rules = list(collection)
        if not rules:
            raise HTTPException(status_code=422, detail="SIGMA kuralı geçersiz — kural bulunamadı")
        final_rule = rules[-1]
        rule_id = str(final_rule.id) if final_rule.id else None
        if not rule_id:
            raise HTTPException(status_code=422, detail="Korelasyon kuralında UUID id alanı zorunlu")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Geçersiz SIGMA YAML: {e}")

    SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    dest = _rule_path(rule_id)
    dest.write_text(body.yaml_content, encoding="utf-8")

    loaded = correlator.load_rules()
    logger.info(f"SIGMA V2 kural yüklendi: {rule_id} → {dest.name}")
    return {"saved": rule_id, "filename": dest.name, "total_rules": loaded}


@router.delete("/sigma/rules/{rule_id}")
def delete_sigma_rule(rule_id: str, _: User = Depends(require_admin)):
    """SIGMA V2 kuralını sil ve motoru yeniden yükle."""
    path = _rule_path(rule_id)
    if not path.exists():
        for f in _list_sigma_files():
            meta = _parse_v2_rule(f)
            if meta and meta["rule_id"] == rule_id:
                path = f
                break
        else:
            raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")

    path.unlink()
    loaded = correlator.load_rules()
    logger.info(f"SIGMA V2 kural silindi: {rule_id}")
    return {"deleted": rule_id, "total_rules": loaded}
