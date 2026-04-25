"""Compliance raporu endpoint'leri."""

from fastapi import APIRouter, Depends, Query
from server.auth import get_current_user, User
from server.database import db
from server.compliance import evaluate_compliance, ALL_CONTROLS, PCI_CONTROLS, ISO_CONTROLS

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/report")
def get_compliance_report(
    framework: str = Query(default="", description="PCI DSS v4.0 | ISO 27001:2022 | boş = ikisi"),
    _: User = Depends(get_current_user),
):
    result = evaluate_compliance(db, framework=framework or None)
    return result


@router.get("/controls")
def list_controls(
    framework: str = Query(default=""),
    _: User = Depends(get_current_user),
):
    controls = ALL_CONTROLS
    if framework:
        controls = [c for c in controls if c.framework == framework]
    return {
        "count": len(controls),
        "controls": [
            {
                "control_id":        c.control_id,
                "title":             c.title,
                "description":       c.description,
                "framework":         c.framework,
                "category":          c.category,
                "netguard_features": c.netguard_features,
            }
            for c in controls
        ],
    }


@router.get("/summary")
def get_compliance_summary(_: User = Depends(get_current_user)):
    pci = evaluate_compliance(db, framework="PCI DSS v4.0")
    iso = evaluate_compliance(db, framework="ISO 27001:2022")
    return {
        "pci_dss": {
            "score":     pci["overall_score"],
            "compliant": pci["compliant"],
            "partial":   pci["partial"],
            "gaps":      pci["gaps"],
            "total":     pci["total_controls"],
        },
        "iso_27001": {
            "score":     iso["overall_score"],
            "compliant": iso["compliant"],
            "partial":   iso["partial"],
            "gaps":      iso["gaps"],
            "total":     iso["total_controls"],
        },
    }
