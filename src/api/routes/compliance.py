"""Compliance Management Endpoints"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.models.compliance import ComplianceCheck
from src.services.registry import audit_service, compliance_service, policy_engine
from src.utils.config import settings

router = APIRouter()
logger = structlog.get_logger()


@router.get("/status")
async def get_compliance_status(
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Get overall real-time HIPAA compliance status."""
    return await compliance_service.get_overall_status()


@router.post("/check", response_model=ComplianceCheck)
async def run_compliance_check(
    resource_type: str,
    resource_id: Optional[str] = None,
    checks: Optional[List[str]] = None,
    principal: UserPrincipal = Depends(require_permission("compliance_write")),
):
    """Run live compliance checks on a resource."""
    try:
        result = await compliance_service.run_checks(
            resource_type=resource_type,
            resource_id=resource_id,
            checks=checks,
        )
        await audit_service.log_access(
            action="compliance_check",
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            details={"score": result.score, "status": result.status.value},
        )
        return result

    except Exception as e:
        logger.error("compliance_check_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report")
async def generate_compliance_report(
    period: str = Query(default="monthly", pattern="^(weekly|monthly|quarterly|annual)$"),
    format: str = Query(default="json", pattern="^(json|pdf|html)$"),
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Generate HIPAA compliance report in JSON or HTML format."""
    report = await compliance_service.generate_report(period=period)
    if format == "html":
        html = compliance_service.export_report_html(report)
        return HTMLResponse(content=html)
    return report


@router.post("/validate")
async def validate_against_policies(
    data: Dict[str, Any] = Body(...),
    policies: Optional[List[str]] = Body(default=None),
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Validate data against HIPAA compliance policies and persist violations."""
    try:
        result = await policy_engine.validate(
            data=data,
            policies=policies,
        )
        await audit_service.log_access(
            action="policy_validate",
            resource_type="data_payload",
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            details={
                "policies_checked": result["policies_checked"],
                "violations_count": result["violations_count"],
            },
        )
        return result

    except Exception as e:
        logger.error("policy_validation_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/policies")
async def list_policies(
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """List all compliance policies."""
    policies = await policy_engine.list_policies()
    return {"policies": policies}


@router.get("/policies/{policy_id}")
async def get_policy(
    policy_id: str,
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Get specific policy details."""
    policy = await policy_engine.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.get("/violations")
async def get_violations(
    severity: Optional[str] = Query(default=None, pattern="^(low|medium|high|critical)$"),
    status: Optional[str] = Query(default=None, pattern="^(open|resolved|accepted)$"),
    days: int = Query(default=30, le=365),
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Get compliance violations filterable by severity and status."""
    violations = await compliance_service.get_violations(
        severity=severity,
        status=status,
        days=days,
    )
    return {"violations": violations, "total": len(violations)}


@router.post("/violations/{violation_id}/resolve")
async def resolve_violation(
    violation_id: str,
    resolution: str,
    notes: Optional[str] = None,
    principal: UserPrincipal = Depends(require_permission("compliance_write")),
):
    """Mark a violation as resolved."""
    try:
        result = await compliance_service.resolve_violation(
            violation_id=violation_id,
            resolution=resolution,
            notes=notes,
            resolved_by=principal.user_id,
        )
        await audit_service.log_access(
            action="resolve_violation",
            resource_type="violation",
            resource_id=violation_id,
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            details={"resolution": resolution},
        )
        return result

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("resolve_violation_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requirements")
async def get_hipaa_requirements(
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Get dynamic HIPAA compliance requirements checklist."""
    overall = await compliance_service.get_overall_status()
    req_status = overall.get("requirements", {})
    return {
        "requirements": [
            {
                "id": "164.312(a)(1)",
                "name": "Access Control",
                "description": "Implement technical policies for electronic systems that maintain PHI",
                "status": req_status.get("access_control", "compliant"),
            },
            {
                "id": "164.312(b)",
                "name": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms to record access",
                "status": req_status.get("audit_control", "compliant"),
            },
            {
                "id": "164.312(c)(1)",
                "name": "Integrity",
                "description": "Implement policies to protect PHI from improper alteration or destruction",
                "status": req_status.get("integrity", "compliant"),
            },
            {
                "id": "164.312(d)",
                "name": "Person Authentication",
                "description": "Implement procedures to verify person seeking access is the one claimed",
                "status": req_status.get("authentication", "compliant"),
            },
            {
                "id": "164.312(e)(1)",
                "name": "Transmission Security",
                "description": "Implement technical security measures for PHI transmitted over networks",
                "status": req_status.get("transmission_security", "compliant"),
            },
        ]
    }
