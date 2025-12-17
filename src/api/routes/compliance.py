"""Compliance Management Endpoints"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from src.models.compliance import (
    ComplianceCheck,
    ComplianceReport,
    PolicyValidation,
    ComplianceStatus
)
from src.services.compliance_service import ComplianceService
from src.rules.policy_engine import PolicyEngine

router = APIRouter()
logger = structlog.get_logger()

compliance_service = ComplianceService()
policy_engine = PolicyEngine()


@router.get("/status")
async def get_compliance_status():
    """
    Get overall HIPAA compliance status

    Checks:
    - Access controls
    - Audit controls
    - Integrity controls
    - Transmission security
    """
    status = await compliance_service.get_overall_status()
    return status


@router.post("/check", response_model=ComplianceCheck)
async def run_compliance_check(
    resource_type: str,
    resource_id: Optional[str] = None,
    checks: Optional[List[str]] = None
):
    """
    Run compliance checks on a resource

    Available checks:
    - encryption_at_rest
    - encryption_in_transit
    - access_controls
    - audit_logging
    - data_integrity
    - phi_protection
    """
    try:
        result = await compliance_service.run_checks(
            resource_type=resource_type,
            resource_id=resource_id,
            checks=checks
        )
        return result

    except Exception as e:
        logger.error("compliance_check_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report", response_model=ComplianceReport)
async def generate_compliance_report(
    period: str = Query(default="monthly", enum=["weekly", "monthly", "quarterly", "annual"]),
    format: str = Query(default="json", enum=["json", "pdf", "html"])
):
    """
    Generate HIPAA compliance report

    Includes:
    - Compliance score
    - Violations summary
    - Remediation recommendations
    - Trend analysis
    """
    report = await compliance_service.generate_report(period=period)
    return report


@router.post("/validate")
async def validate_against_policies(
    data: Dict[str, Any],
    policies: Optional[List[str]] = None
):
    """
    Validate data against compliance policies

    Returns violations and recommendations
    """
    try:
        result = await policy_engine.validate(
            data=data,
            policies=policies
        )
        return result

    except Exception as e:
        logger.error("policy_validation_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/policies")
async def list_policies():
    """List all compliance policies"""
    policies = await policy_engine.list_policies()
    return {"policies": policies}


@router.get("/policies/{policy_id}")
async def get_policy(policy_id: str):
    """Get specific policy details"""
    policy = await policy_engine.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.get("/violations")
async def get_violations(
    severity: Optional[str] = Query(default=None, enum=["low", "medium", "high", "critical"]),
    status: Optional[str] = Query(default=None, enum=["open", "resolved", "accepted"]),
    days: int = Query(default=30, le=365)
):
    """
    Get compliance violations

    Filterable by severity and status
    """
    violations = await compliance_service.get_violations(
        severity=severity,
        status=status,
        days=days
    )
    return {"violations": violations, "total": len(violations)}


@router.post("/violations/{violation_id}/resolve")
async def resolve_violation(
    violation_id: str,
    resolution: str,
    notes: Optional[str] = None
):
    """Mark a violation as resolved"""
    try:
        result = await compliance_service.resolve_violation(
            violation_id=violation_id,
            resolution=resolution,
            notes=notes
        )
        return result

    except Exception as e:
        logger.error("resolve_violation_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requirements")
async def get_hipaa_requirements():
    """Get HIPAA compliance requirements checklist"""
    return {
        "requirements": [
            {
                "id": "164.312(a)(1)",
                "name": "Access Control",
                "description": "Implement technical policies for electronic systems that maintain PHI",
                "status": "compliant"
            },
            {
                "id": "164.312(b)",
                "name": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms to record access",
                "status": "compliant"
            },
            {
                "id": "164.312(c)(1)",
                "name": "Integrity",
                "description": "Implement policies to protect PHI from improper alteration or destruction",
                "status": "compliant"
            },
            {
                "id": "164.312(d)",
                "name": "Person Authentication",
                "description": "Implement procedures to verify person seeking access is the one claimed",
                "status": "compliant"
            },
            {
                "id": "164.312(e)(1)",
                "name": "Transmission Security",
                "description": "Implement technical security measures for PHI transmitted over networks",
                "status": "compliant"
            }
        ]
    }
