"""Audit Trail Endpoints"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.models.audit import AuditQuery
from src.services.registry import audit_service
from src.utils.database import utc_now

router = APIRouter()
logger = structlog.get_logger()


@router.get("/logs")
async def get_audit_logs(
    resource_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """
    Query tamper-evident audit logs with filtering and pagination.
    """
    query = AuditQuery(
        resource_id=resource_id,
        resource_type=resource_type,
        user_id=user_id,
        action=action,
        status=status,
        start_date=start_date or (utc_now() - timedelta(days=30)),
        end_date=end_date or (utc_now() + timedelta(minutes=1)),
        limit=limit,
        offset=offset,
    )

    logs = await audit_service.query_logs(query)
    total = await audit_service.count_logs(query)

    return {
        "logs": logs,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/verify")
async def verify_audit_chain(
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """Verify cryptographic SHA-256 hash chain across all audit logs."""
    return await audit_service.verify_chain_integrity()


@router.get("/logs/{log_id}")
async def get_audit_log(
    log_id: str,
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """Get specific audit log entry."""
    log = await audit_service.get_log(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return log


@router.get("/resource/{resource_id}")
async def get_resource_audit_trail(
    resource_id: str,
    days: int = Query(default=30, le=365),
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """Get complete audit trail for a resource."""
    trail = await audit_service.get_resource_trail(
        resource_id=resource_id,
        days=days,
    )
    return {
        "resource_id": resource_id,
        "period_days": days,
        "events": trail,
        "total_events": len(trail),
    }


@router.get("/user/{user_id}")
async def get_user_audit_trail(
    user_id: str,
    days: int = Query(default=30, le=365),
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """Get complete audit trail for a user."""
    trail = await audit_service.get_user_trail(
        user_id=user_id,
        days=days,
    )
    return {
        "user_id": user_id,
        "period_days": days,
        "events": trail,
        "total_events": len(trail),
    }


@router.get("/report")
async def generate_audit_report(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format: str = Query(default="json", pattern="^(json|csv|pdf)$"),
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """
    Generate compliance audit report in JSON or CSV format.
    """
    report = await audit_service.generate_report(
        start_date=start_date or (utc_now() - timedelta(days=30)),
        end_date=end_date or (utc_now() + timedelta(minutes=1)),
    )

    if format == "csv":
        csv_text = audit_service.export_report_csv(report)
        return PlainTextResponse(content=csv_text, media_type="text/csv")

    return report


@router.get("/anomalies")
async def detect_anomalies(
    days: int = Query(default=7, le=30),
    principal: UserPrincipal = Depends(require_permission("audit_read")),
):
    """Detect access anomalies (bulk access, failed attempts, multi-IP spikes)."""
    anomalies = await audit_service.detect_anomalies(days=days)
    return {"anomalies": anomalies, "period_days": days}
