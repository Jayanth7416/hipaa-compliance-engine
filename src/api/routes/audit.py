"""Audit Trail Endpoints"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from datetime import datetime, timedelta
import structlog

from src.models.audit import AuditLog, AuditQuery, AuditReport
from src.services.audit_service import AuditService

router = APIRouter()
logger = structlog.get_logger()

audit_service = AuditService()


@router.get("/logs")
async def get_audit_logs(
    resource_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0
):
    """
    Query audit logs

    Supports filtering by:
    - Resource ID/Type
    - User ID
    - Action type
    - Date range
    """
    query = AuditQuery(
        resource_id=resource_id,
        resource_type=resource_type,
        user_id=user_id,
        action=action,
        start_date=start_date or datetime.utcnow() - timedelta(days=30),
        end_date=end_date or datetime.utcnow(),
        limit=limit,
        offset=offset
    )

    logs = await audit_service.query_logs(query)
    total = await audit_service.count_logs(query)

    return {
        "logs": logs,
        "total": total,
        "limit": limit,
        "offset": offset
    }


@router.get("/logs/{log_id}")
async def get_audit_log(log_id: str):
    """Get specific audit log entry"""
    log = await audit_service.get_log(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return log


@router.get("/resource/{resource_id}")
async def get_resource_audit_trail(
    resource_id: str,
    days: int = Query(default=30, le=365)
):
    """
    Get complete audit trail for a resource

    Returns all access and modification events
    """
    trail = await audit_service.get_resource_trail(
        resource_id=resource_id,
        days=days
    )

    return {
        "resource_id": resource_id,
        "period_days": days,
        "events": trail,
        "total_events": len(trail)
    }


@router.get("/user/{user_id}")
async def get_user_audit_trail(
    user_id: str,
    days: int = Query(default=30, le=365)
):
    """
    Get audit trail for a user

    Returns all actions performed by user
    """
    trail = await audit_service.get_user_trail(
        user_id=user_id,
        days=days
    )

    return {
        "user_id": user_id,
        "period_days": days,
        "events": trail,
        "total_events": len(trail)
    }


@router.get("/report", response_model=AuditReport)
async def generate_audit_report(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format: str = Query(default="json", enum=["json", "csv", "pdf"])
):
    """
    Generate compliance audit report

    Includes:
    - Access summaries
    - Anomaly detection
    - Compliance status
    """
    report = await audit_service.generate_report(
        start_date=start_date or datetime.utcnow() - timedelta(days=30),
        end_date=end_date or datetime.utcnow()
    )

    return report


@router.get("/anomalies")
async def detect_anomalies(days: int = Query(default=7, le=30)):
    """
    Detect access anomalies

    Identifies:
    - Unusual access patterns
    - After-hours access
    - Bulk data access
    - Failed access attempts
    """
    anomalies = await audit_service.detect_anomalies(days=days)
    return {"anomalies": anomalies, "period_days": days}
