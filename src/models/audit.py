"""Audit Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class AuditLog(BaseModel):
    """Audit log entry"""
    log_id: str
    timestamp: datetime
    action: str
    resource_type: str
    resource_id: Optional[str]
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    details: Dict[str, Any] = Field(default_factory=dict)
    status: str  # success, failure
    duration_ms: Optional[int] = None

    class Config:
        json_schema_extra = {
            "example": {
                "log_id": "audit-12345",
                "timestamp": "2024-01-15T10:30:00Z",
                "action": "phi_access",
                "resource_type": "patient_record",
                "resource_id": "patient-67890",
                "user_id": "user-12345",
                "ip_address": "192.168.1.100",
                "details": {"fields_accessed": ["ssn", "diagnosis"]},
                "status": "success"
            }
        }


class AuditQuery(BaseModel):
    """Query parameters for audit logs"""
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    user_id: Optional[str] = None
    action: Optional[str] = None
    start_date: datetime
    end_date: datetime
    limit: int = 100
    offset: int = 0


class AuditReport(BaseModel):
    """Compliance audit report"""
    report_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_events: int
    events_by_action: Dict[str, int]
    events_by_resource_type: Dict[str, int]
    top_users: List[Dict[str, Any]]
    anomalies_detected: int
    compliance_score: float
    recommendations: List[str]


class AuditAnomaly(BaseModel):
    """Detected audit anomaly"""
    anomaly_id: str
    detected_at: datetime
    anomaly_type: str  # unusual_access, bulk_access, after_hours, failed_attempts
    severity: str  # low, medium, high, critical
    description: str
    affected_resources: List[str]
    user_id: Optional[str]
    details: Dict[str, Any]
    status: str  # open, investigating, resolved, false_positive


class RetentionPolicy(BaseModel):
    """Audit log retention policy"""
    policy_id: str
    resource_type: str
    retention_days: int = 2555  # 7 years default for HIPAA
    archive_after_days: int = 365
    delete_after_days: Optional[int] = None
    encryption_required: bool = True
