"""Compliance Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ComplianceStatus(str, Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Violation severity"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceCheck(BaseModel):
    """Result of a compliance check"""
    check_id: str
    resource_type: str
    resource_id: Optional[str]
    checks_performed: List[str]
    status: ComplianceStatus
    score: float = Field(ge=0, le=100)
    passed: List[str]
    failed: List[str]
    warnings: List[str]
    checked_at: datetime
    details: Dict[str, Any] = Field(default_factory=dict)


class ComplianceViolation(BaseModel):
    """Compliance violation record"""
    violation_id: str
    detected_at: datetime
    resource_type: str
    resource_id: Optional[str]
    policy_id: str
    policy_name: str
    severity: Severity
    description: str
    evidence: Dict[str, Any]
    status: str  # open, resolved, accepted
    resolution: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


class ComplianceReport(BaseModel):
    """HIPAA compliance report"""
    report_id: str
    generated_at: datetime
    period: str
    period_start: datetime
    period_end: datetime
    overall_status: ComplianceStatus
    compliance_score: float
    summary: Dict[str, Any]
    checks_summary: Dict[str, int]
    violations_summary: Dict[str, int]
    trends: Dict[str, List[float]]
    recommendations: List[str]
    detailed_findings: List[Dict[str, Any]]


class Policy(BaseModel):
    """Compliance policy definition"""
    policy_id: str
    name: str
    description: str
    category: str  # access_control, audit, encryption, etc.
    hipaa_reference: Optional[str]  # e.g., "164.312(a)(1)"
    severity: Severity
    rules: List[Dict[str, Any]]
    enabled: bool = True
    created_at: datetime
    updated_at: datetime


class PolicyValidation(BaseModel):
    """Result of policy validation"""
    policy_id: str
    policy_name: str
    status: ComplianceStatus
    violations: List[Dict[str, Any]]
    recommendations: List[str]


class HIPAARequirement(BaseModel):
    """HIPAA requirement definition"""
    requirement_id: str  # e.g., "164.312(a)(1)"
    name: str
    description: str
    category: str
    implementation_specs: List[str]
    status: ComplianceStatus
    evidence: List[str]
    last_assessed: datetime
