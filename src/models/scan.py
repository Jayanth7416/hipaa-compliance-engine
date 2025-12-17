"""PHI Scanning Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class PHIType(str, Enum):
    """Types of Protected Health Information"""
    NAME = "name"
    SSN = "ssn"
    MEDICAL_RECORD_NUMBER = "medical_record_number"
    HEALTH_PLAN_ID = "health_plan_id"
    ACCOUNT_NUMBER = "account_number"
    DATE_OF_BIRTH = "date_of_birth"
    ADMISSION_DATE = "admission_date"
    DISCHARGE_DATE = "discharge_date"
    PHONE_NUMBER = "phone_number"
    FAX_NUMBER = "fax_number"
    EMAIL = "email"
    ADDRESS = "address"
    ZIP_CODE = "zip_code"
    IP_ADDRESS = "ip_address"
    DEVICE_IDENTIFIER = "device_identifier"
    URL = "url"
    BIOMETRIC = "biometric"
    PHOTO = "photo"
    DIAGNOSIS_CODE = "diagnosis_code"
    PROCEDURE_CODE = "procedure_code"


class ScanStatus(str, Enum):
    """Scan job status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class PHIFinding(BaseModel):
    """Individual PHI finding from scan"""
    phi_type: PHIType
    value: str  # Masked value for display
    original_value: Optional[str] = None  # Only included if authorized
    location: Dict[str, Any]  # Position in document/text
    confidence: float = Field(ge=0, le=1)
    context: Optional[str] = None  # Surrounding text (masked)

    class Config:
        json_schema_extra = {
            "example": {
                "phi_type": "ssn",
                "value": "***-**-1234",
                "location": {"start": 45, "end": 56, "field": "patient_ssn"},
                "confidence": 0.98,
                "context": "Patient SSN: ***-**-1234"
            }
        }


class ScanRequest(BaseModel):
    """Request to scan content for PHI"""
    content: str = Field(..., description="Text content to scan")
    reference_id: Optional[str] = Field(None, description="Reference ID for tracking")
    user_id: Optional[str] = Field(None, description="User performing scan")
    categories: Optional[List[PHIType]] = Field(None, description="PHI types to detect")
    confidence_threshold: float = Field(default=0.8, ge=0, le=1)


class ScanResult(BaseModel):
    """Result of PHI scan"""
    reference_id: Optional[str]
    status: ScanStatus
    findings: List[PHIFinding]
    scanned_at: datetime
    phi_detected: bool
    risk_level: str  # none, low, medium, high
    summary: Optional[Dict[str, int]] = None  # Count by PHI type

    class Config:
        json_schema_extra = {
            "example": {
                "reference_id": "doc-12345",
                "status": "completed",
                "findings": [],
                "scanned_at": "2024-01-15T10:30:00Z",
                "phi_detected": True,
                "risk_level": "medium"
            }
        }


class BatchScanJob(BaseModel):
    """Batch scanning job"""
    job_id: str
    status: ScanStatus
    total_items: int
    processed_items: int
    failed_items: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[List[ScanResult]] = None
