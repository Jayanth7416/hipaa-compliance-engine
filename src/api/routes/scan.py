"""PHI Scanning Endpoints"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File
from typing import List, Optional
from datetime import datetime
import structlog

from src.models.scan import ScanRequest, ScanResult, PHIFinding, ScanStatus
from src.services.phi_scanner import PHIScanner
from src.services.audit_service import AuditService

router = APIRouter()
logger = structlog.get_logger()

phi_scanner = PHIScanner()
audit_service = AuditService()


@router.post("/text", response_model=ScanResult)
async def scan_text(request: ScanRequest):
    """
    Scan text content for PHI

    Detects:
    - Patient names
    - SSN, MRN
    - Dates (DOB, admission)
    - Contact information
    - Medical terms
    """
    try:
        findings = await phi_scanner.scan_text(request.content)

        # Log audit trail
        await audit_service.log_access(
            action="phi_scan",
            resource_type="text",
            resource_id=request.reference_id,
            user_id=request.user_id,
            details={"findings_count": len(findings)}
        )

        return ScanResult(
            reference_id=request.reference_id,
            status=ScanStatus.COMPLETED,
            findings=findings,
            scanned_at=datetime.utcnow(),
            phi_detected=len(findings) > 0,
            risk_level=_calculate_risk_level(findings)
        )

    except Exception as e:
        logger.error("scan_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/document", response_model=ScanResult)
async def scan_document(
    file: UploadFile = File(...),
    reference_id: Optional[str] = None,
    background_tasks: BackgroundTasks = None
):
    """
    Scan uploaded document for PHI

    Supports: PDF, DOCX, TXT, CSV, JSON
    """
    allowed_types = [
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain",
        "text/csv",
        "application/json"
    ]

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}"
        )

    try:
        content = await file.read()
        findings = await phi_scanner.scan_document(content, file.content_type)

        return ScanResult(
            reference_id=reference_id or file.filename,
            status=ScanStatus.COMPLETED,
            findings=findings,
            scanned_at=datetime.utcnow(),
            phi_detected=len(findings) > 0,
            risk_level=_calculate_risk_level(findings)
        )

    except Exception as e:
        logger.error("document_scan_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def scan_batch(
    requests: List[ScanRequest],
    background_tasks: BackgroundTasks
):
    """
    Scan multiple items in batch (async)

    Returns job ID for status tracking
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=400,
            detail="Batch size exceeds maximum of 100"
        )

    job_id = await phi_scanner.create_batch_job(requests)
    background_tasks.add_task(phi_scanner.process_batch, job_id, requests)

    return {
        "job_id": job_id,
        "status": "processing",
        "total_items": len(requests)
    }


@router.get("/job/{job_id}")
async def get_job_status(job_id: str):
    """Get batch scan job status"""
    status = await phi_scanner.get_job_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


def _calculate_risk_level(findings: List[PHIFinding]) -> str:
    """Calculate risk level based on findings"""
    if not findings:
        return "none"

    high_risk_types = {"ssn", "medical_record_number", "health_plan_id"}
    medium_risk_types = {"name", "date_of_birth", "address"}

    has_high_risk = any(f.phi_type in high_risk_types for f in findings)
    has_medium_risk = any(f.phi_type in medium_risk_types for f in findings)

    if has_high_risk:
        return "high"
    elif has_medium_risk:
        return "medium"
    return "low"
