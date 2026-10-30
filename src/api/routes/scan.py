"""PHI Scanning Endpoints"""

import time
from typing import Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.models.scan import PHIFinding, ScanRequest, ScanResult, ScanStatus
from src.services.registry import audit_service, phi_scanner
from src.utils.config import settings
from src.utils.database import utc_now

router = APIRouter()
logger = structlog.get_logger()


def _summarize_findings(findings: List[PHIFinding]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for f in findings:
        key = f.phi_type.value
        summary[key] = summary.get(key, 0) + 1
    return summary


@router.post("", response_model=ScanResult, include_in_schema=False)
@router.post("/text", response_model=ScanResult)
async def scan_text(
    request: ScanRequest,
    principal: UserPrincipal = Depends(require_permission("scan")),
):
    """
    Scan text content for PHI across all 18 HIPAA Safe Harbor identifiers.
    """
    start_time = time.perf_counter()
    effective_user = request.user_id or principal.user_id

    try:
        findings = await phi_scanner.scan_text(
            content=request.content,
            categories=request.categories,
            confidence_threshold=request.confidence_threshold,
            include_original=request.include_original,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="phi_scan",
            resource_type="text",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "findings_count": len(findings),
                "confidence_threshold": request.confidence_threshold,
            },
        )

        return ScanResult(
            reference_id=request.reference_id,
            status=ScanStatus.COMPLETED,
            findings=findings,
            scanned_at=utc_now(),
            phi_detected=len(findings) > 0,
            risk_level=_calculate_risk_level(findings),
            summary=_summarize_findings(findings),
        )

    except Exception as e:
        logger.error("scan_failed", error=type(e).__name__)
        await audit_service.log_access(
            action="phi_scan",
            resource_type="text",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            status="failure",
            details={"error": type(e).__name__},
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/document", response_model=ScanResult)
async def scan_document(
    file: UploadFile = File(...),
    reference_id: Optional[str] = None,
    confidence_threshold: float = 0.8,
    background_tasks: BackgroundTasks = None,
    principal: UserPrincipal = Depends(require_permission("scan")),
):
    """
    Scan uploaded document for PHI.

    Supports: PDF, DOCX, TXT, CSV, JSON (enforces max upload size limit).
    """
    allowed_types = {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/docx",
        "text/plain",
        "text/csv",
        "application/json",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}",
        )

    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes",
        )

    start_time = time.perf_counter()
    try:
        findings = await phi_scanner.scan_document(
            content,
            file.content_type,
            confidence_threshold=confidence_threshold,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="phi_document_scan",
            resource_type="document",
            resource_id=reference_id or file.filename,
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "filename": file.filename,
                "content_type": file.content_type,
                "size_bytes": len(content),
                "findings_count": len(findings),
            },
        )

        return ScanResult(
            reference_id=reference_id or file.filename,
            status=ScanStatus.COMPLETED,
            findings=findings,
            scanned_at=utc_now(),
            phi_detected=len(findings) > 0,
            risk_level=_calculate_risk_level(findings),
            summary=_summarize_findings(findings),
        )

    except Exception as e:
        logger.error("document_scan_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def scan_batch(
    requests: List[ScanRequest],
    background_tasks: BackgroundTasks,
    principal: UserPrincipal = Depends(require_permission("scan")),
):
    """
    Scan multiple items in batch (async) with persistent job status tracking.
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=400,
            detail="Batch size exceeds maximum of 100",
        )

    job_id = await phi_scanner.create_batch_job(requests)
    background_tasks.add_task(phi_scanner.process_batch, job_id, requests)

    await audit_service.log_access(
        action="phi_batch_scan",
        resource_type="batch_job",
        resource_id=job_id,
        user_id=principal.user_id,
        ip_address=principal.ip_address,
        user_agent=principal.user_agent,
        details={"total_items": len(requests)},
    )

    return {
        "job_id": job_id,
        "status": "processing",
        "total_items": len(requests),
    }


@router.get("/job/{job_id}")
async def get_job_status(
    job_id: str,
    principal: UserPrincipal = Depends(require_permission("scan")),
):
    """Get batch scan job status."""
    status = await phi_scanner.get_job_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


def _calculate_risk_level(findings: List[PHIFinding]) -> str:
    """Calculate risk level based on findings."""
    if not findings:
        return "none"

    high_risk_types = {
        "ssn",
        "medical_record_number",
        "health_plan_id",
        "account_number",
        "biometric",
    }
    medium_risk_types = {
        "name",
        "date_of_birth",
        "address",
        "license_number",
        "diagnosis_code",
    }

    has_high_risk = any(f.phi_type.value in high_risk_types for f in findings)
    has_medium_risk = any(f.phi_type.value in medium_risk_types for f in findings)

    if has_high_risk:
        return "high"
    if has_medium_risk:
        return "medium"
    return "low"
