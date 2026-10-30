"""Data Masking Endpoints"""

import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, Body, Depends, HTTPException
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.models.mask import MaskingStrategy, MaskRequest, MaskResult
from src.services.registry import audit_service, masking_service

router = APIRouter()
logger = structlog.get_logger()


@router.post("", response_model=MaskResult, include_in_schema=False)
@router.post("/data", response_model=MaskResult)
async def mask_data(
    request: MaskRequest,
    principal: UserPrincipal = Depends(require_permission("mask")),
):
    """
    Apply HIPAA-compliant masking to sensitive data.

    Strategies:
    - REDACT: Replace with [REDACTED]
    - HASH: Keyed HMAC-SHA256 hash (one-way)
    - TOKENIZE: Reversible token stored in encrypted vault
    - GENERALIZE: Reduce precision per HIPAA Safe Harbor
    - ENCRYPT: Authenticated AES-256-GCM encryption
    """
    start_time = time.perf_counter()
    effective_user = request.user_id or principal.user_id
    try:
        masked_data, transformations = await masking_service.mask_data(
            data=request.data,
            field_configs=request.field_configs,
            default_strategy=request.default_strategy,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="data_mask",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "fields_masked": len(transformations),
                "strategy": request.default_strategy.value,
            },
        )

        reversible = any(
            t.strategy in (MaskingStrategy.TOKENIZE, MaskingStrategy.ENCRYPT)
            for t in transformations
        )

        return MaskResult(
            reference_id=request.reference_id,
            masked_data=masked_data,
            transformations=transformations,
            reversible=reversible,
        )

    except Exception as e:
        logger.error("masking_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unmask")
async def unmask_data(
    data: Dict[str, Any] = Body(...),
    tokens: Optional[Dict[str, str]] = Body(default=None),
    reference_id: Optional[str] = Body(default=None),
    principal: UserPrincipal = Depends(require_permission("unmask", require_mfa=True)),
):
    """
    Reverse tokenization or encryption (requires authorized role and MFA).
    """
    start_time = time.perf_counter()
    try:
        unmasked_data = await masking_service.unmask_data(data, tokens)
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="data_unmask",
            resource_type="data",
            resource_id=reference_id,
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={"fields_unmasked": len(tokens or {})},
        )

        return {"data": unmasked_data}

    except Exception as e:
        logger.error("unmask_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto")
async def auto_mask(
    data: Dict[str, Any] = Body(...),
    scan_first: bool = Body(default=True),
    reference_id: Optional[str] = Body(default=None),
    principal: UserPrincipal = Depends(require_permission("mask")),
):
    """
    Automatically detect and mask PHI across both structured fields and free-text notes.
    """
    start_time = time.perf_counter()
    try:
        result = await masking_service.auto_mask(data, scan_first)
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="auto_mask",
            resource_type="data",
            resource_id=reference_id,
            user_id=principal.user_id,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "phi_detected": result["phi_count"],
                "fields_masked": result["masked_count"],
            },
        )

        return result

    except Exception as e:
        logger.error("auto_mask_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/strategies")
async def get_strategies():
    """Get available masking strategies."""
    return {
        "strategies": [
            {
                "name": "REDACT",
                "description": "Replace with [REDACTED]",
                "reversible": False,
                "use_case": "Display to unauthorized users",
            },
            {
                "name": "HASH",
                "description": "Keyed HMAC-SHA256 cryptographic hash",
                "reversible": False,
                "use_case": "Data linkage without exposing values",
            },
            {
                "name": "TOKENIZE",
                "description": "Replace with reversible vault token",
                "reversible": True,
                "use_case": "Secure processing with recovery option",
            },
            {
                "name": "GENERALIZE",
                "description": "HIPAA Safe Harbor generalization (90+ age, 3-digit ZIP, year)",
                "reversible": False,
                "use_case": "Analytics while preserving privacy",
            },
            {
                "name": "ENCRYPT",
                "description": "Authenticated AES-256-GCM encryption",
                "reversible": True,
                "use_case": "Secure storage with key management",
            },
        ]
    }
