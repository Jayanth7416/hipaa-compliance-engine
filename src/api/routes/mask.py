"""Data Masking Endpoints"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Optional
import structlog

from src.models.mask import (
    MaskRequest,
    MaskResult,
    MaskingStrategy,
    FieldMaskConfig
)
from src.services.masking_service import MaskingService
from src.services.audit_service import AuditService

router = APIRouter()
logger = structlog.get_logger()

masking_service = MaskingService()
audit_service = AuditService()


@router.post("/data", response_model=MaskResult)
async def mask_data(request: MaskRequest):
    """
    Apply masking to sensitive data

    Strategies:
    - REDACT: Replace with [REDACTED]
    - HASH: SHA-256 hash (one-way)
    - TOKENIZE: Reversible token
    - GENERALIZE: Reduce precision
    - ENCRYPT: AES-256 encryption
    """
    try:
        masked_data, transformations = await masking_service.mask_data(
            data=request.data,
            field_configs=request.field_configs,
            default_strategy=request.default_strategy
        )

        # Audit log
        await audit_service.log_access(
            action="data_mask",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=request.user_id,
            details={
                "fields_masked": len(transformations),
                "strategy": request.default_strategy.value
            }
        )

        return MaskResult(
            reference_id=request.reference_id,
            masked_data=masked_data,
            transformations=transformations,
            reversible=request.default_strategy in [
                MaskingStrategy.TOKENIZE,
                MaskingStrategy.ENCRYPT
            ]
        )

    except Exception as e:
        logger.error("masking_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unmask")
async def unmask_data(
    data: Dict[str, Any],
    tokens: Dict[str, str],
    reference_id: Optional[str] = None
):
    """
    Reverse tokenization/encryption (requires authorization)

    Only works for TOKENIZE and ENCRYPT strategies
    """
    try:
        unmasked_data = await masking_service.unmask_data(data, tokens)

        await audit_service.log_access(
            action="data_unmask",
            resource_type="data",
            resource_id=reference_id,
            details={"fields_unmasked": len(tokens)}
        )

        return {"data": unmasked_data}

    except Exception as e:
        logger.error("unmask_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto")
async def auto_mask(
    data: Dict[str, Any],
    scan_first: bool = True,
    reference_id: Optional[str] = None
):
    """
    Automatically detect and mask PHI

    1. Scans data for PHI
    2. Applies appropriate masking strategy
    3. Returns masked data with audit trail
    """
    try:
        result = await masking_service.auto_mask(data, scan_first)

        await audit_service.log_access(
            action="auto_mask",
            resource_type="data",
            resource_id=reference_id,
            details={
                "phi_detected": result["phi_count"],
                "fields_masked": result["masked_count"]
            }
        )

        return result

    except Exception as e:
        logger.error("auto_mask_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/strategies")
async def get_strategies():
    """Get available masking strategies"""
    return {
        "strategies": [
            {
                "name": "REDACT",
                "description": "Replace with [REDACTED]",
                "reversible": False,
                "use_case": "Display to unauthorized users"
            },
            {
                "name": "HASH",
                "description": "SHA-256 cryptographic hash",
                "reversible": False,
                "use_case": "Data linkage without exposing values"
            },
            {
                "name": "TOKENIZE",
                "description": "Replace with reversible token",
                "reversible": True,
                "use_case": "Secure processing with recovery option"
            },
            {
                "name": "GENERALIZE",
                "description": "Reduce precision (e.g., age ranges)",
                "reversible": False,
                "use_case": "Analytics while preserving privacy"
            },
            {
                "name": "ENCRYPT",
                "description": "AES-256 encryption",
                "reversible": True,
                "use_case": "Secure storage with key management"
            }
        ]
    }
