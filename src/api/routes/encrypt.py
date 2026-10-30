"""Encryption Endpoints"""

import time
from fastapi import APIRouter, Depends, HTTPException
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.models.encrypt import (
    DecryptRequest,
    EncryptRequest,
    EncryptResult,
    KeyRotationRequest,
)
from src.services.registry import audit_service, encryption_service

router = APIRouter()
logger = structlog.get_logger()


@router.post("", response_model=EncryptResult, include_in_schema=False)
@router.post("/data", response_model=EncryptResult)
async def encrypt_data(
    request: EncryptRequest,
    principal: UserPrincipal = Depends(require_permission("encrypt")),
):
    """
    Encrypt sensitive data fields using authenticated AES-256-GCM.
    """
    start_time = time.perf_counter()
    effective_user = request.user_id or principal.user_id
    try:
        encrypted_data, key_metadata = await encryption_service.encrypt_fields(
            data=request.data,
            fields=request.fields,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="encrypt",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "fields_encrypted": len(request.fields),
                "key_id": key_metadata["key_id"],
            },
        )

        return EncryptResult(
            reference_id=request.reference_id,
            encrypted_data=encrypted_data,
            key_id=key_metadata["key_id"],
            algorithm="AES-256-GCM",
        )

    except Exception as e:
        logger.error("encryption_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decrypt")
async def decrypt_data(
    request: DecryptRequest,
    principal: UserPrincipal = Depends(require_permission("decrypt", require_mfa=True)),
):
    """
    Decrypt previously encrypted data fields and verify AES-256-GCM authentication tag.
    """
    start_time = time.perf_counter()
    effective_user = request.user_id or principal.user_id
    try:
        decrypted_data = await encryption_service.decrypt_fields(
            data=request.data,
            fields=request.fields,
            key_id=request.key_id,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        await audit_service.log_access(
            action="decrypt",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            duration_ms=duration_ms,
            details={
                "fields_decrypted": len(request.fields),
                "key_id": request.key_id or encryption_service.active_key_id,
            },
        )

        return {"data": decrypted_data}

    except ValueError as e:
        await audit_service.log_access(
            action="decrypt",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            status="failure",
            details={"error": str(e)},
        )
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("decryption_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rotate-key")
async def rotate_encryption_key(
    request: KeyRotationRequest,
    principal: UserPrincipal = Depends(require_permission("rotate_key", require_mfa=True)),
):
    """
    Rotate encryption keys and re-encrypt vault / supplied records.
    """
    effective_user = request.user_id or principal.user_id
    try:
        result = await encryption_service.rotate_key(
            old_key_id=request.old_key_id,
            scope=request.scope,
            records=request.records,
            fields=request.fields,
        )

        await audit_service.log_access(
            action="key_rotation",
            resource_type="encryption_key",
            resource_id=request.old_key_id,
            user_id=effective_user,
            ip_address=principal.ip_address,
            user_agent=principal.user_agent,
            details={
                "new_key_id": result["new_key_id"],
                "records_updated": result["records_updated"],
            },
        )

        return result

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error("key_rotation_failed", error=type(e).__name__)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/keys")
async def list_encryption_keys(
    principal: UserPrincipal = Depends(require_permission("encrypt")),
):
    """List available encryption keys."""
    keys = await encryption_service.list_keys()
    return {"keys": keys}
