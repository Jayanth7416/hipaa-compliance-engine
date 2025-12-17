"""Encryption Endpoints"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Optional
import structlog

from src.models.encrypt import (
    EncryptRequest,
    EncryptResult,
    DecryptRequest,
    KeyRotationRequest
)
from src.services.encryption_service import EncryptionService
from src.services.audit_service import AuditService

router = APIRouter()
logger = structlog.get_logger()

encryption_service = EncryptionService()
audit_service = AuditService()


@router.post("/data", response_model=EncryptResult)
async def encrypt_data(request: EncryptRequest):
    """
    Encrypt sensitive data fields

    Uses AES-256-GCM with AWS KMS key management
    """
    try:
        encrypted_data, key_metadata = await encryption_service.encrypt_fields(
            data=request.data,
            fields=request.fields
        )

        await audit_service.log_access(
            action="encrypt",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=request.user_id,
            details={
                "fields_encrypted": len(request.fields),
                "key_id": key_metadata["key_id"]
            }
        )

        return EncryptResult(
            reference_id=request.reference_id,
            encrypted_data=encrypted_data,
            key_id=key_metadata["key_id"],
            algorithm="AES-256-GCM"
        )

    except Exception as e:
        logger.error("encryption_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decrypt")
async def decrypt_data(request: DecryptRequest):
    """
    Decrypt previously encrypted data

    Requires valid key access and audit logging
    """
    try:
        decrypted_data = await encryption_service.decrypt_fields(
            data=request.data,
            fields=request.fields,
            key_id=request.key_id
        )

        await audit_service.log_access(
            action="decrypt",
            resource_type="data",
            resource_id=request.reference_id,
            user_id=request.user_id,
            details={
                "fields_decrypted": len(request.fields),
                "key_id": request.key_id
            }
        )

        return {"data": decrypted_data}

    except Exception as e:
        logger.error("decryption_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rotate-key")
async def rotate_encryption_key(request: KeyRotationRequest):
    """
    Rotate encryption keys

    Re-encrypts data with new key and archives old key
    """
    try:
        result = await encryption_service.rotate_key(
            old_key_id=request.old_key_id,
            scope=request.scope
        )

        await audit_service.log_access(
            action="key_rotation",
            resource_type="encryption_key",
            resource_id=request.old_key_id,
            user_id=request.user_id,
            details={
                "new_key_id": result["new_key_id"],
                "records_updated": result["records_updated"]
            }
        )

        return result

    except Exception as e:
        logger.error("key_rotation_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/keys")
async def list_encryption_keys():
    """List available encryption keys"""
    keys = await encryption_service.list_keys()
    return {"keys": keys}
