"""Encryption Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EncryptRequest(BaseModel):
    """Request to encrypt data"""
    data: Dict[str, Any] = Field(..., description="Data containing fields to encrypt")
    fields: List[str] = Field(..., description="Field paths to encrypt")
    reference_id: Optional[str] = None
    user_id: Optional[str] = None


class EncryptResult(BaseModel):
    """Result of encryption operation"""
    reference_id: Optional[str]
    encrypted_data: Dict[str, Any]
    key_id: str
    algorithm: str

    class Config:
        json_schema_extra = {
            "example": {
                "reference_id": "enc-12345",
                "encrypted_data": {
                    "patient": {
                        "ssn": "AQICAHh...encrypted...=="
                    }
                },
                "key_id": "alias/hipaa-key",
                "algorithm": "AES-256-GCM"
            }
        }


class DecryptRequest(BaseModel):
    """Request to decrypt data"""
    data: Dict[str, Any] = Field(..., description="Data containing encrypted fields")
    fields: List[str] = Field(..., description="Field paths to decrypt")
    key_id: str = Field(..., description="KMS key ID used for encryption")
    reference_id: Optional[str] = None
    user_id: Optional[str] = None


class KeyRotationRequest(BaseModel):
    """Request to rotate encryption keys"""
    old_key_id: str = Field(..., description="Current key to rotate from")
    scope: Optional[str] = Field(None, description="Scope of rotation (all, resource_type)")
    user_id: Optional[str] = None


class EncryptionKey(BaseModel):
    """Encryption key metadata"""
    key_id: str
    alias: str
    algorithm: str
    created_at: datetime
    rotated_at: Optional[datetime] = None
    status: str  # active, pending_rotation, retired
    usage_count: int


class KeyPolicy(BaseModel):
    """Key usage policy"""
    key_id: str
    allowed_users: List[str]
    allowed_roles: List[str]
    allowed_operations: List[str]  # encrypt, decrypt, rotate
    require_mfa: bool = False
    audit_all_usage: bool = True
