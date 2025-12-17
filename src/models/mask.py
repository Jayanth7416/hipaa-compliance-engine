"""Data Masking Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum


class MaskingStrategy(str, Enum):
    """Available masking strategies"""
    REDACT = "redact"          # Replace with [REDACTED]
    HASH = "hash"              # SHA-256 hash
    TOKENIZE = "tokenize"      # Reversible tokenization
    GENERALIZE = "generalize"  # Reduce precision
    ENCRYPT = "encrypt"        # AES-256 encryption


class FieldMaskConfig(BaseModel):
    """Configuration for masking a specific field"""
    field_path: str  # JSON path to field (e.g., "patient.ssn")
    strategy: MaskingStrategy
    options: Optional[Dict[str, Any]] = None

    class Config:
        json_schema_extra = {
            "example": {
                "field_path": "patient.ssn",
                "strategy": "hash",
                "options": {"preserve_last_4": True}
            }
        }


class MaskRequest(BaseModel):
    """Request to mask data"""
    data: Dict[str, Any] = Field(..., description="Data to mask")
    field_configs: Optional[List[FieldMaskConfig]] = Field(
        None,
        description="Per-field masking configuration"
    )
    default_strategy: MaskingStrategy = Field(
        default=MaskingStrategy.REDACT,
        description="Default strategy for unspecified fields"
    )
    reference_id: Optional[str] = None
    user_id: Optional[str] = None


class MaskTransformation(BaseModel):
    """Record of a masking transformation"""
    field_path: str
    strategy: MaskingStrategy
    original_type: str
    token: Optional[str] = None  # For reversible operations


class MaskResult(BaseModel):
    """Result of masking operation"""
    reference_id: Optional[str]
    masked_data: Dict[str, Any]
    transformations: List[MaskTransformation]
    reversible: bool

    class Config:
        json_schema_extra = {
            "example": {
                "reference_id": "mask-12345",
                "masked_data": {
                    "patient": {
                        "name": "[REDACTED]",
                        "ssn": "a1b2c3d4e5f6..."
                    }
                },
                "transformations": [
                    {
                        "field_path": "patient.name",
                        "strategy": "redact",
                        "original_type": "string"
                    }
                ],
                "reversible": False
            }
        }


class GeneralizationRule(BaseModel):
    """Rule for generalizing data"""
    field_type: str
    method: str  # range, category, truncate
    params: Dict[str, Any]

    class Config:
        json_schema_extra = {
            "example": {
                "field_type": "age",
                "method": "range",
                "params": {"bucket_size": 10}  # 45 -> 40-50
            }
        }
