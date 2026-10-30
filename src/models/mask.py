"""Data Masking Models"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MaskingStrategy(str, Enum):
    """Available masking strategies"""

    REDACT = "redact"          # Replace with [REDACTED]
    HASH = "hash"              # HMAC-SHA256 hash
    TOKENIZE = "tokenize"      # Reversible persistent tokenization
    GENERALIZE = "generalize"  # Reduce precision (Safe Harbor)
    ENCRYPT = "encrypt"        # AES-256-GCM encryption


class FieldMaskConfig(BaseModel):
    """Configuration for masking a specific field"""

    field_path: str  # JSON path to field (e.g., "patient.ssn")
    strategy: MaskingStrategy
    options: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "field_path": "patient.ssn",
                "strategy": "hash",
                "options": {"preserve_last_4": True},
            }
        }
    )


class MaskRequest(BaseModel):
    """Request to mask data"""

    data: Dict[str, Any] = Field(..., description="Data to mask")
    field_configs: Optional[List[FieldMaskConfig]] = Field(
        None,
        description="Per-field masking configuration",
    )
    default_strategy: MaskingStrategy = Field(
        default=MaskingStrategy.REDACT,
        description="Default strategy for unspecified fields",
    )
    reference_id: Optional[str] = None
    user_id: Optional[str] = None


class UnmaskRequest(BaseModel):
    """Request to unmask tokenized or encrypted fields"""

    data: Dict[str, Any] = Field(..., description="Masked data")
    tokens: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional map of field_path -> token (auto-detected if omitted)",
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

    reference_id: Optional[str] = None
    masked_data: Dict[str, Any]
    transformations: List[MaskTransformation]
    reversible: bool

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "reference_id": "mask-12345",
                "masked_data": {
                    "patient": {
                        "name": "[REDACTED]",
                        "ssn": "a1b2c3d4e5f6...",
                    }
                },
                "transformations": [
                    {
                        "field_path": "patient.name",
                        "strategy": "redact",
                        "original_type": "str",
                    }
                ],
                "reversible": False,
            }
        }
    )


class GeneralizationRule(BaseModel):
    """Rule for generalizing data"""

    field_type: str
    method: str  # range, category, truncate, safe_harbor_age, safe_harbor_zip, safe_harbor_date
    params: Dict[str, Any]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "field_type": "age",
                "method": "range",
                "params": {"bucket_size": 10},  # 45 -> 40-50, 92 -> 90+
            }
        }
    )
