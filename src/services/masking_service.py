"""Data Masking Service"""

import hashlib
import secrets
import base64
from typing import Dict, Any, List, Tuple, Optional
import structlog

from src.models.mask import MaskingStrategy, FieldMaskConfig, MaskTransformation
from src.services.phi_scanner import PHIScanner

logger = structlog.get_logger()


class MaskingService:
    """
    Data masking service for PHI protection

    Supports multiple masking strategies:
    - REDACT: Replace with [REDACTED]
    - HASH: SHA-256 hash
    - TOKENIZE: Reversible tokenization
    - GENERALIZE: Reduce precision
    - ENCRYPT: AES-256 encryption
    """

    def __init__(self):
        self.token_store: Dict[str, str] = {}  # token -> original (in-memory for demo)
        self.phi_scanner = PHIScanner()

    async def mask_data(
        self,
        data: Dict[str, Any],
        field_configs: Optional[List[FieldMaskConfig]] = None,
        default_strategy: MaskingStrategy = MaskingStrategy.REDACT
    ) -> Tuple[Dict[str, Any], List[MaskTransformation]]:
        """
        Apply masking to data fields

        Args:
            data: Data to mask
            field_configs: Per-field masking configuration
            default_strategy: Default strategy for unspecified fields

        Returns:
            Tuple of (masked_data, transformations)
        """
        masked_data = data.copy()
        transformations = []

        # Build field config map
        config_map = {}
        if field_configs:
            for config in field_configs:
                config_map[config.field_path] = config

        # Process each field
        for field_path in self._get_all_paths(data):
            config = config_map.get(field_path)
            strategy = config.strategy if config else default_strategy

            value = self._get_nested_value(data, field_path)
            if value is None:
                continue

            masked_value, token = await self._apply_strategy(
                value=str(value),
                strategy=strategy,
                options=config.options if config else None
            )

            self._set_nested_value(masked_data, field_path, masked_value)

            transformations.append(MaskTransformation(
                field_path=field_path,
                strategy=strategy,
                original_type=type(value).__name__,
                token=token
            ))

        logger.info(
            "data_masked",
            fields_count=len(transformations),
            strategy=default_strategy.value
        )

        return masked_data, transformations

    async def _apply_strategy(
        self,
        value: str,
        strategy: MaskingStrategy,
        options: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Optional[str]]:
        """Apply masking strategy to a value"""
        options = options or {}

        if strategy == MaskingStrategy.REDACT:
            return "[REDACTED]", None

        elif strategy == MaskingStrategy.HASH:
            preserve_last = options.get("preserve_last_4", False)
            hashed = hashlib.sha256(value.encode()).hexdigest()
            if preserve_last and len(value) >= 4:
                return f"{hashed[:12]}...{value[-4:]}", None
            return hashed, None

        elif strategy == MaskingStrategy.TOKENIZE:
            token = f"TOK_{secrets.token_hex(8)}"
            self.token_store[token] = value
            return token, token

        elif strategy == MaskingStrategy.GENERALIZE:
            return self._generalize_value(value, options), None

        elif strategy == MaskingStrategy.ENCRYPT:
            # Simplified encryption for demo
            encrypted = base64.b64encode(value.encode()).decode()
            token = f"ENC_{secrets.token_hex(8)}"
            self.token_store[token] = value
            return encrypted, token

        return value, None

    def _generalize_value(self, value: str, options: Dict[str, Any]) -> str:
        """Generalize a value to reduce precision"""
        method = options.get("method", "truncate")

        if method == "range":
            # For numeric values, create ranges
            try:
                num = int(value)
                bucket_size = options.get("bucket_size", 10)
                lower = (num // bucket_size) * bucket_size
                upper = lower + bucket_size
                return f"{lower}-{upper}"
            except ValueError:
                return value[:3] + "***"

        elif method == "truncate":
            length = options.get("length", 3)
            return value[:length] + "***"

        elif method == "category":
            # Map to category
            categories = options.get("categories", {})
            return categories.get(value, "OTHER")

        return value

    async def unmask_data(
        self,
        data: Dict[str, Any],
        tokens: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Reverse tokenization/encryption

        Args:
            data: Masked data
            tokens: Map of field_path -> token

        Returns:
            Unmasked data
        """
        unmasked_data = data.copy()

        for field_path, token in tokens.items():
            original = self.token_store.get(token)
            if original:
                self._set_nested_value(unmasked_data, field_path, original)

        logger.info("data_unmasked", fields_count=len(tokens))

        return unmasked_data

    async def auto_mask(
        self,
        data: Dict[str, Any],
        scan_first: bool = True
    ) -> Dict[str, Any]:
        """
        Automatically detect and mask PHI

        Args:
            data: Data to process
            scan_first: Whether to scan for PHI first

        Returns:
            Result with masked data and metadata
        """
        phi_count = 0
        masked_fields = []

        if scan_first:
            # Scan for PHI
            text_content = self._data_to_text(data)
            findings = await self.phi_scanner.scan_text(text_content)
            phi_count = len(findings)

        # Apply masking based on common PHI field names
        phi_field_patterns = [
            "ssn", "social_security", "patient_id", "mrn",
            "dob", "date_of_birth", "birth_date",
            "phone", "email", "address", "zip",
            "name", "first_name", "last_name",
            "insurance_id", "policy_number"
        ]

        masked_data = data.copy()
        for field_path in self._get_all_paths(data):
            field_name = field_path.split(".")[-1].lower()
            if any(pattern in field_name for pattern in phi_field_patterns):
                value = self._get_nested_value(data, field_path)
                if value:
                    masked_value, _ = await self._apply_strategy(
                        str(value),
                        MaskingStrategy.REDACT
                    )
                    self._set_nested_value(masked_data, field_path, masked_value)
                    masked_fields.append(field_path)

        return {
            "masked_data": masked_data,
            "phi_count": phi_count,
            "masked_count": len(masked_fields),
            "masked_fields": masked_fields
        }

    def _get_all_paths(self, data: Dict[str, Any], prefix: str = "") -> List[str]:
        """Get all field paths in nested dictionary"""
        paths = []
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                paths.extend(self._get_all_paths(value, path))
            else:
                paths.append(path)
        return paths

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary by path"""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def _set_nested_value(self, data: Dict[str, Any], path: str, value: Any):
        """Set value in nested dictionary by path"""
        keys = path.split(".")
        current = data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def _data_to_text(self, data: Dict[str, Any]) -> str:
        """Convert data dictionary to searchable text"""
        parts = []
        for path in self._get_all_paths(data):
            value = self._get_nested_value(data, path)
            parts.append(f"{path}: {value}")
        return " ".join(parts)
