"""Data Masking & HIPAA Safe Harbor De-Identification Service"""

import copy
import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
import structlog

from src.models.mask import FieldMaskConfig, MaskingStrategy, MaskTransformation
from src.services.encryption_service import ENVELOPE_PREFIX, EncryptionService
from src.services.phi_scanner import PHIScanner
from src.utils.config import settings
from src.utils.database import TokenVaultModel, get_db_session, utc_now

logger = structlog.get_logger()

# HIPAA Safe Harbor (§164.514(b)(2)(i)(B)) restricted 3-digit ZIP prefixes (<20,000 population)
SAFE_HARBOR_RESTRICTED_ZIP_PREFIXES = {
    "036", "059", "063", "102", "203", "556", "692", "790", "821",
    "823", "830", "831", "878", "879", "884", "890", "893",
}


class MaskingService:
    """
    Data masking and de-identification service for PHI protection.

    Supports multiple masking strategies:
    - REDACT: Replace with [REDACTED]
    - HASH: Keyed HMAC-SHA256 hash (prevents rainbow-table reversal on SSNs/DOBs)
    - TOKENIZE: Reversible tokenization backed by encrypted SQLite/PostgreSQL vault
    - GENERALIZE: HIPAA Safe Harbor generalization (90+ age top-coding, 3-digit ZIP, year-only dates)
    - ENCRYPT: Authenticated AES-256-GCM encryption via EncryptionService
    """

    def __init__(
        self,
        phi_scanner: Optional[PHIScanner] = None,
        encryption_service: Optional[EncryptionService] = None,
    ):
        self.token_store: Dict[str, str] = {}
        self.phi_scanner = phi_scanner or PHIScanner()
        self.encryption_service = encryption_service or EncryptionService()

    def _compute_hmac(self, value: str) -> str:
        """Compute keyed HMAC-SHA256 digest using configured secret pepper."""
        pepper = settings.HASH_PEPPER.encode("utf-8")
        return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _store_token(self, token: str, original_value: str, field_path: Optional[str] = None) -> None:
        """Persist token mapping in memory cache and encrypted database vault."""
        self.token_store[token] = original_value
        encrypted_val = self.encryption_service.encrypt_value(original_value)
        val_hash = self._compute_hmac(original_value)
        with get_db_session() as db:
            existing = db.query(TokenVaultModel).filter_by(token=token).first()
            if not existing:
                db.add(
                    TokenVaultModel(
                        token=token,
                        encrypted_value=encrypted_val,
                        value_hash=val_hash,
                        field_path=field_path,
                        created_at=utc_now(),
                    )
                )
                db.commit()

    def _resolve_token(self, token: str) -> Optional[str]:
        """Resolve a token or AES-256-GCM envelope back to its original plaintext value."""
        if token in self.token_store:
            return self.token_store[token]

        if token.startswith(ENVELOPE_PREFIX):
            return self.encryption_service.decrypt_value(token)

        with get_db_session() as db:
            record = db.query(TokenVaultModel).filter_by(token=token).first()
            if record:
                plaintext = self.encryption_service.decrypt_value(record.encrypted_value)
                self.token_store[token] = plaintext
                return plaintext

        return None

    async def mask_data(
        self,
        data: Dict[str, Any],
        field_configs: Optional[List[FieldMaskConfig]] = None,
        default_strategy: MaskingStrategy = MaskingStrategy.REDACT,
    ) -> Tuple[Dict[str, Any], List[MaskTransformation]]:
        """
        Apply masking to data fields without mutating caller's input dictionary.
        """
        masked_data = copy.deepcopy(data)
        transformations: List[MaskTransformation] = []

        config_map: Dict[str, FieldMaskConfig] = {}
        if field_configs:
            for config in field_configs:
                config_map[config.field_path] = config

        for field_path in self._get_all_paths(masked_data):
            config = config_map.get(field_path)
            strategy = config.strategy if config else default_strategy

            value = self._get_nested_value(masked_data, field_path)
            if value is None:
                continue

            options = dict(config.options) if (config and config.options) else {}
            if "field_name" not in options:
                options["field_name"] = field_path.split(".")[-1].lower()

            masked_value, token = await self._apply_strategy(
                value=str(value),
                strategy=strategy,
                options=options,
                field_path=field_path,
            )

            self._set_nested_value(masked_data, field_path, masked_value)

            transformations.append(
                MaskTransformation(
                    field_path=field_path,
                    strategy=strategy,
                    original_type=type(value).__name__,
                    token=token,
                )
            )

        logger.info(
            "data_masked",
            fields_count=len(transformations),
            strategy=default_strategy.value,
        )

        return masked_data, transformations

    async def _apply_strategy(
        self,
        value: str,
        strategy: MaskingStrategy,
        options: Optional[Dict[str, Any]] = None,
        field_path: Optional[str] = None,
    ) -> Tuple[str, Optional[str]]:
        """Apply a specific masking strategy to a string value."""
        options = options or {}

        if strategy == MaskingStrategy.REDACT:
            return "[REDACTED]", None

        if strategy == MaskingStrategy.HASH:
            preserve_last = options.get("preserve_last_4", False)
            hashed = self._compute_hmac(value)
            if preserve_last and len(value) >= 4:
                return f"{hashed[:12]}...{value[-4:]}", None
            return hashed, None

        if strategy == MaskingStrategy.TOKENIZE:
            deterministic = options.get("deterministic", False)
            if deterministic:
                digest = self._compute_hmac(value)[:16]
                token = f"TOK_{digest}"
            else:
                token = f"TOK_{secrets.token_hex(8)}"
            self._store_token(token, value, field_path=field_path)
            return token, token

        if strategy == MaskingStrategy.GENERALIZE:
            return self._generalize_value(value, options), None

        if strategy == MaskingStrategy.ENCRYPT:
            ciphertext = self.encryption_service.encrypt_value(value)
            token = f"ENC_{secrets.token_hex(8)}"
            self._store_token(token, value, field_path=field_path)
            return ciphertext, token

        return value, None

    def _generalize_value(self, value: str, options: Dict[str, Any]) -> str:
        """
        Generalize a value to reduce precision per HIPAA Safe Harbor (§164.514(b)(2)).

        Handles:
        - Ages >= 90 top-coded to '90+'
        - ZIP codes truncated to 3 digits ('000***' for restricted low-population prefixes)
        - Dates generalized to 4-digit year
        - Custom range, truncate, and category rules
        """
        field_name = str(options.get("field_name", "")).lower()
        method = options.get("method")

        # Auto-select Safe Harbor method based on field name or value format if not explicitly overridden
        if not method:
            if any(k in field_name for k in ("age",)):
                method = "range"
            elif any(k in field_name for k in ("zip", "postal")):
                method = "safe_harbor_zip"
            elif any(k in field_name for k in ("dob", "birth", "date", "admit", "discharge")):
                method = "safe_harbor_date"
            else:
                method = "truncate"

        if method in ("safe_harbor_zip", "zip"):
            digits = re.sub(r"\D", "", value)
            if len(digits) >= 3:
                prefix = digits[:3]
                if prefix in SAFE_HARBOR_RESTRICTED_ZIP_PREFIXES:
                    return "000**"
                return f"{prefix}**"
            return "***"

        if method in ("safe_harbor_date", "date"):
            year_match = re.search(r"\b(19\d{2}|20\d{2})\b", value)
            if year_match:
                year = int(year_match.group(1))
                current_year = utc_now().year
                if current_year - year >= 90:
                    return f"<={current_year - 90}"
                return str(year)
            return value[:4] + "***"

        if method in ("range", "safe_harbor_age"):
            try:
                num = int(float(value))
                # HIPAA Safe Harbor rule: all ages over 89 must be aggregated into 90+
                if num >= 90:
                    return "90+"
                bucket_size = int(options.get("bucket_size", 10))
                lower = (num // bucket_size) * bucket_size
                upper = min(89, lower + bucket_size)
                return f"{lower}-{upper}"
            except ValueError:
                return value[:3] + "***"

        if method == "truncate":
            length = int(options.get("length", 3))
            return value[:length] + "***"

        if method == "category":
            categories = options.get("categories", {})
            return categories.get(value, "OTHER")

        return value

    async def unmask_data(
        self,
        data: Dict[str, Any],
        tokens: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Reverse tokenization or AES-256-GCM encryption.

        Supports both an explicit `tokens` map (field_path -> token) and automatic
        detection of `TOK_...` tokens or `ENCv1:...` ciphertexts in `data`.
        """
        unmasked_data = copy.deepcopy(data)

        if tokens:
            for field_path, token in tokens.items():
                original = self._resolve_token(token)
                if original is not None:
                    self._set_nested_value(unmasked_data, field_path, original)

        # Also auto-unmask any field whose current value is a vault token or AES-256-GCM envelope
        for field_path in self._get_all_paths(unmasked_data):
            current_val = self._get_nested_value(unmasked_data, field_path)
            if isinstance(current_val, str) and (
                current_val.startswith("TOK_") or current_val.startswith(ENVELOPE_PREFIX)
            ):
                original = self._resolve_token(current_val)
                if original is not None:
                    self._set_nested_value(unmasked_data, field_path, original)

        logger.info("data_unmasked", fields_count=len(tokens or {}))
        return unmasked_data

    async def auto_mask(
        self,
        data: Dict[str, Any],
        scan_first: bool = True,
    ) -> Dict[str, Any]:
        """
        Automatically detect and mask PHI in both structured fields and unstructured free text.
        """
        masked_data = copy.deepcopy(data)
        phi_count = 0
        masked_fields: List[str] = []

        if scan_first:
            text_content = self._data_to_text(masked_data)
            findings = await self.phi_scanner.scan_text(text_content)
            phi_count = len(findings)

        phi_field_strategies: Dict[str, MaskingStrategy] = {
            "ssn": MaskingStrategy.REDACT,
            "social_security": MaskingStrategy.REDACT,
            "patient_id": MaskingStrategy.REDACT,
            "mrn": MaskingStrategy.REDACT,
            "medical_record": MaskingStrategy.REDACT,
            "dob": MaskingStrategy.GENERALIZE,
            "date_of_birth": MaskingStrategy.GENERALIZE,
            "birth_date": MaskingStrategy.GENERALIZE,
            "age": MaskingStrategy.GENERALIZE,
            "zip": MaskingStrategy.GENERALIZE,
            "zip_code": MaskingStrategy.GENERALIZE,
            "phone": MaskingStrategy.REDACT,
            "fax": MaskingStrategy.REDACT,
            "email": MaskingStrategy.REDACT,
            "address": MaskingStrategy.REDACT,
            "name": MaskingStrategy.REDACT,
            "first_name": MaskingStrategy.REDACT,
            "last_name": MaskingStrategy.REDACT,
            "insurance_id": MaskingStrategy.REDACT,
            "policy_number": MaskingStrategy.REDACT,
            "health_plan": MaskingStrategy.REDACT,
            "account_number": MaskingStrategy.REDACT,
            "license_number": MaskingStrategy.REDACT,
        }

        for field_path in self._get_all_paths(masked_data):
            field_name = field_path.split(".")[-1].lower()
            value = self._get_nested_value(masked_data, field_path)
            if value is None or value == "":
                continue

            matched_strategy: Optional[MaskingStrategy] = None
            for pattern, strat in phi_field_strategies.items():
                if pattern in field_name:
                    matched_strategy = strat
                    break

            if matched_strategy is not None:
                # For structured PHI fields, default to REDACT for direct identifiers or Safe Harbor
                masked_value, _ = await self._apply_strategy(
                    str(value),
                    MaskingStrategy.REDACT,
                    options={"field_name": field_name},
                    field_path=field_path,
                )
                self._set_nested_value(masked_data, field_path, masked_value)
                masked_fields.append(field_path)
            elif isinstance(value, str):
                # Scan unstructured text field (e.g., clinical notes) and redact inline PHI spans
                inline_findings = await self.phi_scanner.scan_text(
                    value, include_original=True
                )
                if inline_findings:
                    redacted_text = self._redact_inline_findings(value, inline_findings)
                    self._set_nested_value(masked_data, field_path, redacted_text)
                    masked_fields.append(field_path)

        return {
            "masked_data": masked_data,
            "phi_count": max(phi_count, len(masked_fields)),
            "masked_count": len(masked_fields),
            "masked_fields": masked_fields,
        }

    @staticmethod
    def _redact_inline_findings(text: str, findings: List[Any]) -> str:
        """Replace inline PHI spans in free text with [REDACTED:<PHI_TYPE>]."""
        replacements: List[Tuple[int, int, str]] = []
        for f in findings:
            start = f.location.get("start")
            end = f.location.get("end")
            if isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(text):
                replacements.append((start, end, f"[REDACTED:{f.phi_type.value.upper()}]"))

        # Sort in reverse order by start index so offsets remain valid
        replacements.sort(key=lambda item: item[0], reverse=True)
        result = text
        last_start = len(text) + 1
        for start, end, token in replacements:
            if end <= last_start:
                result = result[:start] + token + result[end:]
                last_start = start
        return result

    def _get_all_paths(self, data: Any, prefix: str = "") -> List[str]:
        """Get all leaf field paths in nested dictionaries and lists."""
        paths: List[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, (dict, list)):
                    paths.extend(self._get_all_paths(value, path))
                else:
                    paths.append(path)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                path = f"{prefix}.{idx}" if prefix else str(idx)
                if isinstance(item, (dict, list)):
                    paths.extend(self._get_all_paths(item, path))
                else:
                    paths.append(path)
        return paths

    def _get_nested_value(self, data: Any, path: str) -> Any:
        """Get value from nested dictionary/list by dot-path."""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
                value = value[int(key)]
            else:
                return None
        return value

    def _set_nested_value(self, data: Any, path: str, value: Any) -> None:
        """Set value in nested dictionary/list by dot-path."""
        keys = path.split(".")
        current = data
        for key in keys[:-1]:
            if isinstance(current, list) and key.isdigit():
                current = current[int(key)]
            else:
                if key not in current or not isinstance(current[key], (dict, list)):
                    current[key] = {}
                current = current[key]
        last_key = keys[-1]
        if isinstance(current, list) and last_key.isdigit():
            current[int(last_key)] = value
        else:
            current[last_key] = value

    def _data_to_text(self, data: Dict[str, Any]) -> str:
        """Convert data dictionary to searchable text."""
        parts = []
        for path in self._get_all_paths(data):
            value = self._get_nested_value(data, path)
            parts.append(f"{path}: {value}")
        return " ".join(parts)
