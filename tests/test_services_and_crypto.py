"""Tests for AES-256-GCM Encryption, Safe Harbor Masking, Audit Hash Chain, and Policy Engine"""

import pytest

from src.models.mask import FieldMaskConfig, MaskingStrategy
from src.rules.policy_engine import PolicyEngine
from src.services.audit_service import AuditService
from src.services.compliance_service import ComplianceService
from src.services.encryption_service import ENVELOPE_PREFIX, EncryptionService
from src.services.masking_service import MaskingService


class TestEncryptionService:
    """Test AES-256-GCM encryption, tamper detection, and key rotation."""

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip_and_no_input_mutation(self):
        service = EncryptionService()
        original = {"patient": {"name": "Jane Doe", "ssn": "123-45-6789"}}

        encrypted, meta = await service.encrypt_fields(
            original, fields=["patient.ssn"]
        )

        # Ensure input dict was not mutated
        assert original["patient"]["ssn"] == "123-45-6789"
        assert encrypted["patient"]["ssn"].startswith(ENVELOPE_PREFIX)
        assert meta["algorithm"] == "AES-256-GCM"

        decrypted = await service.decrypt_fields(
            encrypted, fields=["patient.ssn"], key_id=meta["key_id"]
        )
        assert decrypted["patient"]["ssn"] == "123-45-6789"

    @pytest.mark.asyncio
    async def test_tampered_ciphertext_raises_error(self):
        service = EncryptionService()
        encrypted, meta = await service.encrypt_fields(
            {"ssn": "123-45-6789"}, fields=["ssn"]
        )
        # Corrupt the last character of the AES-GCM tag/ciphertext
        corrupted = encrypted["ssn"][:-2] + ("AA" if not encrypted["ssn"].endswith("AA") else "BB")

        with pytest.raises(ValueError, match="Decryption failed"):
            await service.decrypt_fields(
                {"ssn": corrupted}, fields=["ssn"], key_id=meta["key_id"]
            )

    @pytest.mark.asyncio
    async def test_key_rotation_reencrypts_records_and_preserves_old_keys(self):
        service = EncryptionService()
        old_key = service.active_key_id
        encrypted_rec, _ = await service.encrypt_fields(
            {"ssn": "123-45-6789"}, fields=["ssn"]
        )

        rotation = await service.rotate_key(
            old_key_id=old_key,
            records=[encrypted_rec],
            fields=["ssn"],
        )
        assert rotation["new_key_id"] != old_key
        assert rotation["records_updated"] >= 1

        # Historical ciphertext encrypted with old_key can still be decrypted
        decrypted_old = await service.decrypt_fields(
            encrypted_rec, fields=["ssn"], key_id=old_key
        )
        assert decrypted_old["ssn"] == "123-45-6789"

        # Re-encrypted record uses the new active key
        new_rec = rotation["reencrypted_records"][0]
        decrypted_new = await service.decrypt_fields(
            new_rec, fields=["ssn"], key_id=rotation["new_key_id"]
        )
        assert decrypted_new["ssn"] == "123-45-6789"


class TestMaskingService:
    """Test HMAC-SHA256 hashing, persistent vault tokenization, Safe Harbor generalization, and auto-masking."""

    @pytest.mark.asyncio
    async def test_all_masking_strategies_and_unmask(self):
        service = MaskingService()
        payload = {
            "name": "John Smith",
            "ssn": "123-45-6789",
            "mrn": "PAT123456",
            "age": 94,
            "zip_code": "03601",
            "dob": "1980-05-14",
            "secret_note": "Confidential",
        }
        configs = [
            FieldMaskConfig(field_path="name", strategy=MaskingStrategy.REDACT),
            FieldMaskConfig(
                field_path="ssn",
                strategy=MaskingStrategy.HASH,
                options={"preserve_last_4": True},
            ),
            FieldMaskConfig(field_path="mrn", strategy=MaskingStrategy.TOKENIZE),
            FieldMaskConfig(field_path="age", strategy=MaskingStrategy.GENERALIZE),
            FieldMaskConfig(field_path="zip_code", strategy=MaskingStrategy.GENERALIZE),
            FieldMaskConfig(field_path="dob", strategy=MaskingStrategy.GENERALIZE),
            FieldMaskConfig(field_path="secret_note", strategy=MaskingStrategy.ENCRYPT),
        ]

        masked, transformations = await service.mask_data(payload, field_configs=configs)

        assert masked["name"] == "[REDACTED]"
        assert masked["ssn"].endswith("...6789")
        assert masked["mrn"].startswith("TOK_")
        # HIPAA Safe Harbor: age >= 90 must be top-coded to 90+
        assert masked["age"] == "90+"
        # HIPAA Safe Harbor: 036 is a restricted low-population 3-digit ZIP prefix -> 000**
        assert masked["zip_code"] == "000**"
        # HIPAA Safe Harbor: date generalized to year only
        assert masked["dob"] == "1980"
        # AES-256-GCM encryption (not plain base64!)
        assert masked["secret_note"].startswith(ENVELOPE_PREFIX)

        # Unmask both tokenized and encrypted fields
        unmasked = await service.unmask_data(masked)
        assert unmasked["mrn"] == "PAT123456"
        assert unmasked["secret_note"] == "Confidential"

    @pytest.mark.asyncio
    async def test_auto_mask_redacts_both_structured_fields_and_free_text(self):
        service = MaskingService()
        data = {
            "patient_ssn": "123-45-6789",
            "clinical_notes": "Patient: John Smith called from (555) 234-5678 regarding SSN 123-45-6789.",
        }
        result = await service.auto_mask(data)

        assert result["masked_data"]["patient_ssn"] == "[REDACTED]"
        assert "123-45-6789" not in result["masked_data"]["clinical_notes"]
        assert "(555) 234-5678" not in result["masked_data"]["clinical_notes"]
        assert "[REDACTED:" in result["masked_data"]["clinical_notes"]


class TestAuditAndCompliance:
    """Test tamper-evident audit hash chain and policy validation."""

    @pytest.mark.asyncio
    async def test_audit_hash_chain_verification(self):
        audit = AuditService()
        await audit.log_access(action="phi_scan", resource_type="text", user_id="u1")
        await audit.log_access(action="encrypt", resource_type="data", user_id="u2")

        verification = await audit.verify_chain_integrity()
        assert verification["valid"] is True
        assert verification["entries_checked"] >= 2

    @pytest.mark.asyncio
    async def test_policy_engine_detects_unencrypted_phi_and_records_violation(self):
        engine = PolicyEngine()
        compliance = ComplianceService()

        # Payload with plaintext SSN and missing _audit / _checksum
        bad_payload = {"ssn": "123-45-6789"}
        result = await engine.validate(bad_payload)
        assert result["overall_status"] == "non_compliant"
        assert result["violations_count"] >= 1

        violations = await compliance.get_violations(status="open")
        assert len(violations) >= 1

        # Resolve the violation
        resolved = await compliance.resolve_violation(
            violations[0].violation_id, resolution="Encrypted field with AES-256-GCM"
        )
        assert resolved["status"] == "resolved"

        # Compliant payload passes validation
        good_payload = {
            "ssn": "ENCv1:default-key:ciphertext",
            "_audit": {"user_id": "dr-1", "retention_days": 2555},
        }
        good_payload["_checksum"] = engine.compute_payload_checksum(good_payload)
        valid_res = await engine.validate(good_payload)
        assert valid_res["overall_status"] == "compliant"
