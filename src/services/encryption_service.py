"""HIPAA-Compliant Encryption Service (AES-256-GCM + Envelope Key Management)"""

import base64
import copy
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import boto3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import structlog

from src.utils.config import settings
from src.utils.database import EncryptionKeyModel, TokenVaultModel, get_db_session, utc_now

logger = structlog.get_logger()

ENVELOPE_PREFIX = "ENCv1:"


class EncryptionService:
    """
    HIPAA-compliant encryption service (§164.312(a)(2)(iv) & §164.312(e)(2)(ii))

    Features:
    - Authenticated AES-256-GCM encryption with 96-bit random nonces
    - Persistent envelope key wrapping (KEK wraps 256-bit DEKs in database)
    - Optional AWS KMS integration via boto3
    - Key rotation with automatic re-encryption of records and token vault
    """

    def __init__(self):
        self.keys: Dict[str, bytes] = {}
        self.active_key_id = "default-key"
        self._kek: bytes = self._derive_kek()
        self._initialize_keys()

    def _derive_kek(self) -> bytes:
        """Derive 256-bit Key Encryption Key (KEK) using PBKDF2-HMAC-SHA256."""
        password = settings.ENCRYPTION_SECRET.encode("utf-8")
        salt = settings.ENCRYPTION_SALT.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=settings.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password)

    def _wrap_dek(self, dek: bytes) -> str:
        """Wrap a 256-bit Data Encryption Key using KEK (or AWS KMS if enabled)."""
        if settings.USE_AWS_KMS:
            try:
                kms = boto3.client("kms", region_name=settings.AWS_REGION)
                resp = kms.encrypt(KeyId=settings.KMS_KEY_ID, Plaintext=dek)
                return "KMS:" + base64.b64encode(resp["CiphertextBlob"]).decode("ascii")
            except Exception as e:
                logger.warning("kms_wrap_fallback_to_local_kek", error=type(e).__name__)

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._kek)
        ct = aesgcm.encrypt(nonce, dek, b"hipaa-dek-wrap")
        return base64.b64encode(nonce + ct).decode("ascii")

    def _unwrap_dek(self, wrapped: str) -> bytes:
        """Unwrap a stored Data Encryption Key."""
        if wrapped.startswith("KMS:"):
            kms = boto3.client("kms", region_name=settings.AWS_REGION)
            blob = base64.b64decode(wrapped[4:].encode("ascii"))
            resp = kms.decrypt(CiphertextBlob=blob)
            return bytes(resp["Plaintext"])

        raw = base64.b64decode(wrapped.encode("ascii"))
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(self._kek)
        return aesgcm.decrypt(nonce, ct, b"hipaa-dek-wrap")

    def _initialize_keys(self) -> None:
        """Load persistent encryption keys from database or initialize default AES-256 key."""
        with get_db_session() as db:
            stored_keys = db.query(EncryptionKeyModel).all()
            if stored_keys:
                for record in stored_keys:
                    try:
                        self.keys[record.key_id] = self._unwrap_dek(record.wrapped_key)
                        if record.is_active:
                            self.active_key_id = record.key_id
                    except Exception:
                        continue

            if "default-key" not in self.keys:
                # Deterministic 256-bit default DEK derived from KEK so restarts can always decrypt
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=settings.ENCRYPTION_SALT.encode("utf-8") + b":default-dek",
                    iterations=10000,
                )
                default_dek = kdf.derive(self._kek)
                self.keys["default-key"] = default_dek
                existing = db.query(EncryptionKeyModel).filter_by(key_id="default-key").first()
                if not existing:
                    db.add(
                        EncryptionKeyModel(
                            key_id="default-key",
                            alias=settings.KMS_KEY_ID,
                            algorithm="AES-256-GCM",
                            wrapped_key=self._wrap_dek(default_dek),
                            status="active",
                            is_active=True,
                            usage_count=0,
                            created_at=utc_now(),
                        )
                    )
                    db.commit()

    def encrypt_value(self, plaintext: str, key_id: Optional[str] = None) -> str:
        """Encrypt a single string value using AES-256-GCM and return a versioned envelope."""
        target_key_id = key_id or self.active_key_id
        if target_key_id not in self.keys:
            self._initialize_keys()
        if target_key_id not in self.keys:
            raise ValueError(f"Key not found: {target_key_id}")

        key = self.keys[target_key_id]
        raw_key = self._normalize_aes256_key(key)
        nonce = os.urandom(12)
        aesgcm = AESGCM(raw_key)
        aad = f"key:{target_key_id}".encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        payload = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        return f"{ENVELOPE_PREFIX}{target_key_id}:{payload}"

    def decrypt_value(self, token: str, key_id: Optional[str] = None) -> str:
        """Decrypt an AES-256-GCM envelope (or legacy Fernet ciphertext)."""
        if token.startswith(ENVELOPE_PREFIX):
            parts = token.split(":", 2)
            if len(parts) != 3:
                raise ValueError("Malformed encrypted envelope")
            _, envelope_key_id, payload = parts
            effective_key_id = key_id or envelope_key_id
            if effective_key_id != envelope_key_id:
                raise ValueError(
                    f"Key ID mismatch: requested '{effective_key_id}' but ciphertext uses '{envelope_key_id}'"
                )
            if effective_key_id not in self.keys:
                self._initialize_keys()
            if effective_key_id not in self.keys:
                raise ValueError(f"Key not found: {effective_key_id}")

            raw_key = self._normalize_aes256_key(self.keys[effective_key_id])
            raw_bytes = base64.urlsafe_b64decode(payload.encode("ascii"))
            if len(raw_bytes) < 28:
                raise ValueError("Ciphertext too short for AES-256-GCM")
            nonce, ct = raw_bytes[:12], raw_bytes[12:]
            aesgcm = AESGCM(raw_key)
            aad = f"key:{envelope_key_id}".encode("utf-8")
            plaintext_bytes = aesgcm.decrypt(nonce, ct, aad)
            return plaintext_bytes.decode("utf-8")

        # Fallback support if caller injected a raw Fernet key into self.keys
        effective_key_id = key_id or self.active_key_id
        if effective_key_id not in self.keys:
            self._initialize_keys()
        if effective_key_id not in self.keys:
            raise ValueError(f"Key not found: {effective_key_id}")

        candidate_key = self.keys[effective_key_id]
        decoded = base64.b64decode(token.encode("utf-8"))
        if len(candidate_key) == 44:
            fernet = Fernet(candidate_key)
            return fernet.decrypt(decoded).decode("utf-8")

        # Otherwise treat as raw base64(nonce + AESGCM ciphertext)
        raw_key = self._normalize_aes256_key(candidate_key)
        nonce, ct = decoded[:12], decoded[12:]
        aesgcm = AESGCM(raw_key)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")

    @staticmethod
    def _normalize_aes256_key(key: bytes) -> bytes:
        """Ensure key is 32 raw bytes for AES-256-GCM (unwrapping urlsafe_b64 if 44 bytes)."""
        if len(key) == 32:
            return key
        if len(key) == 44:
            decoded = base64.urlsafe_b64decode(key)
            if len(decoded) == 32:
                return decoded
        raise ValueError(f"Invalid AES-256 key length: {len(key)} bytes")

    async def encrypt_fields(
        self,
        data: Dict[str, Any],
        fields: List[str],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Encrypt specified fields in data using AES-256-GCM.

        Args:
            data: Data containing fields to encrypt
            fields: List of dot-separated field paths to encrypt

        Returns:
            Tuple of (encrypted_data, key_metadata)
        """
        encrypted_data = copy.deepcopy(data)
        encrypted_count = 0

        for field_path in fields:
            value = self._get_nested_value(encrypted_data, field_path)
            if value is not None:
                ciphertext = self.encrypt_value(str(value), self.active_key_id)
                self._set_nested_value(encrypted_data, field_path, ciphertext)
                encrypted_count += 1

        with get_db_session() as db:
            record = db.query(EncryptionKeyModel).filter_by(key_id=self.active_key_id).first()
            if record and encrypted_count > 0:
                record.usage_count += encrypted_count
                db.commit()

        logger.info(
            "fields_encrypted",
            fields_count=encrypted_count,
            key_id=self.active_key_id,
            algorithm="AES-256-GCM",
        )

        return encrypted_data, {
            "key_id": self.active_key_id,
            "algorithm": "AES-256-GCM",
            "encrypted_at": utc_now().isoformat(),
        }

    async def decrypt_fields(
        self,
        data: Dict[str, Any],
        fields: List[str],
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt specified fields and verify authenticated encryption tag.

        Raises:
            ValueError: If key_id does not exist or ciphertext integrity verification fails.
        """
        if key_id is not None and key_id not in self.keys:
            self._initialize_keys()
            if key_id not in self.keys:
                raise ValueError(f"Key not found: {key_id}")

        decrypted_data = copy.deepcopy(data)

        for field_path in fields:
            value = self._get_nested_value(decrypted_data, field_path)
            if value is not None:
                try:
                    decrypted = self.decrypt_value(str(value), key_id=key_id)
                    self._set_nested_value(decrypted_data, field_path, decrypted)
                except Exception as e:
                    logger.error(
                        "decryption_failed",
                        field=field_path,
                        error=type(e).__name__,
                    )
                    raise ValueError(f"Decryption failed for field '{field_path}': {e}") from e

        logger.info(
            "fields_decrypted",
            fields_count=len(fields),
            key_id=key_id or self.active_key_id,
        )

        return decrypted_data

    async def rotate_key(
        self,
        old_key_id: str,
        scope: Optional[str] = None,
        records: Optional[List[Dict[str, Any]]] = None,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Rotate encryption key, persist the new 256-bit DEK, and re-encrypt token vault / records.
        """
        if old_key_id not in self.keys:
            self._initialize_keys()
        if old_key_id not in self.keys:
            raise ValueError(f"Key not found: {old_key_id}")

        now = utc_now()
        new_key_id = f"key-{now.strftime('%Y%m%d%H%M%S')}-{os.urandom(2).hex()}"
        new_dek = AESGCM.generate_key(bit_length=256)
        self.keys[new_key_id] = new_dek
        self.active_key_id = new_key_id

        records_updated = 0
        reencrypted_records: List[Dict[str, Any]] = []

        with get_db_session() as db:
            old_record = db.query(EncryptionKeyModel).filter_by(key_id=old_key_id).first()
            if old_record:
                old_record.is_active = False
                old_record.status = "retired"
                old_record.rotated_at = now

            db.add(
                EncryptionKeyModel(
                    key_id=new_key_id,
                    alias=f"{settings.KMS_KEY_ID}/{new_key_id}",
                    algorithm="AES-256-GCM",
                    wrapped_key=self._wrap_dek(new_dek),
                    status="active",
                    is_active=True,
                    usage_count=0,
                    created_at=now,
                )
            )

            # Re-encrypt token vault entries that were encrypted with the old key
            vault_entries = db.query(TokenVaultModel).all()
            for entry in vault_entries:
                if entry.encrypted_value.startswith(f"{ENVELOPE_PREFIX}{old_key_id}:"):
                    plaintext = self.decrypt_value(entry.encrypted_value, key_id=old_key_id)
                    entry.encrypted_value = self.encrypt_value(plaintext, key_id=new_key_id)
                    records_updated += 1

            db.commit()

        # Re-encrypt any caller-supplied records
        if records and fields:
            for rec in records:
                decrypted = await self.decrypt_fields(rec, fields=fields, key_id=old_key_id)
                reencrypted, _ = await self.encrypt_fields(decrypted, fields=fields)
                reencrypted_records.append(reencrypted)
                records_updated += 1

        logger.info(
            "key_rotated",
            old_key_id=old_key_id,
            new_key_id=new_key_id,
            records_updated=records_updated,
        )

        result: Dict[str, Any] = {
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "algorithm": "AES-256-GCM",
            "rotated_at": now.isoformat(),
            "records_updated": records_updated,
        }
        if reencrypted_records:
            result["reencrypted_records"] = reencrypted_records
        return result

    async def list_keys(self) -> List[Dict[str, Any]]:
        """List available encryption keys with metadata."""
        self._initialize_keys()
        with get_db_session() as db:
            records = db.query(EncryptionKeyModel).order_by(EncryptionKeyModel.created_at.asc()).all()
            if records:
                return [
                    {
                        "key_id": r.key_id,
                        "alias": r.alias,
                        "active": r.key_id == self.active_key_id,
                        "status": r.status,
                        "algorithm": r.algorithm,
                        "usage_count": r.usage_count,
                        "created_at": r.created_at.isoformat(),
                        "rotated_at": r.rotated_at.isoformat() if r.rotated_at else None,
                    }
                    for r in records
                ]

        return [
            {
                "key_id": key_id,
                "active": key_id == self.active_key_id,
                "algorithm": "AES-256-GCM",
            }
            for key_id in self.keys.keys()
        ]

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
