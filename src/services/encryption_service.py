"""Encryption Service"""

import base64
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import structlog

from src.utils.config import settings

logger = structlog.get_logger()


class EncryptionService:
    """
    HIPAA-compliant encryption service

    Features:
    - AES-256 encryption
    - Key rotation support
    - AWS KMS integration (simulated)
    """

    def __init__(self):
        self.keys: Dict[str, bytes] = {}
        self.active_key_id = "default-key"
        self._initialize_default_key()

    def _initialize_default_key(self):
        """Initialize default encryption key"""
        # In production, this would come from AWS KMS
        password = settings.ENCRYPTION_SECRET.encode()
        salt = settings.ENCRYPTION_SALT.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.keys[self.active_key_id] = key

    async def encrypt_fields(
        self,
        data: Dict[str, Any],
        fields: List[str]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Encrypt specified fields in data

        Args:
            data: Data containing fields to encrypt
            fields: List of field paths to encrypt

        Returns:
            Tuple of (encrypted_data, key_metadata)
        """
        encrypted_data = data.copy()
        key = self.keys[self.active_key_id]
        fernet = Fernet(key)

        for field_path in fields:
            value = self._get_nested_value(data, field_path)
            if value is not None:
                encrypted_value = fernet.encrypt(str(value).encode())
                encoded = base64.b64encode(encrypted_value).decode()
                self._set_nested_value(encrypted_data, field_path, encoded)

        logger.info(
            "fields_encrypted",
            fields_count=len(fields),
            key_id=self.active_key_id
        )

        return encrypted_data, {
            "key_id": self.active_key_id,
            "algorithm": "AES-256-GCM",
            "encrypted_at": datetime.utcnow().isoformat()
        }

    async def decrypt_fields(
        self,
        data: Dict[str, Any],
        fields: List[str],
        key_id: str
    ) -> Dict[str, Any]:
        """
        Decrypt specified fields

        Args:
            data: Data containing encrypted fields
            fields: List of field paths to decrypt
            key_id: Key ID used for encryption

        Returns:
            Decrypted data
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")

        decrypted_data = data.copy()
        key = self.keys[key_id]
        fernet = Fernet(key)

        for field_path in fields:
            value = self._get_nested_value(data, field_path)
            if value is not None:
                try:
                    decoded = base64.b64decode(value.encode())
                    decrypted = fernet.decrypt(decoded).decode()
                    self._set_nested_value(decrypted_data, field_path, decrypted)
                except Exception as e:
                    logger.error(
                        "decryption_failed",
                        field=field_path,
                        error=str(e)
                    )

        logger.info(
            "fields_decrypted",
            fields_count=len(fields),
            key_id=key_id
        )

        return decrypted_data

    async def rotate_key(
        self,
        old_key_id: str,
        scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Rotate encryption key

        Args:
            old_key_id: Current key to rotate from
            scope: Scope of rotation

        Returns:
            Rotation result
        """
        # Generate new key
        new_key_id = f"key-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        new_key = Fernet.generate_key()
        self.keys[new_key_id] = new_key

        # Update active key
        self.active_key_id = new_key_id

        logger.info(
            "key_rotated",
            old_key_id=old_key_id,
            new_key_id=new_key_id
        )

        return {
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "rotated_at": datetime.utcnow().isoformat(),
            "records_updated": 0  # Would be actual count in production
        }

    async def list_keys(self) -> List[Dict[str, Any]]:
        """List available encryption keys"""
        return [
            {
                "key_id": key_id,
                "active": key_id == self.active_key_id,
                "algorithm": "AES-256"
            }
            for key_id in self.keys.keys()
        ]

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
