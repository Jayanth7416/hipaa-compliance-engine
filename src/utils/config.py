"""Application Configuration"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with production-safe defaults and YAML policy support."""

    APP_NAME: str = "HIPAA Compliance Engine"
    VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8003",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8003",
    ]

    # AWS & Cloud Key Management
    AWS_REGION: str = "us-east-1"
    KMS_KEY_ID: str = "alias/hipaa-compliance-key"
    USE_AWS_KMS: bool = False
    AUDIT_S3_BUCKET: str = "s3://hipaa-audit-logs-bucket/"

    # Database & Cache (SQLite default for out-of-the-box persistence; PostgreSQL in prod)
    DATABASE_URL: str = "sqlite:///./hipaa_compliance.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Cryptography & Hashing
    ENCRYPTION_SECRET: str = "hipaa-engine-master-key-material-change-in-prod"
    ENCRYPTION_SALT: str = "hipaa-engine-kdf-salt-change-in-prod"
    HASH_PEPPER: str = "hipaa-engine-hmac-pepper-change-in-prod"
    PBKDF2_ITERATIONS: int = 200000

    # Authentication, Authorization & Session Security (§164.312(a)(1), §164.312(d))
    JWT_SECRET_KEY: str = "hipaa-jwt-signing-secret-change-in-prod"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ENFORCE_AUTH: bool = False
    DEFAULT_API_KEY: str = "hipaa-dev-api-key"

    # Audit & Upload Limits (§164.312(b))
    AUDIT_LOG_RETENTION_DAYS: int = 2555  # 7 years per HIPAA
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    COMPLIANCE_CONFIG_PATH: str = "config/compliance.yaml"

    model_config = ConfigDict(
        env_file=".env",
        extra="ignore",
    )

    def load_compliance_yaml(self) -> Dict[str, Any]:
        """Load compliance configuration from YAML if available."""
        config_path = Path(self.COMPLIANCE_CONFIG_PATH)
        if not config_path.is_absolute():
            project_root = Path(__file__).resolve().parents[2]
            config_path = project_root / self.COMPLIANCE_CONFIG_PATH
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
