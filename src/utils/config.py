"""Application Configuration"""

from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""

    APP_NAME: str = "HIPAA Compliance Engine"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    # AWS
    AWS_REGION: str = "us-east-1"
    KMS_KEY_ID: str = "alias/hipaa-compliance-key"

    # Database
    DATABASE_URL: str = "postgresql://localhost:5432/hipaa_compliance"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Encryption
    ENCRYPTION_SECRET: str = "dev-secret-change-in-production"
    ENCRYPTION_SALT: str = "dev-salt-change-in-production"

    # Audit
    AUDIT_LOG_RETENTION_DAYS: int = 2555  # 7 years

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
