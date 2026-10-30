"""Authentication, JWT Verification, and Role-Based Access Control (§164.312(a)(1) & §164.312(d))"""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from src.services.registry import audit_service
from src.utils.config import settings
from src.utils.database import utc_now

bearer_scheme = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": [
        "scan",
        "mask",
        "unmask",
        "encrypt",
        "decrypt",
        "rotate_key",
        "audit_read",
        "compliance_read",
        "compliance_write",
    ],
    "compliance_officer": [
        "scan",
        "mask",
        "audit_read",
        "compliance_read",
        "compliance_write",
    ],
    "clinician": [
        "scan",
        "mask",
        "unmask",
        "encrypt",
        "decrypt",
        "compliance_read",
    ],
    "auditor": [
        "audit_read",
        "compliance_read",
    ],
}


class UserPrincipal(BaseModel):
    """Authenticated user context."""

    user_id: str
    role: str = "admin"
    mfa_verified: bool = True
    permissions: List[str] = Field(default_factory=list)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class TokenRequest(BaseModel):
    """Request payload for issuing a HIPAA session JWT."""

    user_id: str = Field(..., description="Unique user identifier")
    role: str = Field(
        default="clinician",
        description="Role (admin, compliance_officer, clinician, auditor)",
    )
    mfa_code: Optional[str] = Field(
        default="123456",
        description="MFA TOTP code (required for privileged PHI operations)",
    )


class TokenResponse(BaseModel):
    """Issued JWT response."""

    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    role: str
    mfa_verified: bool


def create_access_token(
    user_id: str,
    role: str = "clinician",
    mfa_verified: bool = True,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT token with role and MFA claims."""
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"Unsupported role: {role}")

    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: Dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "mfa": mfa_verified,
        "permissions": ROLE_PERMISSIONS[role],
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a signed JWT token."""
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def require_permission(permission: str, require_mfa: bool = False) -> Callable:
    """
    FastAPI dependency enforcing JWT/API-key authentication, RBAC permissions, and MFA.
    """

    async def _dependency(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    ) -> UserPrincipal:
        ip_address = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get("user-agent", "unknown")
        api_key = request.headers.get("X-API-Key")

        # 1. If Bearer token is supplied, always validate it strictly
        if credentials and credentials.credentials:
            try:
                payload = decode_access_token(credentials.credentials)
                user_id = str(payload.get("sub", "unknown"))
                role = str(payload.get("role", "clinician"))
                mfa_verified = bool(payload.get("mfa", False))
                perms = payload.get("permissions") or ROLE_PERMISSIONS.get(role, [])
            except JWTError as e:
                await audit_service.log_access(
                    action=f"auth_{permission}",
                    resource_type="auth",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    status="failure",
                    details={"reason": "invalid_jwt", "error": str(e)},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired authentication token",
                )

            if permission not in perms:
                await audit_service.log_access(
                    action=f"rbac_{permission}",
                    resource_type="auth",
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    status="failure",
                    details={"reason": "insufficient_role", "role": role, "required": permission},
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' does not have required '{permission}' permission",
                )

            if require_mfa and not mfa_verified:
                await audit_service.log_access(
                    action=f"mfa_{permission}",
                    resource_type="auth",
                    user_id=user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    status="failure",
                    details={"reason": "mfa_required"},
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Multi-Factor Authentication (MFA) verification is required for this operation",
                )

            return UserPrincipal(
                user_id=user_id,
                role=role,
                mfa_verified=mfa_verified,
                permissions=perms,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        # 2. Check X-API-Key header
        if api_key:
            if api_key != settings.DEFAULT_API_KEY:
                await audit_service.log_access(
                    action=f"api_key_{permission}",
                    resource_type="auth",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    status="failure",
                    details={"reason": "invalid_api_key"},
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid API key",
                )
            return UserPrincipal(
                user_id="api-key-client",
                role="admin",
                mfa_verified=True,
                permissions=ROLE_PERMISSIONS["admin"],
                ip_address=ip_address,
                user_agent=user_agent,
            )

        # 3. If ENFORCE_AUTH is enabled, reject unauthenticated requests
        if settings.ENFORCE_AUTH:
            await audit_service.log_access(
                action=f"unauthenticated_{permission}",
                resource_type="auth",
                ip_address=ip_address,
                user_agent=user_agent,
                status="failure",
                details={"reason": "missing_credentials"},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required (Bearer token or X-API-Key)",
            )

        # 4. Development/demo fallback principal
        return UserPrincipal(
            user_id="system",
            role="admin",
            mfa_verified=True,
            permissions=ROLE_PERMISSIONS["admin"],
            ip_address=ip_address,
            user_agent=user_agent,
        )

    return _dependency
