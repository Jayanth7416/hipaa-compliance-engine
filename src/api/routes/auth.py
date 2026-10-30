"""Authentication Endpoints for Issuing & Inspecting HIPAA Session Tokens"""

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import (
    ROLE_PERMISSIONS,
    TokenRequest,
    TokenResponse,
    UserPrincipal,
    create_access_token,
    require_permission,
)
from src.services.registry import audit_service
from src.utils.config import settings

router = APIRouter()


@router.post("/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest):
    """Issue a signed JWT access token with RBAC role and MFA verification claims."""
    if request.role not in ROLE_PERMISSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role '{request.role}'. Allowed roles: {list(ROLE_PERMISSIONS.keys())}",
        )

    mfa_verified = bool(request.mfa_code and len(request.mfa_code.strip()) >= 6)
    token = create_access_token(
        user_id=request.user_id,
        role=request.role,
        mfa_verified=mfa_verified,
    )

    await audit_service.log_access(
        action="token_issued",
        resource_type="auth",
        user_id=request.user_id,
        details={"role": request.role, "mfa_verified": mfa_verified},
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        role=request.role,
        mfa_verified=mfa_verified,
    )


@router.get("/me", response_model=UserPrincipal)
async def get_current_principal(
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Return the currently authenticated user principal and permissions."""
    return principal
