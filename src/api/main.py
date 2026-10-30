"""
HIPAA Compliance Engine - Main API
Automated data security and compliance for healthcare
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import Body, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import structlog

from src.api.auth import UserPrincipal, require_permission
from src.api.routes import audit, auth, compliance, encrypt, mask, scan
from src.services.registry import policy_engine
from src.utils.config import settings
from src.utils.database import init_db

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager initializing persistent database tables."""
    init_db()
    logger.info("Starting HIPAA Compliance Engine", version=settings.VERSION)
    yield
    logger.info("Shutting down HIPAA Compliance Engine")


app = FastAPI(
    title="HIPAA Compliance Engine",
    description="Automated data security and compliance pipeline for healthcare",
    version=settings.VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication & RBAC"])
app.include_router(scan.router, prefix="/scan", tags=["PHI Scanning"])
app.include_router(mask.router, prefix="/mask", tags=["Data Masking"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["Encryption"])
app.include_router(audit.router, prefix="/audit", tags=["Audit"])
app.include_router(compliance.router, prefix="/compliance", tags=["Compliance"])


@app.post("/policies/validate", tags=["Compliance"])
async def validate_policies_alias(
    data: Dict[str, Any] = Body(...),
    policies: Optional[List[str]] = Body(default=None),
    principal: UserPrincipal = Depends(require_permission("compliance_read")),
):
    """Validate payload against HIPAA compliance policies (alias for /compliance/validate)."""
    return await policy_engine.validate(data=data, policies=policies)


@app.get("/")
async def root():
    return {
        "service": "HIPAA Compliance Engine",
        "version": settings.VERSION,
        "status": "operational",
        "dashboard": "/dashboard",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": settings.VERSION}


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the interactive HIPAA Compliance Engine dashboard."""
    frontend_file = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
    if frontend_file.exists():
        return FileResponse(frontend_file)
    return HTMLResponse("<h1>Dashboard file not found</h1>", status_code=404)
