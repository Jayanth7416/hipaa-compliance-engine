"""
HIPAA Compliance Engine - Main API
Automated data security and compliance for healthcare
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog

from src.api.routes import scan, mask, encrypt, audit, compliance
from src.utils.config import settings

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting HIPAA Compliance Engine")
    yield
    logger.info("Shutting down HIPAA Compliance Engine")


app = FastAPI(
    title="HIPAA Compliance Engine",
    description="Automated data security and compliance pipeline for healthcare",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router, prefix="/scan", tags=["PHI Scanning"])
app.include_router(mask.router, prefix="/mask", tags=["Data Masking"])
app.include_router(encrypt.router, prefix="/encrypt", tags=["Encryption"])
app.include_router(audit.router, prefix="/audit", tags=["Audit"])
app.include_router(compliance.router, prefix="/compliance", tags=["Compliance"])


@app.get("/")
async def root():
    return {
        "service": "HIPAA Compliance Engine",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
