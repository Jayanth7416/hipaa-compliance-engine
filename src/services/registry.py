"""Shared Service Registry for Dependency Injection across Routes"""

from src.rules.policy_engine import PolicyEngine
from src.services.audit_service import AuditService
from src.services.compliance_service import ComplianceService
from src.services.encryption_service import EncryptionService
from src.services.masking_service import MaskingService
from src.services.phi_scanner import PHIScanner

phi_scanner = PHIScanner()
encryption_service = EncryptionService()
masking_service = MaskingService(
    phi_scanner=phi_scanner,
    encryption_service=encryption_service,
)
audit_service = AuditService()
compliance_service = ComplianceService(
    audit_service=audit_service,
    encryption_service=encryption_service,
    masking_service=masking_service,
    phi_scanner=phi_scanner,
)
policy_engine = PolicyEngine(phi_scanner=phi_scanner)
