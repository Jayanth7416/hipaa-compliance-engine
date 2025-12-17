"""Policy Engine for Compliance Validation"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import structlog

from src.models.compliance import ComplianceStatus, Policy, PolicyValidation, Severity

logger = structlog.get_logger()


class PolicyEngine:
    """
    Rule-based policy engine for HIPAA compliance

    Validates data against defined compliance policies.
    """

    def __init__(self):
        self.policies = self._load_default_policies()

    def _load_default_policies(self) -> Dict[str, Policy]:
        """Load default HIPAA compliance policies"""
        return {
            "phi_encryption": Policy(
                policy_id="phi_encryption",
                name="PHI Encryption Policy",
                description="All PHI must be encrypted at rest and in transit",
                category="encryption",
                hipaa_reference="164.312(e)(1)",
                severity=Severity.CRITICAL,
                rules=[
                    {"type": "field_encrypted", "fields": ["ssn", "mrn", "dob"]},
                    {"type": "encryption_algorithm", "allowed": ["AES-256", "AES-256-GCM"]}
                ],
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            "access_logging": Policy(
                policy_id="access_logging",
                name="Access Logging Policy",
                description="All PHI access must be logged",
                category="audit",
                hipaa_reference="164.312(b)",
                severity=Severity.HIGH,
                rules=[
                    {"type": "audit_required", "actions": ["read", "write", "delete"]},
                    {"type": "log_retention", "min_days": 2555}
                ],
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            "minimum_necessary": Policy(
                policy_id="minimum_necessary",
                name="Minimum Necessary Policy",
                description="Only minimum necessary PHI should be accessed",
                category="access_control",
                hipaa_reference="164.502(b)",
                severity=Severity.MEDIUM,
                rules=[
                    {"type": "field_restriction", "restrict_fields": True},
                    {"type": "purpose_required", "require_purpose": True}
                ],
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            "data_integrity": Policy(
                policy_id="data_integrity",
                name="Data Integrity Policy",
                description="PHI must be protected from improper alteration",
                category="integrity",
                hipaa_reference="164.312(c)(1)",
                severity=Severity.HIGH,
                rules=[
                    {"type": "checksum_required", "algorithm": "SHA-256"},
                    {"type": "version_control", "enabled": True}
                ],
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            ),
            "authentication": Policy(
                policy_id="authentication",
                name="Authentication Policy",
                description="Strong authentication for PHI access",
                category="authentication",
                hipaa_reference="164.312(d)",
                severity=Severity.CRITICAL,
                rules=[
                    {"type": "mfa_required", "for_phi_access": True},
                    {"type": "session_timeout", "max_minutes": 30}
                ],
                enabled=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
        }

    async def validate(
        self,
        data: Dict[str, Any],
        policies: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Validate data against compliance policies

        Args:
            data: Data to validate
            policies: Specific policies to check (None = all)

        Returns:
            Validation result with violations
        """
        policies_to_check = policies or list(self.policies.keys())
        results = []
        all_violations = []

        for policy_id in policies_to_check:
            if policy_id not in self.policies:
                continue

            policy = self.policies[policy_id]
            if not policy.enabled:
                continue

            violations = await self._check_policy(policy, data)

            status = ComplianceStatus.COMPLIANT if not violations else ComplianceStatus.NON_COMPLIANT

            results.append(PolicyValidation(
                policy_id=policy_id,
                policy_name=policy.name,
                status=status,
                violations=violations,
                recommendations=self._get_recommendations(policy, violations)
            ))

            all_violations.extend(violations)

        overall_status = (
            ComplianceStatus.COMPLIANT if not all_violations
            else ComplianceStatus.NON_COMPLIANT
        )

        logger.info(
            "policy_validation_completed",
            policies_checked=len(policies_to_check),
            violations_found=len(all_violations)
        )

        return {
            "overall_status": overall_status.value,
            "validated_at": datetime.utcnow().isoformat(),
            "policies_checked": len(policies_to_check),
            "violations_count": len(all_violations),
            "results": [r.model_dump() for r in results]
        }

    async def _check_policy(
        self,
        policy: Policy,
        data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check data against a single policy"""
        violations = []

        for rule in policy.rules:
            rule_type = rule.get("type")

            if rule_type == "field_encrypted":
                fields = rule.get("fields", [])
                for field in fields:
                    if self._has_unencrypted_field(data, field):
                        violations.append({
                            "rule": rule_type,
                            "field": field,
                            "message": f"Field '{field}' must be encrypted"
                        })

            elif rule_type == "audit_required":
                # Check if audit context is present
                if "_audit" not in data:
                    violations.append({
                        "rule": rule_type,
                        "message": "Audit context is required for PHI operations"
                    })

            elif rule_type == "checksum_required":
                if "_checksum" not in data:
                    violations.append({
                        "rule": rule_type,
                        "message": "Data integrity checksum is required"
                    })

        return violations

    def _has_unencrypted_field(self, data: Dict[str, Any], field: str) -> bool:
        """Check if a field appears to be unencrypted"""
        value = self._get_nested_value(data, field)
        if value is None:
            return False

        # Simple heuristic: encrypted values are typically base64 encoded
        value_str = str(value)
        return not (
            value_str.startswith("ENC_") or
            value_str.startswith("TOK_") or
            len(value_str) > 50  # Likely encrypted
        )

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary"""
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def _get_recommendations(
        self,
        policy: Policy,
        violations: List[Dict[str, Any]]
    ) -> List[str]:
        """Get recommendations for policy violations"""
        if not violations:
            return []

        recommendations = {
            "phi_encryption": "Encrypt all PHI fields using AES-256 encryption",
            "access_logging": "Ensure all PHI access is logged with user context",
            "minimum_necessary": "Limit PHI access to only required fields",
            "data_integrity": "Add checksums to verify data integrity",
            "authentication": "Implement MFA for PHI access"
        }

        return [recommendations.get(policy.policy_id, "Review and address violations")]

    async def list_policies(self) -> List[Dict[str, Any]]:
        """List all compliance policies"""
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "description": p.description,
                "category": p.category,
                "hipaa_reference": p.hipaa_reference,
                "severity": p.severity.value,
                "enabled": p.enabled
            }
            for p in self.policies.values()
        ]

    async def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get specific policy details"""
        return self.policies.get(policy_id)
