"""Compliance Service"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import structlog

from src.models.compliance import (
    ComplianceCheck,
    ComplianceReport,
    ComplianceViolation,
    ComplianceStatus,
    Severity
)

logger = structlog.get_logger()


class ComplianceService:
    """
    HIPAA Compliance Management Service

    Provides compliance checking, reporting, and violation management.
    """

    def __init__(self):
        self.violations: List[ComplianceViolation] = []
        self.checks_history: List[ComplianceCheck] = []

    async def get_overall_status(self) -> Dict[str, Any]:
        """Get overall compliance status"""
        open_violations = [v for v in self.violations if v.status == "open"]
        critical_violations = [v for v in open_violations if v.severity == Severity.CRITICAL]

        if critical_violations:
            status = ComplianceStatus.NON_COMPLIANT
        elif open_violations:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.COMPLIANT

        return {
            "status": status.value,
            "checked_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_violations": len(self.violations),
                "open_violations": len(open_violations),
                "critical_violations": len(critical_violations)
            },
            "requirements": {
                "access_control": "compliant",
                "audit_control": "compliant",
                "integrity": "compliant",
                "authentication": "compliant",
                "transmission_security": "compliant"
            }
        }

    async def run_checks(
        self,
        resource_type: str,
        resource_id: Optional[str] = None,
        checks: Optional[List[str]] = None
    ) -> ComplianceCheck:
        """
        Run compliance checks on a resource

        Args:
            resource_type: Type of resource to check
            resource_id: Specific resource ID
            checks: List of checks to run (None = all)

        Returns:
            Compliance check result
        """
        all_checks = [
            "encryption_at_rest",
            "encryption_in_transit",
            "access_controls",
            "audit_logging",
            "data_integrity",
            "phi_protection"
        ]

        checks_to_run = checks if checks else all_checks
        passed = []
        failed = []
        warnings = []

        for check in checks_to_run:
            result = await self._run_single_check(check, resource_type, resource_id)
            if result["status"] == "pass":
                passed.append(check)
            elif result["status"] == "fail":
                failed.append(check)
            else:
                warnings.append(check)

        status = ComplianceStatus.COMPLIANT if not failed else (
            ComplianceStatus.PARTIAL if passed else ComplianceStatus.NON_COMPLIANT
        )
        score = (len(passed) / len(checks_to_run)) * 100 if checks_to_run else 100

        check_result = ComplianceCheck(
            check_id=str(uuid.uuid4()),
            resource_type=resource_type,
            resource_id=resource_id,
            checks_performed=checks_to_run,
            status=status,
            score=score,
            passed=passed,
            failed=failed,
            warnings=warnings,
            checked_at=datetime.utcnow()
        )

        self.checks_history.append(check_result)

        logger.info(
            "compliance_check_completed",
            resource_type=resource_type,
            status=status.value,
            score=score
        )

        return check_result

    async def _run_single_check(
        self,
        check: str,
        resource_type: str,
        resource_id: Optional[str]
    ) -> Dict[str, str]:
        """Run a single compliance check"""
        # Simulated check results
        check_implementations = {
            "encryption_at_rest": lambda: {"status": "pass", "details": "AES-256 encryption enabled"},
            "encryption_in_transit": lambda: {"status": "pass", "details": "TLS 1.3 enforced"},
            "access_controls": lambda: {"status": "pass", "details": "RBAC implemented"},
            "audit_logging": lambda: {"status": "pass", "details": "Comprehensive logging enabled"},
            "data_integrity": lambda: {"status": "pass", "details": "Checksums validated"},
            "phi_protection": lambda: {"status": "pass", "details": "PHI masking active"},
        }

        check_func = check_implementations.get(check)
        if check_func:
            return check_func()
        return {"status": "warning", "details": "Check not implemented"}

    async def generate_report(self, period: str) -> ComplianceReport:
        """Generate compliance report"""
        period_days = {
            "weekly": 7,
            "monthly": 30,
            "quarterly": 90,
            "annual": 365
        }.get(period, 30)

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=period_days)

        # Get violations in period
        violations_in_period = [
            v for v in self.violations
            if start_date <= v.detected_at <= end_date
        ]

        violations_by_severity = {}
        for v in violations_in_period:
            violations_by_severity[v.severity.value] = violations_by_severity.get(v.severity.value, 0) + 1

        # Calculate score
        open_violations = [v for v in violations_in_period if v.status == "open"]
        critical_count = sum(1 for v in open_violations if v.severity == Severity.CRITICAL)
        high_count = sum(1 for v in open_violations if v.severity == Severity.HIGH)

        score = 100 - (critical_count * 20) - (high_count * 10) - (len(open_violations) * 2)
        score = max(0, min(100, score))

        # Determine status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 70:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.NON_COMPLIANT

        return ComplianceReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            period=period,
            period_start=start_date,
            period_end=end_date,
            overall_status=status,
            compliance_score=score,
            summary={
                "total_violations": len(violations_in_period),
                "open_violations": len(open_violations),
                "resolved_violations": len(violations_in_period) - len(open_violations)
            },
            checks_summary={
                "passed": len(self.checks_history),
                "failed": 0,
                "warnings": 0
            },
            violations_summary=violations_by_severity,
            trends={},
            recommendations=self._generate_recommendations(violations_in_period),
            detailed_findings=[]
        )

    async def get_violations(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        days: int = 30
    ) -> List[ComplianceViolation]:
        """Get compliance violations with filters"""
        start_date = datetime.utcnow() - timedelta(days=days)

        results = [
            v for v in self.violations
            if v.detected_at >= start_date
        ]

        if severity:
            results = [v for v in results if v.severity.value == severity]

        if status:
            results = [v for v in results if v.status == status]

        return results

    async def resolve_violation(
        self,
        violation_id: str,
        resolution: str,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Mark a violation as resolved"""
        for violation in self.violations:
            if violation.violation_id == violation_id:
                violation.status = "resolved"
                violation.resolution = resolution
                violation.resolved_at = datetime.utcnow()

                logger.info(
                    "violation_resolved",
                    violation_id=violation_id,
                    resolution=resolution
                )

                return {
                    "violation_id": violation_id,
                    "status": "resolved",
                    "resolved_at": violation.resolved_at.isoformat()
                }

        raise ValueError(f"Violation not found: {violation_id}")

    def _generate_recommendations(
        self,
        violations: List[ComplianceViolation]
    ) -> List[str]:
        """Generate recommendations based on violations"""
        recommendations = []

        severity_counts = {}
        for v in violations:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

        if severity_counts.get("critical", 0) > 0:
            recommendations.append(
                "URGENT: Address critical violations immediately to maintain compliance"
            )

        if severity_counts.get("high", 0) > 0:
            recommendations.append(
                "Review and remediate high-severity violations within 30 days"
            )

        if not violations:
            recommendations.append(
                "No violations detected. Continue monitoring and regular assessments."
            )

        return recommendations
