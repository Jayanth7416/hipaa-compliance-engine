"""Audit Service"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import structlog

from src.models.audit import AuditLog, AuditQuery, AuditReport, AuditAnomaly

logger = structlog.get_logger()


class AuditService:
    """
    HIPAA-compliant audit logging service

    Features:
    - Immutable audit logs
    - Query and search capabilities
    - Anomaly detection
    - Compliance reporting
    """

    def __init__(self):
        # In-memory store for demo (use DynamoDB/S3 in production)
        self.logs: List[AuditLog] = []

    async def log_access(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        duration_ms: Optional[int] = None
    ) -> str:
        """
        Log an access event

        Args:
            action: Action performed (e.g., phi_access, encrypt, mask)
            resource_type: Type of resource accessed
            resource_id: ID of resource accessed
            user_id: User who performed action
            ip_address: Client IP address
            user_agent: Client user agent
            details: Additional details
            status: success or failure
            duration_ms: Operation duration

        Returns:
            Log ID
        """
        log_id = str(uuid.uuid4())

        log = AuditLog(
            log_id=log_id,
            timestamp=datetime.utcnow(),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {},
            status=status,
            duration_ms=duration_ms
        )

        self.logs.append(log)

        logger.info(
            "audit_log_created",
            log_id=log_id,
            action=action,
            resource_type=resource_type
        )

        return log_id

    async def query_logs(self, query: AuditQuery) -> List[AuditLog]:
        """Query audit logs with filters"""
        results = []

        for log in self.logs:
            if query.start_date and log.timestamp < query.start_date:
                continue
            if query.end_date and log.timestamp > query.end_date:
                continue
            if query.resource_id and log.resource_id != query.resource_id:
                continue
            if query.resource_type and log.resource_type != query.resource_type:
                continue
            if query.user_id and log.user_id != query.user_id:
                continue
            if query.action and log.action != query.action:
                continue

            results.append(log)

        # Apply pagination
        start = query.offset
        end = start + query.limit
        return results[start:end]

    async def count_logs(self, query: AuditQuery) -> int:
        """Count logs matching query"""
        logs = await self.query_logs(
            AuditQuery(
                resource_id=query.resource_id,
                resource_type=query.resource_type,
                user_id=query.user_id,
                action=query.action,
                start_date=query.start_date,
                end_date=query.end_date,
                limit=100000,
                offset=0
            )
        )
        return len(logs)

    async def get_log(self, log_id: str) -> Optional[AuditLog]:
        """Get specific audit log"""
        for log in self.logs:
            if log.log_id == log_id:
                return log
        return None

    async def get_resource_trail(
        self,
        resource_id: str,
        days: int = 30
    ) -> List[AuditLog]:
        """Get complete audit trail for a resource"""
        start_date = datetime.utcnow() - timedelta(days=days)

        return [
            log for log in self.logs
            if log.resource_id == resource_id and log.timestamp >= start_date
        ]

    async def get_user_trail(
        self,
        user_id: str,
        days: int = 30
    ) -> List[AuditLog]:
        """Get audit trail for a user"""
        start_date = datetime.utcnow() - timedelta(days=days)

        return [
            log for log in self.logs
            if log.user_id == user_id and log.timestamp >= start_date
        ]

    async def generate_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> AuditReport:
        """Generate compliance audit report"""
        logs_in_period = [
            log for log in self.logs
            if start_date <= log.timestamp <= end_date
        ]

        # Aggregate by action
        events_by_action: Dict[str, int] = {}
        events_by_resource_type: Dict[str, int] = {}
        user_counts: Dict[str, int] = {}

        for log in logs_in_period:
            events_by_action[log.action] = events_by_action.get(log.action, 0) + 1
            events_by_resource_type[log.resource_type] = events_by_resource_type.get(log.resource_type, 0) + 1
            if log.user_id:
                user_counts[log.user_id] = user_counts.get(log.user_id, 0) + 1

        # Top users
        top_users = sorted(
            [{"user_id": k, "event_count": v} for k, v in user_counts.items()],
            key=lambda x: x["event_count"],
            reverse=True
        )[:10]

        # Detect anomalies
        anomalies = await self.detect_anomalies(days=7)

        return AuditReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            period_start=start_date,
            period_end=end_date,
            total_events=len(logs_in_period),
            events_by_action=events_by_action,
            events_by_resource_type=events_by_resource_type,
            top_users=top_users,
            anomalies_detected=len(anomalies),
            compliance_score=self._calculate_compliance_score(logs_in_period),
            recommendations=self._generate_recommendations(logs_in_period, anomalies)
        )

    async def detect_anomalies(self, days: int = 7) -> List[AuditAnomaly]:
        """Detect access anomalies"""
        anomalies = []
        start_date = datetime.utcnow() - timedelta(days=days)

        recent_logs = [
            log for log in self.logs
            if log.timestamp >= start_date
        ]

        # Check for bulk access
        user_access_counts: Dict[str, int] = {}
        for log in recent_logs:
            if log.user_id:
                user_access_counts[log.user_id] = user_access_counts.get(log.user_id, 0) + 1

        for user_id, count in user_access_counts.items():
            if count > 1000:  # Threshold
                anomalies.append(AuditAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    detected_at=datetime.utcnow(),
                    anomaly_type="bulk_access",
                    severity="high",
                    description=f"User {user_id} accessed {count} resources in {days} days",
                    affected_resources=[],
                    user_id=user_id,
                    details={"access_count": count},
                    status="open"
                ))

        # Check for failed access attempts
        failed_attempts = [log for log in recent_logs if log.status == "failure"]
        if len(failed_attempts) > 50:
            anomalies.append(AuditAnomaly(
                anomaly_id=str(uuid.uuid4()),
                detected_at=datetime.utcnow(),
                anomaly_type="failed_attempts",
                severity="medium",
                description=f"High number of failed access attempts: {len(failed_attempts)}",
                affected_resources=[],
                user_id=None,
                details={"failed_count": len(failed_attempts)},
                status="open"
            ))

        return anomalies

    def _calculate_compliance_score(self, logs: List[AuditLog]) -> float:
        """Calculate compliance score based on audit logs"""
        if not logs:
            return 100.0

        # Factors that affect score
        failed_count = sum(1 for log in logs if log.status == "failure")
        total = len(logs)

        success_rate = (total - failed_count) / total if total > 0 else 1.0

        return round(success_rate * 100, 2)

    def _generate_recommendations(
        self,
        logs: List[AuditLog],
        anomalies: List[AuditAnomaly]
    ) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []

        if anomalies:
            recommendations.append(
                f"Review {len(anomalies)} detected anomalies and investigate suspicious activity"
            )

        failed_logs = [log for log in logs if log.status == "failure"]
        if len(failed_logs) > 10:
            recommendations.append(
                "High number of failed operations detected. Review access policies."
            )

        return recommendations
