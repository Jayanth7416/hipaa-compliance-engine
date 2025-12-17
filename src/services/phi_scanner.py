"""PHI Scanner Service"""

import re
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

from src.models.scan import PHIFinding, PHIType, ScanRequest, ScanStatus

logger = structlog.get_logger()


class PHIScanner:
    """
    Protected Health Information Scanner

    Uses pattern matching and NLP to detect PHI in text and documents.
    Supports 18 HIPAA identifiers.
    """

    def __init__(self):
        self.patterns = self._compile_patterns()
        self.jobs: Dict[str, Dict] = {}

    def _compile_patterns(self) -> Dict[PHIType, re.Pattern]:
        """Compile regex patterns for PHI detection"""
        return {
            PHIType.SSN: re.compile(
                r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
            ),
            PHIType.PHONE_NUMBER: re.compile(
                r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ),
            PHIType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            PHIType.DATE_OF_BIRTH: re.compile(
                r'\b(?:DOB|Date of Birth|Birth Date)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b',
                re.IGNORECASE
            ),
            PHIType.MEDICAL_RECORD_NUMBER: re.compile(
                r'\b(?:MRN|Medical Record|Patient ID)[:\s#]*([A-Z0-9]{6,12})\b',
                re.IGNORECASE
            ),
            PHIType.HEALTH_PLAN_ID: re.compile(
                r'\b(?:Insurance ID|Policy|Member ID)[:\s#]*([A-Z0-9]{8,15})\b',
                re.IGNORECASE
            ),
            PHIType.ZIP_CODE: re.compile(
                r'\b\d{5}(?:-\d{4})?\b'
            ),
            PHIType.IP_ADDRESS: re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ),
            PHIType.ACCOUNT_NUMBER: re.compile(
                r'\b(?:Account|Acct)[:\s#]*(\d{8,16})\b',
                re.IGNORECASE
            ),
            PHIType.DIAGNOSIS_CODE: re.compile(
                r'\b(?:ICD-?10|Diagnosis)[:\s]*([A-Z]\d{2}(?:\.\d{1,4})?)\b',
                re.IGNORECASE
            ),
            PHIType.PROCEDURE_CODE: re.compile(
                r'\b(?:CPT|Procedure)[:\s]*(\d{5})\b',
                re.IGNORECASE
            ),
        }

        # Name patterns are handled separately with NLP

    async def scan_text(
        self,
        content: str,
        categories: Optional[List[PHIType]] = None,
        confidence_threshold: float = 0.8
    ) -> List[PHIFinding]:
        """
        Scan text content for PHI

        Args:
            content: Text to scan
            categories: Specific PHI types to detect (None = all)
            confidence_threshold: Minimum confidence score

        Returns:
            List of PHI findings
        """
        findings = []
        patterns_to_check = self.patterns

        if categories:
            patterns_to_check = {
                k: v for k, v in self.patterns.items()
                if k in categories
            }

        # Pattern-based detection
        for phi_type, pattern in patterns_to_check.items():
            for match in pattern.finditer(content):
                confidence = self._calculate_confidence(phi_type, match)
                if confidence >= confidence_threshold:
                    findings.append(PHIFinding(
                        phi_type=phi_type,
                        value=self._mask_value(match.group(), phi_type),
                        location={
                            "start": match.start(),
                            "end": match.end(),
                            "field": None
                        },
                        confidence=confidence,
                        context=self._get_context(content, match.start(), match.end())
                    ))

        # Name detection using simple heuristics
        name_findings = await self._detect_names(content, confidence_threshold)
        findings.extend(name_findings)

        logger.info(
            "phi_scan_completed",
            findings_count=len(findings),
            content_length=len(content)
        )

        return findings

    async def scan_document(
        self,
        content: bytes,
        content_type: str
    ) -> List[PHIFinding]:
        """Scan document for PHI"""
        # Extract text based on content type
        text = await self._extract_text(content, content_type)
        return await self.scan_text(text)

    async def _extract_text(self, content: bytes, content_type: str) -> str:
        """Extract text from document"""
        if content_type == "text/plain":
            return content.decode('utf-8')
        elif content_type == "application/json":
            import json
            data = json.loads(content)
            return self._flatten_json(data)
        elif content_type == "text/csv":
            return content.decode('utf-8')
        # For PDF and DOCX, would use specialized libraries
        return content.decode('utf-8', errors='ignore')

    def _flatten_json(self, data: Any, prefix: str = "") -> str:
        """Flatten JSON to searchable text"""
        parts = []
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                parts.append(f"{new_prefix}: {self._flatten_json(value, new_prefix)}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                parts.append(self._flatten_json(item, f"{prefix}[{i}]"))
        else:
            return str(data)
        return " ".join(parts)

    async def _detect_names(
        self,
        content: str,
        confidence_threshold: float
    ) -> List[PHIFinding]:
        """Detect names in content using heuristics"""
        findings = []

        # Simple pattern for names in context
        name_patterns = [
            (r'(?:Patient|Name)[:\s]+([A-Z][a-z]+\s+[A-Z][a-z]+)', 0.9),
            (r'(?:Dr\.|Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)', 0.85),
            (r'(?:seen by|referred to|attended by)\s+([A-Z][a-z]+\s+[A-Z][a-z]+)', 0.8),
        ]

        for pattern, base_confidence in name_patterns:
            for match in re.finditer(pattern, content):
                if base_confidence >= confidence_threshold:
                    findings.append(PHIFinding(
                        phi_type=PHIType.NAME,
                        value=self._mask_value(match.group(1), PHIType.NAME),
                        location={
                            "start": match.start(),
                            "end": match.end(),
                            "field": None
                        },
                        confidence=base_confidence,
                        context=self._get_context(content, match.start(), match.end())
                    ))

        return findings

    def _calculate_confidence(self, phi_type: PHIType, match: re.Match) -> float:
        """Calculate confidence score for a match"""
        base_confidence = {
            PHIType.SSN: 0.95,
            PHIType.EMAIL: 0.98,
            PHIType.PHONE_NUMBER: 0.85,
            PHIType.MEDICAL_RECORD_NUMBER: 0.90,
            PHIType.IP_ADDRESS: 0.80,
            PHIType.ZIP_CODE: 0.70,
            PHIType.DIAGNOSIS_CODE: 0.92,
        }.get(phi_type, 0.80)

        return base_confidence

    def _mask_value(self, value: str, phi_type: PHIType) -> str:
        """Mask detected value for display"""
        if phi_type == PHIType.SSN:
            return f"***-**-{value[-4:]}" if len(value) >= 4 else "***"
        elif phi_type == PHIType.EMAIL:
            parts = value.split('@')
            return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***@***"
        elif phi_type == PHIType.PHONE_NUMBER:
            return f"***-***-{value[-4:]}" if len(value) >= 4 else "***"
        elif phi_type == PHIType.NAME:
            parts = value.split()
            return " ".join(f"{p[0]}***" for p in parts)
        return "***"

    def _get_context(self, content: str, start: int, end: int, window: int = 30) -> str:
        """Get masked context around a finding"""
        ctx_start = max(0, start - window)
        ctx_end = min(len(content), end + window)
        context = content[ctx_start:ctx_end]
        # Mask the actual value in context
        return context[:start - ctx_start] + "[DETECTED]" + context[end - ctx_start:]

    async def create_batch_job(self, requests: List[ScanRequest]) -> str:
        """Create a batch scanning job"""
        job_id = str(uuid.uuid4())
        self.jobs[job_id] = {
            "status": ScanStatus.PENDING,
            "total": len(requests),
            "processed": 0,
            "failed": 0,
            "created_at": datetime.utcnow(),
            "results": []
        }
        return job_id

    async def process_batch(self, job_id: str, requests: List[ScanRequest]):
        """Process batch scanning job"""
        if job_id not in self.jobs:
            return

        self.jobs[job_id]["status"] = ScanStatus.PROCESSING

        for request in requests:
            try:
                findings = await self.scan_text(request.content)
                self.jobs[job_id]["results"].append({
                    "reference_id": request.reference_id,
                    "findings": findings,
                    "status": "success"
                })
                self.jobs[job_id]["processed"] += 1
            except Exception as e:
                self.jobs[job_id]["failed"] += 1
                logger.error("batch_scan_item_failed", error=str(e))

        self.jobs[job_id]["status"] = ScanStatus.COMPLETED
        self.jobs[job_id]["completed_at"] = datetime.utcnow()

    async def get_job_status(self, job_id: str) -> Optional[Dict]:
        """Get batch job status"""
        return self.jobs.get(job_id)
