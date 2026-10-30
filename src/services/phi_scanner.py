"""PHI Scanner Service"""

import csv
import io
import json
import re
import uuid
import xml.etree.ElementTree as ET
import zipfile
import zlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import structlog

from src.models.scan import PHIFinding, PHIType, ScanRequest, ScanStatus
from src.utils.database import BatchScanJobModel, get_db_session, utc_now

logger = structlog.get_logger()

# Optional spaCy NLP model if available in environment
_SPACY_NLP = None
try:
    import spacy  # type: ignore

    for _model_name in ("en_core_web_sm", "en_core_web_md"):
        try:
            _SPACY_NLP = spacy.load(_model_name)
            break
        except Exception:
            continue
except Exception:
    _SPACY_NLP = None


class PHIScanner:
    """
    Protected Health Information Scanner

    Uses pattern matching, contextual heuristics, and optional NLP (spaCy NER)
    to detect PHI across all 18 HIPAA Safe Harbor identifier categories plus
    clinical diagnosis/procedure codes.
    """

    _NON_NAME_PHRASES = {
        "patient ssn",
        "social security",
        "medical record",
        "health plan",
        "insurance id",
        "account number",
        "date of birth",
        "birth date",
        "admission date",
        "discharge date",
        "general hospital",
        "main street",
        "blood pressure",
        "heart rate",
        "diagnosis code",
        "procedure code",
    }

    def __init__(self):
        self.patterns = self._compile_patterns()
        self.jobs: Dict[str, Dict[str, Any]] = {}

    def _compile_patterns(self) -> Dict[PHIType, re.Pattern]:
        """Compile regex patterns for HIPAA Safe Harbor PHI detection."""
        return {
            PHIType.SSN: re.compile(
                r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
            ),
            PHIType.PHONE_NUMBER: re.compile(
                r"(?:\+1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\b\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"
            ),
            PHIType.FAX_NUMBER: re.compile(
                r"\b(?:Fax|Facsimile)[:\s#]*(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                re.IGNORECASE,
            ),
            PHIType.EMAIL: re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),
            PHIType.DATE_OF_BIRTH: re.compile(
                r"\b(?:DOB|Date of Birth|Birth Date|Born)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b",
                re.IGNORECASE,
            ),
            PHIType.ADMISSION_DATE: re.compile(
                r"\b(?:Admission(?:\s+Date)?|Admitted(?:\s+On)?|Admit\s+Date)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b",
                re.IGNORECASE,
            ),
            PHIType.DISCHARGE_DATE: re.compile(
                r"\b(?:Discharge(?:\s+Date)?|Discharged(?:\s+On)?)[:\s]*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}[/\-]\d{1,2})\b",
                re.IGNORECASE,
            ),
            PHIType.MEDICAL_RECORD_NUMBER: re.compile(
                r"\b(?:MRN|Medical Record(?:\s+Number)?|Patient ID)[:\s#]*([A-Z0-9][A-Z0-9-]{5,14})\b",
                re.IGNORECASE,
            ),
            PHIType.HEALTH_PLAN_ID: re.compile(
                r"\b(?:Insurance ID|Policy(?:\s+Number)?|Member ID|Health Plan(?:\s+ID)?|Beneficiary ID)[:\s#]*([A-Z0-9][A-Z0-9-]{7,16})\b",
                re.IGNORECASE,
            ),
            PHIType.ACCOUNT_NUMBER: re.compile(
                r"\b(?:Account(?:\s+Number)?|Acct|Billing ID)[:\s#]*([A-Z0-9-]{8,16})\b",
                re.IGNORECASE,
            ),
            PHIType.LICENSE_NUMBER: re.compile(
                r"\b(?:Driver'?s?\s+License|License(?:\s+Number)?|DL|NPI|DEA)[:\s#]*([A-Z0-9-]{7,15})\b",
                re.IGNORECASE,
            ),
            PHIType.VEHICLE_IDENTIFIER: re.compile(
                r"\b(?:VIN|Vehicle(?:\s+ID)?|License Plate|Plate)[:\s#]*([A-HJ-NPR-Z0-9]{17}|[A-Z0-9-]{5,8})\b",
                re.IGNORECASE,
            ),
            PHIType.ADDRESS: re.compile(
                r"\b\d{1,6}\s+(?:[A-Z][a-zA-Z0-9.]*\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Parkway|Pkwy|Terrace|Ter|Circle|Cir|Trail|Trl|Highway|Hwy)\b(?:\s*,?\s*(?:Apt|Suite|Ste|Unit|#)\s*[A-Za-z0-9-]+)?",
            ),
            PHIType.ZIP_CODE: re.compile(
                r"\b\d{5}(?:-\d{4})?\b"
            ),
            PHIType.IP_ADDRESS: re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            PHIType.DEVICE_IDENTIFIER: re.compile(
                r"(?:\b(?:UDI|Device(?:\s+ID)?|Serial(?:\s+Number)?|IMEI)[:\s#]*([A-Za-z0-9:-]{8,25})\b|\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b)",
                re.IGNORECASE,
            ),
            PHIType.URL: re.compile(
                r"\bhttps?://[^\s<>\"')]+\b",
                re.IGNORECASE,
            ),
            PHIType.BIOMETRIC: re.compile(
                r"\b(?:Biometric(?:\s+ID|\s+Template)?|Fingerprint(?:\s+Hash|\s+ID)?|Retinal\s+Scan|Voiceprint)[:\s#]*([A-Za-z0-9_-]{4,36})\b",
                re.IGNORECASE,
            ),
            PHIType.PHOTO: re.compile(
                r"\b(?:Photo(?:\s+ID)?|Facial\s+Image|Full-Face\s+Image|DICOM\s+Image)[:\s#]*([A-Za-z0-9_./-]+\.(?:jpg|jpeg|png|dcm|tiff|webp)|[A-Za-z0-9_-]{6,32})\b",
                re.IGNORECASE,
            ),
            PHIType.DIAGNOSIS_CODE: re.compile(
                r"\b(?:ICD-?10|Diagnosis(?:\s+Code)?)[:\s]*([A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?)\b",
                re.IGNORECASE,
            ),
            PHIType.PROCEDURE_CODE: re.compile(
                r"\b(?:CPT|Procedure(?:\s+Code)?)[:\s]*(\d{5})\b",
                re.IGNORECASE,
            ),
        }

    async def scan_text(
        self,
        content: str,
        categories: Optional[List[PHIType]] = None,
        confidence_threshold: float = 0.8,
        include_original: bool = False,
    ) -> List[PHIFinding]:
        """
        Scan text content for PHI.

        Args:
            content: Text to scan
            categories: Specific PHI types to detect (None = all)
            confidence_threshold: Minimum confidence score (0.0 to 1.0)
            include_original: Whether to populate original_value on findings

        Returns:
            List of PHIFinding objects
        """
        if not content:
            return []

        findings: List[PHIFinding] = []
        occupied_spans: List[Tuple[int, int]] = []

        patterns_to_check = self.patterns
        if categories is not None:
            category_set = set(categories)
            patterns_to_check = {
                k: v for k, v in self.patterns.items() if k in category_set
            }

        # Run higher-specificity patterns before generic numeric patterns (like ZIP_CODE)
        ordered_items = sorted(
            patterns_to_check.items(),
            key=lambda kv: 1 if kv[0] == PHIType.ZIP_CODE else 0,
        )

        for phi_type, pattern in ordered_items:
            for match in pattern.finditer(content):
                start, end = match.start(), match.end()

                # Avoid duplicate overlapping matches (e.g. a 5-digit CPT or SSN segment matching as ZIP)
                if phi_type == PHIType.ZIP_CODE and any(
                    not (end <= s or start >= e) for s, e in occupied_spans
                ):
                    continue

                confidence = self._calculate_confidence(phi_type, match, content)
                if confidence >= confidence_threshold:
                    raw_val = (
                        match.group(1)
                        if match.lastindex and match.group(1)
                        else match.group(0)
                    )
                    occupied_spans.append((start, end))
                    findings.append(
                        PHIFinding(
                            phi_type=phi_type,
                            value=self._mask_value(raw_val, phi_type),
                            original_value=raw_val if include_original else None,
                            location={
                                "start": start,
                                "end": end,
                                "field": None,
                            },
                            confidence=confidence,
                            context=self._get_context(content, start, end),
                        )
                    )

        # Name detection (respecting categories filter)
        if categories is None or PHIType.NAME in categories:
            name_findings = await self._detect_names(
                content,
                confidence_threshold=confidence_threshold,
                occupied_spans=occupied_spans,
                include_original=include_original,
            )
            findings.extend(name_findings)

        logger.info(
            "phi_scan_completed",
            findings_count=len(findings),
            content_length=len(content),
        )

        return findings

    async def scan_document(
        self,
        content: bytes,
        content_type: str,
        categories: Optional[List[PHIType]] = None,
        confidence_threshold: float = 0.8,
    ) -> List[PHIFinding]:
        """Scan an uploaded document (TXT, JSON, CSV, DOCX, PDF) for PHI."""
        text = await self._extract_text(content, content_type)
        return await self.scan_text(
            text,
            categories=categories,
            confidence_threshold=confidence_threshold,
        )

    async def _extract_text(self, content: bytes, content_type: str) -> str:
        """Extract searchable text from supported document formats."""
        if content_type == "text/plain":
            return content.decode("utf-8", errors="replace")

        if content_type == "application/json":
            data = json.loads(content.decode("utf-8", errors="replace"))
            return self._flatten_json(data)

        if content_type == "text/csv":
            decoded = content.decode("utf-8", errors="replace")
            reader = csv.reader(io.StringIO(decoded))
            rows = [" | ".join(cell.strip() for cell in row if cell.strip()) for row in reader]
            return "\n".join(rows)

        if content_type in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/docx",
        ):
            return self._extract_docx_text(content)

        if content_type == "application/pdf":
            return self._extract_pdf_text(content)

        return content.decode("utf-8", errors="ignore")

    def _extract_docx_text(self, content: bytes) -> str:
        """Extract text from a DOCX (Office Open XML) archive using stdlib zipfile + XML."""
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                if "word/document.xml" not in zf.namelist():
                    return ""
                xml_bytes = zf.read("word/document.xml")
                root = ET.fromstring(xml_bytes)
                paragraphs: List[str] = []
                for elem in root.iter():
                    if elem.tag.endswith("}t") and elem.text:
                        paragraphs.append(elem.text)
                return " ".join(paragraphs)
        except Exception as e:
            logger.warning("docx_extraction_fallback", error=str(e))
            return content.decode("utf-8", errors="ignore")

    def _extract_pdf_text(self, content: bytes) -> str:
        """Extract text from PDF bytes using pypdf if installed or stream parser fallback."""
        try:
            import pypdf  # type: ignore

            reader = pypdf.PdfReader(io.BytesIO(content))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            pass

        # Built-in PDF stream/text object parser (supports compressed FlateDecode & raw PDF text)
        extracted_chunks: List[str] = []

        # 1. Inspect decompressed streams
        for stream_match in re.finditer(rb"stream[\r\n]+(.*?)[\r\n]+endstream", content, re.DOTALL):
            raw_stream = stream_match.group(1)
            for candidate in (raw_stream, self._try_zlib_decompress(raw_stream)):
                if not candidate:
                    continue
                for text_obj in re.findall(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj", candidate):
                    extracted_chunks.append(text_obj.decode("latin-1", errors="ignore"))
                for tj_array in re.findall(rb"\[(.*?)\]\s*TJ", candidate, re.DOTALL):
                    for part in re.findall(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)", tj_array):
                        extracted_chunks.append(part.decode("latin-1", errors="ignore"))

        # 2. Check uncompressed literal text strings in PDF body
        if not extracted_chunks:
            for text_obj in re.findall(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)\s*Tj", content):
                extracted_chunks.append(text_obj.decode("latin-1", errors="ignore"))

        if extracted_chunks:
            return " ".join(extracted_chunks)

        return content.decode("utf-8", errors="ignore")

    @staticmethod
    def _try_zlib_decompress(data: bytes) -> Optional[bytes]:
        try:
            return zlib.decompress(data)
        except Exception:
            return None

    def _flatten_json(self, data: Any, prefix: str = "") -> str:
        """Flatten nested JSON dicts and lists to searchable text."""
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
        confidence_threshold: float,
        occupied_spans: Optional[List[Tuple[int, int]]] = None,
        include_original: bool = False,
    ) -> List[PHIFinding]:
        """Detect person names using contextual heuristics and optional spaCy NER."""
        findings: List[PHIFinding] = []
        spans = list(occupied_spans or [])

        name_patterns = [
            (
                r"(?:Patient(?:\s+Name)?|Full\s+Name|Member\s+Name|Client\s+Name|Name)[:\s]+([A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-zA-Z'-]+)",
                0.92,
            ),
            (
                r"(?:Dr\.|Mr\.|Mrs\.|Ms\.|Prof\.)\s+([A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-zA-Z'-]+)?)",
                0.88,
            ),
            (
                r"(?:seen by|referred to|attended by|examined by|signed by|treating physician|provider)[:\s]+(?:Dr\.\s+)?([A-Z][a-zA-Z'-]+\s+[A-Z][a-zA-Z'-]+)",
                0.85,
            ),
        ]

        for pattern, base_confidence in name_patterns:
            if base_confidence < confidence_threshold:
                continue
            for match in re.finditer(pattern, content):
                candidate = match.group(1).strip()
                if candidate.lower() in self._NON_NAME_PHRASES:
                    continue
                start, end = match.start(1), match.end(1)
                if any(not (end <= s or start >= e) for s, e in spans):
                    continue
                spans.append((start, end))
                findings.append(
                    PHIFinding(
                        phi_type=PHIType.NAME,
                        value=self._mask_value(candidate, PHIType.NAME),
                        original_value=candidate if include_original else None,
                        location={
                            "start": match.start(),
                            "end": match.end(),
                            "field": None,
                        },
                        confidence=base_confidence,
                        context=self._get_context(content, match.start(), match.end()),
                    )
                )

        # Supplement with spaCy NER if loaded
        if _SPACY_NLP is not None and 0.85 >= confidence_threshold:
            doc = _SPACY_NLP(content)
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    candidate = ent.text.strip()
                    if len(candidate.split()) < 2 or candidate.lower() in self._NON_NAME_PHRASES:
                        continue
                    start, end = ent.start_char, ent.end_char
                    if any(not (end <= s or start >= e) for s, e in spans):
                        continue
                    spans.append((start, end))
                    findings.append(
                        PHIFinding(
                            phi_type=PHIType.NAME,
                            value=self._mask_value(candidate, PHIType.NAME),
                            original_value=candidate if include_original else None,
                            location={"start": start, "end": end, "field": None},
                            confidence=0.85,
                            context=self._get_context(content, start, end),
                        )
                    )

        return findings

    def _calculate_confidence(
        self,
        phi_type: PHIType,
        match: re.Match,
        content: str = "",
    ) -> float:
        """Calculate contextual confidence score for a regex match."""
        base_confidence = {
            PHIType.SSN: 0.95,
            PHIType.EMAIL: 0.98,
            PHIType.PHONE_NUMBER: 0.85,
            PHIType.FAX_NUMBER: 0.90,
            PHIType.MEDICAL_RECORD_NUMBER: 0.90,
            PHIType.HEALTH_PLAN_ID: 0.90,
            PHIType.ACCOUNT_NUMBER: 0.88,
            PHIType.LICENSE_NUMBER: 0.88,
            PHIType.VEHICLE_IDENTIFIER: 0.90,
            PHIType.DATE_OF_BIRTH: 0.92,
            PHIType.ADMISSION_DATE: 0.90,
            PHIType.DISCHARGE_DATE: 0.90,
            PHIType.ADDRESS: 0.86,
            PHIType.IP_ADDRESS: 0.85,
            PHIType.ZIP_CODE: 0.70,
            PHIType.DEVICE_IDENTIFIER: 0.88,
            PHIType.URL: 0.85,
            PHIType.BIOMETRIC: 0.92,
            PHIType.PHOTO: 0.88,
            PHIType.DIAGNOSIS_CODE: 0.92,
            PHIType.PROCEDURE_CODE: 0.88,
        }.get(phi_type, 0.80)

        # Boost ZIP_CODE confidence when preceded by "ZIP" or state abbreviation
        if phi_type == PHIType.ZIP_CODE and content:
            prefix = content[max(0, match.start() - 20) : match.start()]
            if re.search(r"\b(?:ZIP|Postal|[A-Z]{2})\s*[:,-]?\s*$", prefix, re.IGNORECASE):
                return 0.88

        return base_confidence

    def _mask_value(self, value: str, phi_type: PHIType) -> str:
        """Mask detected PHI value for safe display."""
        if phi_type == PHIType.SSN:
            return f"***-**-{value[-4:]}" if len(value) >= 4 else "***"
        if phi_type == PHIType.EMAIL:
            parts = value.split("@")
            return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***@***"
        if phi_type in (PHIType.PHONE_NUMBER, PHIType.FAX_NUMBER):
            return f"***-***-{value[-4:]}" if len(value) >= 4 else "***"
        if phi_type == PHIType.NAME:
            parts = value.split()
            return " ".join(f"{p[0]}***" for p in parts if p)
        if phi_type in (
            PHIType.MEDICAL_RECORD_NUMBER,
            PHIType.HEALTH_PLAN_ID,
            PHIType.ACCOUNT_NUMBER,
            PHIType.LICENSE_NUMBER,
        ):
            return f"***{value[-3:]}" if len(value) > 4 else "***"
        return "***"

    def _get_context(self, content: str, start: int, end: int, window: int = 30) -> str:
        """Get masked context around a finding."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(content), end + window)
        context = content[ctx_start:ctx_end]
        return context[: start - ctx_start] + "[DETECTED]" + context[end - ctx_start :]

    async def create_batch_job(self, requests: List[ScanRequest]) -> str:
        """Create a persistent batch scanning job."""
        job_id = str(uuid.uuid4())
        now = utc_now()
        job_state = {
            "job_id": job_id,
            "status": ScanStatus.PENDING,
            "total": len(requests),
            "processed": 0,
            "failed": 0,
            "created_at": now,
            "completed_at": None,
            "results": [],
        }
        self.jobs[job_id] = job_state

        with get_db_session() as db:
            db.add(
                BatchScanJobModel(
                    job_id=job_id,
                    status=ScanStatus.PENDING.value,
                    total=len(requests),
                    processed=0,
                    failed=0,
                    created_at=now,
                    results=[],
                )
            )
            db.commit()

        return job_id

    async def process_batch(self, job_id: str, requests: List[ScanRequest]) -> None:
        """Process batch scanning job and persist results."""
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = ScanStatus.PROCESSING

        results_list: List[Dict[str, Any]] = []
        processed = 0
        failed = 0

        for request in requests:
            try:
                findings = await self.scan_text(
                    request.content,
                    categories=request.categories,
                    confidence_threshold=request.confidence_threshold,
                )
                results_list.append(
                    {
                        "reference_id": request.reference_id,
                        "findings": [f.model_dump() for f in findings],
                        "status": "success",
                    }
                )
                processed += 1
            except Exception as e:
                failed += 1
                logger.error("batch_scan_item_failed", error=type(e).__name__)

        completed_at = utc_now()
        if job_id in self.jobs:
            self.jobs[job_id].update(
                {
                    "status": ScanStatus.COMPLETED,
                    "processed": processed,
                    "failed": failed,
                    "completed_at": completed_at,
                    "results": results_list,
                }
            )

        with get_db_session() as db:
            record = db.query(BatchScanJobModel).filter_by(job_id=job_id).first()
            if record:
                record.status = ScanStatus.COMPLETED.value
                record.processed = processed
                record.failed = failed
                record.completed_at = completed_at
                record.results = results_list
                db.commit()

    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get batch job status from memory or persistent database."""
        if job_id in self.jobs:
            return self.jobs[job_id]

        with get_db_session() as db:
            record = db.query(BatchScanJobModel).filter_by(job_id=job_id).first()
            if not record:
                return None
            return {
                "job_id": record.job_id,
                "status": record.status,
                "total": record.total,
                "processed": record.processed,
                "failed": record.failed,
                "created_at": record.created_at,
                "completed_at": record.completed_at,
                "results": record.results,
            }
