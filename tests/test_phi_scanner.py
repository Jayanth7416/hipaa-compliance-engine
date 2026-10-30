"""Tests for PHI Scanner Service (18 HIPAA Safe Harbor Identifiers & Document Parsing)"""

import io
import json
import zipfile
import pytest

from src.models.scan import PHIType, ScanRequest, ScanStatus
from src.services.phi_scanner import PHIScanner


@pytest.fixture
def scanner():
    return PHIScanner()


class TestPHIScanner:
    """Test PHI detection capabilities across Safe Harbor categories and document formats."""

    @pytest.mark.asyncio
    async def test_detect_ssn(self, scanner):
        text = "Patient SSN is 123-45-6789"
        findings = await scanner.scan_text(text)

        ssn_findings = [f for f in findings if f.phi_type == PHIType.SSN]
        assert len(ssn_findings) == 1
        assert "6789" in ssn_findings[0].value

    @pytest.mark.asyncio
    async def test_detect_email(self, scanner):
        text = "Contact: john.doe@hospital.com"
        findings = await scanner.scan_text(text)

        email_findings = [f for f in findings if f.phi_type == PHIType.EMAIL]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_detect_phone_and_fax(self, scanner):
        text = "Call patient at (555) 123-4567 or Fax: (555) 987-6543"
        findings = await scanner.scan_text(text)

        types = {f.phi_type for f in findings}
        assert PHIType.PHONE_NUMBER in types
        assert PHIType.FAX_NUMBER in types

    @pytest.mark.asyncio
    async def test_detect_mrn_and_health_plan(self, scanner):
        text = "MRN: ABC123456, Insurance ID: HP987654321"
        findings = await scanner.scan_text(text)

        types = {f.phi_type for f in findings}
        assert PHIType.MEDICAL_RECORD_NUMBER in types
        assert PHIType.HEALTH_PLAN_ID in types

    @pytest.mark.asyncio
    async def test_detect_diagnosis_and_procedure_codes(self, scanner):
        text = "Diagnosis: ICD-10 I10 (Hypertension), Procedure: CPT 99213"
        findings = await scanner.scan_text(text)

        types = {f.phi_type for f in findings}
        assert PHIType.DIAGNOSIS_CODE in types
        assert PHIType.PROCEDURE_CODE in types

    @pytest.mark.asyncio
    async def test_detect_extended_safe_harbor_identifiers(self, scanner):
        text = """
        Patient: Jane Doe
        DOB: 04/12/1982
        Admission Date: 10/01/2025
        Discharge Date: 10/05/2025
        Address: 742 Evergreen Terrace, Apt 2B
        ZIP: 03601
        Account Number: ACCT12345678
        License Number: DL98765432
        VIN: 1HGCM82633A004352
        Device ID: DEV-99887766
        Portal: https://portal.hospital.org/patient/123
        IP: 192.168.10.25
        Biometric ID: BIO_FP_88219
        Photo: facial_scan_01.jpg
        """
        findings = await scanner.scan_text(text, confidence_threshold=0.70)
        types = {f.phi_type for f in findings}

        assert PHIType.NAME in types
        assert PHIType.DATE_OF_BIRTH in types
        assert PHIType.ADMISSION_DATE in types
        assert PHIType.DISCHARGE_DATE in types
        assert PHIType.ADDRESS in types
        assert PHIType.ZIP_CODE in types
        assert PHIType.ACCOUNT_NUMBER in types
        assert PHIType.LICENSE_NUMBER in types
        assert PHIType.VEHICLE_IDENTIFIER in types
        assert PHIType.DEVICE_IDENTIFIER in types
        assert PHIType.URL in types
        assert PHIType.IP_ADDRESS in types
        assert PHIType.BIOMETRIC in types
        assert PHIType.PHOTO in types

    @pytest.mark.asyncio
    async def test_categories_filter_excludes_unspecified_types(self, scanner):
        text = "Patient: John Smith, SSN: 123-45-6789, Email: john@example.com"
        findings = await scanner.scan_text(text, categories=[PHIType.SSN])

        assert len(findings) == 1
        assert findings[0].phi_type == PHIType.SSN

    @pytest.mark.asyncio
    async def test_no_phi_clean_text(self, scanner):
        text = "The patient is feeling better today."
        findings = await scanner.scan_text(text)

        high_confidence = [f for f in findings if f.confidence >= 0.9]
        assert len(high_confidence) == 0

    @pytest.mark.asyncio
    async def test_multiple_phi_types(self, scanner):
        text = """
        Patient: John Smith
        SSN: 123-45-6789
        Phone: (555) 123-4567
        Email: john.smith@email.com
        MRN: PAT12345678
        """
        findings = await scanner.scan_text(text)

        phi_types_found = set(f.phi_type for f in findings)
        assert PHIType.NAME in phi_types_found
        assert PHIType.SSN in phi_types_found
        assert PHIType.PHONE_NUMBER in phi_types_found
        assert PHIType.EMAIL in phi_types_found
        assert PHIType.MEDICAL_RECORD_NUMBER in phi_types_found

    @pytest.mark.asyncio
    async def test_confidence_threshold(self, scanner):
        text = "SSN: 123-45-6789"
        findings_high = await scanner.scan_text(text, confidence_threshold=0.99)
        findings_low = await scanner.scan_text(text, confidence_threshold=0.5)

        assert len(findings_low) >= len(findings_high)

    @pytest.mark.asyncio
    async def test_scan_docx_and_pdf_documents(self, scanner):
        # 1. Construct a valid DOCX archive in memory
        docx_buf = io.BytesIO()
        with zipfile.ZipFile(docx_buf, "w") as zf:
            zf.writestr(
                "word/document.xml",
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>Patient: Alice Walker SSN: 123-45-6789</w:t></w:r></w:p></w:body>"
                "</w:document>",
            )
        docx_findings = await scanner.scan_document(
            docx_buf.getvalue(),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert any(f.phi_type == PHIType.SSN for f in docx_findings)

        # 2. Construct a minimal PDF stream containing text object
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Length 44 >>\nstream\nBT (Patient SSN: 123-45-6789) Tj ET\nendstream\nendobj\n%%EOF"
        pdf_findings = await scanner.scan_document(pdf_bytes, "application/pdf")
        assert any(f.phi_type == PHIType.SSN for f in pdf_findings)

        # 3. JSON document
        json_bytes = json.dumps({"patient": {"ssn": "123-45-6789"}}).encode("utf-8")
        json_findings = await scanner.scan_document(json_bytes, "application/json")
        assert any(f.phi_type == PHIType.SSN for f in json_findings)

    @pytest.mark.asyncio
    async def test_batch_job_lifecycle(self, scanner):
        requests = [
            ScanRequest(content="SSN: 123-45-6789", reference_id="item-1"),
            ScanRequest(content="Email: doctor@clinic.org", reference_id="item-2"),
        ]
        job_id = await scanner.create_batch_job(requests)
        await scanner.process_batch(job_id, requests)

        status = await scanner.get_job_status(job_id)
        assert status is not None
        assert status["status"] == ScanStatus.COMPLETED
        assert status["processed"] == 2
        assert len(status["results"]) == 2
