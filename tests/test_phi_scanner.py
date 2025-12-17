"""Tests for PHI Scanner"""

import pytest
from src.services.phi_scanner import PHIScanner
from src.models.scan import PHIType


@pytest.fixture
def scanner():
    return PHIScanner()


class TestPHIScanner:
    """Test PHI detection capabilities"""

    @pytest.mark.asyncio
    async def test_detect_ssn(self, scanner):
        """Test SSN detection"""
        text = "Patient SSN is 123-45-6789"
        findings = await scanner.scan_text(text)

        ssn_findings = [f for f in findings if f.phi_type == PHIType.SSN]
        assert len(ssn_findings) == 1
        assert "6789" in ssn_findings[0].value  # Last 4 preserved in mask

    @pytest.mark.asyncio
    async def test_detect_email(self, scanner):
        """Test email detection"""
        text = "Contact: john.doe@hospital.com"
        findings = await scanner.scan_text(text)

        email_findings = [f for f in findings if f.phi_type == PHIType.EMAIL]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_detect_phone(self, scanner):
        """Test phone number detection"""
        text = "Call patient at (555) 123-4567"
        findings = await scanner.scan_text(text)

        phone_findings = [f for f in findings if f.phi_type == PHIType.PHONE_NUMBER]
        assert len(phone_findings) == 1

    @pytest.mark.asyncio
    async def test_detect_mrn(self, scanner):
        """Test Medical Record Number detection"""
        text = "MRN: ABC123456"
        findings = await scanner.scan_text(text)

        mrn_findings = [f for f in findings if f.phi_type == PHIType.MEDICAL_RECORD_NUMBER]
        assert len(mrn_findings) == 1

    @pytest.mark.asyncio
    async def test_detect_diagnosis_code(self, scanner):
        """Test ICD-10 diagnosis code detection"""
        text = "Diagnosis: ICD-10 I10 (Hypertension)"
        findings = await scanner.scan_text(text)

        diagnosis_findings = [f for f in findings if f.phi_type == PHIType.DIAGNOSIS_CODE]
        assert len(diagnosis_findings) == 1

    @pytest.mark.asyncio
    async def test_no_phi_clean_text(self, scanner):
        """Test no false positives on clean text"""
        text = "The patient is feeling better today."
        findings = await scanner.scan_text(text)

        # Should have no findings or only low-confidence ones
        high_confidence = [f for f in findings if f.confidence >= 0.9]
        assert len(high_confidence) == 0

    @pytest.mark.asyncio
    async def test_multiple_phi_types(self, scanner):
        """Test detecting multiple PHI types in one text"""
        text = """
        Patient: John Smith
        SSN: 123-45-6789
        Phone: (555) 123-4567
        Email: john.smith@email.com
        MRN: PAT12345678
        """
        findings = await scanner.scan_text(text)

        phi_types_found = set(f.phi_type for f in findings)
        assert PHIType.SSN in phi_types_found
        assert PHIType.PHONE_NUMBER in phi_types_found
        assert PHIType.EMAIL in phi_types_found

    @pytest.mark.asyncio
    async def test_confidence_threshold(self, scanner):
        """Test confidence threshold filtering"""
        text = "SSN: 123-45-6789"

        # High threshold
        findings_high = await scanner.scan_text(text, confidence_threshold=0.99)

        # Low threshold
        findings_low = await scanner.scan_text(text, confidence_threshold=0.5)

        # Low threshold should capture more or equal findings
        assert len(findings_low) >= len(findings_high)
