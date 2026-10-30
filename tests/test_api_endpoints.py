"""End-to-End FastAPI Endpoint & Security/RBAC Tests"""

from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)


class TestAPIEndpoints:
    """Test REST endpoints, shared cross-route audit state, and JWT RBAC."""

    def test_root_health_and_dashboard(self):
        r_root = client.get("/")
        assert r_root.status_code == 200
        assert r_root.json()["status"] == "operational"

        r_health = client.get("/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "healthy"

        r_dash = client.get("/dashboard")
        assert r_dash.status_code == 200
        assert "HIPAA Compliance Engine" in r_dash.text

    def test_scan_mask_encrypt_logs_appear_in_audit_trail(self):
        # 1. Scan text via /scan/text
        scan_res = client.post(
            "/scan/text",
            json={
                "content": "Patient: John Smith, SSN: 123-45-6789",
                "reference_id": "ref-e2e-101",
                "user_id": "clinician-1",
            },
        )
        assert scan_res.status_code == 200
        scan_body = scan_res.json()
        assert scan_body["phi_detected"] is True
        assert scan_body["risk_level"] == "high"
        assert "ssn" in scan_body["summary"]

        # 2. Mask data via /mask/data
        mask_res = client.post(
            "/mask/data",
            json={
                "data": {"patient": {"ssn": "123-45-6789"}},
                "default_strategy": "tokenize",
                "reference_id": "ref-e2e-101",
            },
        )
        assert mask_res.status_code == 200
        masked_ssn = mask_res.json()["masked_data"]["patient"]["ssn"]
        assert masked_ssn.startswith("TOK_")

        # 3. Unmask data via /mask/unmask
        unmask_res = client.post(
            "/mask/unmask",
            json={"data": {"patient": {"ssn": masked_ssn}}},
        )
        assert unmask_res.status_code == 200
        assert unmask_res.json()["data"]["patient"]["ssn"] == "123-45-6789"

        # 4. Encrypt & Decrypt via /encrypt/data and /encrypt/decrypt
        enc_res = client.post(
            "/encrypt/data",
            json={
                "data": {"ssn": "123-45-6789"},
                "fields": ["ssn"],
                "reference_id": "ref-e2e-101",
            },
        )
        assert enc_res.status_code == 200
        enc_body = enc_res.json()
        assert enc_body["algorithm"] == "AES-256-GCM"

        dec_res = client.post(
            "/encrypt/decrypt",
            json={
                "data": enc_body["encrypted_data"],
                "fields": ["ssn"],
                "key_id": enc_body["key_id"],
            },
        )
        assert dec_res.status_code == 200
        assert dec_res.json()["data"]["ssn"] == "123-45-6789"

        # 5. Verify all operations were persisted to the shared AuditService
        trail_res = client.get("/audit/resource/ref-e2e-101")
        assert trail_res.status_code == 200
        trail = trail_res.json()
        actions = {e["action"] for e in trail["events"]}
        assert "phi_scan" in actions
        assert "data_mask" in actions
        assert "encrypt" in actions

        # 6. Verify cryptographic hash chain via /audit/verify
        verify_res = client.get("/audit/verify")
        assert verify_res.status_code == 200
        assert verify_res.json()["valid"] is True

    def test_jwt_auth_and_rbac_enforcement(self):
        # Issue an 'auditor' token (only has audit_read & compliance_read permissions)
        tok_res = client.post(
            "/auth/token",
            json={"user_id": "auditor-Jane", "role": "auditor", "mfa_code": "123456"},
        )
        assert tok_res.status_code == 200
        auditor_token = tok_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {auditor_token}"}

        # Auditor can read audit logs
        logs_res = client.get("/audit/logs", headers=headers)
        assert logs_res.status_code == 200

        # Auditor is forbidden (403) from rotating encryption keys or scanning PHI
        rotate_res = client.post(
            "/encrypt/rotate-key",
            json={"old_key_id": "default-key"},
            headers=headers,
        )
        assert rotate_res.status_code == 403

        # Invalid JWT is rejected with 401
        bad_res = client.get(
            "/audit/logs",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert bad_res.status_code == 401

    def test_compliance_check_and_reports(self):
        check_res = client.post(
            "/compliance/check",
            params={"resource_type": "database", "resource_id": "prod-db"},
        )
        assert check_res.status_code == 200
        assert check_res.json()["score"] == 100.0

        rep_html = client.get("/compliance/report?period=monthly&format=html")
        assert rep_html.status_code == 200
        assert "HIPAA Compliance Report" in rep_html.text

        audit_csv = client.get("/audit/report?format=csv")
        assert audit_csv.status_code == 200
        assert "Report ID" in audit_csv.text
