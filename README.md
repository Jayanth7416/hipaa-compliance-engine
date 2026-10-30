# HIPAA Compliance Engine

Automated data security, de-identification, and compliance pipeline for healthcare applications. Enforces HIPAA Security and Privacy Rule safeguards (45 CFR §164.312 & §164.514) through Safe Harbor PHI detection, configurable data masking, authenticated AES-256-GCM envelope encryption, tamper-evident hash-chained audit logging, and real-time policy validation.

## Features

- **18-Identifier HIPAA Safe Harbor PHI Detection**: Contextual pattern matching and optional NLP (spaCy NER) across all 18 HIPAA Safe Harbor identifiers plus ICD-10 and CPT clinical codes, supporting text, JSON, CSV, DOCX, and PDF documents.
- **Data Masking & Safe Harbor Generalization**:
  - `REDACT`: Redact direct identifiers (`[REDACTED]`)
  - `HASH`: Keyed **HMAC-SHA256** hashing (prevents rainbow-table reversal on low-entropy identifiers like SSNs and DOBs)
  - `TOKENIZE`: Reversible tokenization backed by an encrypted persistent database vault
  - `GENERALIZE`: True HIPAA Safe Harbor generalization (`90+` age top-coding, 3-digit ZIP truncation with `000` masking for restricted low-population prefixes, and year-only dates)
  - `ENCRYPT`: Authenticated **AES-256-GCM** field encryption
  - `auto_mask`: Automatically detects and masks PHI in both structured JSON keys and unstructured free-text clinical notes.
- **Authenticated AES-256-GCM Envelope Encryption**: 256-bit Data Encryption Keys (DEKs) wrapped by a Key Encryption Key (PBKDF2-HMAC-SHA256 or AWS KMS) with persistent key rotation and automatic vault/record re-encryption.
- **Tamper-Evident Audit Logging**: Persistent SQLite/PostgreSQL audit trail with cryptographic **SHA-256 hash chaining** (`previous_hash` → `entry_hash`), chain verification (`/audit/verify`), anomaly detection, and JSON/CSV export.
- **JWT & Role-Based Access Control (RBAC) with MFA**: Role-based permission enforcement (`admin`, `compliance_officer`, `clinician`, `auditor`) and MFA verification for privileged unmasking, decryption, and key rotation operations.
- **Policy Engine & Live Compliance Checks**: Evaluates payloads and system posture against HIPAA technical safeguards (`§164.312(a)-(e)`, `§164.502(b)`) and tracks violation lifecycles.

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Data Sources   │────▶│   PHI Scanner    │────▶│  Policy Engine   │
│ (Text/PDF/DOCX)  │     │(18 Identifiers)  │     │ (Rule Evaluation)│
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
                         ┌──────────────────┐              │
                         │  Transformation  │◀─────────────┘
                         │(Mask/AES-256-GCM)│
                         └────────┬─────────┘
                                  │
    ┌─────────────────────────────┼─────────────────────────────┐
    │                             │                             │
    ▼                             ▼                             ▼
┌────────┐                 ┌────────────┐                ┌───────────┐
│ Output │                 │Hash-Chained│                │Interactive│
│  Data  │                 │ Audit Logs │                │ Dashboard │
└────────┘                 └────────────┘                └───────────┘
```

## HIPAA Compliance Coverage

| Requirement | CFR Reference | Implementation |
|-------------|---------------|----------------|
| Access Control | §164.312(a)(1) | JWT RBAC (`admin`, `compliance_officer`, `clinician`, `auditor`) & 30m session timeout |
| Audit Controls | §164.312(b) | Persistent SHA-256 hash-chained audit logs with 7-year (2555-day) retention policy |
| Integrity Controls | §164.312(c)(1) | SHA-256 payload checksum verification & AES-256-GCM authenticated encryption tags |
| Person Authentication | §164.312(d) | Signed JWT tokens with MFA verification required for decrypt/unmask/key-rotation |
| Transmission & Storage Security | §164.312(e)(1) | AES-256-GCM envelope encryption with persistent key rotation & AWS KMS support |
| PHI De-identification | §164.514(b)(2) | Safe Harbor 18-identifier scanning, `90+` age capping, and restricted 3-digit ZIP masking |

## Quick Start

```bash
# Clone repository
git clone https://github.com/Jayanth7416/hipaa-compliance-engine.git
cd hipaa-compliance-engine

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run API server (interactive dashboard available at http://localhost:8000/dashboard)
uvicorn src.api.main:app --reload

# Run CLI compliance scan on a file or directory
python -m src.services.scanner --input data/ --output results/

# Run test suite
pytest
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/token` | Issue signed JWT access token with role & MFA claims |
| GET | `/auth/me` | Inspect current authenticated principal and permissions |
| POST | `/scan/text` (or `/scan`) | Scan text content for PHI |
| POST | `/scan/document` | Scan uploaded PDF, DOCX, TXT, CSV, or JSON document |
| POST | `/scan/batch` | Submit asynchronous batch PHI scan job |
| POST | `/mask/data` (or `/mask`) | Apply field-level data masking (`redact`, `hash`, `tokenize`, `generalize`, `encrypt`) |
| POST | `/mask/auto` | Automatically detect and mask PHI in structured fields and free-text notes |
| POST | `/mask/unmask` | Reverse tokenization or encryption (requires MFA) |
| POST | `/encrypt/data` (or `/encrypt`) | Encrypt specified fields using AES-256-GCM |
| POST | `/encrypt/decrypt` | Decrypt AES-256-GCM fields (requires MFA) |
| POST | `/encrypt/rotate-key` | Rotate active encryption key and re-encrypt vault/records |
| GET | `/audit/logs` | Query tamper-evident audit logs |
| GET | `/audit/verify` | Verify SHA-256 cryptographic hash chain across all audit logs |
| GET | `/audit/resource/{resource_id}` | Get complete audit trail for a resource |
| GET | `/audit/report` | Generate compliance audit report (`json` or `csv`) |
| GET | `/compliance/status` | Get real-time overall HIPAA compliance status |
| POST | `/compliance/check` | Run live technical safeguard diagnostics |
| GET | `/compliance/report` | Generate HIPAA compliance report (`json` or `html`) |
| POST | `/compliance/validate` (or `/policies/validate`) | Validate payload against HIPAA policies |

## License

MIT License

## Author

Jayanth Kumar Panuganti - [LinkedIn](https://linkedin.com/in/jayanth7416)
