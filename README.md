# HIPAA Compliance Engine

Automated data security and compliance pipeline for healthcare applications. Ensures 100% HIPAA compliance through data masking, encryption, audit logging, and policy enforcement.

## Features

- **Automated PHI Detection**: ML-powered detection of Protected Health Information
- **Data Masking**: Configurable masking strategies for sensitive data
- **Encryption**: AES-256 encryption with AWS KMS key management
- **Audit Logging**: Comprehensive audit trails for all data access
- **Policy Engine**: Rule-based compliance policy enforcement
- **Real-time Scanning**: Stream processing for continuous compliance monitoring

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Data Sources   │────▶│   PHI Scanner    │────▶│  Policy Engine   │
│  (S3, RDS, APIs) │     │  (ML Detection)  │     │ (Rule Evaluation)│
└──────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                           │
                         ┌──────────────────┐              │
                         │  Transformation  │◀─────────────┘
                         │  (Mask/Encrypt)  │
                         └────────┬─────────┘
                                  │
    ┌─────────────────────────────┼─────────────────────────────┐
    │                             │                             │
    ▼                             ▼                             ▼
┌────────┐                 ┌────────────┐                ┌───────────┐
│ Output │                 │   Audit    │                │  Alerts   │
│  Data  │                 │    Logs    │                │ Dashboard │
└────────┘                 └────────────┘                └───────────┘
```

## HIPAA Compliance Coverage

| Requirement | Implementation |
|-------------|---------------|
| Access Controls | Role-based access with MFA |
| Audit Controls | Immutable audit logs in S3 |
| Integrity Controls | SHA-256 checksums, data validation |
| Transmission Security | TLS 1.3, encrypted at rest |
| PHI De-identification | Safe Harbor / Expert Determination methods |

## Tech Stack

- **Language**: Python 3.11+
- **API Framework**: FastAPI
- **ML/NLP**: spaCy, scikit-learn
- **Cloud**: AWS (S3, KMS, Glue, CloudWatch)
- **Database**: PostgreSQL, DynamoDB
- **Message Queue**: Apache Kafka, AWS SQS

## Project Structure

```
hipaa-compliance-engine/
├── src/
│   ├── api/              # REST API endpoints
│   ├── services/         # Core services
│   ├── models/           # Data models
│   ├── rules/            # Compliance rules
│   └── utils/            # Utilities
├── tests/                # Test suite
├── config/               # Configuration
└── docs/                 # Documentation
```

## Quick Start

```bash
# Clone repository
git clone https://github.com/Jayanth7416/hipaa-compliance-engine.git
cd hipaa-compliance-engine

# Setup environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run API server
uvicorn src.api.main:app --reload

# Run compliance scan
python -m src.services.scanner --input data/ --output results/
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Scan data for PHI |
| POST | `/mask` | Apply data masking |
| POST | `/encrypt` | Encrypt sensitive fields |
| GET | `/audit/{resource_id}` | Get audit trail |
| GET | `/compliance/report` | Generate compliance report |
| POST | `/policies/validate` | Validate against policies |

## PHI Detection Categories

- Patient Names
- Social Security Numbers
- Medical Record Numbers
- Health Plan IDs
- Account Numbers
- Dates (DOB, Admission, Discharge)
- Phone/Fax Numbers
- Email Addresses
- Geographic Data
- Device Identifiers
- Biometric Data

## Masking Strategies

```python
# Available masking strategies
MaskingStrategy.REDACT      # Replace with [REDACTED]
MaskingStrategy.HASH        # SHA-256 hash
MaskingStrategy.TOKENIZE    # Replace with reversible token
MaskingStrategy.GENERALIZE  # Age: 45 -> 40-50
MaskingStrategy.ENCRYPT     # AES-256 encryption
```

## Configuration

```yaml
# config/compliance.yaml
phi_detection:
  enabled: true
  confidence_threshold: 0.85
  categories:
    - names
    - ssn
    - mrn
    - dates

masking:
  default_strategy: tokenize
  field_strategies:
    ssn: hash
    name: redact
    dob: generalize

encryption:
  algorithm: AES-256-GCM
  kms_key_id: alias/hipaa-compliance-key

audit:
  enabled: true
  retention_days: 2555  # 7 years per HIPAA
  destination: s3://audit-logs-bucket/
```

## License

MIT License

## Author

Jayanth Kumar Panuganti - [LinkedIn](https://linkedin.com/in/jayanth7416)
