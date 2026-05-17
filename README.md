# Ghana Savings & Loans — Production Backend

FastAPI-powered savings and loans platform built for the Ghanaian market, with full regulatory compliance baked into the architecture.

## Regulatory Compliance

| Regulation | How enforced |
|---|---|
| AML Act 2020 (Act 1044) | Ghana Card validation, CTR/STR filing, sanctions screening, PEP detection |
| Digital Credit Directive 2025 | Simple interest only (compound raises `ValueError` as CI build gate), 30-second pre-agreement display, 5-day cooling-off |
| Data Protection Act 2012 (Act 843) | ASGI data residency middleware blocks PII to non-Ghana IPs |
| Cybersecurity Act 2020 (Act 1038) | SHA-256 hash-chained audit log, MFA for critical operations, account lockout |
| Borrowers & Lenders Act 2020 | Collateral Registry integration, repayment schedule disclosure |
| Credit Reporting Regulations 2020 (L.I. 2394) | Daily credit bureau submission to XDS, D&B Ghana, MyCredit Score |

## Quick Start

**Requirements:** Python 3.11+, PostgreSQL 15+

```powershell
# 1. Clone and enter directory
git clone https://github.com/KofiBusia/Savings-and-Loans-Python.git
cd "Savings-and-Loans-Python"

# 2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env — set DATABASE_URL, SECRET_KEY at minimum

# 5. Run compliance tests (mandatory — these are the build gate)
pytest tests/test_compliance_guards.py -v

# 6. Start development server
python app.py
```

API available at: `http://localhost:8000/api/v1`  
Swagger UI: `http://localhost:8000/api/docs`

## Project Structure

```
Savings and Loans Python/
├── app.py                          # FastAPI entry point
├── api/
│   ├── config.py                   # Pydantic-settings (all env vars)
│   ├── database.py                 # SQLAlchemy engine + session
│   ├── models.py                   # All ORM models (16 tables)
│   ├── security.py                 # JWT, bcrypt, TOTP
│   ├── deps.py                     # FastAPI dependency injection
│   ├── compliance/
│   │   ├── interest_calculator.py  # SIMPLE INTEREST ONLY — DCD 2025 Cl.14
│   │   ├── kyc_state_machine.py    # 12-step KYC FSM
│   │   └── aml_engine.py           # CTR/STR detection + XML generation
│   ├── integrations/
│   │   ├── ghipss_mmi.py           # GhIPSS Mobile Money (MTN/Telecel/AirtelTigo)
│   │   ├── credit_bureaus.py       # XDS + D&B Ghana + MyCredit Score
│   │   ├── ghana_card_api.py       # NIA Ghana Card verification
│   │   ├── payment_gateway.py      # Paystack / Flutterwave adapter
│   │   └── fic_reporter.py         # FIC goAML submission client
│   ├── middleware/
│   │   └── data_residency.py       # Block PII to non-Ghana IPs
│   ├── routers/
│   │   ├── health.py               # GET /health
│   │   ├── auth.py                 # Staff login/MFA + customer register/login
│   │   ├── customers.py            # CRUD + 12-step KYC workflow
│   │   ├── loans.py                # Application → Approval → Disbursement → Repayment
│   │   ├── savings.py              # Deposit, Withdrawal, Statement
│   │   ├── compliance.py           # AML alerts, STR/CTR filing, audit chain
│   │   └── admin.py                # User management, system stats
│   ├── schemas/                    # Pydantic request/response models
│   ├── utils/
│   │   └── audit_chain.py          # SHA-256 hash-chained immutable audit log
│   └── validators/
│       └── ghana_validators.py     # Ghana Card, phone, GPS, TIN, region
├── tests/
│   ├── conftest.py                 # pytest fixtures (SQLite in-memory)
│   └── test_compliance_guards.py   # 40+ compliance tests — CI build gate
├── .github/workflows/deploy.yml    # 7-job CI/CD pipeline
├── deploy.ps1                      # Local deploy script
└── .vscode/                        # Debug configurations
```

## API Endpoints

### Authentication
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Staff login (email + password) |
| POST | `/api/v1/auth/mfa/verify` | Complete TOTP MFA challenge |
| POST | `/api/v1/auth/mfa/setup` | Set up MFA for current user |
| POST | `/api/v1/auth/refresh` | Rotate refresh token |
| POST | `/api/v1/auth/logout` | Revoke refresh token |
| GET | `/api/v1/auth/me` | Current user profile |
| POST | `/api/v1/auth/customer/register` | Customer registration (mobile app) |
| POST | `/api/v1/auth/customer/login` | Customer login (mobile app) |

### Customers
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/customers` | Create customer (field officer) |
| GET | `/api/v1/customers` | List with search/filter |
| GET | `/api/v1/customers/{id}` | Get customer |
| PUT | `/api/v1/customers/{id}` | Update profile |
| GET | `/api/v1/customers/{id}/kyc` | KYC status |
| POST | `/api/v1/customers/{id}/kyc/advance` | Advance KYC step |
| POST | `/api/v1/customers/{id}/suspend` | Suspend account |

### Loans
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/loans/quote` | Loan quote (no DB write) |
| POST | `/api/v1/loans` | Apply for loan |
| GET | `/api/v1/loans` | List loans |
| POST | `/api/v1/loans/{id}/approve` | Approve/reject (Credit Manager + MFA) |
| POST | `/api/v1/loans/{id}/disburse` | Disburse (Super Admin + MFA) |
| POST | `/api/v1/loans/{id}/repayments` | Record repayment |

### Savings
| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/savings` | Open savings account |
| POST | `/api/v1/savings/{id}/deposit` | Post deposit |
| POST | `/api/v1/savings/{id}/withdraw` | Post withdrawal |
| GET | `/api/v1/savings/{id}/statement` | Account statement |

### Compliance
| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/compliance/dashboard` | Compliance KPIs |
| GET | `/api/v1/compliance/aml/alerts` | AML alert list |
| POST | `/api/v1/compliance/aml/str` | File STR with FIC |
| POST | `/api/v1/compliance/aml/ctr` | File CTR with FIC |
| POST | `/api/v1/compliance/bureau/submit` | Daily credit bureau submission |
| GET | `/api/v1/compliance/audit/verify` | Verify audit chain integrity |
| GET | `/api/v1/compliance/audit/logs` | Export audit log range |

## Staff Roles

| Role | Capabilities |
|---|---|
| `SUPER_ADMIN` | Full access — loan disbursement, user management |
| `ADMIN` | Customer management, reporting |
| `CREDIT_MANAGER` | Loan product management, loan approval |
| `FIELD_OFFICER` | Customer onboarding, loan applications, collections |
| `COMPLIANCE_OFFICER` | AML alerts, STR/CTR filing, KYC review |
| `TELLER` | Deposits, withdrawals |
| `AUDIT_VIEWER` | Read-only audit log access |

## Environment Variables

Copy `.env.example` to `.env` and configure:

```
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
DATABASE_URL=postgresql+psycopg2://user:pass@localhost:5432/gsl_db
INSTITUTION_NAME=Your Institution Name
BOG_LICENCE_NUMBER=MFI-001/2024
ADMIN_EMAIL=admin@yourinstitution.com.gh
ADMIN_PASSWORD=<strong password>
```

All Ghana API keys (NIA, GhIPSS, FIC, credit bureaus) default to mock/sandbox values.
Set `MOCK_GHIPSS=false`, `MOCK_GHANA_CARD_API=false`, etc. in production.

## Running Tests

```powershell
# Compliance build gate only (fast — no DB needed)
pytest tests/test_compliance_guards.py -v

# Full test suite
pytest -v --cov=api --cov-report=term-missing

# Single compliance category
pytest tests/test_compliance_guards.py -k "compound" -v
```

## Deployment

### Render (recommended)

1. Create `KofiBusia/Savings-and-Loans-Python` on GitHub
2. Connect repo to Render — creates a Web Service from `app.py`
3. Set environment variables in Render dashboard
4. Push to `main` — auto-deploys via GitHub Actions

### Local deploy script

```powershell
.\deploy.ps1
```

This runs lint → compliance tests → git commit → git push.
The compliance tests are a hard gate: push is blocked if they fail.

## BoG Pre-Approval Steps

Before going live, obtain:
1. BoG MFI/ARN licence — apply via [BoG licensing portal](https://www.bog.gov.gh)
2. FIC registration for goAML reporting
3. NIA API access for Ghana Card verification
4. GhIPSS membership for MMI access
5. Credit bureau agreements (XDS, D&B Ghana, MyCredit Score)
6. Data Protection Commission registration (Act 843)

## Security Notes

- `SECRET_KEY` must be at least 32 random bytes — never commit to git
- Swagger UI and ReDoc are disabled in `NODE_ENV=production`
- Data residency middleware blocks all PII responses to non-Ghana IP addresses
- MFA is required for loan disbursement and STR/CTR filing
- Audit log is hash-chained and tamper-evident — verify with `/api/v1/compliance/audit/verify`
- Refresh tokens are rotated on use (one-time) and stored as SHA-256 hashes
