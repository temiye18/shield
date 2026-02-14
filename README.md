# 🛡️ AI Data Privacy Shield — Backend

Real-time PII detection and redaction engine for AI prompts. Built with FastAPI, Microsoft Presidio, and PostgreSQL.

## Features

- **PII Detection** — Emails, phone numbers, SSNs, credit cards, person names, and more
- **Secret Scanning** — API keys, AWS keys, GitHub tokens, bearer tokens
- **Smart Pseudonymization** — Session-aware consistent entity replacement (e.g. "John" → "PERSON_A")
- **Custom Patterns** — Organization-specific regex and keyword rules
- **JWT Authentication** — Secure user registration and login with bcrypt
- **Analytics Dashboard API** — Scan history, detection metrics, CSV/JSON export
- **Sub-500ms Latency** — Optimized for real-time interception

## Tech Stack

| Layer      | Technology                      |
| ---------- | ------------------------------- |
| Framework  | FastAPI                         |
| Database   | PostgreSQL (local or Supabase)  |
| ORM        | SQLAlchemy 2.0                  |
| Migrations | Alembic                         |
| PII Engine | Microsoft Presidio + SpaCy NER  |
| Auth       | JWT (python-jose) + bcrypt      |
| Server     | Uvicorn (dev) / Gunicorn (prod) |

## Project Structure

```
backend/
├── app/
│   ├── api/                # Route handlers
│   │   ├── auth.py         # POST /v1/auth/register, /login, /me
│   │   ├── detection.py    # POST /v1/detect/scan
│   │   └── analytics.py    # GET /v1/analytics/overview, /activity-log, /export
│   ├── models/
│   │   └── models.py       # SQLAlchemy models (5 tables)
│   ├── schemas/            # Pydantic request/response schemas
│   ├── services/
│   │   ├── auth_service.py # Password hashing & JWT
│   │   ├── detector.py     # PIIDetector (Presidio + custom patterns)
│   │   └── session_manager.py  # Conversation-aware pseudonymization
│   ├── config.py           # Environment settings
│   ├── database.py         # SQLAlchemy engine & session
│   ├── dependencies.py     # Auth dependencies
│   └── main.py             # FastAPI app entry point
├── alembic/                # Database migrations
├── tests/                  # Pytest test suite (37 tests)
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL (local install or [Supabase](https://supabase.com))

### 1. Install Dependencies

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 2. Configure Environment

```bash
copy .env.example .env         # Windows
# cp .env.example .env         # macOS/Linux
```

Edit `.env` and set your `DATABASE_URL`:

```env
# Local PostgreSQL
DATABASE_URL=postgresql://postgres:yourpassword@localhost:5432/shield_db

# Or Supabase (Session Pooler, port 5432)
DATABASE_URL=postgresql://postgres.[ref]:[password]@aws-0-region.pooler.supabase.com:5432/postgres?sslmode=require
```

### 3. Create Database & Run Migrations

```bash
# If using local PostgreSQL, create the database first:
# CREATE DATABASE shield_db;

alembic upgrade head
```

### 4. Start the Server

```bash
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000/docs** for the interactive Swagger API docs.

## API Endpoints

| Method | Endpoint                     | Description              |
| ------ | ---------------------------- | ------------------------ |
| `POST` | `/v1/auth/register`          | Register a new user      |
| `POST` | `/v1/auth/login`             | Login and get JWT token  |
| `GET`  | `/v1/auth/me`                | Get current user profile |
| `POST` | `/v1/detect/scan`            | Scan text for PII        |
| `GET`  | `/v1/analytics/overview`     | Dashboard metrics        |
| `GET`  | `/v1/analytics/activity-log` | Paginated scan history   |
| `GET`  | `/v1/analytics/export`       | Export data as CSV/JSON  |
| `GET`  | `/health`                    | Health check             |

## Database Schema

5 tables with full indexing:

- **organizations** — Multi-tenant org management
- **users** — Auth with role-based access (admin/analyst/viewer)
- **prompt_logs** — Every scan with original text, redacted text, entities found
- **detection_patterns** — Custom org-specific regex/keyword rules
- **audit_logs** — Full audit trail of all system events

## Running Tests

```bash
pytest tests/ -v
```

```
37 passed in ~100s
```

## Deployment

### Render / Railway (Recommended)

- **Build**: `pip install -r requirements.txt && python -m spacy download en_core_web_sm && alembic upgrade head`
- **Start**: `gunicorn app.main:app --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:10000 --timeout 120`
- **Env vars**:
  - `DATABASE_URL`: Your Supabase connection string
  - `SECRET_KEY`: Random string
  - `CORS_ORIGINS`: Allowed domains
  - `SPACY_MODEL`: `en_core_web_sm` (Essential for Free Tier to save RAM)

### Docker

```bash
docker-compose up --build
```

## License

Private — All rights reserved.
