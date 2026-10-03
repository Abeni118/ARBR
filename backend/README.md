# Backend API

Minimal FastAPI + SQLAlchemy foundation for the Attack-Resistant Backup & Recovery System.

## Structure

- `app/main.py` creates the FastAPI app, keeps the existing root and health endpoints, includes routers, and initializes missing database tables on startup.
- `app/api/` contains read-only domain routers. The assets router also has a basic asset registration endpoint for the initial persistence/read path.
- `app/models.py` contains SQLAlchemy entities and relationships.
- `app/schemas.py` contains request/response validation schemas.
- `app/database/` contains the engine, session dependency, and idempotent database initialization.
- `app/services/` contains shared domain helpers, including the append-oriented audit recorder.
- `app/risk.py` is the shared score-to-risk-level mapping.

## Local setup

From the `backend/` directory, activate the existing virtual environment and install dependencies:

```bash
source venv/bin/activate
python -m pip install -r requirements.txt
```

Initialize the database explicitly (safe to run more than once):

```bash
python -m app.database.init_db
```

Then start the API:

```bash
uvicorn app.main:app --reload
```

The app also initializes missing tables and the default singleton settings row when it starts.

## Database configuration

The default SQLite file is `backend/data/attack_resistant.db`. Local database files are ignored by Git. To select a different SQLAlchemy-compatible database URL, set `DATABASE_URL` before starting the API, for example with a PostgreSQL URL after installing its driver. SQLite-specific connection behavior is enabled only for SQLite URLs.

The database stores metadata and workflow records only; backup file contents are not stored here.

## API documentation

- Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

## Current scope

Implemented: database/session foundation, SQLite initialization, the core workflow models and relationships, Pydantic request/response schemas, shared risk score mapping, paginated read endpoints, basic asset registration, settings read, and an append-oriented audit recording helper.

Intentionally not implemented: Wazuh or other integrations, event ingestion, threat/risk/decision execution, backup creation/protection, integrity verification execution, isolation, recovery, approval/authentication, settings write APIs, or audit write APIs. Current workflow records must be supplied by future authenticated component interfaces; this phase does not invent component behavior or success states.