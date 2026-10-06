# Backend API

Minimal FastAPI + SQLAlchemy foundation for the Attack-Resistant Backup & Recovery System.

## Structure

- `app/main.py` creates the FastAPI app, keeps the existing root and health endpoints, includes routers, and initializes missing database tables on startup.
- `app/api/` contains browser-facing read routers, basic asset registration, and the Phase 2 internal ingestion endpoints.
- `app/models.py` contains SQLAlchemy entities and relationships.
- `app/schemas.py` contains request/response validation schemas.
- `app/database/` contains the engine, session dependency, and idempotent database initialization.
- `app/services/` contains shared domain helpers, including the append-oriented audit recorder.
- `app/risk.py` is the shared score-to-risk-level mapping.
- `app/services/asset_resolution.py` resolves existing internal or external asset references without silently creating assets.

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

Install backend test dependencies from this directory with `python -m pip install -r requirements-dev.txt`, then run `pytest -q`.
This phase uses SQLAlchemy `create_all` and does not include Alembic migrations; `create_all` creates missing tables but does not alter an existing table when a model changes. Use a fresh local database for this phase's schema, and decide on migrations before making schema-evolution changes.

## Database configuration

The default SQLite file is `backend/data/attack_resistant.db`. Local database files are ignored by Git. To select a different SQLAlchemy-compatible database URL, set `DATABASE_URL` before starting the API, for example with a PostgreSQL URL after installing its driver. SQLite-specific connection behavior is enabled only for SQLite URLs.

The database stores metadata and workflow records only; backup file contents are not stored here.

## API documentation

- Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

## Current scope

Implemented: database/session foundation, SQLite initialization, the core workflow models and relationships, Pydantic request/response schemas, shared risk score mapping, paginated read endpoints, basic asset registration, settings read, an append-oriented audit recording helper, normalized security-event ingestion with `(source, source_event_id)` idempotency, threat incident creation and controlled lifecycle operations, historical risk assessments, a recommendation-only decision contract, and a database-derived dashboard summary.

Internal component routes (no production authentication is implemented yet):

- `POST /api/internal/security-events`
- `POST /api/internal/threats`
- `POST /api/internal/risk-assessments`
- `POST /api/internal/decisions`

Browser-facing read routes include `GET /api/security-events`, `GET /api/threats`, `GET /api/risk-assessments`, `GET /api/decisions`, and `GET /api/dashboard/summary`. API payloads and routes are documented in `/docs`.

Intentionally not implemented: real Wazuh or other integrations, detection or risk calculation algorithms, decision-engine logic, backup creation/protection, integrity verification execution, isolation, recovery, production authentication, action approval/execution, settings write APIs, or audit write APIs. An unresolved asset reference returns `404`; assets are never invented during ingest. Incidents may only be marked triaged/investigating or false-positive in this phase. Containment and recovery transitions remain unavailable until their outcomes can be confirmed. Decisions remain recommendations and create no ActionRequest or execution result.