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
- `app/services/backup_readiness.py` checks whether the latest completed verification for an exact backup permits recovery eligibility.

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

Then start the API (set the component token for trusted Phase 3/4 reporting):

```bash
BACKUP_COMPONENT_TOKEN=<component-token> uvicorn app.main:app --reload
```

The app also initializes missing tables and the default singleton settings row when it starts.

Install backend test dependencies from this directory with `python -m pip install -r requirements-dev.txt`, then run `pytest -q`.
The backend uses SQLAlchemy `create_all` and does not include Alembic migrations. Phase 3 applies a narrow additive initialization update for its new verification evidence/timestamp columns on existing databases; future schema changes should use a migration strategy rather than relying on `create_all`.

## Database configuration

The default SQLite file is `backend/data/attack_resistant.db`. Local database files are ignored by Git. To select a different SQLAlchemy-compatible database URL, set `DATABASE_URL` before starting the API, for example with a PostgreSQL URL after installing its driver. SQLite-specific connection behavior is enabled only for SQLite URLs.

The database stores metadata and workflow records only; backup file contents are not stored here.

## API documentation

- Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

## Current scope

Implemented: database/session foundation, SQLite initialization, the core workflow models and relationships, Pydantic request/response schemas, shared risk score mapping, paginated read endpoints, basic asset registration, settings read, an append-oriented audit recording helper, normalized security-event ingestion with `(source, source_event_id)` idempotency, threat incident creation and controlled lifecycle operations, historical risk assessments, a recommendation-only decision contract, and a database-derived dashboard summary.

Phase 1/2 ingestion routes do not yet have production authentication:

- `POST /api/internal/security-events`
- `POST /api/internal/threats`
- `POST /api/internal/risk-assessments`
- `POST /api/internal/decisions`

Browser-facing read routes include `GET /api/security-events`, `GET /api/threats`, `GET /api/risk-assessments`, `GET /api/decisions`, and `GET /api/dashboard/summary`. API payloads and routes are documented in `/docs`.

### Phase 3: backup metadata, protection reporting, and verification state

The database stores backup metadata and component-reported verification evidence only; it never stores backup content or credentials. `GET /api/backups` supports `asset_id`, `lifecycle_status`, `protection_status`, `backup_type`, `from`, and `to` and returns safe metadata plus `verified`, `recovery_eligible`, and eligibility reasons. Detail is `GET /api/backups/{backup_id}`. Candidate inventory is `GET /api/assets/{asset_id}/recovery-points`. Readiness is `GET /api/backups/{backup_id}/recovery-eligibility`; `POST /api/backups/{backup_id}/select-for-recovery` records a readiness-checked selection only and does not execute recovery.

The trusted component reports metadata to `POST /api/internal/backups`, protection outcomes to `POST /api/internal/backups/{backup_id}/protection-result`, and verification outcomes to `POST /api/internal/integrity-verifications/{verification_id}/result`. These internal reporting routes require `X-Internal-Component-Token` matching the `BACKUP_COMPONENT_TOKEN` server environment variable. If that token is not configured, they return 503 rather than trusting frontend-submitted outcomes. Backup registration is idempotent on `(created_by_component, external_backup_id)`: a duplicate returns the original record unchanged with HTTP 200.

Request verification with `POST /api/backups/{backup_id}/integrity-verifications` and request-only metadata (`reason`, `requested_by`, optional `correlation_id`). The initial result remains `queued`; the component owns the actual verification algorithm and reports evidence separately. The backend does not synthesize or compare checksums. A passed result requires an expected digest or trusted manifest reference and observed digest or trusted evidence reference. `/api/action-requests` supports `protect_backup` and `verify_backup`; approval/execution lifecycle remains distinct from component results.

Intentionally not implemented: real backup storage, creation, or immutability; actual integrity algorithms; Wazuh integration; network isolation commands; recovery execution; production user authentication; message brokers; or frontend integration. No development seed backups are added. Existing Phase 1/2 behavior remains in place.

### Phase 4: system isolation / containment orchestration

Isolation uses the existing `ActionRequest` and `IsolationAction` records. Create an isolate ActionRequest at `POST /api/action-requests` (`action_type: isolate`, `asset_id`, controlled `isolation_mode`, optional incident/decision, reason, and correlation). It remains pending/not-started unless a linked decision explicitly says approval is not required. Dispatch/track it with `POST /api/isolation-requests`; duplicate active isolation is rejected. Approval/rejection uses `POST /api/action-requests/{action_request_id}/approve` and `/reject`.

The integration reads `GET /api/isolation`, `GET /api/isolation/{isolation_action_id}`, and `GET /api/assets/{asset_id}/isolation`. Only `POST /api/internal/isolation/{isolation_action_id}/result` can record component results; it uses the same `X-Internal-Component-Token` / `BACKUP_COMPONENT_TOKEN` safeguard as Phase 3. The derived asset state distinguishes `not_isolated`, `isolation_pending`, `isolated`, and `release_pending`. Release creates a separate `release_isolation` ActionRequest and IsolationAction through `POST /api/isolation-requests/{isolation_action_id}/release`; only a confirmed component result changes it to released. Releases with active incidents or unfinished recovery state return `policy_requires_review` rather than guessing policy. An incident may become `contained` only after all of its affected assets have confirmed isolation; isolation never marks an incident resolved.

The token is an integration safeguard, not production authentication. This backend does not issue firewall/EDR/network commands and never fabricates a successful isolation outcome. Recovery behavior and all React pages remain unchanged.