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

Phase 1/2 ingestion routes do not have production authentication; Phase 6B adds MVP per-component token/scope checks to these internal ingestion routes:

- `POST /api/internal/security-events`
- `POST /api/internal/threats`
- `POST /api/internal/risk-assessments`
- `POST /api/internal/decisions`

Browser-facing read routes include `GET /api/security-events`, `GET /api/threats`, `GET /api/risk-assessments`, `GET /api/decisions`, and `GET /api/dashboard/summary`. API payloads and routes are documented in `/docs`.

### Phase 3: backup metadata, protection reporting, and verification state

The database stores backup metadata and component-reported verification evidence only; it never stores backup content or credentials. `GET /api/backups` supports `asset_id`, `lifecycle_status`, `protection_status`, `backup_type`, `from`, and `to` and returns safe metadata plus `verified`, `recovery_eligible`, and eligibility reasons. Detail is `GET /api/backups/{backup_id}`. Candidate inventory is `GET /api/assets/{asset_id}/recovery-points`. Readiness is `GET /api/backups/{backup_id}/recovery-eligibility`; `POST /api/backups/{backup_id}/select-for-recovery` records a readiness-checked selection only and does not execute recovery.

The trusted component reports metadata to `POST /api/internal/backups`, protection outcomes to `POST /api/internal/backups/{backup_id}/protection-result`, and verification outcomes to `POST /api/internal/integrity-verifications/{verification_id}/result`. These internal reporting routes require `X-Internal-Component-Token` authenticated through `MVP_COMPONENT_TOKENS`; the legacy `BACKUP_COMPONENT_TOKEN` remains temporarily supported for Phase 3–5 routes. Missing or invalid component authentication fails with `401`. Backup registration is idempotent on `(created_by_component, external_backup_id)`: a duplicate returns the original record unchanged with HTTP 200.

Request verification with `POST /api/backups/{backup_id}/integrity-verifications` and request-only metadata (`reason`, optional `correlation_id`). The authenticated user is recorded as requester; client-supplied actor identity is not accepted as authority. The initial result remains `queued`; the component owns the actual verification algorithm and reports evidence separately. The backend does not synthesize or compare checksums. A passed result requires an expected digest or trusted manifest reference and observed digest or trusted evidence reference. `/api/action-requests` supports `protect_backup` and `verify_backup`; approval/execution lifecycle remains distinct from component results.

Intentionally not implemented: real backup storage, creation, or immutability; actual integrity algorithms; Wazuh integration; network isolation commands; recovery execution; production user authentication; message brokers; or frontend integration. No development seed backups are added. Existing Phase 1/2 behavior remains in place.

### Phase 4: system isolation / containment orchestration

Isolation uses the existing `ActionRequest` and `IsolationAction` records. Create an isolate ActionRequest at `POST /api/action-requests` (`action_type: isolate`, `asset_id`, controlled `isolation_mode`, optional incident/decision, reason, and correlation). It remains pending/not-started unless a linked decision explicitly says approval is not required. Dispatch/track it with `POST /api/isolation-requests`; duplicate active isolation is rejected. Approval/rejection uses `POST /api/action-requests/{action_request_id}/approve` and `/reject`.

The integration reads `GET /api/isolation`, `GET /api/isolation/{isolation_action_id}`, and `GET /api/assets/{asset_id}/isolation`. Only `POST /api/internal/isolation/{isolation_action_id}/result` can record component results; it uses the same `X-Internal-Component-Token` / `BACKUP_COMPONENT_TOKEN` safeguard as Phase 3. The derived asset state distinguishes `not_isolated`, `isolation_pending`, `isolated`, and `release_pending`. Release creates a separate `release_isolation` ActionRequest and IsolationAction through `POST /api/isolation-requests/{isolation_action_id}/release`; only a confirmed component result changes it to released. Releases with active incidents or unfinished recovery state return `policy_requires_review` rather than guessing policy. An incident may become `contained` only after all of its affected assets have confirmed isolation; isolation never marks an incident resolved.

The token is an integration safeguard, not production authentication. This backend does not issue firewall/EDR/network commands and never fabricates a successful isolation outcome.

### Phase 5: recovery orchestration

Recovery requests use `POST /api/action-requests` with `action_type: recover` and explicit asset, incident, backup, and integrity-verification IDs. Requests always begin pending approval; a decision recommendation never grants approval. Approve or reject through the existing ActionRequest transition endpoints. Create a `RecoveryJob` with `POST /api/recovery-jobs` only after approval and all safety gates pass. `POST /api/recovery-jobs/{recovery_job_id}/dispatch` rechecks authorization, references, backup eligibility, verification freshness, and confirmed isolation before moving the job to `queued`; it does not execute restoration.

Only the token-authenticated recovery component can claim work with `POST /api/internal/recovery-jobs/{recovery_job_id}/claim` or report component outcomes with `POST /api/internal/recovery-jobs/{recovery_job_id}/result`. Claiming moves `queued` to `restoring`. Component reports advance `restoring` to `scanning`, then to `completed` or `failed`; the backend records the reports and does not perform restoration or synthesize success. Completion requires component-reported passed malware scanning and security validation plus an evidence reference. Exact duplicate reports are idempotent; conflicting terminal reports and illegal transitions are rejected. `POST /api/recovery-jobs/{recovery_job_id}/cancel` is allowed only while approved and before dispatch. Cutover is not active: `cutover_status` remains `not_requested` and does not affect the recovery state machine.

Recovery requires an available backup, the exact selected verification in `passed` state with a completion timestamp, a currently confirmed asset isolation, an approved recovery ActionRequest, and consistent asset/incident/backup/verification/decision references. The MVP verification freshness rule is explicit: the passed verification must have completed within the prior 24 hours and no later verification record may exist for that backup, including one still queued or running. These checks run when recording the recovery request (except isolation/approval), creating the job, dispatching it, and when a component claims queued work. Important transitions and rejected component reports are audited using the recovery correlation ID. Internal component tokens remain integration safeguards, not production authentication. React integration and real storage/restoration are not included.

### Phase 6A: MVP authentication and authorization

Human-facing `/api` routes (except the public root, health, and API documentation) require an `Authorization: Bearer <token>` credential. Configure users with the `MVP_USER_TOKENS` environment variable as a JSON array. Each entry contains an opaque `token`, stable `user_id`, and `role`; optional `display_name` is for display only. Example using development-only placeholder credentials:

```bash
export MVP_USER_TOKENS='[{"token":"replace-with-a-long-random-development-token","user_id":"analyst-1","role":"analyst"},{"token":"replace-with-another-long-random-development-token","user_id":"approver-1","role":"approver"}]'
```

Never commit real token values. Generate and deliver development tokens through an appropriate local secret mechanism. Tokens are compared server-side and are never returned or written to audit records. Missing or invalid credentials return `401`; authenticated users without a required role receive `403`.

Roles are `viewer` (authenticated reads), `analyst` (reads plus asset registration and analyst workflow/lifecycle operations), `approver` (reads plus ActionRequest approval/rejection), and `admin` (all human-user operations; settings is currently read-only). Admin authority does not bypass requester/approver separation: the authenticated requester cannot approve or reject their own ActionRequest. Caller-provided actor IDs are not authoritative; audit attribution and stored human actor fields use the authenticated principal.

Human Bearer authentication is separate from trusted internal component reporting. Internal endpoints use `X-Internal-Component-Token`; a human token cannot substitute for a component token.

This environment-configured mechanism is intended only for a university MVP/development deployment. It is not production enterprise IAM: it has no identity provider, token issuance/rotation service, user store, MFA, or session management. Keep tokens outside source control and do not expose this service beyond its intended trusted environment.

### Phase 6B: Trusted component authentication

Every `/api/internal/...` write endpoint requires `X-Internal-Component-Token` and a scope assigned to the authenticated component. Configure scoped credentials in `MVP_COMPONENT_TOKENS` as a JSON array of objects with `component_id`, opaque `token`, and `scopes`. For example:

```bash
export MVP_COMPONENT_TOKENS='[{"component_id":"monitor-agent","token":"replace-with-a-long-random-token","scopes":["security_events:write"]},{"component_id":"backup-agent","token":"replace-with-another-long-random-token","scopes":["backups:write"]}]'
```

The supported identities are deployment-defined; use only the components that operate the existing routes. Available scopes map directly to current writes: `security_events:write`, `threats:write`, `risk_assessments:write`, `decisions:write`, `backups:write`, `verification:write`, `isolation:write`, and `recovery:write`. Assign only the necessary scopes. Missing/invalid tokens return `401`; valid components without a route scope receive `403`. Component identity in audit actor/source fields is resolved from the credential, never from the token value or a request actor label. Tokens are compared in constant time and are not returned or recorded in logs/audit metadata.

For Phase 3–5 backward compatibility, `BACKUP_COMPONENT_TOKEN` is still accepted on backup registration/protection, verification result, isolation result, and recovery claim/result routes using the identity `legacy-backup-component`. That compatibility credential carries those four legacy scopes and should be replaced by separately scoped credentials in `MVP_COMPONENT_TOKENS`; it does not authorize Phase 1/2 ingestion. If explicit configuration and the legacy variable contain the same token, authentication fails closed. The backup registration payload's `created_by_component` continues to describe the producer metadata used by Phase 3; audit identity comes from the authenticated component principal.

Human Bearer credentials configured through `MVP_USER_TOKENS` and component tokens configured through `MVP_COMPONENT_TOKENS` are separate mechanisms. They cannot substitute for each other. This is a university-MVP safeguard, not production enterprise IAM: there is no credential issuance/rotation service, per-instance secret management, MFA, or enterprise identity provider. Keep secrets outside source control and restrict the service to its intended environment.