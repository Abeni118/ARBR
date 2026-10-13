from sqlalchemy import inspect, select, text

from app.database.session import DEFAULT_DATABASE_PATH, SessionLocal, engine
from app.models import Base, SystemSettings
from app.risk import DEFAULT_RISK_THRESHOLDS


DEFAULT_SETTINGS = {
    "risk_thresholds": DEFAULT_RISK_THRESHOLDS,
    "isolation_policy": {},
    "backup_policy": {},
    "recovery_policy": {"automatic_recovery": False},
    "notification_policy": {},
}


def initialize_database() -> None:
    """Create missing tables and seed the singleton settings row if absent."""
    Base.metadata.create_all(bind=engine)
    # create_all does not add columns to existing tables. This nullable evidence
    # reference is additive and safe for the existing Phase 1/2 database.
    with engine.begin() as connection:
        columns = {column["name"] for column in inspect(connection).get_columns("integrity_verifications")}
        if "verification_evidence_reference" not in columns:
            connection.execute(
                text("ALTER TABLE integrity_verifications ADD COLUMN verification_evidence_reference VARCHAR(1024)")
            )
        if "created_at" not in columns:
            connection.execute(
                text("ALTER TABLE integrity_verifications ADD COLUMN created_at TIMESTAMP WITH TIME ZONE")
            )
            connection.execute(
                text("UPDATE integrity_verifications SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
            )
        action_request_columns = {
            column["name"] for column in inspect(connection).get_columns("action_requests")
        }
        if "isolation_mode" not in action_request_columns:
            connection.execute(text("ALTER TABLE action_requests ADD COLUMN isolation_mode VARCHAR(20)"))
        isolation_columns = {
            column["name"] for column in inspect(connection).get_columns("isolation_actions")
        }
        if "decision_id" not in isolation_columns:
            connection.execute(text("ALTER TABLE isolation_actions ADD COLUMN decision_id VARCHAR(36)"))
        if "parent_isolation_action_id" not in isolation_columns:
            connection.execute(text("ALTER TABLE isolation_actions ADD COLUMN parent_isolation_action_id VARCHAR(36)"))
        if "completed_at" not in isolation_columns:
            connection.execute(text("ALTER TABLE isolation_actions ADD COLUMN completed_at TIMESTAMP WITH TIME ZONE"))
        recovery_columns = {
            column["name"] for column in inspect(connection).get_columns("recovery_jobs")
        }
        if "result_evidence_reference" not in recovery_columns:
            connection.execute(text("ALTER TABLE recovery_jobs ADD COLUMN result_evidence_reference VARCHAR(1024)"))
        audit_columns = {column["name"] for column in inspect(connection).get_columns("audit_events")}
        if "isolation_action_id" not in audit_columns:
            connection.execute(text("ALTER TABLE audit_events ADD COLUMN isolation_action_id VARCHAR(36)"))
        user_account_columns = {
            column["name"] for column in inspect(connection).get_columns("user_accounts")
        }
        table_sql = connection.execute(
            text("SELECT sql FROM sqlite_master WHERE type='table' AND name='user_accounts'")
        ).scalar()
        if table_sql and "ck_user_account_non_admin_role" in table_sql:
            has_is_active = "is_active" in user_account_columns
            select_is_active = "is_active" if has_is_active else "1"
            connection.execute(text("""
                CREATE TABLE user_accounts_migrated (
                    user_id VARCHAR(36) NOT NULL,
                    username VARCHAR(64) NOT NULL,
                    username_normalized VARCHAR(64) NOT NULL,
                    display_name VARCHAR(255),
                    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
                    password_hash VARCHAR(255) NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_by_user_id VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL,
                    PRIMARY KEY (user_id),
                    CONSTRAINT uq_user_account_username_normalized UNIQUE (username_normalized),
                    CONSTRAINT ck_user_account_role CHECK (role IN ('viewer', 'analyst', 'approver', 'admin'))
                )
            """))
            connection.execute(text(f"""
                INSERT INTO user_accounts_migrated (user_id, username, username_normalized, display_name, role, password_hash, is_active, created_by_user_id, created_at)
                SELECT user_id, username, username_normalized, display_name, role, password_hash, {select_is_active}, created_by_user_id, created_at
                FROM user_accounts
            """))
            connection.execute(text("DROP TABLE user_accounts"))
            connection.execute(text("ALTER TABLE user_accounts_migrated RENAME TO user_accounts"))
        elif "is_active" not in user_account_columns:
            connection.execute(text("ALTER TABLE user_accounts ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL"))
    with SessionLocal() as db:
        settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
        if settings is None:
            db.add(SystemSettings(is_singleton=True, **DEFAULT_SETTINGS))
            db.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized at: {DEFAULT_DATABASE_PATH}")