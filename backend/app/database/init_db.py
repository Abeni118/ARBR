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
        audit_columns = {column["name"] for column in inspect(connection).get_columns("audit_events")}
        if "isolation_action_id" not in audit_columns:
            connection.execute(text("ALTER TABLE audit_events ADD COLUMN isolation_action_id VARCHAR(36)"))
    with SessionLocal() as db:
        settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
        if settings is None:
            db.add(SystemSettings(is_singleton=True, **DEFAULT_SETTINGS))
            db.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized at: {DEFAULT_DATABASE_PATH}")