from sqlalchemy import select

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
    with SessionLocal() as db:
        settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
        if settings is None:
            db.add(SystemSettings(is_singleton=True, **DEFAULT_SETTINGS))
            db.commit()


if __name__ == "__main__":
    initialize_database()
    print(f"Database initialized at: {DEFAULT_DATABASE_PATH}")