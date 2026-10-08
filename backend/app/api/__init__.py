from fastapi import APIRouter

from app.api import (
    action_requests,
    assets,
    audit_logs,
    backups,
    decisions,
    dashboard,
    health,
    integrity_verifications,
    isolation,
    recovery,
    risk_assessments,
    security_events,
    settings,
    threats,
)

api_router = APIRouter()
for route_module in (
    health,
    dashboard,
    assets,
    security_events,
    threats,
    risk_assessments,
    decisions,
    action_requests,
    backups,
    integrity_verifications,
    isolation,
    recovery,
    audit_logs,
    settings,
):
    api_router.include_router(route_module.router)

for route_module in (security_events, threats, risk_assessments, decisions, backups, integrity_verifications, isolation, recovery):
    api_router.include_router(route_module.internal_router)

api_router.include_router(integrity_verifications.backup_router)
api_router.include_router(backups.recovery_points_router)
api_router.include_router(isolation.request_router)
api_router.include_router(isolation.asset_router)