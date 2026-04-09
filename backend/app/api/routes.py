from fastapi import APIRouter

from app.api.endpoints import auth, alerts, attack_events, dashboard, configurations, notification_channels, integrations

router = APIRouter()

# Include endpoints
router.include_router(auth.router, prefix="/auth", tags=["authentication"])
router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
router.include_router(attack_events.router, prefix="/attack-events", tags=["attack events"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
router.include_router(configurations.router, prefix="/configurations", tags=["configurations"])
router.include_router(notification_channels.router, prefix="/notification-channels", tags=["notification channels"])
router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
