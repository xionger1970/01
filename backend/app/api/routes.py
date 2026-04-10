from fastapi import APIRouter

from app.api.endpoints import auth, alerts, attack_events, dashboard, configurations, notification_channels, integrations, threat_intel, anomalies, attack_tracking, orchestration, ai_analysis, data_sources, detection, response

router = APIRouter()

# Include endpoints
router.include_router(auth.router, prefix="/auth", tags=["authentication"])
router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
router.include_router(attack_events.router, prefix="/attack-events", tags=["attack events"])
router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
router.include_router(configurations.router, prefix="/configurations", tags=["configurations"])
router.include_router(notification_channels.router, prefix="/notification-channels", tags=["notification channels"])
router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
router.include_router(threat_intel.router, prefix="/threat-intel", tags=["threat intelligence"])
router.include_router(anomalies.router, prefix="/anomalies", tags=["anomaly detection"])
router.include_router(attack_tracking.router, prefix="/attack-tracking", tags=["attack tracking"])
router.include_router(orchestration.router, prefix="/orchestration", tags=["orchestration"])
router.include_router(ai_analysis.router, prefix="/ai-analysis", tags=["ai analysis"])
router.include_router(data_sources.router, prefix="/data-sources", tags=["data sources"])
router.include_router(detection.router, prefix="/detection", tags=["detection"])
router.include_router(response.router, prefix="/response", tags=["response"])
