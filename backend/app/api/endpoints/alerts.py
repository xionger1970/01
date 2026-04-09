from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()

# For demonstration purposes, using a simple in-memory store
# In production, use a proper database
alert_rules = [
    {
        "id": 1,
        "name": "SQL Injection Attack",
        "description": "Detects SQL injection attempts",
        "severity": "high",
        "condition": {"attack_type": "sql_injection"},
        "enabled": True,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 2,
        "name": "XSS Attack",
        "description": "Detects cross-site scripting attempts",
        "severity": "medium",
        "condition": {"attack_type": "xss"},
        "enabled": True,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
]

alert_history = [
    {
        "id": 1,
        "rule_id": 1,
        "severity": "high",
        "message": "SQL injection attempt detected",
        "details": {"source_ip": "192.168.1.100", "target_path": "/login"},
        "status": "new",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
]

class AlertRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str
    condition: dict
    enabled: bool = True

class AlertRule(AlertRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

class AlertHistoryBase(BaseModel):
    rule_id: int
    severity: str
    message: str
    details: Optional[dict] = None
    status: str = "new"

class AlertHistory(AlertHistoryBase):
    id: int
    created_at: datetime
    updated_at: datetime

@router.get("/rules", response_model=List[AlertRule])
def get_alert_rules():
    return alert_rules

@router.post("/rules", response_model=AlertRule)
def create_alert_rule(rule: AlertRuleBase):
    new_rule = {
        "id": len(alert_rules) + 1,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "condition": rule.condition,
        "enabled": rule.enabled,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    alert_rules.append(new_rule)
    return new_rule

@router.get("/history", response_model=List[AlertHistory])
def get_alert_history():
    return alert_history

@router.post("/history", response_model=AlertHistory)
def create_alert_history(alert: AlertHistoryBase):
    new_alert = {
        "id": len(alert_history) + 1,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "message": alert.message,
        "details": alert.details,
        "status": alert.status,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    alert_history.append(new_alert)
    return new_alert
