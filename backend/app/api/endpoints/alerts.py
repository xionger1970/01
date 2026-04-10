from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
from app.alerting.alert_manager import alert_manager

router = APIRouter()

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
    priority: int
    group_id: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None

class AlertUpdate(BaseModel):
    status: str
    resolution: Optional[str] = None

class AlertAssign(BaseModel):
    user: str

@router.get("/rules", response_model=List[AlertRule])
def get_alert_rules():
    """获取告警规则"""
    return alert_manager.get_alert_rules()

@router.post("/rules", response_model=AlertRule)
def create_alert_rule(rule: AlertRuleBase):
    """创建告警规则"""
    new_rule = alert_manager.create_alert_rule(rule.dict())
    return new_rule

@router.put("/rules/{rule_id}", response_model=AlertRule)
def update_alert_rule(rule_id: int, rule: AlertRuleBase):
    """更新告警规则"""
    updated_rule = alert_manager.update_alert_rule(rule_id, rule.dict())
    if not updated_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return updated_rule

@router.delete("/rules/{rule_id}")
def delete_alert_rule(rule_id: int):
    """删除告警规则"""
    success = alert_manager.delete_alert_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"message": "Rule deleted successfully"}

@router.get("/history", response_model=List[AlertHistory])
def get_alert_history(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """获取告警历史"""
    filters = {}
    if severity:
        filters['severity'] = severity
    if status:
        filters['status'] = status
    if source_ip:
        filters['source_ip'] = source_ip
    
    alerts = alert_manager.get_alert_history(filters)
    return alerts[:limit]

@router.post("/history", response_model=AlertHistory)
def create_alert_history(alert: AlertHistoryBase):
    """创建告警"""
    new_alert = alert_manager.create_alert(
        rule_id=alert.rule_id,
        severity=alert.severity,
        message=alert.message,
        details=alert.details
    )
    return new_alert

@router.put("/history/{alert_id}", response_model=AlertHistory)
def update_alert_status(alert_id: int, update: AlertUpdate):
    """更新告警状态"""
    updated_alert = alert_manager.update_alert_status(
        alert_id=alert_id,
        status=update.status,
        resolution=update.resolution
    )
    if not updated_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated_alert

@router.post("/history/{alert_id}/assign", response_model=AlertHistory)
def assign_alert(alert_id: int, assign: AlertAssign):
    """分配告警"""
    assigned_alert = alert_manager.assign_alert(alert_id, assign.user)
    if not assigned_alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return assigned_alert

@router.delete("/history/{alert_id}")
def delete_alert(alert_id: int):
    """删除告警"""
    success = alert_manager.delete_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="告警未找到")
    return {"message": "删除成功", "id": alert_id}

@router.get("/groups")
def get_alert_groups():
    """获取告警分组"""
    groups = alert_manager.get_alert_groups()
    return groups

@router.get("/stats")
def get_alert_stats():
    """获取告警统计信息"""
    stats = alert_manager.get_alert_stats()
    return stats

@router.get("/trends")
def get_alert_trends(hours: int = Query(24, ge=1, le=168)):
    """分析告警趋势"""
    trends = alert_manager.analyze_alert_trends(hours)
    return trends

@router.get("/notification-channels")
def get_notification_channels():
    """获取通知渠道配置"""
    channels = alert_manager.get_notification_channels()
    return channels

@router.post("/notification-channels")
def update_notification_channels(channels: Dict):
    """更新通知渠道配置"""
    alert_manager.update_notification_channels(channels)
    return {"message": "Notification channels updated successfully"}

