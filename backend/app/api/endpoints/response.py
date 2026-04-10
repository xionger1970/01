from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Optional

from app.responders.alert_prioritizer import AlertPrioritizer
from app.responders.device_integration import DeviceIntegrationManager

router = APIRouter()

# 初始化响应组件
alert_prioritizer = AlertPrioritizer()
device_manager = DeviceIntegrationManager()

# ==================== 告警优先级相关端点 ====================

@router.post("/prioritizer/blacklist/add")
def add_to_blacklist(ip: str = Query(..., description="要添加到黑名单的IP地址")):
    """
    添加IP到威胁情报黑名单
    """
    alert_prioritizer.add_to_blacklist(ip)
    return {"message": f"IP {ip} 已添加到黑名单", "ip": ip}

@router.delete("/prioritizer/blacklist/remove")
def remove_from_blacklist(ip: str = Query(..., description="要从黑名单移除的IP地址")):
    """
    从威胁情报黑名单移除IP
    """
    alert_prioritizer.remove_from_blacklist(ip)
    return {"message": f"IP {ip} 已从黑名单移除", "ip": ip}

@router.get("/prioritizer/blacklist")
def get_blacklist():
    """
    获取威胁情报黑名单
    """
    return {"blacklist": list(alert_prioritizer.blacklist)}

@router.post("/prioritizer/asset/importance")
def set_asset_importance(
    asset_id: str = Query(..., description="资产ID"),
    importance_score: int = Query(..., description="重要性分数 (1-5)", ge=1, le=5)
):
    """
    设置资产重要性
    """
    alert_prioritizer.set_asset_importance(asset_id, importance_score)
    return {"message": "资产重要性已设置", "asset_id": asset_id, "importance_score": importance_score}

@router.get("/prioritizer/asset/importance")
def get_asset_importance(asset_id: str = Query(..., description="资产ID")):
    """
    获取资产重要性
    """
    importance = alert_prioritizer.get_asset_importance(asset_id)
    return {"asset_id": asset_id, "importance_score": importance}

@router.get("/prioritizer/attack_frequency")
def get_attack_frequency(
    source_ip: str = Query(..., description="源IP地址"),
    alert_type: str = Query(..., description="告警类型"),
    window_seconds: int = Query(300, description="时间窗口秒数")
):
    """
    获取攻击频率
    """
    frequency = alert_prioritizer.get_attack_frequency(source_ip, alert_type, window_seconds)
    return {"source_ip": source_ip, "alert_type": alert_type, "frequency": frequency}

@router.post("/prioritizer/calculate")
def calculate_priority(alert: Dict):
    """
    计算告警优先级
    """
    prioritized_alert = alert_prioritizer.prioritize_alert(alert)
    return prioritized_alert

@router.get("/prioritizer/statistics")
def get_prioritizer_statistics():
    """
    获取告警优先级管理器统计信息
    """
    return alert_prioritizer.get_statistics()

@router.post("/prioritizer/clear_old_records")
def clear_old_attack_records(max_age_seconds: int = Query(3600, description="最大记录保留秒数")):
    """
    清理旧的攻击记录
    """
    alert_prioritizer.clear_old_attack_records(max_age_seconds)
    return {"message": "旧攻击记录已清理"}

# ==================== 设备集成相关端点 ====================

@router.post("/device/block")
def block_ip(
    ip: str = Query(..., description="要阻止的IP地址"),
    duration: Optional[int] = Query(None, description="阻止持续时间（秒），默认3600秒"),
    reason: str = Query("检测到恶意活动", description="阻止原因")
):
    """
    在所有设备上阻止IP
    """
    result = device_manager.block_ip_across_devices(ip, duration, reason)
    return result

@router.post("/device/unblock")
def unblock_ip(ip: str = Query(..., description="要解除阻止的IP地址")):
    """
    在所有设备上解除阻止IP
    """
    result = device_manager.unblock_ip_across_devices(ip)
    return result

@router.get("/device/status")
def get_device_status():
    """
    获取所有设备的状态
    """
    return device_manager.get_status()

@router.get("/device/response_history")
def get_response_history(ip: Optional[str] = Query(None, description="可选的IP地址筛选")):
    """
    获取响应历史
    """
    return {"history": device_manager.get_response_history(ip)}

# ==================== 单个设备控制端点 ====================

@router.post("/device/firewall/block")
def block_ip_firewall(
    ip: str = Query(..., description="要阻止的IP地址"),
    duration: Optional[int] = Query(None, description="阻止持续时间（秒）")
):
    """
    仅通过防火墙阻止IP
    """
    success = device_manager.firewall.block_ip(ip, duration)
    return {"success": success, "ip": ip, "device": "firewall"}

@router.post("/device/firewall/unblock")
def unblock_ip_firewall(ip: str = Query(..., description="要解除阻止的IP地址")):
    """
    仅通过防火墙解除阻止IP
    """
    success = device_manager.firewall.unblock_ip(ip)
    return {"success": success, "ip": ip, "device": "firewall"}

@router.get("/device/firewall/blocked")
def get_firewall_blocked_ips():
    """
    获取防火墙阻止的IP列表
    """
    return {"blocked_ips": device_manager.firewall.get_blocked_ips()}

@router.post("/device/nginx/block")
def block_ip_nginx(ip: str = Query(..., description="要阻止的IP地址")):
    """
    仅通过Nginx阻止IP
    """
    success = device_manager.nginx.block_ip(ip)
    return {"success": success, "ip": ip, "device": "nginx"}

@router.post("/device/nginx/unblock")
def unblock_ip_nginx(ip: str = Query(..., description="要解除阻止的IP地址")):
    """
    仅通过Nginx解除阻止IP
    """
    success = device_manager.nginx.unblock_ip(ip)
    return {"success": success, "ip": ip, "device": "nginx"}

@router.get("/device/nginx/blocked")
def get_nginx_blocked_ips():
    """
    获取Nginx阻止的IP列表
    """
    return {"blocked_ips": device_manager.nginx.get_blocked_ips()}

@router.post("/device/modsecurity/rule")
def add_modsecurity_rule(rule: str = Query(..., description="ModSecurity规则")):
    """
    添加ModSecurity规则
    """
    success = device_manager.modsecurity.add_rule(rule)
    return {"success": success, "rule_id": len(device_manager.modsecurity.get_rules())}

@router.post("/device/modsecurity/block")
def block_ip_modsecurity(
    ip: str = Query(..., description="要阻止的IP地址"),
    reason: str = Query("恶意请求", description="阻止原因")
):
    """
    仅通过ModSecurity阻止IP
    """
    success = device_manager.modsecurity.block_ip(ip, reason)
    return {"success": success, "ip": ip, "device": "modsecurity"}

@router.delete("/device/modsecurity/rule")
def remove_modsecurity_rule(rule_id: int = Query(..., description="规则ID")):
    """
    移除ModSecurity规则
    """
    success = device_manager.modsecurity.remove_rule(rule_id)
    return {"success": success, "rule_id": rule_id}

@router.get("/device/modsecurity/rules")
def get_modsecurity_rules():
    """
    获取所有ModSecurity自定义规则
    """
    return {"rules": device_manager.modsecurity.get_rules()}