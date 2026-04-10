from fastapi import APIRouter, HTTPException, Query
from datetime import datetime
from typing import List, Dict, Optional

from app.detectors.mitre_attack_mapper import MitreAttackMapper
from app.detectors.alert_aggregator import AlertAggregator
from app.detectors.whitelist_manager import WhitelistManager
from app.detectors.time_window_analyzer import TimeWindowAnalyzer
from app.detectors.frequency_detector import FrequencyDetector

router = APIRouter()

# 初始化检测组件
mitre_mapper = MitreAttackMapper()
alert_aggregator = AlertAggregator()
whitelist_manager = WhitelistManager()
time_window_analyzer = TimeWindowAnalyzer()
frequency_detector = FrequencyDetector()

@router.get("/mitre/techniques", response_model=List[Dict])
def get_mitre_techniques():
    """
    获取所有MITRE ATT&CK技术映射
    """
    return [
        {"attack_type": attack_type, **info}
        for attack_type, info in mitre_mapper.get_all_mappings().items()
    ]

@router.get("/mitre/tactics", response_model=List[str])
def get_mitre_tactics():
    """
    获取所有MITRE ATT&CK战术
    """
    return mitre_mapper.get_tactics()

@router.get("/mitre/techniques_by_tactic", response_model=List[Dict])
def get_techniques_by_tactic(tactic: str = Query(..., description="战术名称")):
    """
    根据战术获取MITRE ATT&CK技术
    """
    return mitre_mapper.get_techniques_by_tactic(tactic)

@router.post("/mitre/mapping")
def add_mitre_mapping(attack_type: str, technique_id: str, technique_name: str, tactic: str, description: str):
    """
    添加MITRE ATT&CK映射
    """
    mitre_mapper.add_new_mapping(attack_type, technique_id, technique_name, tactic, description)
    return {"message": "Mapping added successfully"}

@router.get("/alerts/aggregated", response_model=List[Dict])
def get_aggregated_alerts(active_only: bool = True):
    """
    获取聚合后的告警
    """
    return alert_aggregator.get_aggregated_alerts(active_only)

@router.get("/alerts/by_source", response_model=List[Dict])
def get_alerts_by_source(source_ip: str = Query(..., description="源IP地址")):
    """
    根据源IP获取聚合告警
    """
    return alert_aggregator.get_alerts_by_source_ip(source_ip)

@router.get("/alerts/by_type", response_model=List[Dict])
def get_alerts_by_type(alert_type: str = Query(..., description="告警类型")):
    """
    根据告警类型获取聚合告警
    """
    return alert_aggregator.get_alerts_by_type(alert_type)

@router.get("/alerts/top_sources", response_model=List[Dict])
def get_top_sources(limit: int = 10):
    """
    获取攻击次数最多的源IP
    """
    top_sources = alert_aggregator.get_top_sources(limit)
    return [{"source_ip": ip, "count": count} for ip, count in top_sources]

@router.get("/alerts/top_types", response_model=List[Dict])
def get_top_alert_types(limit: int = 10):
    """
    获取最常见的告警类型
    """
    top_types = alert_aggregator.get_top_alert_types(limit)
    return [{"alert_type": alert_type, "count": count} for alert_type, count in top_types]

@router.post("/whitelist/ip")
def add_ip_to_whitelist(ip: str):
    """
    添加IP到白名单
    """
    success = whitelist_manager.add_ip(ip)
    if success:
        return {"message": "IP added to whitelist successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid IP address")

@router.delete("/whitelist/ip")
def remove_ip_from_whitelist(ip: str):
    """
    从白名单移除IP
    """
    success = whitelist_manager.remove_ip(ip)
    if success:
        return {"message": "IP removed from whitelist successfully"}
    else:
        raise HTTPException(status_code=404, detail="IP not found in whitelist")

@router.post("/whitelist/ip_range")
def add_ip_range_to_whitelist(ip_range: str):
    """
    添加IP范围到白名单
    """
    success = whitelist_manager.add_ip_range(ip_range)
    if success:
        return {"message": "IP range added to whitelist successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid IP range")

@router.delete("/whitelist/ip_range")
def remove_ip_range_from_whitelist(ip_range: str):
    """
    从白名单移除IP范围
    """
    success = whitelist_manager.remove_ip_range(ip_range)
    if success:
        return {"message": "IP range removed from whitelist successfully"}
    else:
        raise HTTPException(status_code=404, detail="IP range not found in whitelist")

@router.post("/whitelist/domain")
def add_domain_to_whitelist(domain: str):
    """
    添加域名到白名单
    """
    success = whitelist_manager.add_domain(domain)
    if success:
        return {"message": "Domain added to whitelist successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid domain")

@router.delete("/whitelist/domain")
def remove_domain_from_whitelist(domain: str):
    """
    从白名单移除域名
    """
    success = whitelist_manager.remove_domain(domain)
    if success:
        return {"message": "Domain removed from whitelist successfully"}
    else:
        raise HTTPException(status_code=404, detail="Domain not found in whitelist")

@router.get("/whitelist/status")
def check_whitelist_status(ip: Optional[str] = None, domain: Optional[str] = None):
    """
    检查IP或域名是否在白名单中
    """
    if ip:
        is_whitelisted = whitelist_manager.is_ip_whitelisted(ip)
        return {"ip": ip, "is_whitelisted": is_whitelisted}
    elif domain:
        is_whitelisted = whitelist_manager.is_domain_whitelisted(domain)
        return {"domain": domain, "is_whitelisted": is_whitelisted}
    else:
        raise HTTPException(status_code=400, detail="Either ip or domain must be provided")

@router.get("/whitelist/list")
def get_whitelist():
    """
    获取白名单列表
    """
    return whitelist_manager.export_whitelist()

@router.post("/time_window/event")
def add_time_window_event(event_type: str, key: str):
    """
    添加时间窗口事件
    """
    over_threshold = time_window_analyzer.add_event(event_type, key)
    return {"over_threshold": over_threshold}

@router.get("/time_window/events")
def get_time_window_events(event_type: str, key: str):
    """
    获取时间窗口事件
    """
    events = time_window_analyzer.get_events(event_type, key)
    return {"events": [event.isoformat() for event in events]}

@router.get("/time_window/count")
def get_time_window_event_count(event_type: str, key: str):
    """
    获取时间窗口事件数量
    """
    count = time_window_analyzer.get_event_count(event_type, key)
    return {"count": count}

@router.get("/time_window/top_offenders")
def get_time_window_top_offenders(event_type: str, limit: int = 10):
    """
    获取时间窗口内触发事件最多的键
    """
    top_offenders = time_window_analyzer.get_top_offenders(event_type, limit)
    return [{"key": key, "count": count} for key, count in top_offenders]

@router.post("/frequency/event")
def add_frequency_event(entity: str):
    """
    添加频率检测事件
    """
    over_threshold = frequency_detector.add_event(entity)
    return {"over_threshold": over_threshold}

@router.get("/frequency/status")
def get_frequency_status(entity: str):
    """
    获取频率检测状态
    """
    is_blocked = frequency_detector.is_blocked(entity)
    event_count = frequency_detector.get_event_count(entity)
    return {"is_blocked": is_blocked, "event_count": event_count}

@router.get("/frequency/blocked")
def get_blocked_entities():
    """
    获取被阻止的实体
    """
    blocked = frequency_detector.get_blocked_entities()
    return [{"entity": entity, "unblock_time": unblock_time.isoformat()} for entity, unblock_time in blocked]

@router.post("/frequency/unblock")
def unblock_entity(entity: str):
    """
    解除对实体的阻止
    """
    frequency_detector.unblock_entity(entity)
    return {"message": "Entity unblocked successfully"}