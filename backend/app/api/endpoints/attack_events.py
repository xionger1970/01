from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
from app.core.database import db_manager
from app.detectors.advanced_detector import advanced_detector

router = APIRouter()

class AttackEventBase(BaseModel):
    attack_type: str
    source_ip: str
    target_ip: str
    target_port: int
    user_agent: Optional[str] = None
    status: str
    request_method: str
    request_path: str
    request_params: Optional[dict] = None
    response_code: int
    severity: str
    details: Optional[dict] = None

class AttackEvent(AttackEventBase):
    id: int
    event_time: str

class AttackEventWithAnalysis(AttackEvent):
    advanced_analysis: Optional[List[Dict]] = None

@router.get("/", response_model=List[AttackEvent])
def get_attack_events(
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    # Mock data for demonstration
    from datetime import datetime
    import random
    
    events = []
    for i in range(1, limit + 1):
        events.append({
            "id": i,
            "attack_type": random.choice(['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'CSRF']),
            "source_ip": f'192.168.1.{i}',
            "target_ip": f'10.0.0.{i % 10}',
            "target_port": random.choice([80, 443, 8080, 3306, 22]),
            "user_agent": f'Mozilla/5.0 (Agent-{i})',
            "status": random.choice(['detected', 'blocked', 'investigating']),
            "request_method": random.choice(['GET', 'POST', 'PUT', 'DELETE']),
            "request_path": f'/api/v1/resource/{i}',
            "request_params": {"param": f"value{i}"},
            "response_code": random.choice([200, 403, 404, 500]),
            "severity": random.choice(['low', 'medium', 'high', 'critical']),
            "details": {"description": f"Attack details for event {i}", "payload": f"payload_{i}"},
            "event_time": datetime.now().isoformat()
        })
    
    # Apply filters
    if attack_type:
        events = [e for e in events if e['attack_type'] == attack_type]
    if source_ip:
        events = [e for e in events if e['source_ip'] == source_ip]
    if severity:
        events = [e for e in events if e['severity'] == severity]
    
    return events

@router.post("/", response_model=AttackEventWithAnalysis)
def create_attack_event(event: AttackEventBase):
    # 构建请求数据字符串用于高级威胁检测
    request_data = f"{event.request_method} {event.request_path} {event.request_params}"
    
    # 执行高级威胁检测
    domain = ""
    if event.request_path:
        domain = event.request_path.split('/')[0] if event.request_path else ""
    
    advanced_analysis = advanced_detector.detect_advanced_threats(
        event.source_ip, domain, request_data
    )
    
    # 插入数据库
    query = """
    INSERT INTO attack_events (
        attack_type, source_ip, target_ip, target_port, user_agent, 
        status, request_method, request_path, request_params, 
        response_code, severity, details, timestamp
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    RETURNING id
    """
    
    params = [
        event.attack_type, event.source_ip, event.target_ip, event.target_port,
        event.user_agent, event.status, event.request_method, event.request_path,
        str(event.request_params), event.response_code, event.severity,
        str(event.details), datetime.now()
    ]
    
    cursor = db_manager.execute_pg_query(query, params)
    event_id = cursor.fetchone()[0]
    
    new_event = {
        "id": event_id,
        "attack_type": event.attack_type,
        "source_ip": event.source_ip,
        "target_ip": event.target_ip,
        "target_port": event.target_port,
        "user_agent": event.user_agent,
        "status": event.status,
        "request_method": event.request_method,
        "request_path": event.request_path,
        "request_params": event.request_params,
        "response_code": event.response_code,
        "severity": event.severity,
        "details": event.details,
        "event_time": datetime.now(),
        "advanced_analysis": advanced_analysis
    }
    
    return new_event

@router.get("/stats")
def get_attack_stats():
    # 从数据库获取统计信息
    cursor = db_manager.execute_pg_query("SELECT attack_type, severity, COUNT(*) FROM attack_events GROUP BY attack_type, severity")
    
    stats = {
        "total_events": 0,
        "by_type": {},
        "by_severity": {},
        "type_severity_matrix": {}
    }
    
    for row in cursor.fetchall():
        attack_type, severity, count = row
        stats["total_events"] += count
        stats["by_type"][attack_type] = stats["by_type"].get(attack_type, 0) + count
        stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + count
        
        if attack_type not in stats["type_severity_matrix"]:
            stats["type_severity_matrix"][attack_type] = {}
        stats["type_severity_matrix"][attack_type][severity] = count
    
    # 添加检测能力统计
    stats["detection_capabilities"] = advanced_detector.get_detection_stats()
    
    return stats

@router.put("/{event_id}")
def update_attack_event(event_id: int, update_data: Dict):
    data_store = db_manager.pg_conn.data_store.get('attack_events', [])
    for i, event in enumerate(data_store):
        if event.get('id') == event_id:
            for key, value in update_data.items():
                if key != 'id':
                    data_store[i][key] = value
            return data_store[i]
    raise HTTPException(status_code=404, detail="攻击事件未找到")

@router.delete("/{event_id}")
def delete_attack_event(event_id: int):
    data_store = db_manager.pg_conn.data_store.get('attack_events', [])
    for i, event in enumerate(data_store):
        if event.get('id') == event_id:
            data_store.pop(i)
            return {"message": "删除成功", "id": event_id}
    raise HTTPException(status_code=404, detail="攻击事件未找到")

@router.post("/analyze")
def analyze_attack_data(data: Dict):
    """分析攻击数据"""
    ip = data.get('ip', '')
    domain = data.get('domain', '')
    content = data.get('content', '')
    
    # 执行高级威胁检测
    detections = advanced_detector.detect_advanced_threats(ip, domain, content)
    
    return {
        "ip": ip,
        "domain": domain,
        "detections": detections,
        "analysis_time": datetime.now().isoformat()
    }

