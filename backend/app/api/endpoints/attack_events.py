from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()

# For demonstration purposes, using a simple in-memory store
# In production, use InfluxDB
attack_events = [
    {
        "id": 1,
        "attack_type": "sql_injection",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.1",
        "target_port": 80,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "status": "attempted",
        "request_method": "POST",
        "request_path": "/login",
        "request_params": {"username": "admin' OR 1=1--"},
        "response_code": 403,
        "severity": "high",
        "details": {"payload": "admin' OR 1=1--"},
        "event_time": datetime.now()
    },
    {
        "id": 2,
        "attack_type": "xss",
        "source_ip": "192.168.1.101",
        "target_ip": "10.0.0.1",
        "target_port": 80,
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "status": "attempted",
        "request_method": "GET",
        "request_path": "/search",
        "request_params": {"q": "<script>alert('XSS')</script>"},
        "response_code": 200,
        "severity": "medium",
        "details": {"payload": "<script>alert('XSS')</script>"},
        "event_time": datetime.now()
    }
]

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
    event_time: datetime

@router.get("/", response_model=List[AttackEvent])
def get_attack_events(
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 100
):
    filtered_events = attack_events
    if attack_type:
        filtered_events = [e for e in filtered_events if e["attack_type"] == attack_type]
    if source_ip:
        filtered_events = [e for e in filtered_events if e["source_ip"] == source_ip]
    return filtered_events[:limit]

@router.post("/", response_model=AttackEvent)
def create_attack_event(event: AttackEventBase):
    new_event = {
        "id": len(attack_events) + 1,
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
        "event_time": datetime.now()
    }
    attack_events.append(new_event)
    return new_event

@router.get("/stats")
def get_attack_stats():
    # Simple stats for demonstration
    stats = {
        "total_events": len(attack_events),
        "by_type": {},
        "by_severity": {}
    }
    
    for event in attack_events:
        stats["by_type"][event["attack_type"]] = stats["by_type"].get(event["attack_type"], 0) + 1
        stats["by_severity"][event["severity"]] = stats["by_severity"].get(event["severity"], 0) + 1
    
    return stats
