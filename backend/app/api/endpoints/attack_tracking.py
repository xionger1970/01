from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
from app.analysis.attack_tracker import attack_tracker

router = APIRouter()

class AttackEventBase(BaseModel):
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    attack_type: Optional[str] = None
    severity: str = "medium"
    details: Optional[Dict] = None
    asset_id: Optional[str] = None

class AttackEvent(AttackEventBase):
    id: int
    timestamp: datetime
    status: str
    related_events: List[int]
    attack_phase: str

class AttackChain(BaseModel):
    id: int
    source_ip: str
    start_time: datetime
    end_time: datetime
    event_count: int
    events: List[int]
    attack_phases: List[str]
    status: str
    severity: str
    targets: List[str]

class AttackPath(BaseModel):
    chain: AttackChain
    path: List[Dict]
    phases: List[Dict]
    summary: str

class AttackStatistics(BaseModel):
    total_events: int
    total_chains: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    events_by_phase: Dict[str, int]
    top_sources: Dict[str, int]
    top_targets: Dict[str, int]
    attack_phases: List[Dict]

@router.post("/events", response_model=AttackEvent)
def create_attack_event(event: AttackEventBase):
    """创建攻击事件"""
    new_event = attack_tracker.add_attack_event(event.dict())
    return new_event

@router.get("/events", response_model=List[AttackEvent])
def get_attack_events(
    source_ip: Optional[str] = None,
    target_ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """获取攻击事件"""
    filters = {}
    if source_ip:
        filters['source_ip'] = source_ip
    if target_ip:
        filters['target_ip'] = target_ip
    if attack_type:
        filters['attack_type'] = attack_type
    if severity:
        filters['severity'] = severity
    
    events = attack_tracker.get_attack_events(filters)
    return events[:limit]

@router.get("/chains", response_model=List[AttackChain])
def get_attack_chains(
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100)
):
    """获取攻击链"""
    filters = {}
    if source_ip:
        filters['source_ip'] = source_ip
    if severity:
        filters['severity'] = severity
    
    chains = attack_tracker.get_attack_chains(filters)
    return chains[:limit]

@router.get("/chains/{chain_id}/path", response_model=AttackPath)
def get_attack_path(chain_id: int):
    """获取攻击路径分析"""
    path = attack_tracker.analyze_attack_path(chain_id)
    if not path:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return path

@router.get("/events/{event_id}/relations", response_model=List[AttackEvent])
def get_event_relations(event_id: int):
    """获取事件关联"""
    relations = attack_tracker.get_event_relations(event_id)
    return relations

@router.get("/assets/{asset_id}/impacts", response_model=List[AttackEvent])
def get_asset_impacts(asset_id: str):
    """获取资产影响"""
    impacts = attack_tracker.get_asset_impacts(asset_id)
    return impacts

@router.delete("/chains/{chain_id}")
def delete_attack_chain(chain_id: int):
    """删除攻击链"""
    chains = attack_tracker.attack_chains
    for i, c in enumerate(chains):
        if c.get('id') == chain_id:
            chains.pop(i)
            return {"message": "攻击链删除成功", "id": chain_id}
    raise HTTPException(status_code=404, detail="攻击链未找到")

@router.delete("/events/{event_id}")
def delete_attack_event(event_id: int):
    """删除攻击事件"""
    events = attack_tracker.attack_events
    for i, e in enumerate(events):
        if e.get('id') == event_id:
            events.pop(i)
            return {"message": "攻击事件删除成功", "id": event_id}
    raise HTTPException(status_code=404, detail="攻击事件未找到")

@router.get("/statistics", response_model=AttackStatistics)
def get_attack_statistics(hours: int = Query(24, ge=1, le=168)):
    """获取攻击统计信息"""
    stats = attack_tracker.get_attack_statistics(hours)
    return stats
