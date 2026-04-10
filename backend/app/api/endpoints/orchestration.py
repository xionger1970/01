from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
from app.orchestration.orchestrator import orchestrator

router = APIRouter()

class DeviceBase(BaseModel):
    name: str
    type: str
    ip_address: str
    port: int = 80
    api_key: Optional[str] = None

class Device(DeviceBase):
    id: int
    status: str
    created_at: datetime
    updated_at: datetime

class ActionBase(BaseModel):
    action_type: str
    target: str
    device_id: Optional[int] = None

class Action(ActionBase):
    id: int
    status: str
    result: Optional[Dict] = None
    created_at: datetime
    updated_at: datetime

class RuleAction(BaseModel):
    type: str
    target: Optional[str] = None
    device_id: Optional[int] = None

class RuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    condition: Dict
    actions: List[RuleAction]
    enabled: bool = True

class Rule(RuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

class ConnectionTest(BaseModel):
    status: str
    message: str

@router.post("/devices", response_model=Device)
def add_integrated_device(device: DeviceBase):
    """添加集成设备"""
    new_device = orchestrator.add_integrated_device(device.dict())
    return new_device

@router.get("/devices", response_model=List[Device])
def get_integrated_devices():
    """获取集成设备列表"""
    devices = orchestrator.get_integrated_devices()
    return devices

@router.get("/devices/{device_id}/test", response_model=ConnectionTest)
def test_device_connection(device_id: int):
    """测试设备连接"""
    result = orchestrator.test_device_connection(device_id)
    return result

@router.put("/devices/{device_id}")
def update_device(device_id: int, device: DeviceBase):
    """更新设备信息"""
    devices = orchestrator.integrated_devices
    for i, d in enumerate(devices):
        if d.get('id') == device_id:
            update_data = device.dict()
            update_data['id'] = device_id
            update_data['updated_at'] = datetime.now().isoformat()
            devices[i].update(update_data)
            return devices[i]
    raise HTTPException(status_code=404, detail="设备未找到")

@router.delete("/devices/{device_id}")
def delete_device(device_id: int):
    """删除设备"""
    devices = orchestrator.integrated_devices
    for i, d in enumerate(devices):
        if d.get('id') == device_id:
            devices.pop(i)
            return {"message": "设备删除成功", "id": device_id}
    raise HTTPException(status_code=404, detail="设备未找到")

@router.post("/rules", response_model=Rule)
def add_response_rule(rule: RuleBase):
    """添加响应规则"""
    new_rule = orchestrator.add_response_rule(rule.dict())
    return new_rule

@router.get("/rules", response_model=List[Rule])
def get_response_rules():
    """获取响应规则列表"""
    rules = orchestrator.get_response_rules()
    return rules

@router.put("/rules/{rule_id}", response_model=Rule)
def update_response_rule(rule_id: int, rule: RuleBase):
    """更新响应规则"""
    updated_rule = orchestrator.update_response_rule(rule_id, rule.dict())
    if not updated_rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return updated_rule

@router.delete("/rules/{rule_id}")
def delete_response_rule(rule_id: int):
    """删除响应规则"""
    success = orchestrator.delete_response_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"message": "Rule deleted successfully"}

@router.post("/actions", response_model=Action)
def execute_action(action: ActionBase):
    """执行响应动作"""
    new_action = orchestrator.execute_action(action.dict())
    return new_action

@router.get("/actions", response_model=List[Action])
def get_response_history():
    """获取响应历史"""
    history = orchestrator.get_response_history()
    return history

@router.get("/device-types")
def get_supported_device_types():
    """获取支持的设备类型"""
    types = orchestrator.get_supported_device_types()
    return types

@router.get("/actions/types")
def get_supported_actions():
    """获取支持的响应动作"""
    actions = orchestrator.get_supported_actions()
    return actions

@router.get("/device-status")
def get_device_status():
    """获取设备状态"""
    status = orchestrator.get_device_status()
    return status

QUICK_ACTIONS = [
    {"id": "block_top_attacker", "name": "封锁最高频攻击源", "description": "自动封锁当前攻击频率最高的IP地址", "category": "auto_response", "enabled": True},
    {"id": "isolate_infected", "name": "隔离受感染主机", "description": "将检测到恶意软件的主机从网络中隔离", "category": "containment", "enabled": True},
    {"id": "update_threat_rules", "name": "更新威胁检测规则", "description": "从威胁情报源同步最新检测规则", "category": "rule_update", "enabled": True},
    {"id": "scan_all_assets", "name": "全量资产扫描", "description": "对所有资产执行安全漏洞扫描", "category": "scan", "enabled": False},
    {"id": "enable_strict_mode", "name": "启用严格防护模式", "description": "将所有安全设备切换到严格防护模式", "category": "config", "enabled": True},
    {"id": "export_incident_report", "name": "导出事件报告", "description": "生成当前安全事件的详细分析报告", "category": "report", "enabled": True},
]

@router.get("/quick-actions")
def get_quick_actions():
    """获取快捷操作列表"""
    return QUICK_ACTIONS

@router.post("/quick-actions/{action_id}/execute")
def execute_quick_action(action_id: str):
    """执行快捷操作"""
    action = next((a for a in QUICK_ACTIONS if a["id"] == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail="快捷操作未找到")
    return {"message": f"快捷操作 '{action['name']}' 执行成功", "action_id": action_id, "status": "completed", "executed_at": datetime.now().isoformat()}
