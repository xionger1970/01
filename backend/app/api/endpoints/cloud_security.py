from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
from app.cloud_security import cloud_security_manager

router = APIRouter()

class CloudEnvironmentBase(BaseModel):
    name: str
    provider: str
    region: str
    api_key: str
    secret_key: str

class ContainerEnvironmentBase(BaseModel):
    name: str
    platform: str
    endpoint: str
    api_key: str

class CloudEnvironment(CloudEnvironmentBase):
    id: int
    status: str

class ContainerEnvironment(ContainerEnvironmentBase):
    id: int
    status: str

@router.get("/cloud-environments", response_model=List[CloudEnvironment])
def get_cloud_environments():
    """获取云环境列表"""
    return cloud_security_manager.get_cloud_environments()

@router.post("/cloud-environments", response_model=CloudEnvironment)
def create_cloud_environment(environment: CloudEnvironmentBase):
    """创建云环境"""
    return cloud_security_manager.add_cloud_environment(environment.dict())

@router.get("/container-environments", response_model=List[ContainerEnvironment])
def get_container_environments():
    """获取容器环境列表"""
    return cloud_security_manager.get_container_environments()

@router.post("/container-environments", response_model=ContainerEnvironment)
def create_container_environment(environment: ContainerEnvironmentBase):
    """创建容器环境"""
    return cloud_security_manager.add_container_environment(environment.dict())

@router.get("/cloud-security-status/{env_id}")
def get_cloud_security_status(env_id: int):
    """获取云安全状态"""
    status = cloud_security_manager.get_cloud_security_status(env_id)
    if not status:
        raise HTTPException(status_code=404, detail="云环境未找到")
    return status

@router.get("/container-security-status/{env_id}")
def get_container_security_status(env_id: int):
    """获取容器安全状态"""
    status = cloud_security_manager.get_container_security_status(env_id)
    if not status:
        raise HTTPException(status_code=404, detail="容器环境未找到")
    return status

@router.get("/cloud-security-events")
def get_cloud_security_events(severity: Optional[str] = None, status: Optional[str] = None):
    """获取云安全事件"""
    filters = {}
    if severity:
        filters['severity'] = severity
    if status:
        filters['status'] = status
    return cloud_security_manager.get_cloud_security_events(filters)

@router.get("/container-security-events")
def get_container_security_events(severity: Optional[str] = None, status: Optional[str] = None):
    """获取容器安全事件"""
    filters = {}
    if severity:
        filters['severity'] = severity
    if status:
        filters['status'] = status
    return cloud_security_manager.get_container_security_events(filters)

@router.put("/cloud-security-events/{event_id}/status")
def update_cloud_security_event_status(event_id: int, status: Dict[str, str]):
    """更新云安全事件状态"""
    event = cloud_security_manager.update_cloud_security_event_status(event_id, status['status'])
    if not event:
        raise HTTPException(status_code=404, detail="云安全事件未找到")
    return event

@router.put("/container-security-events/{event_id}/status")
def update_container_security_event_status(event_id: int, status: Dict[str, str]):
    """更新容器安全事件状态"""
    event = cloud_security_manager.update_container_security_event_status(event_id, status['status'])
    if not event:
        raise HTTPException(status_code=404, detail="容器安全事件未找到")
    return event

@router.get("/cloud-security-stats")
def get_cloud_security_stats():
    """获取云安全统计信息"""
    return cloud_security_manager.get_cloud_security_stats()

@router.get("/container-security-stats")
def get_container_security_stats():
    """获取容器安全统计信息"""
    return cloud_security_manager.get_container_security_stats()

@router.get("/supported-cloud-providers")
def get_supported_cloud_providers():
    """获取支持的云服务提供商"""
    return cloud_security_manager.get_supported_cloud_providers()

@router.get("/supported-container-platforms")
def get_supported_container_platforms():
    """获取支持的容器平台"""
    return cloud_security_manager.get_supported_container_platforms()

@router.get("/cloud-security-checks")
def get_cloud_security_checks():
    """获取云安全检查项"""
    return cloud_security_manager.get_cloud_security_checks()

@router.get("/container-security-checks")
def get_container_security_checks():
    """获取容器安全检查项"""
    return cloud_security_manager.get_container_security_checks()