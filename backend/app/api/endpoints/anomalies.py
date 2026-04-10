from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
from app.detectors.anomaly_detector import anomaly_detector

router = APIRouter()

@router.get("/", response_model=Dict)
def get_anomalies_overview():
    """获取异常检测概览"""
    stats = anomaly_detector.get_anomaly_stats()
    thresholds = anomaly_detector.thresholds
    return {
        "stats": stats,
        "thresholds": thresholds,
        "anomalies": anomaly_detector.detected_anomalies[-50:] if hasattr(anomaly_detector, 'detected_anomalies') else []
    }

class TrafficData(BaseModel):
    source_ip: str
    target_ip: str
    bytes_sent: int
    bytes_received: int

class ConnectionData(BaseModel):
    source_ip: str
    target_ip: str
    port: int
    protocol: str

class UserLoginData(BaseModel):
    username: str
    ip: str
    success: bool
    geo_location: Optional[Dict] = None

class UserAccessData(BaseModel):
    username: str
    resource: str
    action: str
    ip: str

class DataTransferData(BaseModel):
    source_ip: str
    target_ip: str
    data_size: int
    data_type: str

class ProcessData(BaseModel):
    host: str
    process_name: str
    process_id: int
    cpu_usage: float
    memory_usage: float

class ResourceData(BaseModel):
    host: str
    cpu_usage: float
    memory_usage: float
    disk_usage: float

class AnomalyResponse(BaseModel):
    type: str
    description: str
    severity: str
    details: Dict
    timestamp: float

@router.post("/traffic")
def add_traffic_data(data: TrafficData):
    """添加流量数据"""
    anomaly_detector.add_traffic_data(
        data.source_ip,
        data.target_ip,
        data.bytes_sent,
        data.bytes_received
    )
    return {"message": "Traffic data added successfully"}

@router.post("/connection")
def add_connection_data(data: ConnectionData):
    """添加连接数据"""
    anomaly_detector.add_connection_data(
        data.source_ip,
        data.target_ip,
        data.port,
        data.protocol
    )
    return {"message": "Connection data added successfully"}

@router.post("/user/login")
def add_user_login(data: UserLoginData):
    """添加用户登录数据"""
    anomaly_detector.add_user_login(
        data.username,
        data.ip,
        data.success,
        data.geo_location
    )
    return {"message": "User login data added successfully"}

@router.post("/user/access")
def add_user_access(data: UserAccessData):
    """添加用户访问数据"""
    anomaly_detector.add_user_access(
        data.username,
        data.resource,
        data.action,
        data.ip
    )
    return {"message": "User access data added successfully"}

@router.post("/data/transfer")
def add_data_transfer(data: DataTransferData):
    """添加数据传输数据"""
    anomaly_detector.add_data_transfer(
        data.source_ip,
        data.target_ip,
        data.data_size,
        data.data_type
    )
    return {"message": "Data transfer data added successfully"}

@router.post("/system/process")
def add_process_data(data: ProcessData):
    """添加进程数据"""
    anomaly_detector.add_process_data(
        data.host,
        data.process_name,
        data.process_id,
        data.cpu_usage,
        data.memory_usage
    )
    return {"message": "Process data added successfully"}

@router.post("/system/resource")
def add_resource_data(data: ResourceData):
    """添加资源使用数据"""
    anomaly_detector.add_resource_data(
        data.host,
        data.cpu_usage,
        data.memory_usage,
        data.disk_usage
    )
    return {"message": "Resource data added successfully"}

@router.get("/detect", response_model=List[AnomalyResponse])
def detect_anomalies(
    anomaly_type: Optional[str] = Query(None, description="异常类型: traffic, user, data, system")
):
    """检测异常"""
    if anomaly_type == 'traffic':
        anomalies = anomaly_detector.detect_traffic_anomalies()
    elif anomaly_type == 'user':
        anomalies = anomaly_detector.detect_user_anomalies()
    elif anomaly_type == 'data':
        anomalies = anomaly_detector.detect_data_anomalies()
    elif anomaly_type == 'system':
        anomalies = anomaly_detector.detect_system_anomalies()
    else:
        anomalies = anomaly_detector.detect_all_anomalies()
    
    return anomalies

@router.get("/stats")
def get_anomaly_stats():
    """获取异常检测统计信息"""
    stats = anomaly_detector.get_anomaly_stats()
    return stats

@router.get("/thresholds")
def get_anomaly_thresholds():
    """获取异常检测阈值"""
    thresholds = anomaly_detector.thresholds
    return thresholds

@router.post("/thresholds")
def update_anomaly_thresholds(thresholds: Dict):
    """更新异常检测阈值"""
    with anomaly_detector.lock:
        anomaly_detector.thresholds.update(thresholds)
    return {"message": "Thresholds updated successfully"}
