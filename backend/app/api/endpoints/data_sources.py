from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
import random

router = APIRouter()

MOCK_DATA_SOURCES = [
    {
        "id": 1,
        "name": "Suricata-IDS-01",
        "type": "suricata",
        "protocol": "syslog-udp",
        "host": "192.168.1.100",
        "port": 514,
        "status": "connected",
        "eps": 1250,
        "total_events": 1580000,
        "last_event": "2026-04-10T10:30:00",
        "created_at": "2026-01-15T08:00:00",
        "description": "Suricata IDS 主检测引擎"
    },
    {
        "id": 2,
        "name": "Zeek-Sensor-01",
        "type": "zeek",
        "protocol": "syslog-tcp",
        "host": "192.168.1.101",
        "port": 514,
        "status": "connected",
        "eps": 800,
        "total_events": 960000,
        "last_event": "2026-04-10T10:29:55",
        "created_at": "2026-01-15T08:00:00",
        "description": "Zeek 网络分析传感器"
    },
    {
        "id": 3,
        "name": "ELK-Stack",
        "type": "elk",
        "protocol": "efk",
        "host": "192.168.1.200",
        "port": 9200,
        "status": "connected",
        "eps": 2100,
        "total_events": 5200000,
        "last_event": "2026-04-10T10:30:01",
        "created_at": "2026-02-01T10:00:00",
        "description": "ELK 日志分析平台"
    },
    {
        "id": 4,
        "name": "Splunk-Enterprise",
        "type": "splunk",
        "protocol": "https",
        "host": "192.168.1.201",
        "port": 8089,
        "status": "disconnected",
        "eps": 0,
        "total_events": 3200000,
        "last_event": "2026-04-09T18:00:00",
        "created_at": "2026-02-10T09:00:00",
        "description": "Splunk 企业版 SIEM"
    },
    {
        "id": 5,
        "name": "Syslog-Collector",
        "type": "syslog",
        "protocol": "syslog-udp",
        "host": "0.0.0.0",
        "port": 514,
        "status": "connected",
        "eps": 3500,
        "total_events": 8900000,
        "last_event": "2026-04-10T10:30:02",
        "created_at": "2026-01-10T08:00:00",
        "description": "通用 Syslog 采集器"
    },
    {
        "id": 6,
        "name": "Kafka-Bus",
        "type": "kafka",
        "protocol": "kafka",
        "host": "192.168.1.150",
        "port": 9092,
        "status": "connected",
        "eps": 5000,
        "total_events": 15000000,
        "last_event": "2026-04-10T10:30:03",
        "created_at": "2026-01-20T10:00:00",
        "description": "Apache Kafka 消息总线"
    },
    {
        "id": 7,
        "name": "NetFlow-Analyzer",
        "type": "netflow",
        "protocol": "syslog-udp",
        "host": "192.168.1.102",
        "port": 2055,
        "status": "error",
        "eps": 0,
        "total_events": 450000,
        "last_event": "2026-04-08T14:22:00",
        "created_at": "2026-03-01T11:00:00",
        "description": "NetFlow/sFlow 流量分析器"
    },
    {
        "id": 8,
        "name": "Wazuh-Agent",
        "type": "wazuh",
        "protocol": "syslog-tcp",
        "host": "192.168.1.103",
        "port": 1514,
        "status": "connected",
        "eps": 600,
        "total_events": 720000,
        "last_event": "2026-04-10T10:29:58",
        "created_at": "2026-03-05T14:00:00",
        "description": "Wazuh 主机入侵检测"
    }
]

SUPPORTED_TYPES = [
    {"type": "suricata", "name": "Suricata IDS", "description": "高性能网络入侵检测/防御系统", "default_port": 514},
    {"type": "zeek", "name": "Zeek", "description": "网络分析框架，提供深度协议分析", "default_port": 514},
    {"type": "elk", "name": "ELK Stack", "description": "Elasticsearch + Logstash + Kibana 日志分析平台", "default_port": 9200},
    {"type": "splunk", "name": "Splunk", "description": "企业级安全信息和事件管理平台", "default_port": 8089},
    {"type": "syslog", "name": "Syslog", "description": "通用系统日志采集协议", "default_port": 514},
    {"type": "kafka", "name": "Apache Kafka", "description": "分布式流处理消息队列", "default_port": 9092},
    {"type": "netflow", "name": "NetFlow/sFlow", "description": "网络流量监控协议", "default_port": 2055},
    {"type": "api", "name": "REST API", "description": "通用 REST API 数据接入", "default_port": 443},
    {"type": "filebeat", "name": "Filebeat", "description": "轻量级日志文件数据采集器", "default_port": 5044},
    {"type": "wazuh", "name": "Wazuh", "description": "开源安全监控与主机入侵检测", "default_port": 1514}
]


class DataSourceBase(BaseModel):
    name: str
    type: str
    protocol: str
    host: str
    port: int
    description: Optional[str] = None


class DataSource(DataSourceBase):
    id: int
    status: str = "disconnected"
    eps: int = 0
    total_events: int = 0
    last_event: Optional[str] = None
    created_at: str


class ConnectionTestResult(BaseModel):
    success: bool
    latency_ms: Optional[float] = None
    version: Optional[str] = None
    error: Optional[str] = None


@router.get("/sources", response_model=List[Dict])
def get_data_sources():
    """获取所有数据源"""
    return MOCK_DATA_SOURCES


@router.post("/sources", response_model=Dict)
def add_data_source(source: DataSourceBase):
    """添加数据源"""
    new_id = max(s["id"] for s in MOCK_DATA_SOURCES) + 1 if MOCK_DATA_SOURCES else 1
    new_source = {
        "id": new_id,
        **source.dict(),
        "status": "disconnected",
        "eps": 0,
        "total_events": 0,
        "last_event": None,
        "created_at": datetime.now().isoformat()
    }
    MOCK_DATA_SOURCES.append(new_source)
    return new_source


@router.put("/sources/{source_id}", response_model=Dict)
def update_data_source(source_id: int, source: DataSourceBase):
    """更新数据源"""
    for i, s in enumerate(MOCK_DATA_SOURCES):
        if s["id"] == source_id:
            update_data = source.dict()
            update_data["id"] = source_id
            update_data["updated_at"] = datetime.now().isoformat()
            MOCK_DATA_SOURCES[i].update(update_data)
            return MOCK_DATA_SOURCES[i]
    raise HTTPException(status_code=404, detail="数据源未找到")


@router.delete("/sources/{source_id}")
def delete_data_source(source_id: int):
    """删除数据源"""
    for i, s in enumerate(MOCK_DATA_SOURCES):
        if s["id"] == source_id:
            MOCK_DATA_SOURCES.pop(i)
            return {"message": "数据源删除成功", "id": source_id}
    raise HTTPException(status_code=404, detail="数据源未找到")


@router.post("/sources/{source_id}/test", response_model=ConnectionTestResult)
def test_connection(source_id: int):
    """测试数据源连接"""
    source = next((s for s in MOCK_DATA_SOURCES if s["id"] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="数据源未找到")

    if source["type"] == "netflow":
        return ConnectionTestResult(
            success=False,
            error="连接超时: 目标主机无响应"
        )

    latency = round(random.uniform(1.5, 50.0), 2)
    versions = {
        "suricata": "7.0.3",
        "zeek": "6.2.0",
        "elk": "8.12.1",
        "splunk": "9.2.0",
        "kafka": "3.6.1",
        "wazuh": "4.8.0",
        "filebeat": "8.12.1",
        "syslog": "RFC5424",
        "api": "v2.1",
    }

    return ConnectionTestResult(
        success=True,
        latency_ms=latency,
        version=versions.get(source["type"], "unknown")
    )


@router.post("/sources/{source_id}/connect")
def connect_source(source_id: int):
    """连接数据源"""
    for s in MOCK_DATA_SOURCES:
        if s["id"] == source_id:
            s["status"] = "connected"
            s["eps"] = random.randint(500, 3000)
            s["last_event"] = datetime.now().isoformat()
            return {"message": "连接成功", "status": "connected", "eps": s["eps"]}
    raise HTTPException(status_code=404, detail="数据源未找到")


@router.post("/sources/{source_id}/disconnect")
def disconnect_source(source_id: int):
    """断开数据源"""
    for s in MOCK_DATA_SOURCES:
        if s["id"] == source_id:
            s["status"] = "disconnected"
            s["eps"] = 0
            return {"message": "已断开连接", "status": "disconnected"}
    raise HTTPException(status_code=404, detail="数据源未找到")


@router.get("/supported-types")
def get_supported_types():
    """获取支持的数据源类型"""
    return SUPPORTED_TYPES


@router.get("/traffic-stats")
def get_traffic_stats():
    """获取实时流量统计"""
    connected = [s for s in MOCK_DATA_SOURCES if s["status"] == "connected"]
    total_eps = sum(s["eps"] for s in connected)
    total_events = sum(s["total_events"] for s in MOCK_DATA_SOURCES)

    return {
        "total_sources": len(MOCK_DATA_SOURCES),
        "connected_sources": len(connected),
        "total_eps": total_eps,
        "total_events": total_events,
        "sources_eps": [
            {"name": s["name"], "type": s["type"], "eps": s["eps"], "status": s["status"]}
            for s in MOCK_DATA_SOURCES
        ]
    }
