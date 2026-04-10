from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import json

from app.collectors.network_collector import network_collector
from app.collectors.extended_log_collector import extended_log_collector
from app.collectors.traffic_statistics import traffic_statistics

router = APIRouter()


class DataSourceConfig(BaseModel):
    name: str
    type: str
    path: str
    format: Optional[str] = None
    device_name: Optional[str] = None
    os_type: Optional[str] = None
    enabled: bool = True


class DataSourceStatus(BaseModel):
    id: int
    name: str
    type: str
    status: str
    last_seen: Optional[str] = None
    error_message: Optional[str] = None


data_sources: List[Dict] = []
collectors_running = False


def process_network_data(data: Dict):
    data_type = data.get('type')
    if data_type == 'flow':
        traffic_statistics.add_flow_data(data)
    elif data_type == 'http':
        traffic_statistics.add_http_data(data)
    elif data_type == 'dns':
        traffic_statistics.add_dns_data(data)


def process_extended_log_data(data: Dict):
    pass


@router.post("/network-collector/start")
def start_network_collector():
    global collectors_running
    if collectors_running:
        raise HTTPException(status_code=400, detail="Collectors already running")
    
    network_collector.start(callback=process_network_data)
    extended_log_collector.start(callback=process_extended_log_data)
    collectors_running = True
    return {"message": "Network and extended log collectors started"}


@router.post("/network-collector/stop")
def stop_network_collector():
    global collectors_running
    if not collectors_running:
        raise HTTPException(status_code=400, detail="Collectors are not running")
    
    network_collector.stop()
    extended_log_collector.stop()
    collectors_running = False
    return {"message": "Network and extended log collectors stopped"}


@router.get("/network-collector/status")
def get_collector_status():
    return {
        "running": collectors_running,
        "network_collector_stats": network_collector.get_flow_stats() if collectors_running else None
    }


@router.post("/data-sources")
def add_data_source(config: DataSourceConfig):
    source_id = len(data_sources) + 1
    source_config = {
        "id": source_id,
        "name": config.name,
        "type": config.type,
        "path": config.path,
        "format": config.format,
        "device_name": config.device_name,
        "os_type": config.os_type,
        "enabled": config.enabled,
        "status": "inactive",
        "created_at": datetime.now().isoformat()
    }
    data_sources.append(source_config)
    
    if config.enabled:
        if config.type in ['firewall', 'waf', 'system']:
            extended_log_config = {
                'path': config.path,
                'type': config.type,
                'format': config.format,
                'device_name': config.device_name,
                'os_type': config.os_type
            }
            extended_log_collector.add_log_source(extended_log_config)
            source_config['status'] = 'active'
    
    return source_config


@router.get("/data-sources")
def list_data_sources():
    return data_sources


@router.get("/data-sources/{source_id}")
def get_data_source(source_id: int):
    source = next((s for s in data_sources if s['id'] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    return source


@router.delete("/data-sources/{source_id}")
def delete_data_source(source_id: int):
    global data_sources
    source = next((s for s in data_sources if s['id'] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    data_sources = [s for s in data_sources if s['id'] != source_id]
    return {"message": "Data source deleted"}


@router.get("/traffic/overview")
def get_traffic_overview():
    return traffic_statistics.get_overview()


@router.get("/traffic/top-talkers")
def get_top_talkers(limit: int = Query(10, ge=1, le=50)):
    overview = traffic_statistics.get_overview()
    return overview.get('top_talkers', [])[:limit]


@router.get("/traffic/top-ports")
def get_top_ports(limit: int = Query(10, ge=1, le=50)):
    overview = traffic_statistics.get_overview()
    return overview.get('top_ports', [])[:limit]


@router.get("/traffic/protocols")
def get_protocol_distribution():
    overview = traffic_statistics.get_overview()
    return overview.get('protocol_distribution', [])


@router.get("/traffic/ip/{ip}")
def get_ip_details(ip: str):
    details = traffic_statistics.get_ip_details(ip)
    if not details:
        raise HTTPException(status_code=404, detail="IP not found in traffic statistics")
    return details


@router.get("/traffic/time-series")
def get_traffic_time_series(minutes: int = Query(60, ge=1, le=1440)):
    return traffic_statistics.get_time_series(minutes)


@router.get("/traffic/alerts")
def get_traffic_alerts():
    return traffic_statistics.check_alerts()


@router.get("/test/suricata-log")
def test_suricata_log():
    test_eve_entry = {
        "timestamp": 1620000000.0,
        "event_type": "flow",
        "src_ip": "192.168.1.100",
        "src_port": 12345,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "bytes_toserver": 100,
        "bytes_toclient": 200,
        "pkts_toserver": 1,
        "pkts_toclient": 1
    }
    
    parsed = network_collector._parse_eve_log(test_eve_entry)
    if parsed:
        process_network_data(parsed)
    
    return {
        "test_entry": test_eve_entry,
        "parsed": parsed,
        "current_stats": traffic_statistics.get_overview()
    }


@router.get("/test/firewall-log")
def test_firewall_log():
    test_fortinet_log = 'date=2024-01-01 time=12:00:00 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcip=10.0.0.1 srcport=12345 srcintf="port1" dstip=172.16.0.1 dstport=80 dstintf="port2" sessionid=1234567890 proto=6 action=accept policyid=1 policytype="policy" service="HTTP" dstcountry="Reserved" srccountry="Reserved" trandisp=noop duration=10 sentbyte=1024 rcvdbyte=2048 sentpkt=10 rcvdpkt=20 appcat="unscanned" app="Web.Browsing" apprisk=medium'
    
    config = {
        'path': '/dev/null',
        'type': 'firewall',
        'format': 'fortinet',
        'device_name': 'test-firewall'
    }
    
    parsed = extended_log_collector._parse_firewall_log(test_fortinet_log, config)
    
    return {
        "test_log": test_fortinet_log,
        "parsed": parsed
    }


@router.get("/test/system-log")
def test_system_log():
    test_syslog = 'Jan  1 12:00:00 server01 sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 54321 ssh2'
    
    config = {
        'path': '/dev/null',
        'type': 'system',
        'os_type': 'linux',
        'device_name': 'test-server'
    }
    
    parsed = extended_log_collector._parse_system_log(test_syslog, config)
    
    return {
        "test_log": test_syslog,
        "parsed": parsed
    }
