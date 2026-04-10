from fastapi import APIRouter
from typing import Dict, List
from datetime import datetime, timedelta
from app.core.cache import cache_manager

router = APIRouter()

@router.get("/overview")
def get_dashboard_overview():
    # 尝试从缓存获取数据
    cache_key = "dashboard:overview"
    cached_data = cache_manager.get(cache_key)
    if cached_data:
        return cached_data
    
    # Mock data for demonstration
    overview = {
        "total_attacks": 156,
        "active_attacks": 5,
        "top_attack_types": [
            {"type": "sql_injection", "count": 45},
            {"type": "xss", "count": 32},
            {"type": "brute_force", "count": 28},
            {"type": "csrf", "count": 15},
            {"type": "command_injection", "count": 10}
        ],
        "top_source_ips": [
            {"ip": "192.168.1.100", "count": 25},
            {"ip": "192.168.1.101", "count": 18},
            {"ip": "10.0.0.5", "count": 12},
            {"ip": "172.16.0.2", "count": 8},
            {"ip": "192.168.2.1", "count": 5}
        ],
        "severity_distribution": {
            "critical": 12,
            "high": 45,
            "medium": 68,
            "low": 31
        },
        "attack_trend": [
            {"timestamp": (datetime.now() - timedelta(days=6)).isoformat(), "count": 12},
            {"timestamp": (datetime.now() - timedelta(days=5)).isoformat(), "count": 18},
            {"timestamp": (datetime.now() - timedelta(days=4)).isoformat(), "count": 25},
            {"timestamp": (datetime.now() - timedelta(days=3)).isoformat(), "count": 22},
            {"timestamp": (datetime.now() - timedelta(days=2)).isoformat(), "count": 30},
            {"timestamp": (datetime.now() - timedelta(days=1)).isoformat(), "count": 28},
            {"timestamp": datetime.now().isoformat(), "count": 21}
        ],
        "attack_type_distribution": {
            "sql_injection": 45,
            "xss": 32,
            "brute_force": 28,
            "csrf": 15,
            "command_injection": 10,
            "dos": 12,
            "other": 14
        }
    }
    
    # 缓存数据，设置过期时间为5分钟
    cache_manager.set(cache_key, overview, expire=300)
    return overview

@router.get("/top-targets")
def get_top_targets():
    # 尝试从缓存获取数据
    cache_key = "dashboard:top-targets"
    cached_data = cache_manager.get(cache_key)
    if cached_data:
        return cached_data
    
    # Mock data for demonstration
    top_targets = [
        {"target": "/login", "count": 45, "attack_types": ["brute_force", "sql_injection"]},
        {"target": "/admin", "count": 32, "attack_types": ["sql_injection", "xss"]},
        {"target": "/search", "count": 28, "attack_types": ["xss", "csrf"]},
        {"target": "/api", "count": 25, "attack_types": ["command_injection", "sql_injection"]},
        {"target": "/profile", "count": 20, "attack_types": ["xss", "csrf"]}
    ]
    
    # 缓存数据，设置过期时间为5分钟
    cache_manager.set(cache_key, top_targets, expire=300)
    return top_targets

@router.get("/system-status")
def get_system_status():
    # 尝试从缓存获取数据
    cache_key = "dashboard:system-status"
    cached_data = cache_manager.get(cache_key)
    if cached_data:
        return cached_data
    
    # Mock data for demonstration
    system_status = {
        "services": [
            {"name": "API Server", "status": "healthy", "uptime": "24h 15m"},
            {"name": "Data Collector", "status": "healthy", "uptime": "24h 10m"},
            {"name": "Detection Engine", "status": "healthy", "uptime": "24h 5m"},
            {"name": "Alert Manager", "status": "healthy", "uptime": "24h 0m"}
        ],
        "resources": {
            "cpu_usage": "45%",
            "memory_usage": "60%",
            "disk_usage": "35%",
            "network_in": "1.2 MB/s",
            "network_out": "800 KB/s"
        }
    }
    
    # 缓存数据，设置过期时间为1分钟（系统状态变化较快）
    cache_manager.set(cache_key, system_status, expire=60)
    return system_status
