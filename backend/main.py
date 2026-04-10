from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import random

app = FastAPI()

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # 前端地址
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 模拟攻击事件数据
attack_types = ["SQL Injection", "XSS", "DDoS", "Brute Force", "CSRF"]
source_ips = [f"192.168.1.{i}" for i in range(1, 255)]
target_ips = [f"10.0.0.{i}" for i in range(1, 10)]
target_ports = [80, 443, 8080, 3306, 22]
severities = ["low", "medium", "high", "critical"]

# 生成模拟攻击事件
def generate_mock_attacks(count=100):
    attacks = []
    for i in range(count):
        attack = {
            "id": i + 1,
            "timestamp": datetime.now().isoformat(),
            "attack_type": random.choice(attack_types),
            "source_ip": random.choice(source_ips),
            "target_ip": random.choice(target_ips),
            "target_port": random.choice(target_ports),
            "user_agent": f"Mozilla/5.0 (Agent-{i})",
            "status": random.choice(["detected", "blocked", "investigating"]),
            "request_method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "request_path": f"/api/v1/resource/{i}",
            "request_params": {"param": f"value{i}"},
            "response_code": random.choice([200, 403, 404, 500]),
            "severity": random.choice(severities),
            "details": {"description": f"Attack details for event {i}", "payload": f"payload_{i}"}
        }
        attacks.append(attack)
    return attacks

# 根路径
@app.get("/")
def read_root():
    return {"message": "Network Attack Situational Awareness System API"}

# 攻击事件接口
@app.get("/api/attack-events")
def get_attack_events(limit: int = 100):
    return generate_mock_attacks(limit)

# 仪表盘概览接口
@app.get("/api/dashboard/overview")
def get_dashboard_overview():
    return {
        "total_attacks": 1234,
        "active_attacks": 45,
        "top_source_ips": [
            {"ip": "192.168.1.1", "count": 120},
            {"ip": "192.168.1.2", "count": 95},
            {"ip": "192.168.1.3", "count": 80}
        ],
        "severity_distribution": {
            "critical": 15,
            "high": 45,
            "medium": 120,
            "low": 200
        }
    }

# 威胁情报统计接口
@app.get("/api/threat-intel/stats")
def get_threat_intel_stats():
    return {
        "malicious_ips_count": 1500,
        "malicious_domains_count": 800,
        "malicious_urls_count": 2000,
        "malicious_hashes_count": 500,
        "apt_groups_count": 30,
        "threat_campaigns_count": 50,
        "vulnerabilities_count": 120
    }

# 告警统计接口
@app.get("/api/alerts/stats")
def get_alerts_stats():
    return {
        "total_alerts": 500,
        "active_alerts": 25,
        "by_severity": {
            "critical": 5,
            "high": 10,
            "medium": 30,
            "low": 55
        }
    }

# 异常检测接口
@app.get("/api/anomalies/detect")
def detect_anomalies():
    return {
        "anomalies": [
            {
                "id": 1,
                "type": "Unusual traffic pattern",
                "severity": "high",
                "description": "Unusual traffic from 192.168.1.100",
                "timestamp": datetime.now().isoformat()
            },
            {
                "id": 2,
                "type": "Suspicious login attempt",
                "severity": "medium",
                "description": "Multiple failed login attempts from 192.168.1.200",
                "timestamp": datetime.now().isoformat()
            }
        ]
    }

# 系统状态接口
@app.get("/api/dashboard/system-status")
def get_system_status():
    return {
        "status": "healthy",
        "uptime": 3600,
        "memory_usage": 45.5,
        "cpu_usage": 25.2,
        "disk_usage": 60.1
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
