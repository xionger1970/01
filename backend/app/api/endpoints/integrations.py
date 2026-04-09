from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict

router = APIRouter()

from app.integrations.security_tools import SecurityToolIntegrator

# Create a singleton instance of the integrator
integrator = SecurityToolIntegrator()

class WAFConfig(BaseModel):
    url: str
    api_key: str
    enabled: bool = True

class IDSConfig(BaseModel):
    url: str
    api_key: str
    enabled: bool = True

class IPSConfig(BaseModel):
    url: str
    api_key: str
    enabled: bool = True

class SIEMConfig(BaseModel):
    url: str
    api_key: str
    enabled: bool = True

class BlockIPRequest(BaseModel):
    ip: str
    reason: str

class SendToSIEMRequest(BaseModel):
    event: Dict

@router.post("/waf/configure")
def configure_waf(config: WAFConfig):
    integrator.configure_waf(config.dict())
    return {"message": "WAF integration configured successfully"}

@router.post("/ids/configure")
def configure_ids(config: IDSConfig):
    integrator.configure_ids(config.dict())
    return {"message": "IDS integration configured successfully"}

@router.post("/ips/configure")
def configure_ips(config: IPSConfig):
    integrator.configure_ips(config.dict())
    return {"message": "IPS integration configured successfully"}

@router.post("/siem/configure")
def configure_siem(config: SIEMConfig):
    integrator.configure_siem(config.dict())
    return {"message": "SIEM integration configured successfully"}

@router.get("/waf/logs")
def get_waf_logs():
    logs = integrator.get_waf_logs()
    return logs

@router.get("/ids/alerts")
def get_ids_alerts():
    alerts = integrator.get_ids_alerts()
    return alerts

@router.post("/ips/block")
def block_ip(request: BlockIPRequest):
    success = integrator.block_ip(request.ip, request.reason)
    if success:
        return {"message": f"IP {request.ip} blocked successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to block IP")

@router.post("/siem/send")
def send_to_siem(request: SendToSIEMRequest):
    success = integrator.send_to_siem(request.event)
    if success:
        return {"message": "Event sent to SIEM successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to send event to SIEM")

@router.get("/status")
def get_integration_status():
    status = integrator.get_integration_status()
    return status
