from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()

# For demonstration purposes, using a simple in-memory store
# In production, use PostgreSQL
configurations = [
    {
        "id": 1,
        "key": "detection_interval",
        "value": "60",
        "description": "Interval in seconds for threat detection",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 2,
        "key": "max_alerts_per_minute",
        "value": "100",
        "description": "Maximum number of alerts per minute",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    },
    {
        "id": 3,
        "key": "log_retention_days",
        "value": "30",
        "description": "Number of days to retain logs",
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
]

class ConfigurationBase(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

class Configuration(ConfigurationBase):
    id: int
    created_at: datetime
    updated_at: datetime

@router.get("/", response_model=List[Configuration])
def get_configurations():
    return configurations

@router.get("/{config_id}", response_model=Configuration)
def get_configuration(config_id: int):
    for config in configurations:
        if config["id"] == config_id:
            return config
    raise HTTPException(status_code=404, detail="Configuration not found")

@router.post("/", response_model=Configuration)
def create_configuration(config: ConfigurationBase):
    # Check if key already exists
    for existing_config in configurations:
        if existing_config["key"] == config.key:
            raise HTTPException(status_code=400, detail="Configuration key already exists")
    
    new_config = {
        "id": len(configurations) + 1,
        "key": config.key,
        "value": config.value,
        "description": config.description,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }
    configurations.append(new_config)
    return new_config

@router.put("/{config_id}", response_model=Configuration)
def update_configuration(config_id: int, config: ConfigurationBase):
    for i, existing_config in enumerate(configurations):
        if existing_config["id"] == config_id:
            configurations[i] = {
                "id": config_id,
                "key": config.key,
                "value": config.value,
                "description": config.description,
                "created_at": existing_config["created_at"],
                "updated_at": datetime.now()
            }
            return configurations[i]
    raise HTTPException(status_code=404, detail="Configuration not found")

@router.delete("/{config_id}")
def delete_configuration(config_id: int):
    for i, config in enumerate(configurations):
        if config["id"] == config_id:
            configurations.pop(i)
            return {"message": "Configuration deleted successfully"}
    raise HTTPException(status_code=404, detail="Configuration not found")
