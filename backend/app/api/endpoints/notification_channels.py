from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter()

# For demonstration purposes, using a simple in-memory store
# In production, use PostgreSQL
notification_channels = [
    {
        "id": 1,
        "name": "Email Notifications",
        "type": "email",
        "config": {"to": "admin@example.com", "from": "alerts@example.com"},
        "enabled": True,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    },
    {
        "id": 2,
        "name": "Webhook Notifications",
        "type": "webhook",
        "config": {"url": "https://example.com/webhook", "secret": "secret_key"},
        "enabled": False,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
]

class NotificationChannelBase(BaseModel):
    name: str
    type: str
    config: dict
    enabled: bool = True

class NotificationChannel(NotificationChannelBase):
    id: int
    created_at: str
    updated_at: str

@router.get("/", response_model=List[NotificationChannel])
def get_notification_channels():
    return notification_channels

@router.post("/", response_model=NotificationChannel)
def create_notification_channel(channel: NotificationChannelBase):
    new_channel = {
        "id": len(notification_channels) + 1,
        "name": channel.name,
        "type": channel.type,
        "config": channel.config,
        "enabled": channel.enabled,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    notification_channels.append(new_channel)
    return new_channel

@router.get("/{channel_id}", response_model=NotificationChannel)
def get_notification_channel(channel_id: int):
    for channel in notification_channels:
        if channel["id"] == channel_id:
            return channel
    raise HTTPException(status_code=404, detail="Notification channel not found")

@router.put("/{channel_id}", response_model=NotificationChannel)
def update_notification_channel(channel_id: int, channel: NotificationChannelBase):
    for i, existing_channel in enumerate(notification_channels):
        if existing_channel["id"] == channel_id:
            notification_channels[i] = {
                "id": channel_id,
                "name": channel.name,
                "type": channel.type,
                "config": channel.config,
                "enabled": channel.enabled,
                "created_at": existing_channel["created_at"],
                "updated_at": datetime.now().isoformat()
            }
            return notification_channels[i]
    raise HTTPException(status_code=404, detail="Notification channel not found")

@router.delete("/{channel_id}")
def delete_notification_channel(channel_id: int):
    for i, channel in enumerate(notification_channels):
        if channel["id"] == channel_id:
            notification_channels.pop(i)
            return {"message": "Notification channel deleted successfully"}
    raise HTTPException(status_code=404, detail="Notification channel not found")
