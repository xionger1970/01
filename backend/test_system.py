#!/usr/bin/env python3
"""
Test script for the Web Attack Situational Awareness System
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000/api"

def test_auth():
    """Test authentication endpoints"""
    print("Testing authentication...")
    
    # Test login
    response = requests.post(f"{BASE_URL}/auth/token", data={
        "username": "admin",
        "password": "admin123"
    })
    print(f"Login response: {response.status_code}")
    print(f"Login data: {response.json()}")
    
    # Test get current user
    response = requests.get(f"{BASE_URL}/auth/me")
    print(f"Get current user response: {response.status_code}")
    print(f"Current user data: {response.json()}")

def test_attack_events():
    """Test attack events endpoints"""
    print("\nTesting attack events...")
    
    # Test get attack events
    response = requests.get(f"{BASE_URL}/attack-events")
    print(f"Get attack events response: {response.status_code}")
    print(f"Number of attack events: {len(response.json())}")
    
    # Test get attack stats
    response = requests.get(f"{BASE_URL}/attack-events/stats")
    print(f"Get attack stats response: {response.status_code}")
    print(f"Attack stats: {response.json()}")

def test_alerts():
    """Test alerts endpoints"""
    print("\nTesting alerts...")
    
    # Test get alert rules
    response = requests.get(f"{BASE_URL}/alerts/rules")
    print(f"Get alert rules response: {response.status_code}")
    print(f"Number of alert rules: {len(response.json())}")
    
    # Test get alert history
    response = requests.get(f"{BASE_URL}/alerts/history")
    print(f"Get alert history response: {response.status_code}")
    print(f"Number of alert history: {len(response.json())}")

def test_dashboard():
    """Test dashboard endpoints"""
    print("\nTesting dashboard...")
    
    # Test get dashboard overview
    response = requests.get(f"{BASE_URL}/dashboard/overview")
    print(f"Get dashboard overview response: {response.status_code}")
    print(f"Dashboard overview: {response.json()}")
    
    # Test get top targets
    response = requests.get(f"{BASE_URL}/dashboard/top-targets")
    print(f"Get top targets response: {response.status_code}")
    print(f"Top targets: {response.json()}")
    
    # Test get system status
    response = requests.get(f"{BASE_URL}/dashboard/system-status")
    print(f"Get system status response: {response.status_code}")
    print(f"System status: {response.json()}")

def test_configurations():
    """Test configurations endpoints"""
    print("\nTesting configurations...")
    
    # Test get configurations
    response = requests.get(f"{BASE_URL}/configurations")
    print(f"Get configurations response: {response.status_code}")
    print(f"Number of configurations: {len(response.json())}")

def test_notification_channels():
    """Test notification channels endpoints"""
    print("\nTesting notification channels...")
    
    # Test get notification channels
    response = requests.get(f"{BASE_URL}/notification-channels")
    print(f"Get notification channels response: {response.status_code}")
    print(f"Number of notification channels: {len(response.json())}")

def test_integrations():
    """Test integrations endpoints"""
    print("\nTesting integrations...")
    
    # Test get integration status
    response = requests.get(f"{BASE_URL}/integrations/status")
    print(f"Get integration status response: {response.status_code}")
    print(f"Integration status: {response.json()}")
    
    # Test get WAF logs
    response = requests.get(f"{BASE_URL}/integrations/waf/logs")
    print(f"Get WAF logs response: {response.status_code}")
    print(f"Number of WAF logs: {len(response.json())}")
    
    # Test get IDS alerts
    response = requests.get(f"{BASE_URL}/integrations/ids/alerts")
    print(f"Get IDS alerts response: {response.status_code}")
    print(f"Number of IDS alerts: {len(response.json())}")

def main():
    """Run all tests"""
    print("Starting system tests...")
    
    test_auth()
    test_attack_events()
    test_alerts()
    test_dashboard()
    test_configurations()
    test_notification_channels()
    test_integrations()
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    main()
