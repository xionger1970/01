from datetime import datetime
from typing import Dict, List, Optional
from app.response import response_manager

class AlertManager:
    def __init__(self):
        self.alert_rules = []
        self.notification_channels = []
        self.alert_history = []
    
    def add_alert_rule(self, rule: Dict) -> Dict:
        """Add a new alert rule"""
        rule['id'] = len(self.alert_rules) + 1
        rule['created_at'] = datetime.now().isoformat()
        rule['updated_at'] = datetime.now().isoformat()
        self.alert_rules.append(rule)
        return rule
    
    def get_alert_rules(self) -> List[Dict]:
        """Get all alert rules"""
        return self.alert_rules
    
    def get_alert_rule(self, rule_id: int) -> Optional[Dict]:
        """Get a specific alert rule"""
        for rule in self.alert_rules:
            if rule['id'] == rule_id:
                return rule
        return None
    
    def update_alert_rule(self, rule_id: int, updates: Dict) -> Optional[Dict]:
        """Update an alert rule"""
        for i, rule in enumerate(self.alert_rules):
            if rule['id'] == rule_id:
                self.alert_rules[i] = {
                    **rule,
                    **updates,
                    'updated_at': datetime.now().isoformat()
                }
                return self.alert_rules[i]
        return None
    
    def delete_alert_rule(self, rule_id: int) -> bool:
        """Delete an alert rule"""
        for i, rule in enumerate(self.alert_rules):
            if rule['id'] == rule_id:
                self.alert_rules.pop(i)
                return True
        return False
    
    def add_notification_channel(self, channel: Dict) -> Dict:
        """Add a new notification channel"""
        channel['id'] = len(self.notification_channels) + 1
        channel['created_at'] = datetime.now().isoformat()
        channel['updated_at'] = datetime.now().isoformat()
        self.notification_channels.append(channel)
        return channel
    
    def get_notification_channels(self) -> List[Dict]:
        """Get all notification channels"""
        return self.notification_channels
    
    def process_attack(self, attack: Dict):
        """Process an attack and generate alerts if needed"""
        for rule in self.alert_rules:
            if rule['enabled'] and self._matches_rule(attack, rule):
                self._generate_alert(attack, rule)
        
        # Handle the attack with response manager
        response_result = response_manager.handle_attack(attack)
        if response_result:
            print(f"Response action taken: {response_result}")
    
    def _matches_rule(self, attack: Dict, rule: Dict) -> bool:
        """Check if an attack matches a rule"""
        condition = rule['condition']
        
        # Simple condition matching
        for key, value in condition.items():
            if key in attack and attack[key] != value:
                return False
        
        return True
    
    def _generate_alert(self, attack: Dict, rule: Dict):
        """Generate an alert for a matched rule"""
        alert = {
            'id': len(self.alert_history) + 1,
            'rule_id': rule['id'],
            'severity': rule['severity'],
            'message': f"{rule['name']} detected: {attack.get('attack_type')} from {attack.get('source_ip')}",
            'details': attack,
            'status': 'new',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        self.alert_history.append(alert)
        self._send_notifications(alert)
    
    def _send_notifications(self, alert: Dict):
        """Send notifications for an alert"""
        # Get enabled notification channels
        enabled_channels = [c for c in self.notification_channels if c['enabled']]
        
        for channel in enabled_channels:
            self._send_notification(alert, channel)
    
    def _send_notification(self, alert: Dict, channel: Dict):
        """Send a notification through a specific channel"""
        channel_type = channel['type']
        config = channel['config']
        
        if channel_type == 'email':
            self._send_email_notification(alert, config)
        elif channel_type == 'webhook':
            self._send_webhook_notification(alert, config)
        elif channel_type == 'sms':
            self._send_sms_notification(alert, config)
    
    def _send_email_notification(self, alert: Dict, config: Dict):
        """Send email notification"""
        # In production, use a real email service
        print(f"Sending email notification to {config.get('to')}: {alert['message']}")
    
    def _send_webhook_notification(self, alert: Dict, config: Dict):
        """Send webhook notification"""
        # In production, use requests to send webhook
        print(f"Sending webhook notification to {config.get('url')}: {alert['message']}")
    
    def _send_sms_notification(self, alert: Dict, config: Dict):
        """Send SMS notification"""
        # In production, use a real SMS service
        print(f"Sending SMS notification to {config.get('phone')}: {alert['message']}")
    
    def get_alert_history(self) -> List[Dict]:
        """Get alert history"""
        return self.alert_history
    
    def update_alert_status(self, alert_id: int, status: str) -> Optional[Dict]:
        """Update alert status"""
        for i, alert in enumerate(self.alert_history):
            if alert['id'] == alert_id:
                self.alert_history[i]['status'] = status
                self.alert_history[i]['updated_at'] = datetime.now().isoformat()
                return self.alert_history[i]
        return None
