import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading
import requests
from collections import defaultdict, deque
from app.threat_intel.intel_manager import threat_intel_manager
from app.detectors.advanced_detector import advanced_detector
from app.detectors.anomaly_detector import anomaly_detector

class AlertManager:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 告警规则
        self.alert_rules = []
        
        # 告警历史
        self.alert_history = []
        
        # 告警状态
        self.alert_statuses = {
            'new': '新告警',
            'acknowledged': '已确认',
            'in_progress': '处理中',
            'resolved': '已解决',
            'false_positive': '误报',
            'dismissed': '已忽略'
        }
        
        # 告警优先级
        self.alert_priorities = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        
        # 通知渠道
        self.notification_channels = {
            'email': False,
            'sms': False,
            'webhook': False,
            'syslog': False,
            'slack': False,
            'telegram': False,
            'dingtalk': False
        }
        
        # 通知渠道配置
        self.notification_configs = {
            'email': {
                'smtp_server': 'smtp.example.com',
                'smtp_port': 587,
                'username': 'alerts@example.com',
                'password': 'password',
                'from_email': 'alerts@example.com',
                'to_emails': ['admin@example.com']
            },
            'webhook': {
                'url': 'https://example.com/webhook',
                'secret': 'secret_key'
            },
            'slack': {
                'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
                'channel': '#security-alerts'
            },
            'telegram': {
                'bot_token': 'YOUR_TELEGRAM_BOT_TOKEN',
                'chat_id': 'YOUR_CHAT_ID'
            },
            'dingtalk': {
                'webhook_url': 'https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN',
                'secret': 'YOUR_SECRET'
            }
        }
        
        # 告警分组
        self.alert_groups = defaultdict(list)
        
        # 告警统计
        self.alert_stats = {
            'total': 0,
            'by_status': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'by_source': defaultdict(int)
        }
        
        # 初始化默认规则
        self._init_default_rules()
        
        # 启动告警处理线程
        self._start_alert_processing_thread()
    
    def _init_default_rules(self):
        """初始化默认告警规则"""
        default_rules = [
            {
                "id": 1,
                "name": "SQL注入攻击",
                "description": "检测SQL注入尝试",
                "severity": "high",
                "condition": {"attack_type": "sql_injection"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            },
            {
                "id": 2,
                "name": "XSS攻击",
                "description": "检测跨站脚本攻击",
                "severity": "medium",
                "condition": {"attack_type": "xss"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            },
            {
                "id": 3,
                "name": "命令注入攻击",
                "description": "检测命令注入尝试",
                "severity": "critical",
                "condition": {"attack_type": "command_injection"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            },
            {
                "id": 4,
                "name": "恶意IP检测",
                "description": "检测来自恶意IP的访问",
                "severity": "high",
                "condition": {"threat_intel": "malicious_ip"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            },
            {
                "id": 5,
                "name": "异常流量检测",
                "description": "检测异常流量行为",
                "severity": "medium",
                "condition": {"anomaly_type": "traffic_anomaly"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            },
            {
                "id": 6,
                "name": "登录失败异常",
                "description": "检测登录失败次数异常",
                "severity": "high",
                "condition": {"anomaly_type": "login_attempts"},
                "enabled": True,
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
        ]
        
        self.alert_rules.extend(default_rules)
    
    def _start_alert_processing_thread(self):
        """启动告警处理线程"""
        def process_alerts():
            while True:
                time.sleep(10)  # 每10秒处理一次
                self._process_pending_alerts()
        
        processing_thread = threading.Thread(target=process_alerts, daemon=True)
        processing_thread.start()
    
    def _process_pending_alerts(self):
        """处理待处理的告警"""
        with self.lock:
            # 处理新告警
            for alert in self.alert_history:
                if alert['status'] == 'new':
                    # 尝试自动处理
                    self._auto_process_alert(alert)
    
    def _auto_process_alert(self, alert):
        """自动处理告警"""
        # 这里可以添加自动处理逻辑
        # 例如：基于规则的自动响应
        pass
    
    def create_alert(self, rule_id: int, severity: str, message: str, details: Optional[Dict] = None):
        """创建告警"""
        with self.lock:
            alert_id = len(self.alert_history) + 1
            new_alert = {
                "id": alert_id,
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "details": details or {},
                "status": "new",
                "priority": self.alert_priorities.get(severity, 3),
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "group_id": None,
                "assigned_to": None,
                "resolution": None
            }
            
            # 告警分组
            group_key = self._generate_group_key(new_alert)
            if group_key:
                new_alert['group_id'] = group_key
                self.alert_groups[group_key].append(alert_id)
            
            self.alert_history.append(new_alert)
            
            # 更新统计信息
            self._update_alert_stats(new_alert, 'add')
            
            # 发送通知
            self._send_notification(new_alert)
            
            return new_alert
    
    def _generate_group_key(self, alert: Dict) -> Optional[str]:
        """生成告警分组键"""
        # 基于来源IP和攻击类型分组
        source_ip = alert['details'].get('source_ip')
        attack_type = alert['details'].get('attack_type')
        
        if source_ip and attack_type:
            return f"{source_ip}:{attack_type}"
        return None
    
    def _update_alert_stats(self, alert: Dict, action: str):
        """更新告警统计信息"""
        if action == 'add':
            self.alert_stats['total'] += 1
            self.alert_stats['by_status'][alert['status']] += 1
            self.alert_stats['by_severity'][alert['severity']] += 1
            
            attack_type = alert['details'].get('attack_type', 'unknown')
            self.alert_stats['by_type'][attack_type] += 1
            
            source_ip = alert['details'].get('source_ip', 'unknown')
            self.alert_stats['by_source'][source_ip] += 1
        elif action == 'update':
            # 更新状态统计
            old_status = alert.get('old_status')
            if old_status:
                self.alert_stats['by_status'][old_status] -= 1
            self.alert_stats['by_status'][alert['status']] += 1
    
    def _send_notification(self, alert: Dict):
        """发送告警通知"""
        # 构建通知消息
        message = self._build_notification_message(alert)
        
        # 发送到各个启用的渠道
        if self.notification_channels.get('email'):
            self._send_email_notification(alert, message)
        
        if self.notification_channels.get('webhook'):
            self._send_webhook_notification(alert, message)
        
        if self.notification_channels.get('slack'):
            self._send_slack_notification(alert, message)
        
        if self.notification_channels.get('telegram'):
            self._send_telegram_notification(alert, message)
        
        if self.notification_channels.get('dingtalk'):
            self._send_dingtalk_notification(alert, message)
        
        print(f"Notification: {alert['severity']} - {alert['message']}")
    
    def _build_notification_message(self, alert: Dict) -> str:
        """构建通知消息"""
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '🔔',
            'low': 'ℹ️',
            'info': '💡'
        }
        
        emoji = severity_emoji.get(alert['severity'], 'ℹ️')
        
        message = f"{emoji} *{alert['severity'].upper()} Alert*: {alert['message']}\n"
        message += f"ID: {alert['id']}\n"
        message += f"Created: {alert['created_at'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if alert['details']:
            message += "Details:\n"
            for key, value in alert['details'].items():
                message += f"  - {key}: {value}\n"
        
        return message
    
    def _send_email_notification(self, alert: Dict, message: str):
        """发送邮件通知"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            config = self.notification_configs['email']
            
            msg = MIMEMultipart()
            msg['From'] = config['from_email']
            msg['To'] = ', '.join(config['to_emails'])
            msg['Subject'] = f"[{alert['severity'].upper()}] Security Alert: {alert['message']}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                server.starttls()
                server.login(config['username'], config['password'])
                server.send_message(msg)
            
            print("Email notification sent")
        except Exception as e:
            print(f"Failed to send email notification: {e}")
    
    def _send_webhook_notification(self, alert: Dict, message: str):
        """发送Webhook通知"""
        try:
            config = self.notification_configs['webhook']
            
            payload = {
                'alert': alert,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
            
            headers = {
                'Content-Type': 'application/json',
                'X-Webhook-Secret': config['secret']
            }
            
            response = requests.post(config['url'], json=payload, headers=headers)
            response.raise_for_status()
            
            print("Webhook notification sent")
        except Exception as e:
            print(f"Failed to send webhook notification: {e}")
    
    def _send_slack_notification(self, alert: Dict, message: str):
        """发送Slack通知"""
        try:
            config = self.notification_configs['slack']
            
            payload = {
                'channel': config['channel'],
                'text': message,
                'username': 'Security Alert Bot',
                'icon_emoji': ':warning:'
            }
            
            response = requests.post(config['webhook_url'], json=payload)
            response.raise_for_status()
            
            print("Slack notification sent")
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
    
    def _send_telegram_notification(self, alert: Dict, message: str):
        """发送Telegram通知"""
        try:
            config = self.notification_configs['telegram']
            
            url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
            payload = {
                'chat_id': config['chat_id'],
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=payload)
            response.raise_for_status()
            
            print("Telegram notification sent")
        except Exception as e:
            print(f"Failed to send Telegram notification: {e}")
    
    def _send_dingtalk_notification(self, alert: Dict, message: str):
        """发送DingTalk通知"""
        try:
            config = self.notification_configs['dingtalk']
            
            payload = {
                'msgtype': 'text',
                'text': {
                    'content': message
                }
            }
            
            response = requests.post(config['webhook_url'], json=payload)
            response.raise_for_status()
            
            print("DingTalk notification sent")
        except Exception as e:
            print(f"Failed to send DingTalk notification: {e}")
    
    def get_alert_rules(self) -> List[Dict]:
        """获取告警规则"""
        with self.lock:
            return self.alert_rules.copy()
    
    def create_alert_rule(self, rule_data: Dict) -> Dict:
        """创建告警规则"""
        with self.lock:
            new_rule = {
                "id": len(self.alert_rules) + 1,
                "name": rule_data['name'],
                "description": rule_data.get('description'),
                "severity": rule_data['severity'],
                "condition": rule_data['condition'],
                "enabled": rule_data.get('enabled', True),
                "created_at": datetime.now(),
                "updated_at": datetime.now()
            }
            self.alert_rules.append(new_rule)
            return new_rule
    
    def update_alert_rule(self, rule_id: int, updates: Dict) -> Optional[Dict]:
        """更新告警规则"""
        with self.lock:
            for rule in self.alert_rules:
                if rule['id'] == rule_id:
                    rule.update(updates)
                    rule['updated_at'] = datetime.now()
                    return rule
        return None
    
    def delete_alert_rule(self, rule_id: int) -> bool:
        """删除告警规则"""
        with self.lock:
            for i, rule in enumerate(self.alert_rules):
                if rule['id'] == rule_id:
                    self.alert_rules.pop(i)
                    return True
        return False
    
    def get_alert_history(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取告警历史"""
        with self.lock:
            alerts = self.alert_history.copy()
            
            if filters:
                filtered_alerts = []
                for alert in alerts:
                    match = True
                    for key, value in filters.items():
                        if key == 'severity' and alert.get('severity') != value:
                            match = False
                        elif key == 'status' and alert.get('status') != value:
                            match = False
                        elif key == 'source_ip' and alert.get('details', {}).get('source_ip') != value:
                            match = False
                    if match:
                        filtered_alerts.append(alert)
                return filtered_alerts
            
            return alerts
    
    def update_alert_status(self, alert_id: int, status: str, resolution: Optional[str] = None) -> Optional[Dict]:
        """更新告警状态"""
        with self.lock:
            for alert in self.alert_history:
                if alert['id'] == alert_id:
                    old_status = alert['status']
                    alert['status'] = status
                    alert['updated_at'] = datetime.now()
                    if resolution:
                        alert['resolution'] = resolution
                    
                    # 更新统计信息
                    alert['old_status'] = old_status
                    self._update_alert_stats(alert, 'update')
                    del alert['old_status']
                    
                    return alert
        return None
    
    def assign_alert(self, alert_id: int, user: str) -> Optional[Dict]:
        """分配告警"""
        with self.lock:
            for alert in self.alert_history:
                if alert['id'] == alert_id:
                    alert['assigned_to'] = user
                    alert['updated_at'] = datetime.now()
                    return alert
        return None
    
    def delete_alert(self, alert_id: int) -> bool:
        """删除告警"""
        with self.lock:
            for i, alert in enumerate(self.alert_history):
                if alert['id'] == alert_id:
                    self.alert_history.pop(i)
                    return True
        return False
    
    def get_alert_groups(self) -> Dict:
        """获取告警分组"""
        with self.lock:
            groups = {}
            for group_key, alert_ids in self.alert_groups.items():
                group_alerts = [alert for alert in self.alert_history if alert['id'] in alert_ids]
                if group_alerts:
                    groups[group_key] = {
                        'count': len(alert_ids),
                        'alerts': group_alerts,
                        'highest_severity': max([alert['severity'] for alert in group_alerts], key=lambda x: self.alert_priorities.get(x, 0)),
                        'first_seen': min([alert['created_at'] for alert in group_alerts]),
                        'last_seen': max([alert['created_at'] for alert in group_alerts])
                    }
            return groups
    
    def get_alert_stats(self) -> Dict:
        """获取告警统计信息"""
        with self.lock:
            return self.alert_stats.copy()
    
    def get_notification_channels(self) -> Dict:
        """获取通知渠道配置"""
        with self.lock:
            return self.notification_channels.copy()
    
    def update_notification_channels(self, channels: Dict):
        """更新通知渠道配置"""
        with self.lock:
            self.notification_channels.update(channels)
    
    def analyze_alert_trends(self, hours: int = 24) -> Dict:
        """分析告警趋势"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_alerts = [alert for alert in self.alert_history if alert['created_at'] >= cutoff_time]
            
            trends = {
                'total': len(recent_alerts),
                'by_hour': defaultdict(int),
                'by_severity': defaultdict(int),
                'by_type': defaultdict(int),
                'top_sources': defaultdict(int)
            }
            
            for alert in recent_alerts:
                hour_key = alert['created_at'].strftime('%Y-%m-%d %H:00')
                trends['by_hour'][hour_key] += 1
                trends['by_severity'][alert['severity']] += 1
                
                attack_type = alert['details'].get('attack_type', 'unknown')
                trends['by_type'][attack_type] += 1
                
                source_ip = alert['details'].get('source_ip', 'unknown')
                trends['top_sources'][source_ip] += 1
            
            # 排序顶部来源
            trends['top_sources'] = dict(sorted(trends['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            return trends

# 创建单例实例
alert_manager = AlertManager()
