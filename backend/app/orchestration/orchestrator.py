import time
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading
from collections import defaultdict
from app.alerting.alert_manager import alert_manager
from app.threat_intel.intel_manager import threat_intel_manager
from app.detectors.advanced_detector import advanced_detector
from app.detectors.anomaly_detector import anomaly_detector

class Orchestrator:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 集成的安全设备
        self.integrated_devices = []
        
        # 自动化响应规则
        self.response_rules = []
        
        # 响应历史
        self.response_history = []
        
        # 设备状态
        self.device_status = {}
        
        # 支持的设备类型
        self.supported_device_types = {
            'firewall': '防火墙',
            'ids': '入侵检测系统',
            'ips': '入侵防御系统',
            'waf': 'Web应用防火墙',
            'endpoint': '终端防护',
            'siem': '安全信息与事件管理',
            'other': '其他设备'
        }
        
        # 支持的响应动作
        self.supported_actions = {
            'block_ip': '阻断IP',
            'block_url': '阻断URL',
            'block_domain': '阻断域名',
            'quarantine_endpoint': '隔离终端',
            'alert': '发送告警',
            'log': '记录日志',
            'execute_script': '执行脚本',
            'update_rule': '更新规则'
        }
        
        # 启动监控线程
        self._start_monitoring_thread()
    
    def _start_monitoring_thread(self):
        """启动监控线程"""
        def monitor_devices():
            while True:
                time.sleep(60)  # 每分钟检查一次设备状态
                self._check_device_status()
        
        monitoring_thread = threading.Thread(target=monitor_devices, daemon=True)
        monitoring_thread.start()
    
    def add_integrated_device(self, device: Dict) -> Dict:
        """添加集成设备"""
        with self.lock:
            device_id = len(self.integrated_devices) + 1
            device_with_id = {
                'id': device_id,
                'name': device.get('name'),
                'type': device.get('type'),
                'ip_address': device.get('ip_address'),
                'port': device.get('port', 80),
                'api_key': device.get('api_key'),
                'status': 'offline',
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.integrated_devices.append(device_with_id)
            self.device_status[device_id] = 'offline'
            
            # 立即检查设备状态
            self._check_single_device_status(device_with_id)
            
            return device_with_id
    
    def _check_device_status(self):
        """检查所有设备状态"""
        for device in self.integrated_devices:
            self._check_single_device_status(device)
    
    def _check_single_device_status(self, device: Dict):
        """检查单个设备状态"""
        try:
            # 这里应该根据设备类型和API进行实际的状态检查
            # 现在使用模拟检查
            import random
            status = random.choice(['online', 'online', 'online', 'offline'])  # 模拟80%的设备在线
            
            with self.lock:
                self.device_status[device['id']] = status
                for d in self.integrated_devices:
                    if d['id'] == device['id']:
                        d['status'] = status
                        d['updated_at'] = datetime.now()
        except Exception as e:
            print(f"Error checking device status: {e}")
            with self.lock:
                self.device_status[device['id']] = 'error'
                for d in self.integrated_devices:
                    if d['id'] == device['id']:
                        d['status'] = 'error'
                        d['updated_at'] = datetime.now()
    
    def add_response_rule(self, rule: Dict) -> Dict:
        """添加响应规则"""
        with self.lock:
            rule_id = len(self.response_rules) + 1
            rule_with_id = {
                'id': rule_id,
                'name': rule.get('name'),
                'description': rule.get('description'),
                'condition': rule.get('condition'),
                'actions': rule.get('actions', []),
                'enabled': rule.get('enabled', True),
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.response_rules.append(rule_with_id)
            return rule_with_id
    
    def update_response_rule(self, rule_id: int, updates: Dict) -> Optional[Dict]:
        """更新响应规则"""
        with self.lock:
            for rule in self.response_rules:
                if rule['id'] == rule_id:
                    rule.update(updates)
                    rule['updated_at'] = datetime.now()
                    return rule
        return None
    
    def delete_response_rule(self, rule_id: int) -> bool:
        """删除响应规则"""
        with self.lock:
            for i, rule in enumerate(self.response_rules):
                if rule['id'] == rule_id:
                    self.response_rules.pop(i)
                    return True
        return False
    
    def execute_action(self, action: Dict) -> Dict:
        """执行响应动作"""
        with self.lock:
            action_id = len(self.response_history) + 1
            action_with_id = {
                'id': action_id,
                'action_type': action.get('action_type'),
                'target': action.get('target'),
                'device_id': action.get('device_id'),
                'status': 'pending',
                'result': None,
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            # 执行动作
            try:
                result = self._perform_action(action)
                action_with_id['status'] = 'success'
                action_with_id['result'] = result
            except Exception as e:
                action_with_id['status'] = 'failed'
                action_with_id['result'] = str(e)
            
            action_with_id['updated_at'] = datetime.now()
            self.response_history.append(action_with_id)
            
            return action_with_id
    
    def _perform_action(self, action: Dict) -> Dict:
        """执行具体动作"""
        action_type = action.get('action_type')
        target = action.get('target')
        device_id = action.get('device_id')
        
        # 模拟不同动作的执行
        if action_type == 'block_ip':
            return {'message': f'IP {target} blocked successfully'}
        elif action_type == 'block_url':
            return {'message': f'URL {target} blocked successfully'}
        elif action_type == 'block_domain':
            return {'message': f'Domain {target} blocked successfully'}
        elif action_type == 'quarantine_endpoint':
            return {'message': f'Endpoint {target} quarantined successfully'}
        elif action_type == 'alert':
            # 创建告警
            alert_manager.create_alert(
                rule_id=1,
                severity='high',
                message=f'Automated alert: {target}',
                details=action
            )
            return {'message': 'Alert sent successfully'}
        elif action_type == 'log':
            return {'message': f'Log created for {target}'}
        elif action_type == 'execute_script':
            return {'message': f'Script executed for {target}'}
        elif action_type == 'update_rule':
            return {'message': f'Rule updated for {target}'}
        else:
            raise Exception(f'Unknown action type: {action_type}')
    
    def process_alert(self, alert: Dict):
        """处理告警，触发响应规则"""
        # 匹配响应规则
        for rule in self.response_rules:
            if not rule.get('enabled', True):
                continue
            
            # 简单的规则匹配逻辑
            condition = rule.get('condition', {})
            match = True
            
            for key, value in condition.items():
                if key == 'severity' and alert.get('severity') != value:
                    match = False
                elif key == 'attack_type' and alert.get('details', {}).get('attack_type') != value:
                    match = False
                elif key == 'source_ip' and alert.get('details', {}).get('source_ip') != value:
                    match = False
            
            if match:
                # 执行规则中的动作
                for action in rule.get('actions', []):
                    self.execute_action({
                        'action_type': action.get('type'),
                        'target': action.get('target', alert.get('details', {}).get('source_ip')),
                        'device_id': action.get('device_id')
                    })
    
    def get_integrated_devices(self) -> List[Dict]:
        """获取集成设备列表"""
        with self.lock:
            return self.integrated_devices.copy()
    
    def get_response_rules(self) -> List[Dict]:
        """获取响应规则列表"""
        with self.lock:
            return self.response_rules.copy()
    
    def get_response_history(self) -> List[Dict]:
        """获取响应历史"""
        with self.lock:
            return self.response_history.copy()
    
    def get_device_status(self) -> Dict:
        """获取设备状态"""
        with self.lock:
            return self.device_status.copy()
    
    def get_supported_device_types(self) -> Dict:
        """获取支持的设备类型"""
        return self.supported_device_types
    
    def get_supported_actions(self) -> Dict:
        """获取支持的响应动作"""
        return self.supported_actions
    
    def test_device_connection(self, device_id: int) -> Dict:
        """测试设备连接"""
        device = next((d for d in self.integrated_devices if d['id'] == device_id), None)
        if not device:
            return {'status': 'error', 'message': 'Device not found'}
        
        try:
            # 模拟设备连接测试
            import random
            success = random.choice([True, True, True, False])  # 80%成功率
            
            if success:
                return {'status': 'success', 'message': 'Connection successful'}
            else:
                return {'status': 'failed', 'message': 'Connection failed'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

# 创建单例实例
orchestrator = Orchestrator()
