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
        
        # 自动化响应剧本
        self.playbooks = []
        
        # 剧本执行历史
        self.playbook_execution_history = []
        
        # 剧本模板
        self.playbook_templates = self._load_playbook_templates()
        
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
            'update_rule': '更新规则',
            'notify': '发送通知',
            'isolate_network': '隔离网络',
            'reset_account': '重置账户',
            'scan_system': '扫描系统'
        }
        
        # 支持的触发条件类型
        self.supported_trigger_types = {
            'alert': '基于告警',
            'event': '基于事件',
            'anomaly': '基于异常',
            'schedule': '基于定时',
            'manual': '手动触发'
        }
        
        # 启动监控线程
        self._start_monitoring_thread()
        self._start_playbook_monitoring_thread()
    
    def _start_monitoring_thread(self):
        """启动监控线程"""
        def monitor_devices():
            while True:
                time.sleep(60)  # 每分钟检查一次设备状态
                self._check_device_status()
        
        monitoring_thread = threading.Thread(target=monitor_devices, daemon=True)
        monitoring_thread.start()
    
    def _start_playbook_monitoring_thread(self):
        """启动剧本监控线程"""
        def monitor_playbooks():
            while True:
                time.sleep(30)  # 每30秒检查一次剧本触发条件
                self._check_playbook_triggers()
        
        monitoring_thread = threading.Thread(target=monitor_playbooks, daemon=True)
        monitoring_thread.start()
    
    def _load_playbook_templates(self) -> List[Dict]:
        """加载剧本模板"""
        return [
            {
                'id': 1,
                'name': 'IP阻断剧本',
                'description': '当检测到恶意IP时，在所有防火墙和WAF上阻断该IP',
                'triggers': [
                    {
                        'type': 'alert',
                        'condition': {'severity': 'high', 'attack_type': 'brute_force'}
                    }
                ],
                'steps': [
                    {
                        'id': 1,
                        'name': '阻断IP',
                        'action': 'block_ip',
                        'target': '{{source_ip}}',
                        'devices': ['firewall', 'waf']
                    },
                    {
                        'id': 2,
                        'name': '发送告警',
                        'action': 'alert',
                        'target': 'Security Team',
                        'message': '恶意IP {{source_ip}}已被阻断'
                    }
                ]
            },
            {
                'id': 2,
                'name': '终端隔离剧本',
                'description': '当检测到终端异常时，隔离该终端并扫描',
                'triggers': [
                    {
                        'type': 'anomaly',
                        'condition': {'type': 'malware_detection'}
                    }
                ],
                'steps': [
                    {
                        'id': 1,
                        'name': '隔离终端',
                        'action': 'quarantine_endpoint',
                        'target': '{{endpoint_id}}'
                    },
                    {
                        'id': 2,
                        'name': '扫描系统',
                        'action': 'scan_system',
                        'target': '{{endpoint_id}}'
                    },
                    {
                        'id': 3,
                        'name': '发送通知',
                        'action': 'notify',
                        'target': 'Endpoint Team',
                        'message': '终端 {{endpoint_id}} 已被隔离并扫描'
                    }
                ]
            },
            {
                'id': 3,
                'name': '数据泄露响应剧本',
                'description': '当检测到数据泄露时，执行一系列响应措施',
                'triggers': [
                    {
                        'type': 'event',
                        'condition': {'event_type': 'data_exfiltration'}
                    }
                ],
                'steps': [
                    {
                        'id': 1,
                        'name': '阻断IP',
                        'action': 'block_ip',
                        'target': '{{source_ip}}'
                    },
                    {
                        'id': 2,
                        'name': '隔离网络',
                        'action': 'isolate_network',
                        'target': '{{network_segment}}'
                    },
                    {
                        'id': 3,
                        'name': '发送告警',
                        'action': 'alert',
                        'target': 'Security Team',
                        'message': '检测到数据泄露，已采取响应措施'
                    },
                    {
                        'id': 4,
                        'name': '记录日志',
                        'action': 'log',
                        'target': 'Data Breach',
                        'details': '{{event_details}}'
                    }
                ]
            }
        ]
    
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
    
    def add_playbook(self, playbook: Dict) -> Dict:
        """添加自动化响应剧本"""
        with self.lock:
            playbook_id = len(self.playbooks) + 1
            playbook_with_id = {
                'id': playbook_id,
                'name': playbook.get('name'),
                'description': playbook.get('description'),
                'triggers': playbook.get('triggers', []),
                'steps': playbook.get('steps', []),
                'enabled': playbook.get('enabled', True),
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            self.playbooks.append(playbook_with_id)
            return playbook_with_id
    
    def update_playbook(self, playbook_id: int, updates: Dict) -> Optional[Dict]:
        """更新自动化响应剧本"""
        with self.lock:
            for playbook in self.playbooks:
                if playbook['id'] == playbook_id:
                    playbook.update(updates)
                    playbook['updated_at'] = datetime.now()
                    return playbook
        return None
    
    def delete_playbook(self, playbook_id: int) -> bool:
        """删除自动化响应剧本"""
        with self.lock:
            for i, playbook in enumerate(self.playbooks):
                if playbook['id'] == playbook_id:
                    self.playbooks.pop(i)
                    return True
        return False
    
    def execute_playbook(self, playbook_id: int, context: Optional[Dict] = None) -> Dict:
        """执行自动化响应剧本"""
        with self.lock:
            playbook = next((p for p in self.playbooks if p['id'] == playbook_id), None)
            if not playbook:
                return {'status': 'error', 'message': 'Playbook not found'}
            
            execution_id = len(self.playbook_execution_history) + 1
            execution = {
                'id': execution_id,
                'playbook_id': playbook_id,
                'playbook_name': playbook['name'],
                'status': 'running',
                'steps': [],
                'context': context or {},
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            # 执行剧本步骤
            try:
                for step in playbook['steps']:
                    step_execution = {
                        'step_id': step['id'],
                        'step_name': step['name'],
                        'action': step['action'],
                        'status': 'running',
                        'result': None
                    }
                    
                    # 替换步骤中的变量
                    target = self._replace_variables(step['target'], context or {})
                    
                    # 执行动作
                    action_result = self.execute_action({
                        'action_type': step['action'],
                        'target': target,
                        'device_id': step.get('device_id')
                    })
                    
                    step_execution['status'] = action_result['status']
                    step_execution['result'] = action_result['result']
                    execution['steps'].append(step_execution)
                
                execution['status'] = 'completed'
            except Exception as e:
                execution['status'] = 'failed'
                execution['error'] = str(e)
            
            execution['updated_at'] = datetime.now()
            self.playbook_execution_history.append(execution)
            
            return execution
    
    def _replace_variables(self, text: str, context: Dict) -> str:
        """替换文本中的变量"""
        result = text
        for key, value in context.items():
            result = result.replace(f'{{{{{key}}}}}', str(value))
        return result
    
    def _check_playbook_triggers(self):
        """检查剧本触发条件"""
        # 这里应该根据实际情况检查触发条件
        # 现在使用模拟数据
        pass
    
    def get_playbooks(self) -> List[Dict]:
        """获取自动化响应剧本列表"""
        with self.lock:
            return self.playbooks.copy()
    
    def get_playbook_execution_history(self) -> List[Dict]:
        """获取剧本执行历史"""
        with self.lock:
            return self.playbook_execution_history.copy()
    
    def get_playbook_templates(self) -> List[Dict]:
        """获取剧本模板"""
        return self.playbook_templates
    
    def get_supported_trigger_types(self) -> Dict:
        """获取支持的触发条件类型"""
        return self.supported_trigger_types
    
    def create_playbook_from_template(self, template_id: int, name: str, description: Optional[str] = None) -> Dict:
        """从模板创建剧本"""
        template = next((t for t in self.playbook_templates if t['id'] == template_id), None)
        if not template:
            raise Exception('Template not found')
        
        playbook = {
            'name': name,
            'description': description or template['description'],
            'triggers': template['triggers'],
            'steps': template['steps'],
            'enabled': True
        }
        
        return self.add_playbook(playbook)

# 创建单例实例
orchestrator = Orchestrator()
