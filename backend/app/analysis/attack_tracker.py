import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
import threading
from app.alerting.alert_manager import alert_manager
from app.threat_intel.intel_manager import threat_intel_manager
from app.detectors.advanced_detector import advanced_detector
from app.detectors.anomaly_detector import anomaly_detector

class AttackTracker:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 攻击事件存储
        self.attack_events = []
        
        # 攻击链存储
        self.attack_chains = []
        
        # 事件关联关系
        self.event_relations = defaultdict(list)
        
        # 资产影响记录
        self.asset_impacts = defaultdict(list)
        
        # 攻击路径
        self.attack_paths = []
        
        # 多源事件存储
        self.multi_source_events = {
            'network': [],
            'host': [],
            'application': [],
            'cloud': [],
            'container': []
        }
        
        # 事件关联网络
        self.event_network = {
            'nodes': [],
            'edges': []
        }
        
        # 事件关联规则
        self.correlation_rules = {
            'time_based': {
                'window': 300,  # 5分钟时间窗口
                'description': '时间窗口内的事件关联'
            },
            'ip_based': {
                'description': '基于IP地址的事件关联'
            },
            'asset_based': {
                'description': '基于资产的事件关联'
            },
            'user_based': {
                'description': '基于用户的事件关联'
            },
            'attack_pattern_based': {
                'description': '基于攻击模式的事件关联'
            }
        }
        
        # 攻击模式识别
        self.attack_patterns = {
            'reconnaissance': {
                'name': '侦察阶段',
                'description': '攻击者收集目标信息',
                'events': ['port_scan', 'service_discovery', 'information_gathering']
            },
            'initial_access': {
                'name': '初始访问',
                'description': '攻击者获取初始访问权限',
                'events': ['phishing', 'exploit', 'weak_credential', 'social_engineering']
            },
            'execution': {
                'name': '执行阶段',
                'description': '攻击者在目标系统上执行代码',
                'events': ['command_execution', 'malware_execution', 'script_execution']
            },
            'persistence': {
                'name': '持久化',
                'description': '攻击者确保持续访问',
                'events': ['backdoor', 'scheduled_task', 'registry_modification']
            },
            'privilege_escalation': {
                'name': '权限提升',
                'description': '攻击者获取更高权限',
                'events': ['privilege_escalation', 'sudo_exploitation', 'token_stealing']
            },
            'lateral_movement': {
                'name': '横向移动',
                'description': '攻击者在网络中横向移动',
                'events': ['lateral_movement', 'pass_the_hash', 'remote_access']
            },
            'data_collection': {
                'name': '数据收集',
                'description': '攻击者收集敏感数据',
                'events': ['data_exfiltration', 'screenshot', 'keylogging']
            },
            'exfiltration': {
                'name': '数据泄露',
                'description': '攻击者将数据传输出目标网络',
                'events': ['data_transfer', 'dns_tunneling', 'http_exfiltration']
            }
        }
        
        # 启动分析线程
        self._start_analysis_thread()
        self._start_multi_source_analysis_thread()
    
    def _start_analysis_thread(self):
        """启动分析线程"""
        def analyze_events():
            while True:
                time.sleep(15)  # 每15秒分析一次
                self._analyze_recent_events()
        
        analysis_thread = threading.Thread(target=analyze_events, daemon=True)
        analysis_thread.start()
    
    def _start_multi_source_analysis_thread(self):
        """启动多源事件分析线程"""
        def analyze_multi_source_events():
            while True:
                time.sleep(30)  # 每30秒分析一次
                self._analyze_multi_source_events()
        
        analysis_thread = threading.Thread(target=analyze_multi_source_events, daemon=True)
        analysis_thread.start()
    
    def add_attack_event(self, event: Dict) -> Dict:
        """添加攻击事件"""
        with self.lock:
            event_id = len(self.attack_events) + 1
            event_with_id = {
                'id': event_id,
                'timestamp': event.get('timestamp', datetime.now()),
                'source_ip': event.get('source_ip'),
                'target_ip': event.get('target_ip'),
                'target_port': event.get('target_port'),
                'attack_type': event.get('attack_type'),
                'severity': event.get('severity', 'medium'),
                'details': event.get('details', {}),
                'status': 'analyzed',
                'related_events': [],
                'attack_phase': self._determine_attack_phase(event.get('attack_type')),
                'asset_id': event.get('asset_id')
            }
            
            self.attack_events.append(event_with_id)
            
            # 关联事件
            self._correlate_events(event_with_id)
            
            # 分析资产影响
            if event_with_id.get('asset_id'):
                self.asset_impacts[event_with_id['asset_id']].append(event_id)
            
            return event_with_id
    
    def add_multi_source_event(self, event: Dict, source_type: str) -> Dict:
        """添加多源事件"""
        with self.lock:
            if source_type not in self.multi_source_events:
                self.multi_source_events[source_type] = []
            
            event_id = len(self.multi_source_events[source_type]) + 1
            event_with_id = {
                'id': event_id,
                'source_type': source_type,
                'timestamp': event.get('timestamp', datetime.now()),
                'event_type': event.get('event_type'),
                'source_ip': event.get('source_ip'),
                'target_ip': event.get('target_ip'),
                'asset_id': event.get('asset_id'),
                'user': event.get('user'),
                'severity': event.get('severity', 'medium'),
                'details': event.get('details', {})
            }
            
            self.multi_source_events[source_type].append(event_with_id)
            
            # 构建事件关联网络
            self._build_event_network()
            
            return event_with_id
    
    def _analyze_multi_source_events(self):
        """分析多源事件，进行关联分析"""
        with self.lock:
            # 获取所有多源事件
            all_events = []
            for source_type, events in self.multi_source_events.items():
                all_events.extend(events)
            
            # 按时间排序
            all_events.sort(key=lambda x: x['timestamp'])
            
            # 基于时间窗口关联事件
            self._correlate_events_by_time_window(all_events)
            
            # 基于IP地址关联事件
            self._correlate_events_by_ip(all_events)
            
            # 基于资产关联事件
            self._correlate_events_by_asset(all_events)
            
            # 基于用户关联事件
            self._correlate_events_by_user(all_events)
            
            # 基于攻击模式关联事件
            self._correlate_events_by_attack_pattern(all_events)
    
    def _correlate_events_by_time_window(self, events: List[Dict]):
        """基于时间窗口关联事件"""
        time_window = self.correlation_rules['time_based']['window']
        
        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                time_diff = abs((event2['timestamp'] - event1['timestamp']).total_seconds())
                if time_diff <= time_window:
                    # 构建关联
                    self._add_event_relation(event1, event2, 'time_based')
    
    def _correlate_events_by_ip(self, events: List[Dict]):
        """基于IP地址关联事件"""
        # 按源IP分组
        events_by_source_ip = defaultdict(list)
        for event in events:
            if event.get('source_ip'):
                events_by_source_ip[event['source_ip']].append(event)
        
        # 按目标IP分组
        events_by_target_ip = defaultdict(list)
        for event in events:
            if event.get('target_ip'):
                events_by_target_ip[event['target_ip']].append(event)
        
        # 关联相同源IP的事件
        for ip, ip_events in events_by_source_ip.items():
            for i, event1 in enumerate(ip_events):
                for event2 in ip_events[i+1:]:
                    self._add_event_relation(event1, event2, 'ip_based')
        
        # 关联相同目标IP的事件
        for ip, ip_events in events_by_target_ip.items():
            for i, event1 in enumerate(ip_events):
                for event2 in ip_events[i+1:]:
                    self._add_event_relation(event1, event2, 'ip_based')
    
    def _correlate_events_by_asset(self, events: List[Dict]):
        """基于资产关联事件"""
        events_by_asset = defaultdict(list)
        for event in events:
            if event.get('asset_id'):
                events_by_asset[event['asset_id']].append(event)
        
        for asset_id, asset_events in events_by_asset.items():
            for i, event1 in enumerate(asset_events):
                for event2 in asset_events[i+1:]:
                    self._add_event_relation(event1, event2, 'asset_based')
    
    def _correlate_events_by_user(self, events: List[Dict]):
        """基于用户关联事件"""
        events_by_user = defaultdict(list)
        for event in events:
            if event.get('user'):
                events_by_user[event['user']].append(event)
        
        for user, user_events in events_by_user.items():
            for i, event1 in enumerate(user_events):
                for event2 in user_events[i+1:]:
                    self._add_event_relation(event1, event2, 'user_based')
    
    def _correlate_events_by_attack_pattern(self, events: List[Dict]):
        """基于攻击模式关联事件"""
        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                # 检查是否属于相同的攻击模式
                phase1 = self._determine_attack_phase(event1.get('event_type'))
                phase2 = self._determine_attack_phase(event2.get('event_type'))
                
                if phase1 != 'unknown' and phase2 != 'unknown' and phase1 == phase2:
                    self._add_event_relation(event1, event2, 'attack_pattern_based')
    
    def _add_event_relation(self, event1: Dict, event2: Dict, relation_type: str):
        """添加事件关联"""
        # 构建关联ID
        relation_id = f"{event1['source_type']}_{event1['id']}_{event2['source_type']}_{event2['id']}"
        
        # 检查是否已存在关联
        for edge in self.event_network['edges']:
            if edge['id'] == relation_id:
                return
        
        # 添加节点
        self._add_event_node(event1)
        self._add_event_node(event2)
        
        # 添加边
        self.event_network['edges'].append({
            'id': relation_id,
            'source': f"{event1['source_type']}_{event1['id']}",
            'target': f"{event2['source_type']}_{event2['id']}",
            'relation_type': relation_type,
            'timestamp': datetime.now().isoformat()
        })
    
    def _add_event_node(self, event: Dict):
        """添加事件节点"""
        node_id = f"{event['source_type']}_{event['id']}"
        
        # 检查节点是否已存在
        for node in self.event_network['nodes']:
            if node['id'] == node_id:
                return
        
        # 添加节点
        self.event_network['nodes'].append({
            'id': node_id,
            'source_type': event['source_type'],
            'event_type': event.get('event_type'),
            'timestamp': event['timestamp'].isoformat(),
            'severity': event.get('severity'),
            'details': event.get('details')
        })
    
    def _build_event_network(self):
        """构建事件关联网络"""
        # 清空现有网络
        self.event_network = {'nodes': [], 'edges': []}
        
        # 获取所有多源事件
        all_events = []
        for source_type, events in self.multi_source_events.items():
            all_events.extend(events)
        
        # 关联事件
        self._correlate_events_by_time_window(all_events)
        self._correlate_events_by_ip(all_events)
        self._correlate_events_by_asset(all_events)
        self._correlate_events_by_user(all_events)
        self._correlate_events_by_attack_pattern(all_events)
    
    def _determine_attack_phase(self, attack_type: Optional[str]) -> str:
        """确定攻击阶段"""
        if not attack_type:
            return 'unknown'
        
        for phase, pattern in self.attack_patterns.items():
            if attack_type in pattern['events']:
                return phase
        
        return 'unknown'
    
    def _correlate_events(self, new_event: Dict):
        """关联事件"""
        for event in self.attack_events[:-1]:  # 排除新事件本身
            # 基于时间、来源IP、目标IP等关联
            time_diff = abs((new_event['timestamp'] - event['timestamp']).total_seconds())
            
            # 时间窗口内的事件
            if time_diff < 3600:  # 1小时内
                # 相同来源IP
                if new_event.get('source_ip') == event.get('source_ip'):
                    self.event_relations[new_event['id']].append(event['id'])
                    self.event_relations[event['id']].append(new_event['id'])
                    new_event['related_events'].append(event['id'])
                    event['related_events'].append(new_event['id'])
                
                # 相同目标IP
                if new_event.get('target_ip') == event.get('target_ip'):
                    if event['id'] not in self.event_relations[new_event['id']]:
                        self.event_relations[new_event['id']].append(event['id'])
                        self.event_relations[event['id']].append(new_event['id'])
                        new_event['related_events'].append(event['id'])
                        event['related_events'].append(new_event['id'])
    
    def _analyze_recent_events(self):
        """分析最近的事件，构建攻击链"""
        with self.lock:
            # 获取最近24小时的事件
            cutoff_time = datetime.now() - timedelta(hours=24)
            recent_events = [event for event in self.attack_events if event['timestamp'] >= cutoff_time]
            
            # 按来源IP分组
            events_by_source = defaultdict(list)
            for event in recent_events:
                if event.get('source_ip'):
                    events_by_source[event['source_ip']].append(event)
            
            # 为每个来源IP构建攻击链
            for source_ip, events in events_by_source.items():
                if len(events) >= 3:  # 至少3个事件才构成攻击链
                    # 按时间排序
                    sorted_events = sorted(events, key=lambda x: x['timestamp'])
                    
                    # 构建攻击链
                    attack_chain = {
                        'id': len(self.attack_chains) + 1,
                        'source_ip': source_ip,
                        'start_time': sorted_events[0]['timestamp'],
                        'end_time': sorted_events[-1]['timestamp'],
                        'event_count': len(sorted_events),
                        'events': [event['id'] for event in sorted_events],
                        'attack_phases': list(set([event['attack_phase'] for event in sorted_events if event['attack_phase'] != 'unknown'])),
                        'status': 'active',
                        'severity': max([event['severity'] for event in sorted_events], key=self._severity_to_int),
                        'targets': list(set([event.get('target_ip') for event in sorted_events if event.get('target_ip')]))
                    }
                    
                    # 检查是否已存在类似的攻击链
                    existing_chain = self._find_existing_chain(attack_chain)
                    if not existing_chain:
                        self.attack_chains.append(attack_chain)
                    else:
                        # 更新现有攻击链
                        self._update_attack_chain(existing_chain, attack_chain)
    
    def _severity_to_int(self, severity: str) -> int:
        """将严重程度转换为整数"""
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_map.get(severity, 3)
    
    def _find_existing_chain(self, new_chain: Dict) -> Optional[Dict]:
        """查找现有的攻击链"""
        for chain in self.attack_chains:
            if chain['source_ip'] == new_chain['source_ip']:
                time_diff = abs((new_chain['start_time'] - chain['end_time']).total_seconds())
                if time_diff < 3600:  # 1小时内
                    return chain
        return None
    
    def _update_attack_chain(self, existing_chain: Dict, new_chain: Dict):
        """更新现有攻击链"""
        existing_chain['end_time'] = new_chain['end_time']
        existing_chain['event_count'] = new_chain['event_count']
        existing_chain['events'] = new_chain['events']
        existing_chain['attack_phases'] = new_chain['attack_phases']
        existing_chain['severity'] = new_chain['severity']
        existing_chain['targets'] = new_chain['targets']
    
    def get_attack_events(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取攻击事件"""
        with self.lock:
            events = self.attack_events.copy()
            
            if filters:
                filtered_events = []
                for event in events:
                    match = True
                    for key, value in filters.items():
                        if key == 'source_ip' and event.get('source_ip') != value:
                            match = False
                        elif key == 'target_ip' and event.get('target_ip') != value:
                            match = False
                        elif key == 'attack_type' and event.get('attack_type') != value:
                            match = False
                        elif key == 'severity' and event.get('severity') != value:
                            match = False
                    if match:
                        filtered_events.append(event)
                return filtered_events
            
            return events
    
    def get_attack_chains(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取攻击链"""
        with self.lock:
            chains = self.attack_chains.copy()
            
            if filters:
                filtered_chains = []
                for chain in chains:
                    match = True
                    for key, value in filters.items():
                        if key == 'source_ip' and chain.get('source_ip') != value:
                            match = False
                        elif key == 'severity' and chain.get('severity') != value:
                            match = False
                    if match:
                        filtered_chains.append(chain)
                return filtered_chains
            
            return chains
    
    def get_event_relations(self, event_id: int) -> List[Dict]:
        """获取事件关联"""
        with self.lock:
            related_event_ids = self.event_relations.get(event_id, [])
            related_events = [event for event in self.attack_events if event['id'] in related_event_ids]
            return related_events
    
    def get_asset_impacts(self, asset_id: str) -> List[Dict]:
        """获取资产影响"""
        with self.lock:
            event_ids = self.asset_impacts.get(asset_id, [])
            events = [event for event in self.attack_events if event['id'] in event_ids]
            return events
    
    def analyze_attack_path(self, chain_id: int) -> Dict:
        """分析攻击路径"""
        with self.lock:
            chain = next((c for c in self.attack_chains if c['id'] == chain_id), None)
            if not chain:
                return {}
            
            # 获取链中的所有事件
            chain_events = [event for event in self.attack_events if event['id'] in chain['events']]
            chain_events.sort(key=lambda x: x['timestamp'])
            
            # 构建攻击路径
            path = []
            for event in chain_events:
                path.append({
                    'timestamp': event['timestamp'],
                    'event_id': event['id'],
                    'source_ip': event.get('source_ip'),
                    'target_ip': event.get('target_ip'),
                    'target_port': event.get('target_port'),
                    'attack_type': event.get('attack_type'),
                    'attack_phase': event.get('attack_phase'),
                    'severity': event.get('severity')
                })
            
            # 分析攻击阶段演进
            phases = []
            for phase in chain['attack_phases']:
                if phase in self.attack_patterns:
                    phases.append({
                        'phase': phase,
                        'name': self.attack_patterns[phase]['name'],
                        'description': self.attack_patterns[phase]['description']
                    })
            
            return {
                'chain': chain,
                'path': path,
                'phases': phases,
                'summary': self._generate_attack_summary(chain, chain_events)
            }
    
    def _generate_attack_summary(self, chain: Dict, events: List[Dict]) -> str:
        """生成攻击摘要"""
        if not events:
            return "无事件数据"
        
        first_event = events[0]
        last_event = events[-1]
        
        summary = f"攻击者从 {chain['source_ip']} 发起攻击，"
        summary += f"开始于 {first_event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}，"
        summary += f"结束于 {last_event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}，"
        summary += f"共检测到 {len(events)} 个事件，"
        summary += f"攻击目标包括 {', '.join(chain['targets'])}，"
        summary += f"涉及攻击阶段：{', '.join([self.attack_patterns.get(p, {'name': p})['name'] for p in chain['attack_phases']])}，"
        summary += f"严重程度：{chain['severity']}"
        
        return summary
    
    def get_attack_statistics(self, hours: int = 24) -> Dict:
        """获取攻击统计信息"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_events = [event for event in self.attack_events if event['timestamp'] >= cutoff_time]
            recent_chains = [chain for chain in self.attack_chains if chain['start_time'] >= cutoff_time]
            
            stats = {
                'total_events': len(recent_events),
                'total_chains': len(recent_chains),
                'events_by_type': defaultdict(int),
                'events_by_severity': defaultdict(int),
                'events_by_phase': defaultdict(int),
                'top_sources': defaultdict(int),
                'top_targets': defaultdict(int),
                'attack_phases': []
            }
            
            for event in recent_events:
                stats['events_by_type'][event.get('attack_type', 'unknown')] += 1
                stats['events_by_severity'][event.get('severity', 'medium')] += 1
                stats['events_by_phase'][event.get('attack_phase', 'unknown')] += 1
                
                if event.get('source_ip'):
                    stats['top_sources'][event['source_ip']] += 1
                if event.get('target_ip'):
                    stats['top_targets'][event['target_ip']] += 1
            
            # 排序统计
            stats['top_sources'] = dict(sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10])
            stats['top_targets'] = dict(sorted(stats['top_targets'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            # 分析攻击阶段
            for phase, pattern in self.attack_patterns.items():
                phase_count = stats['events_by_phase'].get(phase, 0)
                if phase_count > 0:
                    stats['attack_phases'].append({
                        'phase': phase,
                        'name': pattern['name'],
                        'count': phase_count,
                        'percentage': (phase_count / len(recent_events) * 100) if recent_events else 0
                    })
            
            return stats
    
    def get_multi_source_events(self, source_type: Optional[str] = None) -> Dict:
        """获取多源事件"""
        with self.lock:
            if source_type and source_type in self.multi_source_events:
                return self.multi_source_events[source_type]
            return self.multi_source_events
    
    def get_event_network(self) -> Dict:
        """获取事件关联网络"""
        with self.lock:
            return self.event_network
    
    def get_multi_source_statistics(self, hours: int = 24) -> Dict:
        """获取多源事件统计信息"""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            all_events = []
            for source_type, events in self.multi_source_events.items():
                recent_events = [event for event in events if event['timestamp'] >= cutoff_time]
                all_events.extend(recent_events)
            
            stats = {
                'total_events': len(all_events),
                'events_by_source': defaultdict(int),
                'events_by_type': defaultdict(int),
                'events_by_severity': defaultdict(int),
                'top_sources': defaultdict(int),
                'top_targets': defaultdict(int),
                'event_network': {
                    'nodes_count': len(self.event_network['nodes']),
                    'edges_count': len(self.event_network['edges'])
                }
            }
            
            for event in all_events:
                stats['events_by_source'][event['source_type']] += 1
                stats['events_by_type'][event.get('event_type', 'unknown')] += 1
                stats['events_by_severity'][event.get('severity', 'medium')] += 1
                
                if event.get('source_ip'):
                    stats['top_sources'][event['source_ip']] += 1
                if event.get('target_ip'):
                    stats['top_targets'][event['target_ip']] += 1
            
            # 排序统计
            stats['top_sources'] = dict(sorted(stats['top_sources'].items(), key=lambda x: x[1], reverse=True)[:10])
            stats['top_targets'] = dict(sorted(stats['top_targets'].items(), key=lambda x: x[1], reverse=True)[:10])
            
            return stats
    
    def get_correlated_events(self, event_id: int, source_type: str) -> List[Dict]:
        """获取与指定事件相关联的事件"""
        with self.lock:
            correlated_events = []
            node_id = f"{source_type}_{event_id}"
            
            # 查找相关联的边
            for edge in self.event_network['edges']:
                if edge['source'] == node_id:
                    # 获取目标事件
                    target_node_id = edge['target']
                    target_source_type, target_event_id = target_node_id.split('_', 1)
                    
                    # 查找目标事件
                    for event in self.multi_source_events.get(target_source_type, []):
                        if event['id'] == int(target_event_id):
                            correlated_events.append(event)
                elif edge['target'] == node_id:
                    # 获取源事件
                    source_node_id = edge['source']
                    source_source_type, source_event_id = source_node_id.split('_', 1)
                    
                    # 查找源事件
                    for event in self.multi_source_events.get(source_source_type, []):
                        if event['id'] == int(source_event_id):
                            correlated_events.append(event)
            
            return correlated_events

# 创建单例实例
attack_tracker = AttackTracker()
