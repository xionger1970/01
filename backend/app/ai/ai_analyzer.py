import time
import json
import random
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import threading
from collections import defaultdict, Counter
from app.alerting.alert_manager import alert_manager
from app.threat_intel.intel_manager import threat_intel_manager
from app.detectors.advanced_detector import advanced_detector
from app.detectors.anomaly_detector import anomaly_detector
from app.analysis.attack_tracker import attack_tracker
import numpy as np

class AIAnalyzer:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 分析历史
        self.analysis_history = []
        
        # 威胁模型
        self.threat_models = {
            'ransomware': {
                'name': '勒索软件攻击',
                'description': '检测勒索软件攻击模式',
                'patterns': [
                    '文件加密行为',
                    '勒索通知',
                    '异常网络通信',
                    '权限提升',
                    '横向移动'
                ],
                'severity': 'critical',
                'mitigation': ['隔离受感染系统', '断开网络连接', '恢复备份']
            },
            'apt': {
                'name': '高级持续性威胁',
                'description': '检测APT攻击特征',
                'patterns': [
                    '长期潜伏',
                    '多阶段攻击',
                    '自定义恶意代码',
                    '数据窃取',
                    '反检测技术'
                ],
                'severity': 'critical',
                'mitigation': ['全面安全审计', '网络流量分析', '威胁狩猎']
            },
            'phishing': {
                'name': '钓鱼攻击',
                'description': '检测钓鱼攻击模式',
                'patterns': [
                    '钓鱼邮件',
                    '恶意URL',
                    '社会工程学',
                    '凭证窃取',
                    '恶意附件'
                ],
                'severity': 'high',
                'mitigation': ['邮件过滤', '用户培训', '多因素认证']
            },
            'ddos': {
                'name': 'DDoS攻击',
                'description': '检测分布式拒绝服务攻击',
                'patterns': [
                    '流量突增',
                    '异常请求模式',
                    '多源IP攻击',
                    '服务不可用',
                    '资源耗尽'
                ],
                'severity': 'high',
                'mitigation': ['流量过滤', 'CDN防护', '速率限制']
            },
            'insider_threat': {
                'name': '内部威胁',
                'description': '检测内部人员恶意行为',
                'patterns': [
                    '异常数据访问',
                    '权限滥用',
                    '异常登录行为',
                    '数据泄露',
                    '违反安全策略'
                ],
                'severity': 'medium',
                'mitigation': ['访问控制审计', '行为分析', '权限管理']
            },
            'web_attack': {
                'name': 'Web攻击',
                'description': '检测Web应用攻击',
                'patterns': [
                    'SQL注入',
                    'XSS攻击',
                    'CSRF攻击',
                    '命令注入',
                    '权限绕过'
                ],
                'severity': 'high',
                'mitigation': ['WAF部署', '输入验证', '代码审计']
            },
            'malware': {
                'name': '恶意软件',
                'description': '检测恶意软件感染',
                'patterns': [
                    '异常进程',
                    '恶意文件',
                    '异常网络连接',
                    '系统修改',
                    '资源异常使用'
                ],
                'severity': 'high',
                'mitigation': ['端点保护', '恶意软件扫描', '系统隔离']
            }
        }
        
        # 分析结果缓存
        self.analysis_cache = {}
        
        # 机器学习模型参数
        self.ml_model = {
            'anomaly_threshold': 0.7,
            'confidence_threshold': 0.65,
            'pattern_weights': {
                'network': 0.3,
                'system': 0.25,
                'user': 0.2,
                'data': 0.25
            }
        }
        
        # 攻击模式识别
        self.attack_patterns = {
            'lateral_movement': ['SMB连接', '远程桌面', 'PowerShell执行'],
            'privilege_escalation': ['权限提升', 'UAC绕过', '服务利用'],
            'data_exfiltration': ['大量数据传输', '异常DNS查询', '加密通信']
        }
        
        # 启动分析线程
        self._start_analysis_thread()
        
        # 启动实时分析线程
        self._start_realtime_analysis_thread()
    
    def _start_analysis_thread(self):
        """启动分析线程"""
        def analyze_alerts():
            while True:
                time.sleep(30)  # 每30秒分析一次
                self._analyze_pending_alerts()
        
        analysis_thread = threading.Thread(target=analyze_alerts, daemon=True)
        analysis_thread.start()
    
    def _start_realtime_analysis_thread(self):
        """启动实时分析线程"""
        def realtime_analysis():
            while True:
                time.sleep(5)  # 每5秒进行一次实时分析
                self._analyze_realtime_events()
        
        realtime_thread = threading.Thread(target=realtime_analysis, daemon=True)
        realtime_thread.start()
    
    def analyze_alert(self, alert: Dict) -> Dict:
        """分析单个告警"""
        with self.lock:
            analysis_id = len(self.analysis_history) + 1
            analysis_start = datetime.now()
            
            # 分析告警
            analysis_result = self._analyze_alert_content(alert)
            
            # 增强分析：添加攻击模式识别
            attack_patterns = self._identify_attack_patterns(alert)
            if attack_patterns:
                analysis_result['attack_patterns'] = attack_patterns
            
            # 增强分析：添加威胁评分
            threat_score = self._calculate_threat_score(analysis_result, alert)
            analysis_result['threat_score'] = threat_score
            
            # 增强分析：添加预测性分析
            predictive_analysis = self._predict_attack_outcome(alert, analysis_result)
            if predictive_analysis:
                analysis_result['predictive_analysis'] = predictive_analysis
            
            analysis_end = datetime.now()
            analysis_duration = (analysis_end - analysis_start).total_seconds()
            
            analysis_record = {
                'id': analysis_id,
                'alert_id': alert.get('id'),
                'analysis_time': analysis_start,
                'duration': analysis_duration,
                'result': analysis_result,
                'confidence': analysis_result.get('confidence', 0.5),
                'threat_score': threat_score,
                'recommendations': analysis_result.get('recommendations', []),
                'created_at': datetime.now()
            }
            
            self.analysis_history.append(analysis_record)
            return analysis_record
    
    def _analyze_alert_content(self, alert: Dict) -> Dict:
        """分析告警内容"""
        details = alert.get('details', {})
        attack_type = details.get('attack_type')
        source_ip = details.get('source_ip')
        target = details.get('target')
        
        # 基础分析
        analysis = {
            'threat_type': 'unknown',
            'confidence': 0.5,
            'description': '未知威胁',
            'indicators': [],
            'recommendations': []
        }
        
        # 基于攻击类型分析
        if attack_type:
            analysis = self._analyze_by_attack_type(attack_type, details)
        
        # 基于威胁情报分析
        if source_ip:
            intel_analysis = self._analyze_by_threat_intel(source_ip)
            if intel_analysis['confidence'] > analysis['confidence']:
                analysis.update(intel_analysis)
        
        # 生成建议
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_by_attack_type(self, attack_type: str, details: Dict) -> Dict:
        """基于攻击类型分析"""
        analysis_map = {
            'sql_injection': {
                'threat_type': 'web_attack',
                'confidence': 0.85,
                'description': 'SQL注入攻击',
                'indicators': ['SQL语法特征', '数据库操作尝试']
            },
            'xss': {
                'threat_type': 'web_attack',
                'confidence': 0.80,
                'description': '跨站脚本攻击',
                'indicators': ['脚本标签', '事件处理程序']
            },
            'command_injection': {
                'threat_type': 'code_execution',
                'confidence': 0.90,
                'description': '命令注入攻击',
                'indicators': ['系统命令特征', '管道操作符']
            },
            'csrf': {
                'threat_type': 'web_attack',
                'confidence': 0.75,
                'description': '跨站请求伪造',
                'indicators': ['伪造请求', '会话利用']
            },
            'phishing': {
                'threat_type': 'social_engineering',
                'confidence': 0.85,
                'description': '钓鱼攻击',
                'indicators': ['欺骗性URL', '社会工程学特征']
            },
            'ransomware': {
                'threat_type': 'ransomware',
                'confidence': 0.95,
                'description': '勒索软件攻击',
                'indicators': ['文件加密', '勒索通知']
            },
            'c2_communication': {
                'threat_type': 'apt',
                'confidence': 0.90,
                'description': '命令与控制通信',
                'indicators': ['异常网络通信', '加密流量']
            }
        }
        
        return analysis_map.get(attack_type, {
            'threat_type': 'unknown',
            'confidence': 0.5,
            'description': '未知攻击类型',
            'indicators': []
        })
    
    def _analyze_by_threat_intel(self, source_ip: str) -> Dict:
        """基于威胁情报分析"""
        # 模拟威胁情报分析
        is_malicious = random.choice([True, False, False, False])  # 25%概率为恶意
        
        if is_malicious:
            return {
                'threat_type': 'malicious_ip',
                'confidence': 0.85,
                'description': '来自恶意IP的攻击',
                'indicators': ['恶意IP', '威胁情报匹配']
            }
        
        return {
            'threat_type': 'unknown',
            'confidence': 0.3,
            'description': '未发现威胁情报匹配',
            'indicators': []
        }
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """生成安全建议"""
        recommendations_map = {
            'web_attack': [
                '实施输入验证',
                '使用WAF防护',
                '更新Web应用程序',
                '实施内容安全策略'
            ],
            'code_execution': [
                '实施最小权限原则',
                '使用容器化隔离',
                '监控异常进程行为',
                '定期安全审计'
            ],
            'social_engineering': [
                '员工安全意识培训',
                '实施邮件过滤',
                '使用多因素认证',
                '建立安全事件响应流程'
            ],
            'ransomware': [
                '备份关键数据',
                '实施网络隔离',
                '使用端点保护',
                '建立勒索软件响应计划'
            ],
            'apt': [
                '实施高级威胁检测',
                '网络流量分析',
                '定期安全评估',
                '建立威胁狩猎程序'
            ],
            'malicious_ip': [
                '阻断恶意IP',
                '实施IP信誉系统',
                '监控相关IP范围',
                '更新防火墙规则'
            ]
        }
        
        return recommendations_map.get(analysis.get('threat_type'), [
            '进一步分析告警',
            '监控相关活动',
            '更新安全策略',
            '实施安全最佳实践'
        ])
    
    def analyze_attack_chain(self, chain_id: int) -> Dict:
        """分析攻击链"""
        with self.lock:
            # 获取攻击链信息
            chain_analysis = attack_tracker.analyze_attack_path(chain_id)
            if not chain_analysis:
                return {'error': 'Attack chain not found'}
            
            analysis_id = len(self.analysis_history) + 1
            analysis_start = datetime.now()
            
            # 分析攻击链
            chain_result = self._analyze_chain_content(chain_analysis)
            
            analysis_end = datetime.now()
            analysis_duration = (analysis_end - analysis_start).total_seconds()
            
            analysis_record = {
                'id': analysis_id,
                'chain_id': chain_id,
                'analysis_time': analysis_start,
                'duration': analysis_duration,
                'result': chain_result,
                'confidence': chain_result.get('confidence', 0.6),
                'recommendations': chain_result.get('recommendations', []),
                'created_at': datetime.now()
            }
            
            self.analysis_history.append(analysis_record)
            return analysis_record
    
    def _analyze_chain_content(self, chain_analysis: Dict) -> Dict:
        """分析攻击链内容"""
        path = chain_analysis.get('path', [])
        phases = chain_analysis.get('phases', [])
        
        # 分析攻击阶段
        phase_names = [phase.get('name') for phase in phases]
        
        # 基于攻击阶段判断威胁类型
        if '侦察阶段' in phase_names and '初始访问' in phase_names and '权限提升' in phase_names:
            return {
                'threat_type': 'apt',
                'confidence': 0.9,
                'description': '高级持续性威胁(APT)攻击',
                'indicators': phase_names,
                'attack_path': path,
                'recommendations': [
                    '隔离受影响系统',
                    '清除恶意软件',
                    '重置 compromised 凭证',
                    '实施网络分段',
                    '加强监控'
                ]
            }
        elif '执行阶段' in phase_names and '数据收集' in phase_names and '数据泄露' in phase_names:
            return {
                'threat_type': 'data_breach',
                'confidence': 0.85,
                'description': '数据泄露攻击',
                'indicators': phase_names,
                'attack_path': path,
                'recommendations': [
                    '评估数据泄露范围',
                    '通知相关方',
                    '实施数据保护措施',
                    '加强访问控制',
                    '进行安全审计'
                ]
            }
        else:
            return {
                'threat_type': 'general_attack',
                'confidence': 0.6,
                'description': '一般性攻击链',
                'indicators': phase_names,
                'attack_path': path,
                'recommendations': [
                    '分析攻击路径',
                    '修补漏洞',
                    '加强监控',
                    '更新安全策略'
                ]
            }
    
    def analyze_anomaly(self, anomaly: Dict) -> Dict:
        """分析异常行为"""
        with self.lock:
            analysis_id = len(self.analysis_history) + 1
            analysis_start = datetime.now()
            
            # 分析异常
            anomaly_result = self._analyze_anomaly_content(anomaly)
            
            analysis_end = datetime.now()
            analysis_duration = (analysis_end - analysis_start).total_seconds()
            
            analysis_record = {
                'id': analysis_id,
                'anomaly_id': anomaly.get('id'),
                'analysis_time': analysis_start,
                'duration': analysis_duration,
                'result': anomaly_result,
                'confidence': anomaly_result.get('confidence', 0.5),
                'recommendations': anomaly_result.get('recommendations', []),
                'created_at': datetime.now()
            }
            
            self.analysis_history.append(analysis_record)
            return analysis_record
    
    def _analyze_anomaly_content(self, anomaly: Dict) -> Dict:
        """分析异常内容"""
        anomaly_type = anomaly.get('type')
        severity = anomaly.get('severity', 'medium')
        
        anomaly_analysis = {
            'threat_type': 'anomaly',
            'confidence': 0.6,
            'description': '异常行为',
            'indicators': [anomaly_type],
            'recommendations': []
        }
        
        if anomaly_type == 'traffic_anomaly':
            anomaly_analysis.update({
                'confidence': 0.75,
                'description': '流量异常',
                'recommendations': [
                    '分析流量模式',
                    '检查DDoS攻击',
                    '调整流量阈值',
                    '实施流量过滤'
                ]
            })
        elif anomaly_type == 'user_behavior_anomaly':
            anomaly_analysis.update({
                'confidence': 0.8,
                'description': '用户行为异常',
                'recommendations': [
                    '验证用户身份',
                    '检查账户活动',
                    '实施行为分析',
                    '加强认证'
                ]
            })
        elif anomaly_type == 'data_access_anomaly':
            anomaly_analysis.update({
                'confidence': 0.85,
                'description': '数据访问异常',
                'recommendations': [
                    '审计数据访问',
                    '检查权限设置',
                    '实施数据保护',
                    '监控敏感数据访问'
                ]
            })
        
        return anomaly_analysis
    
    def get_analysis_history(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取分析历史"""
        with self.lock:
            analyses = self.analysis_history.copy()
            
            if filters:
                filtered_analyses = []
                for analysis in analyses:
                    match = True
                    for key, value in filters.items():
                        if key == 'threat_type' and analysis.get('result', {}).get('threat_type') != value:
                            match = False
                        elif key == 'min_confidence' and analysis.get('confidence', 0) < value:
                            match = False
                    if match:
                        filtered_analyses.append(analysis)
                return filtered_analyses
            
            return analyses
    
    def get_threat_models(self) -> Dict:
        """获取威胁模型"""
        return self.threat_models
    
    def _analyze_pending_alerts(self):
        """分析待处理的告警"""
        # 这里可以添加自动分析逻辑
        # 例如：分析新的告警并生成智能建议
        pass
    
    def _analyze_realtime_events(self):
        """分析实时事件"""
        # 这里可以添加实时事件分析逻辑
        # 例如：监控网络流量、系统行为等
        pass
    
    def _identify_attack_patterns(self, alert: Dict) -> List[str]:
        """识别攻击模式"""
        patterns = []
        details = alert.get('details', {})
        alert_message = details.get('message', '').lower()
        
        # 识别横向移动模式
        for pattern in self.attack_patterns['lateral_movement']:
            if pattern.lower() in alert_message:
                patterns.append('lateral_movement')
                break
        
        # 识别权限提升模式
        for pattern in self.attack_patterns['privilege_escalation']:
            if pattern.lower() in alert_message:
                patterns.append('privilege_escalation')
                break
        
        # 识别数据泄露模式
        for pattern in self.attack_patterns['data_exfiltration']:
            if pattern.lower() in alert_message:
                patterns.append('data_exfiltration')
                break
        
        return patterns
    
    def _calculate_threat_score(self, analysis_result: Dict, alert: Dict) -> float:
        """计算威胁评分"""
        score = 0.0
        
        # 基于威胁类型的基础分数
        threat_type = analysis_result.get('threat_type')
        threat_scores = {
            'ransomware': 0.9,
            'apt': 0.85,
            'web_attack': 0.75,
            'malware': 0.7,
            'phishing': 0.65,
            'ddos': 0.6,
            'insider_threat': 0.5
        }
        
        if threat_type in threat_scores:
            score += threat_scores[threat_type] * 0.5
        
        # 基于置信度的分数
        confidence = analysis_result.get('confidence', 0.5)
        score += confidence * 0.3
        
        # 基于告警严重性的分数
        severity = alert.get('severity', 'medium')
        severity_scores = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3
        }
        
        if severity in severity_scores:
            score += severity_scores[severity] * 0.2
        
        # 确保分数在0-1之间
        return min(max(score, 0), 1)
    
    def _predict_attack_outcome(self, alert: Dict, analysis_result: Dict) -> Dict:
        """预测攻击结果"""
        threat_type = analysis_result.get('threat_type')
        
        predictions = {
            'ransomware': {
                'outcome': '数据加密和勒索要求',
                'impact': '高',
                'probability': 0.85,
                'mitigation_time': '立即'
            },
            'apt': {
                'outcome': '长期潜伏和数据窃取',
                'impact': '严重',
                'probability': 0.75,
                'mitigation_time': '24小时内'
            },
            'web_attack': {
                'outcome': '数据泄露或服务中断',
                'impact': '中等',
                'probability': 0.7,
                'mitigation_time': '4小时内'
            },
            'malware': {
                'outcome': '系统感染和数据损坏',
                'impact': '高',
                'probability': 0.8,
                'mitigation_time': '立即'
            },
            'phishing': {
                'outcome': '凭证泄露和账户接管',
                'impact': '中等',
                'probability': 0.65,
                'mitigation_time': '2小时内'
            }
        }
        
        return predictions.get(threat_type, {
            'outcome': '未知',
            'impact': '低',
            'probability': 0.3,
            'mitigation_time': '不确定'
        })
    
    def analyze_batch_alerts(self, alerts: List[Dict]) -> Dict:
        """批量分析告警"""
        with self.lock:
            analysis_start = datetime.now()
            results = []
            threat_summary = Counter()
            
            for alert in alerts:
                analysis = self.analyze_alert(alert)
                results.append(analysis)
                threat_type = analysis.get('result', {}).get('threat_type')
                if threat_type:
                    threat_summary[threat_type] += 1
            
            analysis_end = datetime.now()
            analysis_duration = (analysis_end - analysis_start).total_seconds()
            
            return {
                'total_alerts': len(alerts),
                'analysis_duration': analysis_duration,
                'threat_summary': dict(threat_summary),
                'results': results,
                'created_at': datetime.now()
            }

# 创建单例实例
ai_analyzer = AIAnalyzer()
