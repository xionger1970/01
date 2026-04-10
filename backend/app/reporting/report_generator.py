import time
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
from collections import defaultdict
from app.core.database import db_manager
from app.threat_intel import threat_intel_manager
from app.detectors.anomaly_detector import anomaly_detector
from app.analysis.attack_tracker import attack_tracker
from app.cloud_security import cloud_security_manager

class ReportGenerator:
    def __init__(self):
        self.lock = threading.Lock()
        
        # 报告模板
        self.report_templates = {
            'daily': {
                'name': '每日安全报告',
                'description': '每日安全事件和威胁分析报告',
                'sections': ['summary', 'attack_stats', 'anomalies', 'threat_intel', 'recommendations']
            },
            'weekly': {
                'name': '每周安全报告',
                'description': '每周安全趋势和威胁分析报告',
                'sections': ['summary', 'attack_stats', 'anomalies', 'threat_intel', 'cloud_security', 'recommendations']
            },
            'monthly': {
                'name': '月度安全报告',
                'description': '月度安全趋势和威胁分析报告',
                'sections': ['summary', 'attack_stats', 'anomalies', 'threat_intel', 'cloud_security', 'container_security', 'recommendations']
            },
            'incident': {
                'name': '事件响应报告',
                'description': '安全事件详细分析报告',
                'sections': ['incident_summary', 'timeline', 'impact', 'response_actions', 'lessons_learned']
            }
        }
        
        # 生成的报告
        self.generated_reports = []
        
        # 报告生成状态
        self.report_status = {}
        
        # 启动报告生成线程
        self._start_report_thread()
    
    def _start_report_thread(self):
        """启动报告生成线程"""
        def generate_scheduled_reports():
            while True:
                # 每天生成日报告
                if datetime.now().hour == 0 and datetime.now().minute == 0:
                    self.generate_report('daily')
                # 每周一生成周报告
                if datetime.now().weekday() == 0 and datetime.now().hour == 1 and datetime.now().minute == 0:
                    self.generate_report('weekly')
                # 每月1日生成月报告
                if datetime.now().day == 1 and datetime.now().hour == 2 and datetime.now().minute == 0:
                    self.generate_report('monthly')
                time.sleep(60)  # 每分钟检查一次
        
        report_thread = threading.Thread(target=generate_scheduled_reports, daemon=True)
        report_thread.start()
    
    def generate_report(self, report_type: str, parameters: Optional[Dict] = None) -> Dict:
        """生成报告"""
        with self.lock:
            report_id = len(self.generated_reports) + 1
            report = {
                'id': report_id,
                'type': report_type,
                'name': self.report_templates[report_type]['name'],
                'status': 'generating',
                'created_at': datetime.now(),
                'updated_at': datetime.now(),
                'parameters': parameters or {}
            }
            
            self.generated_reports.append(report)
            self.report_status[report_id] = 'generating'
        
        # 异步生成报告
        def generate_report_async():
            try:
                report_content = self._generate_report_content(report_type, parameters or {})
                with self.lock:
                    for r in self.generated_reports:
                        if r['id'] == report_id:
                            r['content'] = report_content
                            r['status'] = 'completed'
                            r['updated_at'] = datetime.now()
                            self.report_status[report_id] = 'completed'
                            break
            except Exception as e:
                with self.lock:
                    for r in self.generated_reports:
                        if r['id'] == report_id:
                            r['status'] = 'failed'
                            r['error'] = str(e)
                            r['updated_at'] = datetime.now()
                            self.report_status[report_id] = 'failed'
                            break
        
        threading.Thread(target=generate_report_async, daemon=True).start()
        return report
    
    def _generate_report_content(self, report_type: str, parameters: Dict) -> Dict:
        """生成报告内容"""
        content = {
            'title': self.report_templates[report_type]['name'],
            'generated_at': datetime.now().isoformat(),
            'sections': {}
        }
        
        # 根据报告类型生成不同的章节
        if report_type == 'daily':
            content['time_range'] = {
                'start': (datetime.now() - timedelta(days=1)).isoformat(),
                'end': datetime.now().isoformat()
            }
        elif report_type == 'weekly':
            content['time_range'] = {
                'start': (datetime.now() - timedelta(weeks=1)).isoformat(),
                'end': datetime.now().isoformat()
            }
        elif report_type == 'monthly':
            content['time_range'] = {
                'start': (datetime.now() - timedelta(days=30)).isoformat(),
                'end': datetime.now().isoformat()
            }
        
        # 生成各个章节
        for section in self.report_templates[report_type]['sections']:
            if section == 'summary':
                content['sections']['summary'] = self._generate_summary_section(report_type)
            elif section == 'attack_stats':
                content['sections']['attack_stats'] = self._generate_attack_stats_section(report_type)
            elif section == 'anomalies':
                content['sections']['anomalies'] = self._generate_anomalies_section(report_type)
            elif section == 'threat_intel':
                content['sections']['threat_intel'] = self._generate_threat_intel_section(report_type)
            elif section == 'cloud_security':
                content['sections']['cloud_security'] = self._generate_cloud_security_section(report_type)
            elif section == 'container_security':
                content['sections']['container_security'] = self._generate_container_security_section(report_type)
            elif section == 'recommendations':
                content['sections']['recommendations'] = self._generate_recommendations_section(report_type)
            elif section == 'incident_summary':
                content['sections']['incident_summary'] = self._generate_incident_summary_section(parameters)
            elif section == 'timeline':
                content['sections']['timeline'] = self._generate_timeline_section(parameters)
            elif section == 'impact':
                content['sections']['impact'] = self._generate_impact_section(parameters)
            elif section == 'response_actions':
                content['sections']['response_actions'] = self._generate_response_actions_section(parameters)
            elif section == 'lessons_learned':
                content['sections']['lessons_learned'] = self._generate_lessons_learned_section(parameters)
        
        return content
    
    def _generate_summary_section(self, report_type: str) -> Dict:
        """生成摘要章节"""
        # 获取攻击统计信息
        attack_stats = attack_tracker.get_attack_statistics(24 if report_type == 'daily' else 168 if report_type == 'weekly' else 720)
        
        # 获取异常检测统计信息
        anomaly_stats = anomaly_detector.get_anomaly_stats()
        
        return {
            'total_attacks': attack_stats.get('total_events', 0),
            'total_chains': attack_stats.get('total_chains', 0),
            'top_attack_types': dict(sorted(attack_stats.get('events_by_type', {}).items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_source_ips': dict(sorted(attack_stats.get('top_sources', {}).items(), key=lambda x: x[1], reverse=True)[:5]),
            'anomaly_count': len(anomaly_detector.detect_all_anomalies()),
            'threat_intel_count': len(threat_intel_manager.threat_intel_data['threat_indicators']),
            'cloud_security_status': cloud_security_manager.get_cloud_security_stats(),
            'container_security_status': cloud_security_manager.get_container_security_stats()
        }
    
    def _generate_attack_stats_section(self, report_type: str) -> Dict:
        """生成攻击统计章节"""
        hours = 24 if report_type == 'daily' else 168 if report_type == 'weekly' else 720
        attack_stats = attack_tracker.get_attack_statistics(hours)
        
        return {
            'by_type': attack_stats.get('events_by_type', {}),
            'by_severity': attack_stats.get('events_by_severity', {}),
            'by_phase': attack_stats.get('events_by_phase', {}),
            'top_sources': attack_stats.get('top_sources', {}),
            'top_targets': attack_stats.get('top_targets', {}),
            'attack_phases': attack_stats.get('attack_phases', [])
        }
    
    def _generate_anomalies_section(self, report_type: str) -> Dict:
        """生成异常检测章节"""
        anomalies = anomaly_detector.detect_all_anomalies()
        
        # 按类型分组异常
        anomalies_by_type = defaultdict(list)
        for anomaly in anomalies:
            anomalies_by_type[anomaly['type']].append(anomaly)
        
        return {
            'total_anomalies': len(anomalies),
            'by_type': dict(anomalies_by_type),
            'top_severities': defaultdict(int),
            'behavior_patterns': anomaly_detector.get_behavior_patterns()
        }
    
    def _generate_threat_intel_section(self, report_type: str) -> Dict:
        """生成威胁情报章节"""
        return {
            'malicious_ips_count': len(threat_intel_manager.threat_intel_data['malicious_ips']),
            'malicious_domains_count': len(threat_intel_manager.threat_intel_data['malicious_domains']),
            'malicious_urls_count': len(threat_intel_manager.threat_intel_data['malicious_urls']),
            'malicious_hashes_count': len(threat_intel_manager.threat_intel_data['malicious_hashes']),
            'apt_groups_count': len(threat_intel_manager.threat_intel_data['apt_groups']),
            'threat_campaigns_count': len(threat_intel_manager.threat_intel_data['threat_campaigns']),
            'vulnerabilities_count': len(threat_intel_manager.threat_intel_data['vulnerabilities']),
            'recent_indicators': threat_intel_manager.get_threat_indicators(10)
        }
    
    def _generate_cloud_security_section(self, report_type: str) -> Dict:
        """生成云安全章节"""
        return {
            'cloud_environments': cloud_security_manager.get_cloud_environments(),
            'cloud_security_status': cloud_security_manager.get_cloud_security_status(),
            'cloud_security_events': cloud_security_manager.get_cloud_security_events(),
            'cloud_security_stats': cloud_security_manager.get_cloud_security_stats()
        }
    
    def _generate_container_security_section(self, report_type: str) -> Dict:
        """生成容器安全章节"""
        return {
            'container_environments': cloud_security_manager.get_container_environments(),
            'container_security_status': cloud_security_manager.get_container_security_status(),
            'container_security_events': cloud_security_manager.get_container_security_events(),
            'container_security_stats': cloud_security_manager.get_container_security_stats()
        }
    
    def _generate_recommendations_section(self, report_type: str) -> List[Dict]:
        """生成建议章节"""
        recommendations = []
        
        # 基于攻击统计生成建议
        attack_stats = attack_tracker.get_attack_statistics(24)
        if attack_stats.get('total_events', 0) > 100:
            recommendations.append({
                'id': 1,
                'title': '加强访问控制',
                'description': '检测到大量攻击尝试，建议加强访问控制措施',
                'severity': 'high',
                'action': '配置更严格的访问控制策略'
            })
        
        # 基于异常检测生成建议
        anomalies = anomaly_detector.detect_all_anomalies()
        if len(anomalies) > 10:
            recommendations.append({
                'id': 2,
                'title': '调查异常行为',
                'description': '检测到大量异常行为，建议调查',
                'severity': 'medium',
                'action': '分析异常行为模式，识别潜在威胁'
            })
        
        # 基于云安全生成建议
        cloud_stats = cloud_security_manager.get_cloud_security_stats()
        if cloud_stats.get('status_counts', {}).get('critical', 0) > 0:
            recommendations.append({
                'id': 3,
                'title': '修复云安全问题',
                'description': '云环境中存在严重安全问题',
                'severity': 'critical',
                'action': '立即修复云环境中的安全问题'
            })
        
        return recommendations
    
    def _generate_incident_summary_section(self, parameters: Dict) -> Dict:
        """生成事件摘要章节"""
        return {
            'incident_id': parameters.get('incident_id', 'N/A'),
            'title': parameters.get('title', 'N/A'),
            'description': parameters.get('description', 'N/A'),
            'severity': parameters.get('severity', 'medium'),
            'status': parameters.get('status', 'investigating'),
            'detected_at': parameters.get('detected_at', datetime.now().isoformat()),
            'resolved_at': parameters.get('resolved_at', None)
        }
    
    def _generate_timeline_section(self, parameters: Dict) -> List[Dict]:
        """生成时间线章节"""
        return parameters.get('timeline', [])
    
    def _generate_impact_section(self, parameters: Dict) -> Dict:
        """生成影响章节"""
        return {
            'affected_systems': parameters.get('affected_systems', []),
            'data_breach': parameters.get('data_breach', False),
            'service_disruption': parameters.get('service_disruption', False),
            'financial_impact': parameters.get('financial_impact', 'N/A'),
            'reputational_impact': parameters.get('reputational_impact', 'N/A')
        }
    
    def _generate_response_actions_section(self, parameters: Dict) -> List[Dict]:
        """生成响应动作章节"""
        return parameters.get('response_actions', [])
    
    def _generate_lessons_learned_section(self, parameters: Dict) -> List[Dict]:
        """生成经验教训章节"""
        return parameters.get('lessons_learned', [])
    
    def get_reports(self, filters: Optional[Dict] = None) -> List[Dict]:
        """获取生成的报告"""
        with self.lock:
            reports = self.generated_reports.copy()
            
            if filters:
                filtered_reports = []
                for report in reports:
                    match = True
                    for key, value in filters.items():
                        if report.get(key) != value:
                            match = False
                    if match:
                        filtered_reports.append(report)
                return filtered_reports
            
            return reports
    
    def get_report(self, report_id: int) -> Optional[Dict]:
        """获取单个报告"""
        with self.lock:
            return next((report for report in self.generated_reports if report['id'] == report_id), None)
    
    def get_report_status(self, report_id: int) -> Optional[str]:
        """获取报告生成状态"""
        with self.lock:
            return self.report_status.get(report_id)
    
    def get_report_templates(self) -> Dict:
        """获取报告模板"""
        return self.report_templates
    
    def delete_report(self, report_id: int) -> bool:
        """删除报告"""
        with self.lock:
            for i, report in enumerate(self.generated_reports):
                if report['id'] == report_id:
                    self.generated_reports.pop(i)
                    if report_id in self.report_status:
                        del self.report_status[report_id]
                    return True
        return False

# 创建单例实例
report_generator = ReportGenerator()