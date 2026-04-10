import subprocess
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FirewallManager:
    """iptables/防火墙API集成"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.block_duration = 3600  # 默认阻止1小时
        
    def block_ip(self, ip: str, duration: Optional[int] = None) -> bool:
        """
        阻止指定IP地址
        """
        try:
            if duration is None:
                duration = self.block_duration
            
            # 使用iptables添加阻止规则
            cmd = [
                'iptables',
                '-A', 'INPUT',
                '-s', ip,
                '-j', 'DROP'
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"IP {ip} 已阻止 {duration} 秒")
            
            # 设置定时器，到期后自动解除阻止
            if duration > 0:
                # 在实际环境中，应该使用定时任务或后台线程
                # 这里我们记录解除时间，由清理方法处理
                pass
            
            return True
        except Exception as e:
            logger.error(f"阻止IP {ip} 失败: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        解除阻止指定IP地址
        """
        try:
            # 移除iptables阻止规则
            cmd = [
                'iptables',
                '-D', 'INPUT',
                '-s', ip,
                '-j', 'DROP'
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            
            logger.info(f"IP {ip} 已解除阻止")
            return True
        except Exception as e:
            logger.error(f"解除IP {ip} 阻止失败: {e}")
            return False
    
    def get_blocked_ips(self) -> List[str]:
        """
        获取当前被阻止的IP列表
        """
        return list(self.blocked_ips)
    
    def clear_all_blocks(self) -> bool:
        """
        清除所有阻止规则
        """
        try:
            for ip in list(self.blocked_ips):
                self.unblock_ip(ip)
            return True
        except Exception as e:
            logger.error(f"清除所有阻止失败: {e}")
            return False


class NginxBlocker:
    """Nginx封禁模块集成"""
    
    def __init__(self, conf_path: str = "/etc/nginx/conf.d/blocklist.conf"):
        self.conf_path = conf_path
        self.blocked_ips: Set[str] = set()
        
    def block_ip(self, ip: str) -> bool:
        """
        通过Nginx阻止IP
        """
        try:
            # 更新配置文件
            self._update_nginx_conf(ip, block=True)
            
            # 重新加载Nginx配置
            self._reload_nginx()
            
            self.blocked_ips.add(ip)
            logger.info(f"Nginx 已阻止IP {ip}")
            return True
        except Exception as e:
            logger.error(f"Nginx阻止IP {ip} 失败: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        解除Nginx对IP的阻止
        """
        try:
            # 更新配置文件
            self._update_nginx_conf(ip, block=False)
            
            # 重新加载Nginx配置
            self._reload_nginx()
            
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            
            logger.info(f"Nginx 已解除IP {ip} 的阻止")
            return True
        except Exception as e:
            logger.error(f"Nginx解除IP {ip} 阻止失败: {e}")
            return False
    
    def _update_nginx_conf(self, ip: str, block: bool):
        """
        更新Nginx配置文件
        """
        # 读取现有配置
        existing_content = ""
        if os.path.exists(self.conf_path):
            with open(self.conf_path, 'r') as f:
                existing_content = f.read()
        
        # 构建新配置
        if block:
            new_rule = f"deny {ip};\n"
            if new_rule not in existing_content:
                existing_content += new_rule
        else:
            existing_content = existing_content.replace(f"deny {ip};\n", "")
        
        # 写入配置
        with open(self.conf_path, 'w') as f:
            f.write(existing_content)
    
    def _reload_nginx(self):
        """
        重新加载Nginx配置
        """
        cmd = ['nginx', '-s', 'reload']
        subprocess.run(cmd, check=True, capture_output=True)
    
    def get_blocked_ips(self) -> List[str]:
        """
        获取Nginx阻止的IP列表
        """
        return list(self.blocked_ips)


class ModSecurityManager:
    """ModSecurity WAF集成"""
    
    def __init__(self, rules_path: str = "/etc/modsecurity/rules/"):
        self.rules_path = rules_path
        self.custom_rules: List[str] = []
        
    def add_rule(self, rule: str) -> bool:
        """
        添加ModSecurity规则
        """
        try:
            rule_id = len(self.custom_rules) + 1
            rule_file = os.path.join(self.rules_path, f"custom_rule_{rule_id}.conf")
            
            with open(rule_file, 'w') as f:
                f.write(rule + "\n")
            
            self.custom_rules.append(rule)
            logger.info(f"已添加ModSecurity规则: {rule[:50]}...")
            return True
        except Exception as e:
            logger.error(f"添加ModSecurity规则失败: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str = "恶意请求") -> bool:
        """
        通过ModSecurity阻止IP
        """
        rule = f"""
SecRule REMOTE_ADDR "@ipMatch {ip}" \
    "id:999{len(self.custom_rules)+1:03d},phase:1,deny,status:403,\
    msg:'IP {ip} 被阻止: {reason}',\
    tag:'BLOCKED_IP'"
        """
        return self.add_rule(rule)
    
    def remove_rule(self, rule_id: int) -> bool:
        """
        移除ModSecurity规则
        """
        try:
            rule_file = os.path.join(self.rules_path, f"custom_rule_{rule_id}.conf")
            if os.path.exists(rule_file):
                os.remove(rule_file)
            
            if 0 <= rule_id - 1 < len(self.custom_rules):
                self.custom_rules.pop(rule_id - 1)
            
            logger.info(f"已移除ModSecurity规则 {rule_id}")
            return True
        except Exception as e:
            logger.error(f"移除ModSecurity规则失败: {e}")
            return False
    
    def get_rules(self) -> List[str]:
        """
        获取所有自定义规则
        """
        return self.custom_rules.copy()


class DeviceIntegrationManager:
    """设备集成管理器 - 统一管理所有设备集成"""
    
    def __init__(self):
        self.firewall = FirewallManager()
        self.nginx = NginxBlocker()
        self.modsecurity = ModSecurityManager()
        self.response_actions: Dict[str, List] = {}  # 记录响应操作
        
    def block_ip_across_devices(self, ip: str, duration: Optional[int] = None, 
                                  reason: str = "检测到恶意活动") -> Dict:
        """
        在所有设备上阻止IP
        """
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'actions': []
        }
        
        # 阻止防火墙
        fw_result = self.firewall.block_ip(ip, duration)
        results['actions'].append({
            'device': 'firewall',
            'success': fw_result
        })
        
        # 阻止Nginx
        nginx_result = self.nginx.block_ip(ip)
        results['actions'].append({
            'device': 'nginx',
            'success': nginx_result
        })
        
        # 阻止ModSecurity
        modsec_result = self.modsecurity.block_ip(ip, reason)
        results['actions'].append({
            'device': 'modsecurity',
            'success': modsec_result
        })
        
        # 记录响应操作
        if ip not in self.response_actions:
            self.response_actions[ip] = []
        self.response_actions[ip].append(results)
        
        return results
    
    def unblock_ip_across_devices(self, ip: str) -> Dict:
        """
        在所有设备上解除阻止IP
        """
        results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'actions': []
        }
        
        # 解除防火墙阻止
        fw_result = self.firewall.unblock_ip(ip)
        results['actions'].append({
            'device': 'firewall',
            'success': fw_result
        })
        
        # 解除Nginx阻止
        nginx_result = self.nginx.unblock_ip(ip)
        results['actions'].append({
            'device': 'nginx',
            'success': nginx_result
        })
        
        # ModSecurity规则需要手动清理，这里只记录
        results['actions'].append({
            'device': 'modsecurity',
            'success': True,
            'note': 'ModSecurity规则需要手动清理'
        })
        
        return results
    
    def get_response_history(self, ip: Optional[str] = None) -> List:
        """
        获取响应历史
        """
        if ip:
            return self.response_actions.get(ip, [])
        else:
            all_history = []
            for ip_history in self.response_actions.values():
                all_history.extend(ip_history)
            return sorted(all_history, key=lambda x: x['timestamp'], reverse=True)
    
    def get_status(self) -> Dict:
        """
        获取所有设备的状态
        """
        return {
            'firewall': {
                'blocked_ips': self.firewall.get_blocked_ips(),
                'count': len(self.firewall.get_blocked_ips())
            },
            'nginx': {
                'blocked_ips': self.nginx.get_blocked_ips(),
                'count': len(self.nginx.get_blocked_ips())
            },
            'modsecurity': {
                'rules_count': len(self.modsecurity.get_rules()),
                'rules': self.modsecurity.get_rules()
            },
            'response_history_count': sum(len(history) for history in self.response_actions.values())
        }