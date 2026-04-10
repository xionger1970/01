import ipaddress
from typing import List, Optional, Set

class WhitelistManager:
    def __init__(self):
        """
        初始化白名单管理器
        """
        self.ip_whitelist = set()  # 存储白名单IP地址
        self.domain_whitelist = set()  # 存储白名单域名
        self.ip_ranges = []  # 存储白名单IP范围
    
    def add_ip(self, ip: str) -> bool:
        """
        添加IP到白名单
        :param ip: IP地址
        :return: 是否添加成功
        """
        try:
            # 验证IP地址格式
            ipaddress.ip_address(ip)
            self.ip_whitelist.add(ip)
            return True
        except ValueError:
            return False
    
    def remove_ip(self, ip: str) -> bool:
        """
        从白名单移除IP
        :param ip: IP地址
        :return: 是否移除成功
        """
        if ip in self.ip_whitelist:
            self.ip_whitelist.remove(ip)
            return True
        return False
    
    def add_ip_range(self, ip_range: str) -> bool:
        """
        添加IP范围到白名单
        :param ip_range: IP范围，格式如 "192.168.1.0/24"
        :return: 是否添加成功
        """
        try:
            # 验证IP范围格式
            network = ipaddress.ip_network(ip_range)
            self.ip_ranges.append(network)
            return True
        except ValueError:
            return False
    
    def remove_ip_range(self, ip_range: str) -> bool:
        """
        从白名单移除IP范围
        :param ip_range: IP范围，格式如 "192.168.1.0/24"
        :return: 是否移除成功
        """
        try:
            network = ipaddress.ip_network(ip_range)
            if network in self.ip_ranges:
                self.ip_ranges.remove(network)
                return True
            return False
        except ValueError:
            return False
    
    def add_domain(self, domain: str) -> bool:
        """
        添加域名到白名单
        :param domain: 域名
        :return: 是否添加成功
        """
        # 简单的域名格式验证
        if domain and '.' in domain:
            self.domain_whitelist.add(domain)
            return True
        return False
    
    def remove_domain(self, domain: str) -> bool:
        """
        从白名单移除域名
        :param domain: 域名
        :return: 是否移除成功
        """
        if domain in self.domain_whitelist:
            self.domain_whitelist.remove(domain)
            return True
        return False
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        """
        检查IP是否在白名单中
        :param ip: IP地址
        :return: 是否在白名单中
        """
        # 首先检查是否在直接白名单中
        if ip in self.ip_whitelist:
            return True
        
        # 然后检查是否在IP范围内
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.ip_ranges:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        
        return False
    
    def is_domain_whitelisted(self, domain: str) -> bool:
        """
        检查域名是否在白名单中
        :param domain: 域名
        :return: 是否在白名单中
        """
        # 直接检查域名是否在白名单中
        if domain in self.domain_whitelist:
            return True
        
        # 检查子域名是否在白名单中（例如，example.com 白名单包含 sub.example.com）
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.domain_whitelist:
                return True
        
        return False
    
    def get_ip_whitelist(self) -> Set[str]:
        """
        获取IP白名单
        :return: IP白名单集合
        """
        return self.ip_whitelist
    
    def get_ip_ranges(self) -> List[ipaddress.IPv4Network]:
        """
        获取IP范围白名单
        :return: IP范围列表
        """
        return self.ip_ranges
    
    def get_domain_whitelist(self) -> Set[str]:
        """
        获取域名白名单
        :return: 域名白名单集合
        """
        return self.domain_whitelist
    
    def clear_ip_whitelist(self):
        """
        清空IP白名单
        """
        self.ip_whitelist.clear()
    
    def clear_ip_ranges(self):
        """
        清空IP范围白名单
        """
        self.ip_ranges.clear()
    
    def clear_domain_whitelist(self):
        """
        清空域名白名单
        """
        self.domain_whitelist.clear()
    
    def clear_all(self):
        """
        清空所有白名单
        """
        self.clear_ip_whitelist()
        self.clear_ip_ranges()
        self.clear_domain_whitelist()
    
    def import_whitelist(self, ip_list: List[str] = None, domain_list: List[str] = None, ip_range_list: List[str] = None):
        """
        导入白名单
        :param ip_list: IP列表
        :param domain_list: 域名列表
        :param ip_range_list: IP范围列表
        """
        if ip_list:
            for ip in ip_list:
                self.add_ip(ip)
        
        if domain_list:
            for domain in domain_list:
                self.add_domain(domain)
        
        if ip_range_list:
            for ip_range in ip_range_list:
                self.add_ip_range(ip_range)
    
    def export_whitelist(self) -> dict:
        """
        导出白名单
        :return: 包含所有白名单的字典
        """
        return {
            'ips': list(self.ip_whitelist),
            'domains': list(self.domain_whitelist),
            'ip_ranges': [str(network) for network in self.ip_ranges]
        }