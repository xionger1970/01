import pytest
from app.detectors.whitelist_manager import WhitelistManager

class TestWhitelistManager:
    def setup_method(self):
        self.manager = WhitelistManager()
    
    def test_add_ip(self):
        """测试添加IP到白名单"""
        # 测试添加有效IP
        result = self.manager.add_ip('192.168.1.1')
        assert result is True
        
        # 测试添加无效IP
        result = self.manager.add_ip('invalid_ip')
        assert result is False
    
    def test_remove_ip(self):
        """测试从白名单移除IP"""
        # 添加IP
        self.manager.add_ip('192.168.1.1')
        
        # 测试移除存在的IP
        result = self.manager.remove_ip('192.168.1.1')
        assert result is True
        
        # 测试移除不存在的IP
        result = self.manager.remove_ip('192.168.1.1')
        assert result is False
    
    def test_add_ip_range(self):
        """测试添加IP范围到白名单"""
        # 测试添加有效IP范围
        result = self.manager.add_ip_range('192.168.1.0/24')
        assert result is True
        
        # 测试添加无效IP范围
        result = self.manager.add_ip_range('invalid_range')
        assert result is False
    
    def test_remove_ip_range(self):
        """测试从白名单移除IP范围"""
        # 添加IP范围
        self.manager.add_ip_range('192.168.1.0/24')
        
        # 测试移除存在的IP范围
        result = self.manager.remove_ip_range('192.168.1.0/24')
        assert result is True
        
        # 测试移除不存在的IP范围
        result = self.manager.remove_ip_range('192.168.1.0/24')
        assert result is False
    
    def test_add_domain(self):
        """测试添加域名到白名单"""
        # 测试添加有效域名
        result = self.manager.add_domain('example.com')
        assert result is True
        
        # 测试添加无效域名
        result = self.manager.add_domain('invalid')
        assert result is False
    
    def test_remove_domain(self):
        """测试从白名单移除域名"""
        # 添加域名
        self.manager.add_domain('example.com')
        
        # 测试移除存在的域名
        result = self.manager.remove_domain('example.com')
        assert result is True
        
        # 测试移除不存在的域名
        result = self.manager.remove_domain('example.com')
        assert result is False
    
    def test_is_ip_whitelisted(self):
        """测试检查IP是否在白名单中"""
        # 添加IP
        self.manager.add_ip('192.168.1.1')
        
        # 测试存在的IP
        assert self.manager.is_ip_whitelisted('192.168.1.1') is True
        
        # 测试不存在的IP
        assert self.manager.is_ip_whitelisted('192.168.1.2') is False
    
    def test_is_ip_in_range_whitelisted(self):
        """测试检查IP是否在白名单IP范围内"""
        # 添加IP范围
        self.manager.add_ip_range('192.168.1.0/24')
        
        # 测试范围内的IP
        assert self.manager.is_ip_whitelisted('192.168.1.5') is True
        
        # 测试范围外的IP
        assert self.manager.is_ip_whitelisted('192.168.2.1') is False
    
    def test_is_domain_whitelisted(self):
        """测试检查域名是否在白名单中"""
        # 添加域名
        self.manager.add_domain('example.com')
        
        # 测试存在的域名
        assert self.manager.is_domain_whitelisted('example.com') is True
        
        # 测试不存在的域名
        assert self.manager.is_domain_whitelisted('test.com') is False
    
    def test_is_subdomain_whitelisted(self):
        """测试检查子域名是否在白名单中"""
        # 添加域名
        self.manager.add_domain('example.com')
        
        # 测试子域名
        assert self.manager.is_domain_whitelisted('sub.example.com') is True
        assert self.manager.is_domain_whitelisted('sub.sub.example.com') is True
    
    def test_get_ip_whitelist(self):
        """测试获取IP白名单"""
        # 添加IP
        self.manager.add_ip('192.168.1.1')
        self.manager.add_ip('192.168.1.2')
        
        # 获取IP白名单
        ip_whitelist = self.manager.get_ip_whitelist()
        assert isinstance(ip_whitelist, set)
        assert '192.168.1.1' in ip_whitelist
        assert '192.168.1.2' in ip_whitelist
    
    def test_get_ip_ranges(self):
        """测试获取IP范围白名单"""
        # 添加IP范围
        self.manager.add_ip_range('192.168.1.0/24')
        
        # 获取IP范围白名单
        ip_ranges = self.manager.get_ip_ranges()
        assert isinstance(ip_ranges, list)
        assert len(ip_ranges) == 1
    
    def test_get_domain_whitelist(self):
        """测试获取域名白名单"""
        # 添加域名
        self.manager.add_domain('example.com')
        self.manager.add_domain('test.com')
        
        # 获取域名白名单
        domain_whitelist = self.manager.get_domain_whitelist()
        assert isinstance(domain_whitelist, set)
        assert 'example.com' in domain_whitelist
        assert 'test.com' in domain_whitelist
    
    def test_clear_ip_whitelist(self):
        """测试清空IP白名单"""
        # 添加IP
        self.manager.add_ip('192.168.1.1')
        
        # 清空IP白名单
        self.manager.clear_ip_whitelist()
        
        # 验证IP白名单已清空
        ip_whitelist = self.manager.get_ip_whitelist()
        assert len(ip_whitelist) == 0
    
    def test_clear_ip_ranges(self):
        """测试清空IP范围白名单"""
        # 添加IP范围
        self.manager.add_ip_range('192.168.1.0/24')
        
        # 清空IP范围白名单
        self.manager.clear_ip_ranges()
        
        # 验证IP范围白名单已清空
        ip_ranges = self.manager.get_ip_ranges()
        assert len(ip_ranges) == 0
    
    def test_clear_domain_whitelist(self):
        """测试清空域名白名单"""
        # 添加域名
        self.manager.add_domain('example.com')
        
        # 清空域名白名单
        self.manager.clear_domain_whitelist()
        
        # 验证域名白名单已清空
        domain_whitelist = self.manager.get_domain_whitelist()
        assert len(domain_whitelist) == 0
    
    def test_clear_all(self):
        """测试清空所有白名单"""
        # 添加IP、IP范围和域名
        self.manager.add_ip('192.168.1.1')
        self.manager.add_ip_range('192.168.1.0/24')
        self.manager.add_domain('example.com')
        
        # 清空所有白名单
        self.manager.clear_all()
        
        # 验证所有白名单已清空
        assert len(self.manager.get_ip_whitelist()) == 0
        assert len(self.manager.get_ip_ranges()) == 0
        assert len(self.manager.get_domain_whitelist()) == 0
    
    def test_import_whitelist(self):
        """测试导入白名单"""
        # 导入白名单
        self.manager.import_whitelist(
            ip_list=['192.168.1.1', '192.168.1.2'],
            domain_list=['example.com', 'test.com'],
            ip_range_list=['192.168.1.0/24', '10.0.0.0/8']
        )
        
        # 验证导入成功
        assert '192.168.1.1' in self.manager.get_ip_whitelist()
        assert 'example.com' in self.manager.get_domain_whitelist()
        assert len(self.manager.get_ip_ranges()) == 2
    
    def test_export_whitelist(self):
        """测试导出白名单"""
        # 添加IP、IP范围和域名
        self.manager.add_ip('192.168.1.1')
        self.manager.add_ip_range('192.168.1.0/24')
        self.manager.add_domain('example.com')
        
        # 导出白名单
        whitelist = self.manager.export_whitelist()
        
        # 验证导出成功
        assert isinstance(whitelist, dict)
        assert '192.168.1.1' in whitelist['ips']
        assert '192.168.1.0/24' in whitelist['ip_ranges']
        assert 'example.com' in whitelist['domains']