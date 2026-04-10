import pytest
import os
import tempfile
import shutil
from datetime import datetime
from app.responders.device_integration import (
    FirewallManager,
    NginxBlocker,
    ModSecurityManager,
    DeviceIntegrationManager
)

class TestFirewallManager:
    def setup_method(self):
        self.firewall = FirewallManager()
    
    def test_block_ip(self, monkeypatch):
        """测试阻止IP"""
        # 模拟subprocess.run
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        success = self.firewall.block_ip('192.168.1.1')
        assert success is True
        assert '192.168.1.1' in self.firewall.blocked_ips
    
    def test_unblock_ip(self, monkeypatch):
        """测试解除阻止IP"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.firewall.block_ip('192.168.1.1')
        success = self.firewall.unblock_ip('192.168.1.1')
        assert success is True
        assert '192.168.1.1' not in self.firewall.blocked_ips
    
    def test_get_blocked_ips(self, monkeypatch):
        """测试获取被阻止的IP列表"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.firewall.block_ip('192.168.1.1')
        self.firewall.block_ip('192.168.1.2')
        
        blocked_ips = self.firewall.get_blocked_ips()
        assert '192.168.1.1' in blocked_ips
        assert '192.168.1.2' in blocked_ips
        assert len(blocked_ips) == 2
    
    def test_clear_all_blocks(self, monkeypatch):
        """测试清除所有阻止"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.firewall.block_ip('192.168.1.1')
        self.firewall.block_ip('192.168.1.2')
        
        success = self.firewall.clear_all_blocks()
        assert success is True
        assert len(self.firewall.blocked_ips) == 0


class TestNginxBlocker:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.conf_path = os.path.join(self.temp_dir, 'blocklist.conf')
        self.nginx = NginxBlocker(conf_path=self.conf_path)
    
    def teardown_method(self):
        shutil.rmtree(self.temp_dir)
    
    def test_block_ip(self, monkeypatch):
        """测试通过Nginx阻止IP"""
        def mock_reload(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_reload)
        
        success = self.nginx.block_ip('192.168.1.1')
        assert success is True
        assert '192.168.1.1' in self.nginx.blocked_ips
        
        # 验证配置文件
        with open(self.conf_path, 'r') as f:
            content = f.read()
            assert 'deny 192.168.1.1;' in content
    
    def test_unblock_ip(self, monkeypatch):
        """测试解除Nginx阻止"""
        def mock_reload(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_reload)
        
        self.nginx.block_ip('192.168.1.1')
        success = self.nginx.unblock_ip('192.168.1.1')
        assert success is True
        assert '192.168.1.1' not in self.nginx.blocked_ips
    
    def test_get_blocked_ips(self, monkeypatch):
        """测试获取Nginx阻止的IP列表"""
        def mock_reload(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_reload)
        
        self.nginx.block_ip('192.168.1.1')
        self.nginx.block_ip('192.168.1.2')
        
        blocked_ips = self.nginx.get_blocked_ips()
        assert '192.168.1.1' in blocked_ips
        assert '192.168.1.2' in blocked_ips


class TestModSecurityManager:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.modsec = ModSecurityManager(rules_path=self.temp_dir)
    
    def teardown_method(self):
        shutil.rmtree(self.temp_dir)
    
    def test_add_rule(self):
        """测试添加ModSecurity规则"""
        rule = "SecRule ARGS \"attack\" \"id:1000,deny\""
        success = self.modsec.add_rule(rule)
        assert success is True
        assert len(self.modsec.get_rules()) == 1
    
    def test_block_ip(self):
        """测试通过ModSecurity阻止IP"""
        success = self.modsec.block_ip('192.168.1.1', '恶意请求')
        assert success is True
        assert len(self.modsec.get_rules()) == 1
    
    def test_remove_rule(self):
        """测试移除ModSecurity规则"""
        self.modsec.block_ip('192.168.1.1')
        success = self.modsec.remove_rule(1)
        assert success is True
        assert len(self.modsec.get_rules()) == 0
    
    def test_get_rules(self):
        """测试获取所有自定义规则"""
        self.modsec.block_ip('192.168.1.1')
        self.modsec.block_ip('192.168.1.2')
        
        rules = self.modsec.get_rules()
        assert len(rules) == 2


class TestDeviceIntegrationManager:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = DeviceIntegrationManager()
        
        # 配置测试路径
        self.manager.nginx = NginxBlocker(conf_path=os.path.join(self.temp_dir, 'blocklist.conf'))
        self.manager.modsecurity = ModSecurityManager(rules_path=self.temp_dir)
    
    def teardown_method(self):
        shutil.rmtree(self.temp_dir)
    
    def test_block_ip_across_devices(self, monkeypatch):
        """测试在所有设备上阻止IP"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        result = self.manager.block_ip_across_devices('192.168.1.1', 3600, '测试阻止')
        
        assert result['ip'] == '192.168.1.1'
        assert 'actions' in result
        assert len(result['actions']) == 3
    
    def test_unblock_ip_across_devices(self, monkeypatch):
        """测试在所有设备上解除阻止IP"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.manager.block_ip_across_devices('192.168.1.1')
        result = self.manager.unblock_ip_across_devices('192.168.1.1')
        
        assert result['ip'] == '192.168.1.1'
        assert 'actions' in result
        assert len(result['actions']) == 3
    
    def test_get_response_history(self, monkeypatch):
        """测试获取响应历史"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.manager.block_ip_across_devices('192.168.1.1')
        self.manager.block_ip_across_devices('192.168.1.2')
        
        # 获取所有历史
        history = self.manager.get_response_history()
        assert len(history) == 2
        
        # 获取特定IP的历史
        ip_history = self.manager.get_response_history('192.168.1.1')
        assert len(ip_history) == 1
    
    def test_get_status(self, monkeypatch):
        """测试获取所有设备的状态"""
        def mock_run(*args, **kwargs):
            return None
        
        monkeypatch.setattr('subprocess.run', mock_run)
        
        self.manager.block_ip_across_devices('192.168.1.1')
        
        status = self.manager.get_status()
        
        assert 'firewall' in status
        assert 'nginx' in status
        assert 'modsecurity' in status
        assert 'response_history_count' in status
