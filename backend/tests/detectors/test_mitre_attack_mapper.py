import pytest
from app.detectors.mitre_attack_mapper import MitreAttackMapper

class TestMitreAttackMapper:
    def setup_method(self):
        self.mapper = MitreAttackMapper()
    
    def test_map_attack(self):
        """测试攻击类型映射到MITRE ATT&CK技术"""
        result = self.mapper.map_attack("SQL注入")
        assert result is not None
        assert result["technique_id"] == "T1571"
        assert result["tactic"] == "初始访问"
    
    def test_map_nonexistent_attack(self):
        """测试不存在的攻击类型"""
        result = self.mapper.map_attack("不存在的攻击")
        assert result is None
    
    def test_get_mitre_info(self):
        """测试根据技术ID获取MITRE ATT&CK信息"""
        result = self.mapper.get_mitre_info("T1110")
        assert result is not None
        assert result["technique_name"] == "暴力破解"
    
    def test_get_tactics(self):
        """测试获取所有战术"""
        tactics = self.mapper.get_tactics()
        assert isinstance(tactics, list)
        assert len(tactics) > 0
        assert "初始访问" in tactics
    
    def test_get_techniques_by_tactic(self):
        """测试根据战术获取技术"""
        techniques = self.mapper.get_techniques_by_tactic("初始访问")
        assert isinstance(techniques, list)
        assert len(techniques) > 0
        for technique in techniques:
            assert technique["tactic"] == "初始访问"
    
    def test_add_new_mapping(self):
        """测试添加新的映射"""
        self.mapper.add_new_mapping(
            "新攻击",
            "T9999",
            "新技术",
            "新战术",
            "新描述"
        )
        result = self.mapper.map_attack("新攻击")
        assert result is not None
        assert result["technique_id"] == "T9999"
        assert result["tactic"] == "新战术"
    
    def test_update_mapping(self):
        """测试更新映射"""
        self.mapper.update_mapping(
            "SQL注入",
            "T1571",
            "更新的技术",
            "更新的战术",
            "更新的描述"
        )
        result = self.mapper.map_attack("SQL注入")
        assert result is not None
        assert result["technique_name"] == "更新的技术"
        assert result["tactic"] == "更新的战术"
    
    def test_remove_mapping(self):
        """测试移除映射"""
        self.mapper.remove_mapping("SQL注入")
        result = self.mapper.map_attack("SQL注入")
        assert result is None
    
    def test_get_all_mappings(self):
        """测试获取所有映射"""
        mappings = self.mapper.get_all_mappings()
        assert isinstance(mappings, dict)
        assert len(mappings) > 0
    
    def test_export_import_mappings(self, tmp_path):
        """测试导出和导入映射"""
        # 导出映射
        export_path = tmp_path / "mitre_mappings.json"
        self.mapper.export_mappings(str(export_path))
        
        # 创建新的映射器并导入
        new_mapper = MitreAttackMapper()
        new_mapper.import_mappings(str(export_path))
        
        # 验证导入成功
        mappings = new_mapper.get_all_mappings()
        assert isinstance(mappings, dict)
        assert len(mappings) > 0