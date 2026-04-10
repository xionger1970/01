import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple

class MitreAttackMapper:
    def __init__(self):
        self.mitre_attack_mappings = {
            # 映射常见攻击类型到MITRE ATT&CK技术
            "SQL注入": {
                "technique_id": "T1571",
                "technique_name": "非预期的命令执行",
                "tactic": "初始访问",
                "description": "通过SQL注入执行未授权的数据库操作"
            },
            "XSS攻击": {
                "technique_id": "T1589",
                "technique_name": "创建账户",
                "tactic": "权限提升",
                "description": "通过跨站脚本攻击获取用户会话信息"
            },
            "命令注入": {
                "technique_id": "T1059",
                "technique_name": "命令和脚本解释器",
                "tactic": "执行",
                "description": "通过命令注入执行恶意命令"
            },
            "暴力破解": {
                "technique_id": "T1110",
                "technique_name": "暴力破解",
                "tactic": "凭证获取",
                "description": "通过暴力破解获取用户凭证"
            },
            "恶意文件上传": {
                "technique_id": "T1132",
                "technique_name": "数据编码",
                "tactic": "防御规避",
                "description": "上传恶意文件到目标系统"
            },
            "DDoS攻击": {
                "technique_id": "T1498",
                "technique_name": "网络拒绝服务",
                "tactic": "影响",
                "description": "通过分布式拒绝服务攻击瘫痪目标系统"
            },
            "敏感信息泄露": {
                "technique_id": "T1530",
                "technique_name": "数据从本地系统泄露",
                "tactic": "数据泄露",
                "description": "未授权访问敏感信息"
            },
            "未授权访问": {
                "technique_id": "T1078",
                "technique_name": "有效账户",
                "tactic": "初始访问",
                "description": "使用有效账户进行未授权访问"
            },
            "Log4Shell": {
                "technique_id": "T1190",
                "technique_name": "利用公开的 exploits",
                "tactic": "初始访问",
                "description": "利用Log4j远程代码执行漏洞"
            },
            "Spring4Shell": {
                "technique_id": "T1190",
                "technique_name": "利用公开的 exploits",
                "tactic": "初始访问",
                "description": "利用Spring框架远程代码执行漏洞"
            },
            "Heartbleed": {
                "technique_id": "T1190",
                "technique_name": "利用公开的 exploits",
                "tactic": "初始访问",
                "description": "利用OpenSSL Heartbleed漏洞获取敏感信息"
            },
            "Shellshock": {
                "technique_id": "T1190",
                "technique_name": "利用公开的 exploits",
                "tactic": "初始访问",
                "description": "利用Bash Shellshock漏洞执行代码"
            },
            "POC验证": {
                "technique_id": "T1190",
                "technique_name": "利用公开的 exploits",
                "tactic": "初始访问",
                "description": "对目标系统进行漏洞验证测试"
            }
        }
    
    def map_attack(self, attack_type: str) -> Optional[Dict]:
        """将攻击类型映射到MITRE ATT&CK框架"""
        return self.mitre_attack_mappings.get(attack_type)
    
    def get_mitre_info(self, technique_id: str) -> Optional[Dict]:
        """根据技术ID获取MITRE ATT&CK信息"""
        for attack_type, info in self.mitre_attack_mappings.items():
            if info.get("technique_id") == technique_id:
                return info
        return None
    
    def get_tactics(self) -> List[str]:
        """获取所有可用的战术"""
        tactics = set()
        for info in self.mitre_attack_mappings.values():
            tactics.add(info.get("tactic"))
        return list(tactics)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """根据战术获取相关技术"""
        techniques = []
        for attack_type, info in self.mitre_attack_mappings.items():
            if info.get("tactic") == tactic:
                techniques.append({
                    "attack_type": attack_type,
                    **info
                })
        return techniques
    
    def update_mapping(self, attack_type: str, technique_id: str, technique_name: str, tactic: str, description: str):
        """更新攻击类型到MITRE ATT&CK的映射"""
        self.mitre_attack_mappings[attack_type] = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "description": description
        }
    
    def add_new_mapping(self, attack_type: str, technique_id: str, technique_name: str, tactic: str, description: str):
        """添加新的攻击类型到MITRE ATT&CK的映射"""
        self.update_mapping(attack_type, technique_id, technique_name, tactic, description)
    
    def remove_mapping(self, attack_type: str):
        """移除攻击类型到MITRE ATT&CK的映射"""
        if attack_type in self.mitre_attack_mappings:
            del self.mitre_attack_mappings[attack_type]
    
    def get_all_mappings(self) -> Dict:
        """获取所有映射"""
        return self.mitre_attack_mappings
    
    def export_mappings(self, file_path: str):
        """导出映射到JSON文件"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(self.mitre_attack_mappings, f, ensure_ascii=False, indent=2)
    
    def import_mappings(self, file_path: str):
        """从JSON文件导入映射"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.mitre_attack_mappings = json.load(f)
            return True
        except Exception as e:
            print(f"导入映射失败: {e}")
            return False