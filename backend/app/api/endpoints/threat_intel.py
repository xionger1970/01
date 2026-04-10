from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict
from app.threat_intel.intel_manager import threat_intel_manager

router = APIRouter()

@router.get("/stats", response_model=Dict)
def get_threat_intel_stats():
    """获取威胁情报统计信息"""
    stats = threat_intel_manager.get_stats()
    return stats

@router.get("/malicious-ips", response_model=List[str])
def get_malicious_ips():
    """获取恶意IP列表"""
    from app.core.database import db_manager
    cursor = db_manager.execute_pg_query("SELECT DISTINCT source_ip FROM attack_events WHERE severity IN ('high', 'critical')")
    rows = cursor.fetchall()
    ips = []
    for row in rows:
        if isinstance(row, dict):
            ips.append(str(row.get('source_ip', '')))
        elif isinstance(row, (list, tuple)):
            ips.append(str(row[3] if len(row) > 3 else row[0]))
    ips = [ip for ip in ips if ip]
    intel_ips = list(threat_intel_manager.threat_intel_data.get('malicious_ips', []))
    all_ips = list(set(ips + intel_ips))
    return all_ips

@router.get("/malicious-domains", response_model=List[str])
def get_malicious_domains():
    """获取恶意域名列表"""
    domains = list(threat_intel_manager.threat_intel_data['malicious_domains'])
    return domains

@router.get("/apt-groups", response_model=Dict)
def get_apt_groups():
    """获取APT组织信息"""
    apt_groups = threat_intel_manager.get_all_apt_groups()
    return apt_groups

@router.get("/threat-indicators", response_model=List[Dict])
def get_threat_indicators(limit: int = Query(100, ge=1, le=1000)):
    """获取威胁指标"""
    indicators = threat_intel_manager.get_threat_indicators(limit)
    return indicators

@router.post("/malicious-ips")
def add_malicious_ip(ip: str):
    """添加恶意IP"""
    threat_intel_manager.add_malicious_ip(ip)
    return {"message": f"IP {ip} added to malicious IP list"}

@router.post("/malicious-domains")
def add_malicious_domain(domain: str):
    """添加恶意域名"""
    threat_intel_manager.add_malicious_domain(domain)
    return {"message": f"Domain {domain} added to malicious domain list"}

@router.post("/malicious-urls")
def add_malicious_url(url: str):
    """添加恶意URL"""
    threat_intel_manager.add_malicious_url(url)
    return {"message": f"URL {url} added to malicious URL list"}

@router.delete("/malicious-ips/{ip}")
def delete_malicious_ip(ip: str):
    """删除恶意IP"""
    ips = threat_intel_manager.threat_intel_data.get('malicious_ips', [])
    if ip in ips:
        ips.remove(ip)
        return {"message": f"IP {ip} 已删除"}
    raise HTTPException(status_code=404, detail="IP未找到")

@router.delete("/malicious-domains/{domain}")
def delete_malicious_domain(domain: str):
    """删除恶意域名"""
    domains = threat_intel_manager.threat_intel_data.get('malicious_domains', [])
    if domain in domains:
        domains.remove(domain)
        return {"message": f"域名 {domain} 已删除"}
    raise HTTPException(status_code=404, detail="域名未找到")

@router.delete("/malicious-urls/{url:path}")
def delete_malicious_url(url: str):
    """删除恶意URL"""
    urls = threat_intel_manager.threat_intel_data.get('malicious_urls', [])
    if url in urls:
        urls.remove(url)
        return {"message": f"URL 已删除"}
    raise HTTPException(status_code=404, detail="URL未找到")

@router.delete("/threat-indicators/{indicator_id}")
def delete_threat_indicator(indicator_id: str):
    """删除威胁指标"""
    indicators = threat_intel_manager.threat_intel_data.get('threat_indicators', [])
    for i, indicator in enumerate(indicators):
        if isinstance(indicator, dict) and str(indicator.get('id', '')) == str(indicator_id):
            indicators.pop(i)
            return {"message": "威胁指标已删除", "id": indicator_id}
    raise HTTPException(status_code=404, detail="威胁指标未找到")

@router.get("/check/ip/{ip}")
def check_ip(ip: str):
    """检查IP是否为恶意IP"""
    is_malicious = threat_intel_manager.check_ip(ip)
    return {"ip": ip, "is_malicious": is_malicious}

@router.get("/check/domain/{domain}")
def check_domain(domain: str):
    """检查域名是否为恶意域名"""
    is_malicious = threat_intel_manager.check_domain(domain)
    return {"domain": domain, "is_malicious": is_malicious}

@router.get("/check/url")
def check_url(url: str = Query(..., description="URL to check")):
    """检查URL是否为恶意URL"""
    is_malicious = threat_intel_manager.check_url(url)
    return {"url": url, "is_malicious": is_malicious}

@router.get("/malicious-hashes", response_model=List[str])
def get_malicious_hashes():
    """获取恶意文件哈希列表"""
    hashes = list(threat_intel_manager.threat_intel_data['malicious_hashes'])
    return hashes

@router.get("/threat-campaigns", response_model=Dict)
def get_threat_campaigns():
    """获取威胁活动信息"""
    campaigns = threat_intel_manager.get_threat_campaigns()
    return campaigns

@router.get("/vulnerabilities", response_model=Dict)
def get_vulnerabilities():
    """获取漏洞情报"""
    vulnerabilities = threat_intel_manager.get_vulnerabilities()
    return vulnerabilities

@router.get("/vulnerabilities/{cve_id}", response_model=Dict)
def get_vulnerability_by_cve(cve_id: str):
    """根据CVE ID获取漏洞情报"""
    vulnerability = threat_intel_manager.get_vulnerability_by_cve(cve_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability

@router.get("/check/hash/{hash_val}")
def check_hash(hash_val: str):
    """检查文件哈希是否为恶意哈希"""
    is_malicious = threat_intel_manager.check_hash(hash_val)
    return {"hash": hash_val, "is_malicious": is_malicious}

@router.get("/threat-score/{indicator_type}/{indicator}")
def get_threat_score(indicator_type: str, indicator: str):
    """获取威胁指标的评分"""
    if indicator_type not in ['ip', 'domain', 'url', 'hash']:
        raise HTTPException(status_code=400, detail="Invalid indicator type")
    score = threat_intel_manager.get_threat_score(indicator, indicator_type)
    return {"indicator": indicator, "indicator_type": indicator_type, "threat_score": score}

@router.post("/malicious-hashes")
def add_malicious_hash(hash_val: str):
    """添加恶意文件哈希"""
    threat_intel_manager.add_malicious_hash(hash_val)
    return {"message": f"Hash {hash_val} added to malicious hash list"}

@router.delete("/malicious-hashes/{hash_val}")
def delete_malicious_hash(hash_val: str):
    """删除恶意文件哈希"""
    hashes = threat_intel_manager.threat_intel_data.get('malicious_hashes', [])
    if hash_val in hashes:
        hashes.remove(hash_val)
        return {"message": f"Hash {hash_val} 已删除"}
    raise HTTPException(status_code=404, detail="哈希未找到")
