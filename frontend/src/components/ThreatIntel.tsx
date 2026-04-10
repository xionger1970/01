import React, { useEffect, useState, useCallback } from 'react';
import { Card, Row, Col, Table, Tag, Statistic, Tabs, Button, Input, Modal, Form, Select, Alert, Spin, Popconfirm, message, Space, Descriptions, Divider, Upload } from 'antd';
import { ApiOutlined, AlertOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, SearchOutlined, SafetyCertificateOutlined, GlobalOutlined, LinkOutlined, UploadOutlined, DownloadOutlined, EyeOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { TextArea } = Input;

interface ThreatIntelStats {
  malicious_ips_count: number;
  malicious_domains_count: number;
  malicious_urls_count: number;
  malicious_hashes_count: number;
  apt_groups_count: number;
  threat_campaigns_count: number;
  vulnerabilities_count: number;
  threat_indicators_count: number;
  last_updated: string;
}

interface APTGroup {
  name: string;
  country: string;
  description: string;
  tactics: string[];
  indicators: string[];
}

interface ThreatIndicator {
  id: string;
  type: string;
  indicator: string;
  description: string;
  severity: string;
  created_at: string;
}

const severityLabels: Record<string, string> = {
  critical: '严重', high: '高', medium: '中', low: '低', info: '信息'
};

const severityColors: Record<string, string> = {
  critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff'
};

const typeLabels: Record<string, string> = {
  ip: 'IP地址', domain: '域名', url: 'URL', hash: '文件哈希', email: '邮箱', file: '文件'
};

const ThreatIntel: React.FC = () => {
  const [stats, setStats] = useState<ThreatIntelStats | null>(null);
  const [maliciousIPs, setMaliciousIPs] = useState<any[]>([]);
  const [maliciousDomains, setMaliciousDomains] = useState<any[]>([]);
  const [maliciousHashes, setMaliciousHashes] = useState<any[]>([]);
  const [aptGroups, setAptGroups] = useState<{ [key: string]: APTGroup }>({});
  const [threatCampaigns, setThreatCampaigns] = useState<{ [key: string]: any }>({});
  const [vulnerabilities, setVulnerabilities] = useState<{ [key: string]: any }>({});
  const [threatIndicators, setThreatIndicators] = useState<ThreatIndicator[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIndicator | null>(null);
  const [form] = Form.useForm();
  const [actionType, setActionType] = useState<'ip' | 'domain' | 'url' | 'hash'>('ip');
  const [searchText, setSearchText] = useState('');
  const [batchModalVisible, setBatchModalVisible] = useState(false);
  const [batchText, setBatchText] = useState('');
  const [batchType, setBatchType] = useState<'ip' | 'domain' | 'url' | 'hash'>('ip');

  const fetchThreatIntelData = useCallback(async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    setError(null);
    try {
      const [statsRes, ipsRes, domainsRes, hashesRes, aptRes, campaignsRes, vulnsRes, indicatorsRes] = await Promise.all([
        axios.get('/api/threat-intel/stats'),
        axios.get('/api/threat-intel/malicious-ips'),
        axios.get('/api/threat-intel/malicious-domains'),
        axios.get('/api/threat-intel/malicious-hashes'),
        axios.get('/api/threat-intel/apt-groups'),
        axios.get('/api/threat-intel/threat-campaigns'),
        axios.get('/api/threat-intel/vulnerabilities'),
        axios.get('/api/threat-intel/threat-indicators')
      ]);
      setStats(statsRes.data);
      setMaliciousIPs(Array.isArray(ipsRes.data) ? ipsRes.data : []);
      setMaliciousDomains(Array.isArray(domainsRes.data) ? domainsRes.data : []);
      setMaliciousHashes(Array.isArray(hashesRes.data) ? hashesRes.data : []);
      setAptGroups(typeof aptRes.data === 'object' && aptRes.data !== null ? aptRes.data : {});
      setThreatCampaigns(typeof campaignsRes.data === 'object' && campaignsRes.data !== null ? campaignsRes.data : {});
      setVulnerabilities(typeof vulnsRes.data === 'object' && vulnsRes.data !== null ? vulnsRes.data : {});
      setThreatIndicators(Array.isArray(indicatorsRes.data) ? indicatorsRes.data : []);
    } catch (err) {
      setError('获取威胁情报数据失败');
      console.error('获取威胁情报数据失败:', err);
      setStats(null);
      setMaliciousIPs([]);
      setMaliciousDomains([]);
      setMaliciousHashes([]);
      setAptGroups({});
      setThreatCampaigns({});
      setVulnerabilities({});
      setThreatIndicators([]);
    } finally {
      if (showLoading) setInitialLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatIntelData(true);
    const interval = setInterval(() => fetchThreatIntelData(false), 30000);
    return () => clearInterval(interval);
  }, [fetchThreatIntelData]);

  const handleAddMaliciousItem = async (values: any) => {
    try {
      switch (actionType) {
        case 'ip':
          await axios.post('/api/threat-intel/malicious-ips', null, { params: { ip: values.item } });
          break;
        case 'domain':
          await axios.post('/api/threat-intel/malicious-domains', null, { params: { domain: values.item } });
          break;
        case 'url':
          await axios.post('/api/threat-intel/malicious-urls', null, { params: { url: values.item } });
          break;
        case 'hash':
          await axios.post('/api/threat-intel/malicious-hashes', null, { params: { hash_val: values.item } });
          break;
      }
      message.success('添加成功');
      setModalVisible(false);
      form.resetFields();
      fetchThreatIntelData();
    } catch (err) {
      message.error('添加失败，请重试');
      console.error('添加失败:', err);
    }
  };

  const handleBatchImport = async () => {
    if (!batchText.trim()) {
      message.warning('请输入要导入的数据');
      return;
    }
    const items = batchText.split('\n').map(item => item.trim()).filter(item => item.length > 0);
    if (items.length === 0) {
      message.warning('没有有效的数据');
      return;
    }
    let successCount = 0;
    let failCount = 0;
    for (const item of items) {
      try {
        switch (batchType) {
          case 'ip':
            await axios.post('/api/threat-intel/malicious-ips', null, { params: { ip: item } });
            break;
          case 'domain':
            await axios.post('/api/threat-intel/malicious-domains', null, { params: { domain: item } });
            break;
          case 'url':
            await axios.post('/api/threat-intel/malicious-urls', null, { params: { url: item } });
            break;
          case 'hash':
            await axios.post('/api/threat-intel/malicious-hashes', null, { params: { hash_val: item } });
            break;
        }
        successCount++;
      } catch (err) {
        failCount++;
      }
    }
    message.success(`批量导入完成：成功 ${successCount} 条，失败 ${failCount} 条`);
    setBatchModalVisible(false);
    setBatchText('');
    fetchThreatIntelData();
  };

  const handleDeleteIP = async (ip: string) => {
    try {
      await axios.delete(`/api/threat-intel/malicious-ips/${encodeURIComponent(ip)}`);
      message.success('删除成功');
      fetchThreatIntelData();
    } catch (err) {
      message.error('删除失败');
    }
  };

  const handleDeleteDomain = async (domain: string) => {
    try {
      await axios.delete(`/api/threat-intel/malicious-domains/${encodeURIComponent(domain)}`);
      message.success('删除成功');
      fetchThreatIntelData();
    } catch (err) {
      message.error('删除失败');
    }
  };

  const handleDeleteIndicator = async (id: string) => {
    try {
      await axios.delete(`/api/threat-intel/threat-indicators/${id}`);
      message.success('删除成功');
      fetchThreatIntelData();
    } catch (err) {
      message.error('删除失败');
    }
  };

  const handleDeleteHash = async (hash: string) => {
    try {
      await axios.delete(`/api/threat-intel/malicious-hashes/${encodeURIComponent(hash)}`);
      message.success('删除成功');
      fetchThreatIntelData();
    } catch (err) {
      message.error('删除失败');
    }
  };

  const handleExport = () => {
    const data = {
      malicious_ips: maliciousIPs,
      malicious_domains: maliciousDomains,
      malicious_hashes: maliciousHashes,
      threat_indicators: threatIndicators,
      apt_groups: aptGroups,
      threat_campaigns: threatCampaigns,
      vulnerabilities: vulnerabilities,
      exported_at: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_export_${dayjs().format('YYYYMMDD_HHmmss')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    message.success('导出成功');
  };

  const ipColumns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (ip: string) => <span style={{ fontFamily: 'monospace', color: '#ff4d4f', fontWeight: 500 }}>{ip}</span> },
    { title: '威胁等级', key: 'severity', width: 120, render: () => <Tag color="red">高危</Tag> },
    { title: '类型', key: 'type', width: 100, render: () => <Tag color="orange">恶意IP</Tag> },
    { title: '操作', key: 'action', width: 80, render: (_: any, record: any) => (
      <Popconfirm title="确定要删除该IP吗？" onConfirm={() => handleDeleteIP(record.ip)} okText="确定" cancelText="取消">
        <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
      </Popconfirm>
    )}
  ];

  const domainColumns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: '域名', dataIndex: 'domain', key: 'domain', render: (domain: string) => <span style={{ fontFamily: 'monospace', color: '#fa8c16', fontWeight: 500 }}>{domain}</span> },
    { title: '威胁等级', key: 'severity', width: 120, render: () => <Tag color="red">高危</Tag> },
    { title: '类型', key: 'type', width: 100, render: () => <Tag color="orange">恶意域名</Tag> },
    { title: '操作', key: 'action', width: 80, render: (_: any, record: any) => (
      <Popconfirm title="确定要删除该域名吗？" onConfirm={() => handleDeleteDomain(record.domain)} okText="确定" cancelText="取消">
        <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
      </Popconfirm>
    )}
  ];

  const hashColumns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: '文件哈希', dataIndex: 'hash', key: 'hash', render: (hash: string) => <span style={{ fontFamily: 'monospace', color: '#1890ff', fontWeight: 500, fontSize: 12 }}>{hash}</span> },
    { title: '威胁等级', key: 'severity', width: 120, render: () => <Tag color="red">高危</Tag> },
    { title: '类型', key: 'type', width: 100, render: () => <Tag color="blue">恶意哈希</Tag> },
    { title: '操作', key: 'action', width: 80, render: (_: any, record: any) => (
      <Popconfirm title="确定要删除该哈希吗？" onConfirm={() => handleDeleteHash(record.hash)} okText="确定" cancelText="取消">
        <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
      </Popconfirm>
    )}
  ];

  const indicatorColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 80 },
    { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (type: string) => <Tag color="blue">{typeLabels[type] || type}</Tag> },
    { title: '指标', dataIndex: 'indicator', key: 'indicator', render: (indicator: string) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{indicator}</span> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 100, render: (severity: string) => <Tag color={severityColors[severity] || 'blue'}>{severityLabels[severity] || severity}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 180, render: (time: string) => new Date(time).toLocaleString() },
    { title: '操作', key: 'action', width: 120, render: (_: any, record: ThreatIndicator) => (
      <Space size={4}>
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedIndicator(record); setDetailModalVisible(true); }}>详情</Button>
        <Popconfirm title="确定要删除该指标吗？" onConfirm={() => handleDeleteIndicator(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const filteredIPs = maliciousIPs.filter((ip: any) => {
    if (!searchText) return true;
    const ipStr = typeof ip === 'string' ? ip : ip.ip || '';
    return ipStr.toLowerCase().includes(searchText.toLowerCase());
  }).map((ip: any, index: number) => ({
    key: index, ip: typeof ip === 'string' ? ip : ip.ip || ip.source_ip || '', status: 'malicious'
  }));

  const filteredDomains = maliciousDomains.filter((domain: any) => {
    if (!searchText) return true;
    const domainStr = typeof domain === 'string' ? domain : domain.domain || '';
    return domainStr.toLowerCase().includes(searchText.toLowerCase());
  }).map((domain: any, index: number) => ({
    key: index, domain: typeof domain === 'string' ? domain : domain.domain || '', status: 'malicious'
  }));

  const filteredHashes = maliciousHashes.filter((hash: any) => {
    if (!searchText) return true;
    const hashStr = typeof hash === 'string' ? hash : hash.hash || '';
    return hashStr.toLowerCase().includes(searchText.toLowerCase());
  }).map((hash: any, index: number) => ({
    key: index, hash: typeof hash === 'string' ? hash : hash.hash || '', status: 'malicious'
  }));

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #1890ff, #722ed1)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          威胁情报中心
        </h2>
        <Space>
          <Input placeholder="搜索IP/域名/指标..." prefix={<SearchOutlined />} value={searchText} onChange={(e) => setSearchText(e.target.value)} style={{ width: 220 }} allowClear />
          <Button icon={<ReloadOutlined />} onClick={() => fetchThreatIntelData()}>刷新</Button>
          <Button icon={<UploadOutlined />} onClick={() => setBatchModalVisible(true)}>批量导入</Button>
          <Button icon={<DownloadOutlined />} onClick={handleExport}>导出</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalVisible(true)} style={{ background: 'linear-gradient(135deg, #1890ff, #722ed1)', border: 'none' }}>
            添加指标
          </Button>
        </Space>
      </div>

      {error && <Alert message={error} type="error" style={{ marginBottom: 24 }} closable onClose={() => setError(null)} />}

      <Spin spinning={initialLoading} description="加载中...">
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'恶意IP'}</span>} value={stats?.malicious_ips_count || 0} prefix={<ApiOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'恶意域名'}</span>} value={stats?.malicious_domains_count || 0} prefix={<GlobalOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'恶意哈希'}</span>} value={stats?.malicious_hashes_count || 0} prefix={<UploadOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'APT组织'}</span>} value={stats?.apt_groups_count || 0} prefix={<SafetyCertificateOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #eb2f96, #f56a00)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'威胁活动'}</span>} value={stats?.threat_campaigns_count || 0} prefix={<AlertOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={4}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'漏洞情报'}</span>} value={stats?.vulnerabilities_count || 0} prefix={<SafetyCertificateOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        </Row>

        <Card variant="borderless" style={{ borderRadius: 12 }}>
          <Tabs defaultActiveKey="ips" items={[
            { key: 'ips', label: <span><ApiOutlined /> {'恶意IP'}</span>, children: (
              <Table columns={ipColumns} dataSource={filteredIPs} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            )},
            { key: 'domains', label: <span><GlobalOutlined /> {'恶意域名'}</span>, children: (
              <Table columns={domainColumns} dataSource={filteredDomains} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            )},
            { key: 'hashes', label: <span><UploadOutlined /> {'恶意哈希'}</span>, children: (
              <Table columns={hashColumns} dataSource={filteredHashes} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            )},
            { key: 'apt', label: <span><SafetyCertificateOutlined /> {'APT组织'}</span>, children: (
              <Row gutter={16}>
                {Object.entries(aptGroups).map(([key, group]) => (
                  <Col span={8} key={key} style={{ marginBottom: 16 }}>
                    <Card title={<span style={{ fontWeight: 600 }}>{group.name}</span>} extra={<Tag color="blue">{group.country}</Tag>} variant="borderless" style={{ borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }}>
                      <p style={{ color: '#666', marginBottom: 12 }}>{group.description}</p>
                      <div style={{ marginBottom: 12 }}>
                        <strong style={{ fontSize: 13 }}>{'战术手法：'}</strong>
                        <div style={{ marginTop: 4 }}>{group.tactics.map((tactic, index) => <Tag key={index} color="blue" style={{ margin: 2 }}>{tactic}</Tag>)}</div>
                      </div>
                      <div>
                        <strong style={{ fontSize: 13 }}>{'威胁指标：'}</strong>
                        <div style={{ marginTop: 4 }}>{group.indicators.map((indicator, index) => <Tag key={index} color="orange" style={{ margin: 2 }}>{indicator}</Tag>)}</div>
                      </div>
                      {group.activity && (
                        <div style={{ marginTop: 12 }}>
                          <strong style={{ fontSize: 13 }}>{'活动时间：'}</strong>
                          <div style={{ marginTop: 4 }}>{group.activity}</div>
                        </div>
                      )}
                      {group.targets && group.targets.length > 0 && (
                        <div style={{ marginTop: 12 }}>
                          <strong style={{ fontSize: 13 }}>{'攻击目标：'}</strong>
                          <div style={{ marginTop: 4 }}>{group.targets.map((target, index) => <Tag key={index} color="green" style={{ margin: 2 }}>{target}</Tag>)}</div>
                        </div>
                      )}
                    </Card>
                  </Col>
                ))}
              </Row>
            )},
            { key: 'campaigns', label: <span><AlertOutlined /> {'威胁活动'}</span>, children: (
              <Row gutter={16}>
                {Object.entries(threatCampaigns).map(([key, campaign]) => (
                  <Col span={8} key={key} style={{ marginBottom: 16 }}>
                    <Card title={<span style={{ fontWeight: 600 }}>{campaign.name}</span>} extra={<Tag color="red">{campaign.status || 'Active'}</Tag>} variant="borderless" style={{ borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }}>
                      <p style={{ color: '#666', marginBottom: 12 }}>{campaign.description}</p>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'开始日期：'}</strong>
                        <div style={{ marginTop: 4 }}>{campaign.start_date}</div>
                      </div>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'APT组织：'}</strong>
                        <div style={{ marginTop: 4 }}>{campaign.apt_group}</div>
                      </div>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'攻击目标：'}</strong>
                        <div style={{ marginTop: 4 }}>{campaign.targets?.map((target: string, index: number) => <Tag key={index} color="blue" style={{ margin: 2 }}>{target}</Tag>)}</div>
                      </div>
                      <div>
                        <strong style={{ fontSize: 13 }}>{'战术手法：'}</strong>
                        <div style={{ marginTop: 4 }}>{campaign.tactics?.map((tactic: string, index: number) => <Tag key={index} color="orange" style={{ margin: 2 }}>{tactic}</Tag>)}</div>
                      </div>
                    </Card>
                  </Col>
                ))}
              </Row>
            )},
            { key: 'vulnerabilities', label: <span><SafetyCertificateOutlined /> {'漏洞情报'}</span>, children: (
              <Row gutter={16}>
                {Object.entries(vulnerabilities).map(([key, vuln]) => (
                  <Col span={8} key={key} style={{ marginBottom: 16 }}>
                    <Card title={<span style={{ fontWeight: 600 }}>{vuln.name}</span>} extra={<Tag color={vuln.severity === 'Critical' ? 'red' : vuln.severity === 'High' ? 'orange' : 'yellow'}>{vuln.severity}</Tag>} variant="borderless" style={{ borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }}>
                      <p style={{ color: '#666', marginBottom: 12 }}>{vuln.description}</p>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'CVE ID：'}</strong>
                        <div style={{ marginTop: 4, fontFamily: 'monospace' }}>{vuln.cve_id}</div>
                      </div>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'CVSS评分：'}</strong>
                        <div style={{ marginTop: 4 }}>{vuln.cvss_score}</div>
                      </div>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'发布日期：'}</strong>
                        <div style={{ marginTop: 4 }}>{vuln.published_date}</div>
                      </div>
                      <div style={{ marginBottom: 8 }}>
                        <strong style={{ fontSize: 13 }}>{'受影响软件：'}</strong>
                        <div style={{ marginTop: 4 }}>{vuln.affected_software?.map((software: string, index: number) => <Tag key={index} color="blue" style={{ margin: 2 }}>{software}</Tag>)}</div>
                      </div>
                      <div>
                        <strong style={{ fontSize: 13 }}>{'是否有漏洞利用：'}</strong>
                        <div style={{ marginTop: 4 }}>{vuln.exploit_available ? <Tag color="red">是</Tag> : <Tag color="green">否</Tag>}</div>
                      </div>
                    </Card>
                  </Col>
                ))}
              </Row>
            )},
            { key: 'indicators', label: <span><LinkOutlined /> {'威胁指标'}</span>, children: (
              <Table columns={indicatorColumns} dataSource={threatIndicators.map((item, i) => ({ ...item, key: item.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            )},
          ]} />
        </Card>

        {stats?.last_updated && (
          <div style={{ marginTop: 16, textAlign: 'right', color: '#999', fontSize: 12 }}>
            {'最后更新'}: {new Date(stats.last_updated).toLocaleString()}
          </div>
        )}
      </Spin>

      <Modal title="添加恶意指标" open={modalVisible} onCancel={() => setModalVisible(false)} footer={null} width={500}>
        <Form form={form} layout="vertical" onFinish={handleAddMaliciousItem}>
          <Form.Item name="type" label="指标类型" rules={[{ required: true, message: '请选择指标类型' }]}>
            <Select onChange={(value) => setActionType(value)} placeholder="选择指标类型">
              <Option value="ip">IP地址</Option>
              <Option value="domain">域名</Option>
              <Option value="url">URL</Option>
              <Option value="hash">文件哈希</Option>
            </Select>
          </Form.Item>
          <Form.Item name="item" label={actionType === 'ip' ? 'IP地址' : actionType === 'domain' ? '域名' : actionType === 'url' ? 'URL' : '文件哈希'} rules={[{ required: true, message: `请输入${actionType === 'ip' ? 'IP地址' : actionType === 'domain' ? '域名' : actionType === 'url' ? 'URL' : '文件哈希'}` }]}>
            <Input placeholder={`请输入${actionType === 'ip' ? 'IP地址' : actionType === 'domain' ? '域名' : actionType === 'url' ? 'URL' : '文件哈希（MD5/SHA1/SHA256）'}`} />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <TextArea rows={3} placeholder="请输入描述信息" />
          </Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button onClick={() => setModalVisible(false)} style={{ marginRight: 8 }}>取消</Button>
            <Button type="primary" htmlType="submit">确定</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="批量导入" open={batchModalVisible} onCancel={() => { setBatchModalVisible(false); setBatchText(''); }} onOk={handleBatchImport} okText="导入" width={600}>
        <Form layout="vertical">
          <Form.Item label="导入类型">
            <Select value={batchType} onChange={setBatchType}>
              <Option value="ip">IP地址</Option>
              <Option value="domain">域名</Option>
              <Option value="url">URL</Option>
              <Option value="hash">文件哈希</Option>
            </Select>
          </Form.Item>
          <Form.Item label={`请输入${batchType === 'ip' ? 'IP地址' : batchType === 'domain' ? '域名' : batchType === 'url' ? 'URL' : '文件哈希'}列表（每行一个）`}>
            <TextArea rows={10} value={batchText} onChange={(e) => setBatchText(e.target.value)} placeholder={`请输入${batchType === 'ip' ? 'IP地址' : batchType === 'domain' ? '域名' : batchType === 'url' ? 'URL' : '文件哈希（MD5/SHA1/SHA256）'}，每行一个\n例如：\n{batchType === 'ip' ? '192.168.1.1\n10.0.0.1\n172.16.0.1' : batchType === 'domain' ? 'malicious.com\nattackers.net\nphishing.org' : batchType === 'url' ? 'http://malicious.com/exploit\nhttps://phishing.org/login' : '5f4dcc3b5aa765d61d8327deb882cf99\ne10adc3949ba59abbe56e057f20f883e\n25f9e794323b453885f5181f1b624d0b'}`} />
          </Form.Item>
          <div style={{ color: '#999', fontSize: 12 }}>
            已输入 {batchText.split('\n').filter(item => item.trim().length > 0).length} 条数据
          </div>
        </Form>
      </Modal>

      <Modal title="威胁指标详情" open={detailModalVisible} onCancel={() => setDetailModalVisible(false)} footer={[<Button key="close" onClick={() => setDetailModalVisible(false)}>关闭</Button>]} width={600}>
        {selectedIndicator && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="ID">{selectedIndicator.id}</Descriptions.Item>
            <Descriptions.Item label="类型"><Tag color="blue">{typeLabels[selectedIndicator.type] || selectedIndicator.type}</Tag></Descriptions.Item>
            <Descriptions.Item label="指标"><span style={{ fontFamily: 'monospace' }}>{selectedIndicator.indicator}</span></Descriptions.Item>
            <Descriptions.Item label="描述">{selectedIndicator.description || '-'}</Descriptions.Item>
            <Descriptions.Item label="严重程度"><Tag color={severityColors[selectedIndicator.severity] || 'blue'}>{severityLabels[selectedIndicator.severity] || selectedIndicator.severity}</Tag></Descriptions.Item>
            <Descriptions.Item label="创建时间">{new Date(selectedIndicator.created_at).toLocaleString()}</Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
};

export default ThreatIntel;
