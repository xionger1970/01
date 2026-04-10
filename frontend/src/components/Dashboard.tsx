import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Row, Col, Statistic, Progress, Typography, Alert, Skeleton, Button, Modal, Checkbox, Select, Space, Divider, List, Tag, Badge, Tooltip, Tabs } from 'antd';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import type { PieLabelRenderProps } from 'recharts';
import { SettingOutlined, EyeOutlined, EyeInvisibleOutlined, ReloadOutlined, BellOutlined, StopOutlined, ThunderboltOutlined, DashboardOutlined, SafetyCertificateOutlined, AlertOutlined, SearchOutlined, AimOutlined, SecurityScanOutlined, CheckCircleOutlined, WarningOutlined } from '@ant-design/icons';
import { fetchOverview, fetchTopTargets, fetchSystemStatus, toggleWidgetVisibility, updateLayout, resetDashboard } from '../store/slices/dashboardSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import type { DashboardWidget } from '../types';
import axios from 'axios';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

const MITRE_TACTICS = [
  { id: 'reconnaissance', name: '侦察', techniques: ['T1595主动扫描', 'T1592收集信息'], detected: [3, 1] },
  { id: 'initial-access', name: '初始访问', techniques: ['T1190利用面向公众的应用', 'T1078有效账号'], detected: [12, 5] },
  { id: 'execution', name: '执行', techniques: ['T1059命令脚本', 'T1204用户执行'], detected: [8, 2] },
  { id: 'persistence', name: '持久化', techniques: ['T1053计划任务', 'T1136创建账号'], detected: [4, 1] },
  { id: 'priv-escalation', name: '权限提升', techniques: ['T1068漏洞利用', 'T1548滥用机制'], detected: [6, 2] },
  { id: 'defense-evasion', name: '防御规避', techniques: ['T1070痕迹清除', 'T1562禁用安全'], detected: [3, 1] },
  { id: 'credential-access', name: '凭证访问', techniques: ['T1110暴力破解', 'T1552凭证文件'], detected: [15, 3] },
  { id: 'discovery', name: '发现', techniques: ['T1046网络服务发现', 'T1082系统信息'], detected: [7, 2] },
  { id: 'lateral-movement', name: '横向移动', techniques: ['T1021远程服务', 'T1570L2中继'], detected: [4, 1] },
  { id: 'collection', name: '收集', techniques: ['T1005本地数据', 'T1039远程数据'], detected: [2, 0] },
  { id: 'exfiltration', name: '数据外传', techniques: ['T1041通过C2通道', 'T1567Web服务'], detected: [3, 1] },
  { id: 'impact', name: '影响', techniques: ['T1486数据加密', 'T1489服务停止'], detected: [2, 1] },
];

const ASSET_RISK_DATA = [
  { name: 'Web服务器-01', ip: '192.168.1.10', risk: 85, critical: 3, high: 8, type: '服务器' },
  { name: '数据库-01', ip: '192.168.1.20', risk: 72, critical: 1, high: 5, type: '数据库' },
  { name: 'API网关', ip: '192.168.1.30', risk: 68, critical: 2, high: 4, type: '网关' },
  { name: '邮件服务器', ip: '192.168.1.40', risk: 55, critical: 0, high: 3, type: '服务器' },
  { name: '文件服务器', ip: '192.168.1.50', risk: 42, critical: 0, high: 2, type: '存储' },
];

const COMPLIANCE_ITEMS = [
  { name: '等保2.0-安全通信网络', score: 92, status: 'pass' },
  { name: '等保2.0-安全区域边界', score: 85, status: 'pass' },
  { name: '等保2.0-安全计算环境', score: 78, status: 'warning' },
  { name: '等保2.0-安全管理中心', score: 88, status: 'pass' },
  { name: 'ISO27001-访问控制', score: 90, status: 'pass' },
  { name: 'ISO27001-密码学', score: 75, status: 'warning' },
];

const Dashboard: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { overview, topTargets, systemStatus, configuration, loading, error } = useSelector((state: RootState) => state.dashboard);
  const [settingsModalVisible, setSettingsModalVisible] = useState(false);
  const [recentEvents, setRecentEvents] = useState<any[]>([]);
  const [quickActionLoading, setQuickActionLoading] = useState<string | null>(null);

  useEffect(() => {
    dispatch(fetchOverview());
    dispatch(fetchTopTargets());
    dispatch(fetchSystemStatus());
    fetchRecentEvents();
    const interval = setInterval(() => {
      dispatch(fetchOverview());
      dispatch(fetchTopTargets());
      dispatch(fetchSystemStatus());
      fetchRecentEvents();
    }, 30000);
    return () => clearInterval(interval);
  }, [dispatch]);

  const fetchRecentEvents = async () => {
    try {
      const response = await axios.get('/api/attack-events', { params: { limit: 10 } });
      setRecentEvents(Array.isArray(response.data) ? response.data.slice(0, 10) : []);
    } catch (err) {
      console.error('获取最近事件失败:', err);
    }
  };

  const handleQuickAction = async (action: string) => {
    setQuickActionLoading(action);
    try {
      switch (action) {
        case 'block_top_ip':
          if (overview?.top_source_ips?.[0]?.ip) {
            await axios.post('/api/threat-intel/malicious-ips', null, { params: { ip: overview.top_source_ips[0].ip } });
            alert(`已封锁最高频攻击源IP: ${overview.top_source_ips[0].ip}`);
          }
          break;
        case 'scan_anomalies':
          await axios.get('/api/anomalies/detect');
          alert('异常扫描已触发');
          break;
        case 'update_threat_intel':
          await axios.get('/api/threat-intel/stats');
          alert('威胁情报已更新');
          break;
        case 'check_system':
          await axios.get('/api/dashboard/system-status');
          alert('系统健康检查完成');
          break;
      }
    } catch (err) {
      console.error('快捷操作失败:', err);
    } finally {
      setQuickActionLoading(null);
    }
  };

  if (loading) {
    return (
      <div className="loading-container" style={{ padding: '24px' }}>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          {[1, 2, 3, 4].map((i) => (<Col span={6} key={i}><Card><Skeleton active paragraph={{ rows: 1 }} /></Card></Col>))}
        </Row>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={16}><Card><Skeleton active paragraph={{ rows: 10 }} /></Card></Col>
          <Col span={8}><Card><Skeleton active paragraph={{ rows: 10 }} /></Card></Col>
        </Row>
      </div>
    );
  }

  if (error) {
    return <Alert message="错误" description={error} type="error" showIcon style={{ margin: '24px' }} />;
  }

  const severityData = overview ? [
    { name: '严重', value: overview.severity_distribution.critical, color: '#ff4d4f' },
    { name: '高', value: overview.severity_distribution.high, color: '#fa8c16' },
    { name: '中', value: overview.severity_distribution.medium, color: '#faad14' },
    { name: '低', value: overview.severity_distribution.low, color: '#52c41a' },
  ] : [];

  const trendData = overview ? overview.attack_trend.map(item => ({
    name: new Date(item.timestamp).toLocaleTimeString(),
    attacks: item.count,
  })) : [];

  const securityScore = overview ? Math.max(0, Math.min(100, 100 - (overview.active_attacks * 2) - (overview.severity_distribution?.critical || 0) * 5 - (overview.severity_distribution?.high || 0) * 2)) : 0;
  const scoreColor = securityScore >= 80 ? '#52c41a' : securityScore >= 60 ? '#faad14' : '#ff4d4f';
  const scoreLabel = securityScore >= 80 ? '良好' : securityScore >= 60 ? '一般' : '危险';

  const complianceScore = Math.round(COMPLIANCE_ITEMS.reduce((acc, item) => acc + item.score, 0) / COMPLIANCE_ITEMS.length);

  const renderWidgetContent = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'summary':
        return (
          <Row gutter={16}>
            <Col span={6}><Card><Statistic title="攻击总数" value={overview?.total_attacks || 0} suffix="次" valueStyle={{ color: '#1890ff' }} /></Card></Col>
            <Col span={6}><Card><Statistic title="活跃攻击" value={overview?.active_attacks || 0} suffix="进行中" valueStyle={{ color: '#ff4d4f' }} /></Card></Col>
            <Col span={6}><Card><Statistic title="主要攻击类型" value={overview?.top_attack_types[0]?.type || '无'} suffix={`${overview?.top_attack_types[0]?.count || 0} 次`} valueStyle={{ color: '#fa8c16' }} /></Card></Col>
            <Col span={6}><Card><Statistic title="主要攻击源" value={overview?.top_source_ips[0]?.ip || '无'} suffix={`${overview?.top_source_ips[0]?.count || 0} 次`} valueStyle={{ color: '#52c41a' }} /></Card></Col>
          </Row>
        );
      case 'trend':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trendData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <RechartsTooltip />
              <Area type="monotone" dataKey="attacks" stroke="#1890ff" fill="#e6f7ff" />
            </AreaChart>
          </ResponsiveContainer>
        );
      case 'severity':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie data={severityData} cx="50%" cy="50%" labelLine={false} outerRadius={80} fill="#8884d8" dataKey="value"
                label={(props: PieLabelRenderProps) => props.name && props.percent ? `${props.name}: ${(props.percent * 100).toFixed(0)}%` : ''}>
                {severityData.map((entry, index) => (<Cell key={`cell-${index}`} fill={entry.color} />))}
              </Pie>
              <RechartsTooltip />
            </PieChart>
          </ResponsiveContainer>
        );
      case 'targets':
        return (
          <div className="top-targets">
            {topTargets.map((target, index) => (
              <div key={index} className="target-item" style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <Text strong>{target.target}</Text>
                  <Text type="secondary">{target.count} {'次攻击'}</Text>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {target.attack_types.map((type, i) => (<span key={i} style={{ padding: '2px 8px', backgroundColor: '#f0f0f0', borderRadius: 4, fontSize: 12 }}>{type}</span>))}
                </div>
              </div>
            ))}
          </div>
        );
      case 'system':
        return (
          <div className="system-status">
            <div style={{ marginBottom: 24 }}>
              <Title level={5}>{'服务状态'}</Title>
              {systemStatus?.services.map((service, index) => (
                <div key={index} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <Text>{service.name}</Text>
                  <Text style={{ color: service.status === 'healthy' ? '#52c41a' : '#ff4d4f' }}>
                    {service.status === 'healthy' ? '正常' : '异常'} ({service.uptime})
                  </Text>
                </div>
              ))}
            </div>
            <div>
              <Title level={5}>{'系统资源'}</Title>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text>{'CPU使用率'}</Text><Text>{systemStatus?.resources.cpu_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.cpu_usage || '0')} status="active" />
              </div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text>{'内存使用率'}</Text><Text>{systemStatus?.resources.memory_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.memory_usage || '0')} status="active" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text>{'磁盘使用率'}</Text><Text>{systemStatus?.resources.disk_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.disk_usage || '0')} status="active" />
              </div>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  const handleResetDashboard = () => { dispatch(resetDashboard()); };

  const severityMap: Record<string, { text: string; color: string }> = {
    critical: { text: '严重', color: 'red' }, high: { text: '高危', color: 'orange' },
    medium: { text: '中危', color: 'gold' }, low: { text: '低危', color: 'blue' }, info: { text: '信息', color: 'green' }
  };

  return (
    <div className="dashboard" style={{ position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2}>{'网络攻击态势感知系统'}</Title>
        <Space>
          <Button icon={<SettingOutlined />} onClick={() => setSettingsModalVisible(true)}>{'仪表盘设置'}</Button>
          <Button icon={<ReloadOutlined />} onClick={handleResetDashboard}>{'重置布局'}</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        {configuration.widgets.filter(widget => widget.visible).map((widget) => (
          <Col key={widget.id} span={widget.type === 'summary' ? 24 : widget.type === 'trend' ? 16 : 8}>
            <Card title={<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><span>{widget.title}</span><Button type="text" icon={widget.visible ? <EyeOutlined /> : <EyeInvisibleOutlined />} onClick={() => dispatch(toggleWidgetVisibility(widget.id))} /></div>} variant="borderless" style={{ height: '100%' }}>
              {renderWidgetContent(widget)}
            </Card>
          </Col>
        ))}
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={8}>
          <Card title={<span><SafetyCertificateOutlined style={{ marginRight: 8 }} />安全评分</span>} variant="borderless" style={{ borderRadius: 12 }}>
            <div style={{ textAlign: 'center', padding: '20px 0' }}>
              <Progress type="dashboard" percent={securityScore} strokeColor={scoreColor} format={(percent) => (<div><div style={{ fontSize: 32, fontWeight: 700, color: scoreColor }}>{percent}</div><div style={{ fontSize: 14, color: scoreColor }}>{scoreLabel}</div></div>)} size={160} />
              <div style={{ marginTop: 16, textAlign: 'left' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}><Text type="secondary">攻击威胁扣分</Text><Text type="danger">-{Math.min(overview?.active_attacks || 0, 40) * 2}</Text></div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}><Text type="secondary">严重告警扣分</Text><Text type="danger">-{(overview?.severity_distribution?.critical || 0) * 5}</Text></div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><Text type="secondary">高危告警扣分</Text><Text type="danger">-{(overview?.severity_distribution?.high || 0) * 2}</Text></div>
              </div>
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card title={<span><ThunderboltOutlined style={{ marginRight: 8 }} />快捷操作</span>} variant="borderless" style={{ borderRadius: 12 }}>
            <Space direction="vertical" style={{ width: '100%' }} size={12}>
              <Button block icon={<StopOutlined />} loading={quickActionLoading === 'block_top_ip'} onClick={() => handleQuickAction('block_top_ip')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: '#fff1f0', borderColor: '#ffccc7', color: '#ff4d4f' }}>
                封锁最高频攻击源IP {overview?.top_source_ips?.[0]?.ip && <Tag color="red" style={{ marginLeft: 8 }}>{overview.top_source_ips[0].ip}</Tag>}
              </Button>
              <Button block icon={<SearchOutlined />} loading={quickActionLoading === 'scan_anomalies'} onClick={() => handleQuickAction('scan_anomalies')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: '#fff7e6', borderColor: '#ffe58f', color: '#fa8c16' }}>触发异常行为扫描</Button>
              <Button block icon={<AlertOutlined />} loading={quickActionLoading === 'update_threat_intel'} onClick={() => handleQuickAction('update_threat_intel')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: '#e6f7ff', borderColor: '#91d5ff', color: '#1890ff' }}>更新威胁情报库</Button>
              <Button block icon={<DashboardOutlined />} loading={quickActionLoading === 'check_system'} onClick={() => handleQuickAction('check_system')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: '#f6ffed', borderColor: '#b7eb8f', color: '#52c41a' }}>系统健康检查</Button>
            </Space>
          </Card>
        </Col>
        <Col span={8}>
          <Card title={<span><BellOutlined style={{ marginRight: 8 }} />实时事件流</span>} variant="borderless" style={{ borderRadius: 12 }} extra={<Badge count={recentEvents.length} style={{ backgroundColor: '#1890ff' }} />}>
            <List size="small" dataSource={recentEvents} style={{ maxHeight: 340, overflowY: 'auto' }}
              renderItem={(event: any) => (
                <List.Item style={{ padding: '8px 0' }}>
                  <div style={{ display: 'flex', alignItems: 'center', width: '100%', gap: 8 }}>
                    <Tag color={severityMap[event.severity]?.color || 'blue'} style={{ margin: 0, minWidth: 44, textAlign: 'center' }}>{severityMap[event.severity]?.text || event.severity}</Tag>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{event.attack_type}</div>
                      <div style={{ fontSize: 11, color: '#999', fontFamily: 'monospace' }}>{event.source_ip} → {event.target_ip}:{event.target_port}</div>
                    </div>
                    <Text type="secondary" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{dayjs(event.event_time).format('HH:mm:ss')}</Text>
                  </div>
                </List.Item>
              )}
              locale={{ emptyText: '暂无事件' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card title={<span><AimOutlined style={{ marginRight: 8 }} />MITRE ATT&CK 攻击矩阵</span>} variant="borderless" style={{ borderRadius: 12 }} extra={<Tag color="blue">检测覆盖 {Math.round(MITRE_TACTICS.filter(t => t.detected.some(d => d > 0)).length / MITRE_TACTICS.length * 100)}%</Tag>}>
            <div style={{ overflowX: 'auto' }}>
              <div style={{ display: 'flex', gap: 4, minWidth: 900 }}>
                {MITRE_TACTICS.map(tactic => (
                  <div key={tactic.id} style={{ flex: 1, minWidth: 70 }}>
                    <div style={{ textAlign: 'center', fontSize: 11, fontWeight: 600, marginBottom: 6, color: '#333', lineHeight: '14px' }}>{tactic.name}</div>
                    {tactic.techniques.map((tech, i) => {
                      const count = tactic.detected[i] || 0;
                      const bgColor = count >= 10 ? '#ff4d4f' : count >= 5 ? '#fa8c16' : count > 0 ? '#faad14' : '#f0f0f0';
                      const textColor = count > 0 ? '#fff' : '#999';
                      return (
                        <Tooltip key={i} title={`${tech}: ${count}次检测`}>
                          <div style={{ backgroundColor: bgColor, color: textColor, padding: '4px 2px', margin: '2px 0', borderRadius: 3, fontSize: 9, textAlign: 'center', cursor: 'pointer', transition: 'all 0.2s' }}>
                            {tech.split(' ')[0]}
                            {count > 0 && <div style={{ fontSize: 10, fontWeight: 700 }}>{count}</div>}
                          </div>
                        </Tooltip>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card title={<span><SecurityScanOutlined style={{ marginRight: 8 }} />资产风险TOP5</span>} variant="borderless" style={{ borderRadius: 12 }}>
            {ASSET_RISK_DATA.map((asset, index) => (
              <div key={index} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div>
                    <Text strong style={{ fontSize: 13 }}>{asset.name}</Text>
                    <Text type="secondary" style={{ fontSize: 11, marginLeft: 8, fontFamily: 'monospace' }}>{asset.ip}</Text>
                  </div>
                  <Tag color={asset.risk >= 80 ? 'red' : asset.risk >= 60 ? 'orange' : 'blue'} style={{ margin: 0 }}>
                    {asset.risk}分
                  </Tag>
                </div>
                <Progress percent={asset.risk} size="small" strokeColor={asset.risk >= 80 ? '#ff4d4f' : asset.risk >= 60 ? '#fa8c16' : '#1890ff'} showInfo={false} />
                <div style={{ marginTop: 2 }}>
                  <Tag color="red" style={{ fontSize: 10 }}>严重 {asset.critical}</Tag>
                  <Tag color="orange" style={{ fontSize: 10 }}>高危 {asset.high}</Tag>
                </div>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={6}>
          <Card title={<span><CheckCircleOutlined style={{ marginRight: 8 }} />合规状态</span>} variant="borderless" style={{ borderRadius: 12 }} extra={<Tag color={complianceScore >= 80 ? 'green' : 'orange'}>{complianceScore}分</Tag>}>
            {COMPLIANCE_ITEMS.map((item, index) => (
              <div key={index} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ fontSize: 12 }}>{item.name}</Text>
                  <Text style={{ fontSize: 12, color: item.status === 'pass' ? '#52c41a' : '#fa8c16' }}>
                    {item.status === 'pass' ? <CheckCircleOutlined /> : <WarningOutlined />} {item.score}
                  </Text>
                </div>
                <Progress percent={item.score} size="small" strokeColor={item.status === 'pass' ? '#52c41a' : '#fa8c16'} showInfo={false} />
              </div>
            ))}
          </Card>
        </Col>
      </Row>

      <Modal title="仪表盘设置" open={settingsModalVisible} onCancel={() => setSettingsModalVisible(false)}
        footer={[<Button key="cancel" onClick={() => setSettingsModalVisible(false)}>取消</Button>, <Button key="ok" type="primary" onClick={() => setSettingsModalVisible(false)}>确定</Button>]}>
        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          <h3>{'组件显示'}</h3>
          {configuration.widgets.map((widget) => (<div key={widget.id} style={{ marginBottom: 12 }}><Checkbox checked={widget.visible} onChange={() => dispatch(toggleWidgetVisibility(widget.id))}>{widget.title}</Checkbox></div>))}
          <Divider />
          <h3>{'布局设置'}</h3>
          <div style={{ marginBottom: 16 }}>
            <span style={{ marginRight: 12 }}>{'布局类型：'}</span>
            <Select value={configuration.layout} onChange={(value) => dispatch(updateLayout(value))} style={{ width: 120 }}>
              <Select.Option value="grid">{'网格布局'}</Select.Option>
              <Select.Option value="custom">{'自定义布局'}</Select.Option>
            </Select>
          </div>
          <Button type="primary" onClick={handleResetDashboard}>{'重置为默认布局'}</Button>
        </div>
      </Modal>
    </div>
  );
};

export default Dashboard;
