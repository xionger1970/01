import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Row, Col, Statistic, Progress, Typography, Alert, Skeleton, Button, Modal, Checkbox, Select, Space, Divider, Tag, Badge, Tooltip } from 'antd';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Legend } from 'recharts';
import type { PieLabelRenderProps } from 'recharts';
import { SettingOutlined, EyeOutlined, EyeInvisibleOutlined, ReloadOutlined, BellOutlined, StopOutlined, ThunderboltOutlined, DashboardOutlined, SafetyCertificateOutlined, AlertOutlined, SearchOutlined, AimOutlined, SecurityScanOutlined, CheckCircleOutlined, WarningOutlined, ApiOutlined, DatabaseOutlined, GlobalOutlined, TeamOutlined } from '@ant-design/icons';
import { fetchOverview, fetchTopTargets, fetchSystemStatus, toggleWidgetVisibility, updateLayout, resetDashboard } from '../store/slices/dashboardSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import type { DashboardWidget } from '../types';
import axios from 'axios';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

const MITRE_TACTICS = [
  { id: 'reconnaissance', name: '侦察', techniques: ['T1595', 'T1592'], detected: [3, 1] },
  { id: 'initial-access', name: '初始访问', techniques: ['T1190', 'T1078'], detected: [12, 5] },
  { id: 'execution', name: '执行', techniques: ['T1059', 'T1204'], detected: [8, 2] },
  { id: 'persistence', name: '持久化', techniques: ['T1053', 'T1136'], detected: [4, 1] },
  { id: 'priv-escalation', name: '权限提升', techniques: ['T1068', 'T1548'], detected: [6, 2] },
  { id: 'defense-evasion', name: '防御规避', techniques: ['T1070', 'T1562'], detected: [3, 1] },
  { id: 'credential-access', name: '凭证访问', techniques: ['T1110', 'T1552'], detected: [15, 3] },
  { id: 'discovery', name: '发现', techniques: ['T1046', 'T1082'], detected: [7, 2] },
  { id: 'lateral-movement', name: '横向移动', techniques: ['T1021', 'T1570'], detected: [4, 1] },
  { id: 'collection', name: '收集', techniques: ['T1005', 'T1039'], detected: [2, 0] },
  { id: 'exfiltration', name: '数据外传', techniques: ['T1041', 'T1567'], detected: [3, 1] },
  { id: 'impact', name: '影响', techniques: ['T1486', 'T1489'], detected: [2, 1] },
];

const ASSET_RISK_DATA = [
  { name: 'Web服务器-01', ip: '192.168.1.10', risk: 85, critical: 3, high: 8, type: '服务器' },
  { name: '数据库-01', ip: '192.168.1.20', risk: 72, critical: 1, high: 5, type: '数据库' },
  { name: 'API网关', ip: '192.168.1.30', risk: 68, critical: 2, high: 4, type: '网关' },
  { name: '邮件服务器', ip: '192.168.1.40', risk: 55, critical: 0, high: 3, type: '服务器' },
  { name: '文件服务器', ip: '192.168.1.50', risk: 42, critical: 0, high: 2, type: '存储' },
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
          }
          break;
        case 'scan_anomalies':
          await axios.get('/api/anomalies/detect');
          break;
        case 'update_threat_intel':
          await axios.get('/api/threat-intel/stats');
          break;
        case 'check_system':
          await axios.get('/api/dashboard/system-status');
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
      <div style={{ padding: '24px' }}>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          {[1, 2, 3, 4].map((i) => (<Col span={6} key={i}><Card><Skeleton active paragraph={{ rows: 1 }} /></Card></Col>))}
        </Row>
      </div>
    );
  }

  if (error) {
    return <Alert message="错误" description={error} type="error" showIcon style={{ margin: '24px' }} />;
  }

  const severityData = overview ? [
    { name: '严重', value: overview.severity_distribution.critical, color: '#f85149' },
    { name: '高', value: overview.severity_distribution.high, color: '#d29922' },
    { name: '中', value: overview.severity_distribution.medium, color: '#58a6ff' },
    { name: '低', value: overview.severity_distribution.low, color: '#3fb950' },
  ] : [];

  const trendData = overview ? overview.attack_trend.map(item => ({
    name: new Date(item.timestamp).toLocaleTimeString(),
    attacks: item.count,
  })) : [];

  const securityScore = overview ? Math.max(0, Math.min(100, 100 - (overview.active_attacks * 2) - (overview.severity_distribution?.critical || 0) * 5 - (overview.severity_distribution?.high || 0) * 2)) : 0;
  const scoreColor = securityScore >= 80 ? '#3fb950' : securityScore >= 60 ? '#d29922' : '#f85149';
  const scoreLabel = securityScore >= 80 ? '良好' : securityScore >= 60 ? '一般' : '危险';

  const attackTypeData = overview ? [
    { name: 'SQL注入', value: overview.attack_type_distribution?.sql_injection || 0, color: '#f85149' },
    { name: 'XSS', value: overview.attack_type_distribution?.xss || 0, color: '#d29922' },
    { name: 'CSRF', value: overview.attack_type_distribution?.csrf || 0, color: '#58a6ff' },
    { name: '命令注入', value: overview.attack_type_distribution?.command_injection || 0, color: '#3fb950' },
    { name: 'DoS', value: overview.attack_type_distribution?.dos || 0, color: '#a371f7' },
  ] : [];

  const mitreRadarData = MITRE_TACTICS.map(tactic => ({
    subject: tactic.name,
    A: tactic.detected.reduce((sum, count) => sum + count, 0),
    fullMark: 20,
  }));

  const renderWidgetContent = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'summary':
        return (
          <Row gutter={16}>
            <Col span={6}>
              <div className="stat-card stat-card-blue" style={{ padding: 20, borderRadius: 12 }}>
                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>总请求数</span>} value={overview?.total_attacks || 0} prefix={<ApiOutlined />} styles={{ content: { color: '#fff', fontWeight: 700 } }} />
              </div>
            </Col>
            <Col span={6}>
              <div className="stat-card stat-card-red" style={{ padding: 20, borderRadius: 12 }}>
                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>拦截请求</span>} value={overview?.active_attacks || 0} prefix={<StopOutlined />} styles={{ content: { color: '#fff', fontWeight: 700 } }} />
              </div>
            </Col>
            <Col span={6}>
              <div className="stat-card stat-card-orange" style={{ padding: 20, borderRadius: 12 }}>
                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>攻击者IP</span>} value={overview?.top_source_ips?.length || 0} prefix={<GlobalOutlined />} styles={{ content: { color: '#fff', fontWeight: 700 } }} />
              </div>
            </Col>
            <Col span={6}>
              <div className="stat-card stat-card-green" style={{ padding: 20, borderRadius: 12 }}>
                <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>防护站点</span>} value={12} prefix={<DatabaseOutlined />} styles={{ content: { color: '#fff', fontWeight: 700 } }} />
              </div>
            </Col>
          </Row>
        );
      case 'trend':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trendData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="name" stroke="#8b949e" />
              <YAxis stroke="#8b949e" />
              <RechartsTooltip contentStyle={{ background: '#161b22', border: '1px solid #21262d', borderRadius: 8 }} />
              <Area type="monotone" dataKey="attacks" stroke="#58a6ff" fill="#58a6ff" fillOpacity={0.2} />
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
              <RechartsTooltip contentStyle={{ background: '#161b22', border: '1px solid #21262d', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
        );
      case 'attack-types':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={attackTypeData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis dataKey="name" stroke="#8b949e" />
              <YAxis stroke="#8b949e" />
              <RechartsTooltip contentStyle={{ background: '#161b22', border: '1px solid #21262d', borderRadius: 8 }} />
              <Bar dataKey="value" name="攻击次数">
                {attackTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        );
      case 'mitre-radar':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart outerRadius={90} data={mitreRadarData}>
              <PolarGrid stroke="#30363d" />
              <PolarAngleAxis dataKey="subject" stroke="#8b949e" />
              <PolarRadiusAxis angle={30} domain={[0, 20]} stroke="#8b949e" />
              <Radar name="检测次数" dataKey="A" stroke="#58a6ff" fill="#58a6ff" fillOpacity={0.3} />
              <Legend />
              <RechartsTooltip contentStyle={{ background: '#161b22', border: '1px solid #21262d', borderRadius: 8 }} />
            </RadarChart>
          </ResponsiveContainer>
        );
      case 'targets':
        return (
          <div>
            {topTargets.map((target, index) => (
              <div key={index} style={{ marginBottom: 16, padding: 12, background: '#21262d', borderRadius: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <Text strong style={{ color: '#c9d1d9' }}>{target.target}</Text>
                  <Text style={{ color: '#8b949e' }}>{target.count} 次攻击</Text>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {target.attack_types.map((type, i) => (<Tag key={i} color="#30363d" style={{ color: '#c9d1d9', border: '1px solid #484f58' }}>{type}</Tag>))}
                </div>
              </div>
            ))}
          </div>
        );
      case 'system':
        return (
          <div>
            <div style={{ marginBottom: 24 }}>
              <Title level={5} style={{ color: '#c9d1d9' }}>服务状态</Title>
              {systemStatus?.services.map((service, index) => (
                <div key={index} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, padding: '8px 12px', background: '#21262d', borderRadius: 6 }}>
                  <Text style={{ color: '#c9d1d9' }}>{service.name}</Text>
                  <Text style={{ color: service.status === 'healthy' ? '#3fb950' : '#f85149' }}>
                    {service.status === 'healthy' ? '正常' : '异常'} ({service.uptime})
                  </Text>
                </div>
              ))}
            </div>
            <div>
              <Title level={5} style={{ color: '#c9d1d9' }}>系统资源</Title>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>CPU使用率</Text><Text style={{ color: '#c9d1d9' }}>{systemStatus?.resources.cpu_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.cpu_usage || '0')} strokeColor="#58a6ff" railColor="#21262d" />
              </div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>内存使用率</Text><Text style={{ color: '#c9d1d9' }}>{systemStatus?.resources.memory_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.memory_usage || '0')} strokeColor="#3fb950" railColor="#21262d" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>磁盘使用率</Text><Text style={{ color: '#c9d1d9' }}>{systemStatus?.resources.disk_usage}</Text></div>
                <Progress percent={parseInt(systemStatus?.resources.disk_usage || '0')} strokeColor="#d29922" railColor="#21262d" />
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
    critical: { text: '严重', color: '#f85149' }, high: { text: '高危', color: '#d29922' },
    medium: { text: '中危', color: '#58a6ff' }, low: { text: '低危', color: '#3fb950' }, info: { text: '信息', color: '#8b949e' }
  };

  return (
    <div style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <DashboardOutlined style={{ fontSize: 24, color: '#58a6ff' }} />
          <Title level={3} style={{ margin: 0, color: '#c9d1d9' }}>仪表盘</Title>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={handleResetDashboard}>刷新</Button>
          <Button icon={<SettingOutlined />} onClick={() => setSettingsModalVisible(true)}>设置</Button>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        {configuration.widgets.filter(widget => widget.visible).map((widget) => (
          <Col key={widget.id} span={widget.type === 'summary' ? 24 : widget.type === 'trend' ? 16 : 8}>
            <Card 
              title={<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><span style={{ color: '#c9d1d9' }}>{widget.title}</span><Button type="text" icon={widget.visible ? <EyeOutlined style={{ color: '#8b949e' }} /> : <EyeInvisibleOutlined style={{ color: '#8b949e' }} />} onClick={() => dispatch(toggleWidgetVisibility(widget.id))} /></div>} 
              variant="borderless" 
              style={{ height: '100%' }}
            >
              {renderWidgetContent(widget)}
            </Card>
          </Col>
        ))}
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={8}>
          <Card title={<span><SafetyCertificateOutlined style={{ marginRight: 8, color: '#58a6ff' }} />安全评分</span>} variant="borderless">
            <div style={{ textAlign: 'center', padding: '20px 0' }}>
              <Progress type="dashboard" percent={securityScore} strokeColor={scoreColor} railColor="#21262d" format={(percent) => (<div><div style={{ fontSize: 32, fontWeight: 700, color: scoreColor }}>{percent}</div><div style={{ fontSize: 14, color: scoreColor }}>{scoreLabel}</div></div>)} size={160} />
              <div style={{ marginTop: 16, textAlign: 'left' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, padding: '8px 12px', background: '#21262d', borderRadius: 6 }}><Text style={{ color: '#8b949e' }}>攻击威胁扣分</Text><Text style={{ color: '#f85149' }}>-{Math.min(overview?.active_attacks || 0, 40) * 2}</Text></div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, padding: '8px 12px', background: '#21262d', borderRadius: 6 }}><Text style={{ color: '#8b949e' }}>严重告警扣分</Text><Text style={{ color: '#f85149' }}>-{(overview?.severity_distribution?.critical || 0) * 5}</Text></div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: '#21262d', borderRadius: 6 }}><Text style={{ color: '#8b949e' }}>高危告警扣分</Text><Text style={{ color: '#d29922' }}>-{(overview?.severity_distribution?.high || 0) * 2}</Text></div>
              </div>
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card title={<span><ThunderboltOutlined style={{ marginRight: 8, color: '#d29922' }} />快捷操作</span>} variant="borderless">
            <Space orientation="vertical" style={{ width: '100%' }} size={12}>
              <Button block icon={<StopOutlined />} loading={quickActionLoading === 'block_top_ip'} onClick={() => handleQuickAction('block_top_ip')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: 'rgba(248, 81, 73, 0.1)', border: '1px solid #f85149', color: '#f85149' }}>
                封锁最高频攻击源 {overview?.top_source_ips?.[0]?.ip && <Tag color="#f85149" style={{ marginLeft: 8 }}>{overview.top_source_ips[0].ip}</Tag>}
              </Button>
              <Button block icon={<SearchOutlined />} loading={quickActionLoading === 'scan_anomalies'} onClick={() => handleQuickAction('scan_anomalies')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: 'rgba(210, 153, 34, 0.1)', border: '1px solid #d29922', color: '#d29922' }}>触发异常行为扫描</Button>
              <Button block icon={<AlertOutlined />} loading={quickActionLoading === 'update_threat_intel'} onClick={() => handleQuickAction('update_threat_intel')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: 'rgba(88, 166, 255, 0.1)', border: '1px solid #58a6ff', color: '#58a6ff' }}>更新威胁情报库</Button>
              <Button block icon={<DashboardOutlined />} loading={quickActionLoading === 'check_system'} onClick={() => handleQuickAction('check_system')} style={{ textAlign: 'left', height: 44, borderRadius: 8, background: 'rgba(63, 185, 80, 0.1)', border: '1px solid #3fb950', color: '#3fb950' }}>系统健康检查</Button>
            </Space>
          </Card>
        </Col>
        <Col span={8}>
          <Card title={<span><BellOutlined style={{ marginRight: 8, color: '#58a6ff' }} />实时事件流</span>} variant="borderless" extra={<Badge count={recentEvents.length} style={{ backgroundColor: '#58a6ff' }} />}>
            <div style={{ maxHeight: 340, overflowY: 'auto' }}>
              {recentEvents.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 24, color: '#8b949e' }}>暂无事件</div>
              ) : (
                recentEvents.map((event: any, index: number) => (
                  <div key={index} style={{ padding: '8px 0', borderBottom: '1px solid #21262d' }}>
                    <div style={{ display: 'flex', alignItems: 'center', width: '100%', gap: 8 }}>
                      <Tag color={severityMap[event.severity]?.color || '#58a6ff'} style={{ margin: 0, minWidth: 44, textAlign: 'center', border: 'none' }}>{severityMap[event.severity]?.text || event.severity}</Tag>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 500, color: '#c9d1d9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{event.attack_type}</div>
                        <div style={{ fontSize: 11, color: '#8b949e', fontFamily: 'monospace' }}>{event.source_ip} → {event.target_ip}:{event.target_port}</div>
                      </div>
                      <Text style={{ fontSize: 11, color: '#8b949e', whiteSpace: 'nowrap' }}>{dayjs(event.event_time).format('HH:mm:ss')}</Text>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col span={12}>
          <Card title={<span><AimOutlined style={{ marginRight: 8, color: '#a371f7' }} />MITRE ATT&CK 攻击矩阵</span>} variant="borderless" extra={<Tag color="#a371f7" style={{ border: 'none' }}>检测覆盖 {Math.round(MITRE_TACTICS.filter(t => t.detected.some(d => d > 0)).length / MITRE_TACTICS.length * 100)}%</Tag>}>
            <div style={{ overflowX: 'auto' }}>
              <div style={{ display: 'flex', gap: 4, minWidth: 900 }}>
                {MITRE_TACTICS.map(tactic => (
                  <div key={tactic.id} style={{ flex: 1, minWidth: 70 }}>
                    <div style={{ textAlign: 'center', fontSize: 11, fontWeight: 600, marginBottom: 6, color: '#8b949e', lineHeight: '14px' }}>{tactic.name}</div>
                    {tactic.techniques.map((tech, i) => {
                      const count = tactic.detected[i] || 0;
                      const bgColor = count >= 10 ? '#f85149' : count >= 5 ? '#d29922' : count > 0 ? '#58a6ff' : '#21262d';
                      const textColor = count > 0 ? '#fff' : '#8b949e';
                      return (
                        <Tooltip key={i} title={`${tech}: ${count}次检测`}>
                          <div style={{ backgroundColor: bgColor, color: textColor, padding: '4px 2px', margin: '2px 0', borderRadius: 3, fontSize: 9, textAlign: 'center', cursor: 'pointer', transition: 'all 0.2s' }}>
                            {tech}
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
          <Card title={<span><SecurityScanOutlined style={{ marginRight: 8, color: '#f85149' }} />资产风险TOP5</span>} variant="borderless">
            {ASSET_RISK_DATA.map((asset, index) => (
              <div key={index} style={{ marginBottom: 12, padding: 12, background: '#21262d', borderRadius: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div>
                    <Text strong style={{ fontSize: 13, color: '#c9d1d9' }}>{asset.name}</Text>
                    <Text style={{ fontSize: 11, marginLeft: 8, fontFamily: 'monospace', color: '#8b949e' }}>{asset.ip}</Text>
                  </div>
                  <Tag color={asset.risk >= 80 ? '#f85149' : asset.risk >= 60 ? '#d29922' : '#58a6ff'} style={{ margin: 0, border: 'none' }}>
                    {asset.risk}分
                  </Tag>
                </div>
                <Progress percent={asset.risk} size="small" strokeColor={asset.risk >= 80 ? '#f85149' : asset.risk >= 60 ? '#d29922' : '#58a6ff'} railColor="#30363d" showInfo={false} />
                <div style={{ marginTop: 4 }}>
                  <Tag style={{ fontSize: 10, background: 'rgba(248, 81, 73, 0.2)', border: 'none', color: '#f85149' }}>严重 {asset.critical}</Tag>
                  <Tag style={{ fontSize: 10, background: 'rgba(210, 153, 34, 0.2)', border: 'none', color: '#d29922' }}>高危 {asset.high}</Tag>
                </div>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={6}>
          <Card title={<span><TeamOutlined style={{ marginRight: 8, color: '#3fb950' }} />系统状态</span>} variant="borderless">
            <div style={{ marginBottom: 16, padding: 12, background: '#21262d', borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text style={{ color: '#8b949e' }}>数据源状态</Text>
                <Tag color="#3fb950" style={{ border: 'none' }}>正常</Tag>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text style={{ color: '#8b949e' }}>威胁情报</Text>
                <Tag color="#3fb950" style={{ border: 'none' }}>已同步</Tag>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text style={{ color: '#8b949e' }}>异常检测</Text>
                <Tag color="#58a6ff" style={{ border: 'none' }}>运行中</Tag>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Text style={{ color: '#8b949e' }}>AI分析</Text>
                <Tag color="#a371f7" style={{ border: 'none' }}>就绪</Tag>
              </div>
            </div>
            <div style={{ padding: 12, background: '#21262d', borderRadius: 8 }}>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>CPU</Text><Text style={{ color: '#c9d1d9' }}>32%</Text></div>
                <Progress percent={32} size="small" strokeColor="#58a6ff" railColor="#30363d" showInfo={false} />
              </div>
              <div style={{ marginBottom: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>内存</Text><Text style={{ color: '#c9d1d9' }}>58%</Text></div>
                <Progress percent={58} size="small" strokeColor="#3fb950" railColor="#30363d" showInfo={false} />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}><Text style={{ color: '#8b949e' }}>磁盘</Text><Text style={{ color: '#c9d1d9' }}>45%</Text></div>
                <Progress percent={45} size="small" strokeColor="#d29922" railColor="#30363d" showInfo={false} />
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      <Modal title={<span style={{ color: '#e4e6eb', fontWeight: 600 }}>仪表盘设置</span>} open={settingsModalVisible} onCancel={() => setSettingsModalVisible(false)}
        footer={[<Button key="cancel" onClick={() => setSettingsModalVisible(false)}>取消</Button>, <Button key="ok" type="primary" onClick={() => setSettingsModalVisible(false)}>确定</Button>]}>
        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          <h3 style={{ color: '#e4e6eb', fontWeight: 600, fontSize: 16, marginBottom: 16 }}>组件显示</h3>
          {configuration.widgets.map((widget) => (<div key={widget.id} style={{ marginBottom: 12 }}><Checkbox checked={widget.visible} onChange={() => dispatch(toggleWidgetVisibility(widget.id))} style={{ color: '#e4e6eb' }}><span style={{ color: '#e4e6eb' }}>{widget.title}</span></Checkbox></div>))}
          <Divider />
          <h3 style={{ color: '#e4e6eb', fontWeight: 600, fontSize: 16, marginBottom: 16 }}>布局设置</h3>
          <div style={{ marginBottom: 16 }}>
            <span style={{ marginRight: 12, color: '#e4e6eb' }}>布局类型：</span>
            <Select value={configuration.layout} onChange={(value) => dispatch(updateLayout(value))} style={{ width: 120 }}>
              <Select.Option value="grid">网格布局</Select.Option>
              <Select.Option value="custom">自定义布局</Select.Option>
            </Select>
          </div>
          <Button type="primary" onClick={handleResetDashboard}>重置为默认布局</Button>
        </div>
      </Modal>
    </div>
  );
};

export default Dashboard;
