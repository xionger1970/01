import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Row, Col, Statistic, Progress, Typography, Alert, Space, Tag, Skeleton, List, Divider, Button } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, ExclamationCircleOutlined, AlertOutlined, ReloadOutlined, SafetyCertificateOutlined, DashboardOutlined, CloudServerOutlined, DatabaseOutlined, LockOutlined, UnlockOutlined } from '@ant-design/icons';
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import { fetchOverview, fetchSystemStatus } from '../store/slices/dashboardSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import axios from 'axios';

const { Text, Title } = Typography;

const SecurityOverview: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { overview, systemStatus, loading, error } = useSelector((state: RootState) => state.dashboard);
  const [alertStats, setAlertStats] = useState<any>({});
  const [threatStats, setThreatStats] = useState<any>(null);

  useEffect(() => {
    dispatch(fetchOverview());
    dispatch(fetchSystemStatus());
    fetchAdditionalStats();
    const interval = setInterval(() => {
      dispatch(fetchOverview());
      dispatch(fetchSystemStatus());
      fetchAdditionalStats();
    }, 30000);
    return () => clearInterval(interval);
  }, [dispatch]);

  const fetchAdditionalStats = async () => {
    try {
      const [alertRes, threatRes] = await Promise.all([
        axios.get('/api/alerts/stats').catch(() => ({ data: {} })),
        axios.get('/api/threat-intel/stats').catch(() => ({ data: null }))
      ]);
      setAlertStats(alertRes.data || {});
      setThreatStats(threatRes.data);
    } catch (err) {
      console.error('获取附加统计失败:', err);
    }
  };

  const calculateSecurityScore = () => {
    let score = 100;
    if (overview) {
      score -= Math.min((overview.active_attacks || 0) * 3, 30);
      score -= Math.min((overview.severity_distribution?.critical || 0) * 5, 25);
      score -= Math.min((overview.severity_distribution?.high || 0) * 2, 15);
    }
    if (systemStatus) {
      const unhealthy = systemStatus.services?.filter((s: any) => s.status !== 'healthy').length || 0;
      score -= unhealthy * 5;
    }
    return Math.max(0, Math.min(100, score));
  };

  const securityScore = calculateSecurityScore();
  const scoreColor = securityScore >= 80 ? '#52c41a' : securityScore >= 60 ? '#faad14' : '#ff4d4f';
  const scoreLevel = securityScore >= 80 ? '安全' : securityScore >= 60 ? '警告' : '危险';

  const securityPostureData = [
    { subject: '攻击检测', A: overview ? Math.min(95, 70 + (overview.total_attacks > 0 ? 25 : 0)) : 0, fullMark: 100 },
    { subject: '自动响应', A: 70, fullMark: 100 },
    { subject: '系统健康', A: systemStatus ? Math.max(30, 100 - (systemStatus.services?.filter((s: any) => s.status !== 'healthy').length || 0) * 20) : 0, fullMark: 100 },
    { subject: '漏洞管理', A: 65, fullMark: 100 },
    { subject: '合规性', A: 80, fullMark: 100 },
    { subject: '威胁情报', A: threatStats ? Math.min(90, 50 + (threatStats.threat_indicators_count || 0)) : 75, fullMark: 100 },
  ];

  const attackTypeData = overview?.top_attack_types?.map((item: any) => ({
    name: item.type,
    count: item.count,
  })) || [];

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      case 'warning':
        return <ExclamationCircleOutlined style={{ color: '#faad14' }} />;
      case 'critical':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '24px' }}>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={24}>
            <Card>
              <Row gutter={16}>
                {[1, 2, 3, 4].map((i) => (
                  <Col span={6} key={i}>
                    <Skeleton active paragraph={{ rows: 1 }} />
                  </Col>
                ))}
              </Row>
            </Card>
          </Col>
        </Row>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={12}>
            <Card title="安全态势" variant="borderless">
              <Skeleton active paragraph={{ rows: 10 }} />
            </Card>
          </Col>
          <Col span={12}>
            <Card title="系统健康" variant="borderless">
              <Skeleton active paragraph={{ rows: 8 }} />
            </Card>
          </Col>
        </Row>
      </div>
    );
  }

  if (error) {
    return <Alert message="错误" description={error} type="error" showIcon style={{ margin: '24px' }} />;
  }

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #52c41a, #1890ff)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <SafetyCertificateOutlined style={{ marginRight: 8, WebkitTextFillColor: '#52c41a' }} />
          安全概览
        </h2>
        <Button icon={<ReloadOutlined />} onClick={() => { dispatch(fetchOverview()); dispatch(fetchSystemStatus()); fetchAdditionalStats(); }}>
          刷新
        </Button>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>安全评分</span>}
              value={securityScore}
              suffix="分"
              prefix={<DashboardOutlined />}
              valueStyle={{ color: '#fff', fontWeight: 700 }}
            />
            <Tag color={securityScore >= 80 ? 'green' : securityScore >= 60 ? 'gold' : 'red'} style={{ marginTop: 8 }}>
              {scoreLevel}
            </Tag>
          </Card>
        </Col>
        <Col span={6}>
          <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>总攻击数</span>}
              value={overview?.total_attacks || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#fff', fontWeight: 700 }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>活跃攻击</span>}
              value={overview?.active_attacks || 0}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: '#fff', fontWeight: 700 }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}>
            <Statistic
              title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>未处理告警</span>}
              value={alertStats.by_status?.new || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#fff', fontWeight: 700 }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card title="安全评分详情" variant="borderless" style={{ borderRadius: 12 }}>
            <div style={{ textAlign: 'center', marginBottom: 20 }}>
              <Progress
                type="dashboard"
                percent={securityScore}
                strokeColor={scoreColor}
                format={(percent) => (
                  <div>
                    <div style={{ fontSize: 28, fontWeight: 700, color: scoreColor }}>{percent}</div>
                    <div style={{ fontSize: 12, color: scoreColor }}>{scoreLevel}</div>
                  </div>
                )}
                size={140}
              />
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text><LockOutlined style={{ marginRight: 4, color: '#52c41a' }} />攻击防护</Text>
                <Progress percent={Math.min(95, 60 + (overview?.total_attacks || 0) > 0 ? 30 : 0)} size="small" style={{ width: 120 }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text><SafetyCertificateOutlined style={{ marginRight: 4, color: '#1890ff' }} />威胁情报</Text>
                <Progress percent={threatStats ? Math.min(90, 50 + (threatStats.threat_indicators_count || 0)) : 75} size="small" style={{ width: 120 }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <Text><CloudServerOutlined style={{ marginRight: 4, color: '#722ed1' }} />系统健康</Text>
                <Progress percent={systemStatus ? Math.max(30, 100 - (systemStatus.services?.filter((s: any) => s.status !== 'healthy').length || 0) * 20) : 0} size="small" style={{ width: 120 }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Text><DatabaseOutlined style={{ marginRight: 4, color: '#fa8c16' }} />漏洞管理</Text>
                <Progress percent={65} size="small" style={{ width: 120 }} />
              </div>
            </div>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="安全态势" variant="borderless" style={{ borderRadius: 12 }}>
            <ResponsiveContainer width="100%" height={300}>
              <RadarChart outerRadius={90} data={securityPostureData}>
                <PolarGrid />
                <PolarAngleAxis dataKey="subject" />
                <PolarRadiusAxis angle={30} domain={[0, 100]} />
                <Radar name="安全态势" dataKey="A" stroke="#1890ff" fill="#1890ff" fillOpacity={0.6} />
              </RadarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="攻击类型分布" variant="borderless" style={{ borderRadius: 12 }}>
            {attackTypeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={attackTypeData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="count" fill="#1890ff" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '100px 0', color: '#999' }}>
                <AlertOutlined style={{ fontSize: 36, marginBottom: 8 }} />
                <div>暂无攻击类型数据</div>
              </div>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="系统健康" variant="borderless" style={{ borderRadius: 12 }}>
            {systemStatus?.services.map((service, index) => (
              <div key={index} style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>{service.name}</Text>
                  <Space>
                    <Tag color={service.status === 'healthy' ? 'green' : 'red'}>
                      {service.status === 'healthy' ? '正常' : '异常'}
                    </Tag>
                    <Text type="secondary">{service.uptime}</Text>
                  </Space>
                </div>
                <Progress
                  percent={service.status === 'healthy' ? 100 : 0}
                  status={service.status === 'healthy' ? 'success' : 'exception'}
                />
              </div>
            ))}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="系统资源" variant="borderless" style={{ borderRadius: 12 }}>
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <Text>{'CPU使用率'}</Text>
                <Text>{systemStatus?.resources.cpu_usage}</Text>
              </div>
              <Progress
                percent={parseInt(systemStatus?.resources.cpu_usage || '0')}
                status={parseInt(systemStatus?.resources.cpu_usage || '0') > 80 ? 'exception' : 'active'}
                strokeColor="#1890ff"
              />
            </div>
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <Text>{'内存使用率'}</Text>
                <Text>{systemStatus?.resources.memory_usage}</Text>
              </div>
              <Progress
                percent={parseInt(systemStatus?.resources.memory_usage || '0')}
                status={parseInt(systemStatus?.resources.memory_usage || '0') > 80 ? 'exception' : 'active'}
                strokeColor="#52c41a"
              />
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <Text>{'磁盘使用率'}</Text>
                <Text>{systemStatus?.resources.disk_usage}</Text>
              </div>
              <Progress
                percent={parseInt(systemStatus?.resources.disk_usage || '0')}
                status={parseInt(systemStatus?.resources.disk_usage || '0') > 80 ? 'exception' : 'active'}
                strokeColor="#fa8c16"
              />
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col span={12}>
          <Card title="威胁情报摘要" variant="borderless" style={{ borderRadius: 12 }}>
            {threatStats ? (
              <div>
                <Row gutter={16}>
                  <Col span={12}>
                    <Statistic title="恶意IP" value={threatStats.malicious_ips_count || 0} prefix={<CloseCircleOutlined style={{ color: '#ff4d4f' }} />} />
                  </Col>
                  <Col span={12}>
                    <Statistic title="恶意域名" value={threatStats.malicious_domains_count || 0} prefix={<ExclamationCircleOutlined style={{ color: '#fa8c16' }} />} />
                  </Col>
                </Row>
                <Divider />
                <Row gutter={16}>
                  <Col span={12}>
                    <Statistic title="APT组织" value={threatStats.apt_groups_count || 0} prefix={<LockOutlined style={{ color: '#722ed1' }} />} />
                  </Col>
                  <Col span={12}>
                    <Statistic title="威胁指标" value={threatStats.threat_indicators_count || 0} prefix={<SafetyCertificateOutlined style={{ color: '#1890ff' }} />} />
                  </Col>
                </Row>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
                <SafetyCertificateOutlined style={{ fontSize: 36, marginBottom: 8 }} />
                <div>暂无威胁情报数据</div>
              </div>
            )}
          </Card>
        </Col>
        <Col span={12}>
          <Card title="告警状态分布" variant="borderless" style={{ borderRadius: 12 }}>
            {alertStats.by_status ? (
              <div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text><Tag color="red">新告警</Tag></Text>
                    <Text strong>{alertStats.by_status.new || 0}</Text>
                  </div>
                  <Progress percent={alertStats.total ? Math.round(((alertStats.by_status.new || 0) / alertStats.total) * 100) : 0} strokeColor="#ff4d4f" size="small" />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text><Tag color="orange">已确认</Tag></Text>
                    <Text strong>{alertStats.by_status.acknowledged || 0}</Text>
                  </div>
                  <Progress percent={alertStats.total ? Math.round(((alertStats.by_status.acknowledged || 0) / alertStats.total) * 100) : 0} strokeColor="#fa8c16" size="small" />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text><Tag color="blue">处理中</Tag></Text>
                    <Text strong>{alertStats.by_status.in_progress || 0}</Text>
                  </div>
                  <Progress percent={alertStats.total ? Math.round(((alertStats.by_status.in_progress || 0) / alertStats.total) * 100) : 0} strokeColor="#1890ff" size="small" />
                </div>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text><Tag color="green">已解决</Tag></Text>
                    <Text strong>{alertStats.by_status.resolved || 0}</Text>
                  </div>
                  <Progress percent={alertStats.total ? Math.round(((alertStats.by_status.resolved || 0) / alertStats.total) * 100) : 0} strokeColor="#52c41a" size="small" />
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
                <AlertOutlined style={{ fontSize: 36, marginBottom: 8 }} />
                <div>暂无告警数据</div>
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default SecurityOverview;
