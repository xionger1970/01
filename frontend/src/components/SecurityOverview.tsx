import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Row, Col, Statistic, Progress, Typography, Alert, Space, Tag, Skeleton } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, ExclamationCircleOutlined, AlertOutlined } from '@ant-design/icons';
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer } from 'recharts';
import { fetchOverview, fetchSystemStatus } from '../store/slices/dashboardSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';

const { Text } = Typography;

const SecurityOverview: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { overview, systemStatus, loading, error } = useSelector((state: RootState) => state.dashboard);

  useEffect(() => {
    dispatch(fetchOverview());
    dispatch(fetchSystemStatus());
  }, [dispatch]);

  // Security posture data for radar chart
  const securityPostureData = [
    { subject: '攻击检测', A: overview ? 85 : 0, fullMark: 100 },
    { subject: '自动响应', A: 70, fullMark: 100 },
    { subject: '系统健康', A: systemStatus ? 90 : 0, fullMark: 100 },
    { subject: '漏洞管理', A: 65, fullMark: 100 },
    { subject: '合规性', A: 80, fullMark: 100 },
    { subject: '威胁情报', A: 75, fullMark: 100 },
  ];

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
            <Card title="安全态势" bordered={false}>
              <Skeleton active paragraph={{ rows: 10 }} />
            </Card>
          </Col>
          <Col span={12}>
            <Card title="系统健康" bordered={false}>
              <Skeleton active paragraph={{ rows: 8 }} />
            </Card>
          </Col>
        </Row>

        <Row gutter={16}>
          <Col span={8}>
            <Card title="CPU使用率" bordered={false}>
              <Skeleton active paragraph={{ rows: 3 }} />
            </Card>
          </Col>
          <Col span={8}>
            <Card title="内存使用率" bordered={false}>
              <Skeleton active paragraph={{ rows: 3 }} />
            </Card>
          </Col>
          <Col span={8}>
            <Card title="磁盘使用率" bordered={false}>
              <Skeleton active paragraph={{ rows: 3 }} />
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
    <div>
      {/* Security Summary */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={24}>
          <Card style={{ transition: 'all 0.3s' }}>
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="总攻击数"
                  value={overview?.total_attacks || 0}
                  prefix={<AlertOutlined />}
                  valueStyle={{ color: '#1890ff' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="活跃攻击"
                  value={overview?.active_attacks || 0}
                  prefix={<ExclamationCircleOutlined />}
                  valueStyle={{ color: '#ff4d4f' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="最高攻击类型"
                  value={overview?.top_attack_types[0]?.type || 'N/A'}
                  suffix={`${overview?.top_attack_types[0]?.count || 0}次`}
                  valueStyle={{ color: '#fa8c16' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="系统状态"
                  value={systemStatus ? '正常' : '未知'}
                  prefix={getStatusIcon(systemStatus ? 'healthy' : 'warning')}
                  valueStyle={{ color: systemStatus ? '#52c41a' : '#faad14' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      {/* Security Posture and System Health */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={12}>
          <Card title="安全态势" bordered={false} style={{ transition: 'all 0.3s' }}>
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
        <Col span={12}>
          <Card title="系统健康" bordered={false} style={{ transition: 'all 0.3s' }}>
            {systemStatus?.services.map((service, index) => (
              <div key={index} style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>{service.name}</Text>
                  <Space>
                    <Tag color={service.status === 'healthy' ? 'green' : 'red'}>
                      {service.status}
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
      </Row>

      {/* Resource Usage */}
      <Row gutter={16}>
        <Col span={8}>
          <Card title="CPU使用率" bordered={false} style={{ transition: 'all 0.3s' }}>
            <Progress 
              percent={parseInt(systemStatus?.resources.cpu_usage || '0')} 
              status="active" 
              strokeColor="#1890ff"
            />
            <Text style={{ marginTop: 16, display: 'block' }} type="secondary">
              {systemStatus?.resources.cpu_usage || '0%'}
            </Text>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="内存使用率" bordered={false} style={{ transition: 'all 0.3s' }}>
            <Progress 
              percent={parseInt(systemStatus?.resources.memory_usage || '0')} 
              status="active" 
              strokeColor="#52c41a"
            />
            <Text style={{ marginTop: 16, display: 'block' }} type="secondary">
              {systemStatus?.resources.memory_usage || '0%'}
            </Text>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="磁盘使用率" bordered={false} style={{ transition: 'all 0.3s' }}>
            <Progress 
              percent={parseInt(systemStatus?.resources.disk_usage || '0')} 
              status="active" 
              strokeColor="#fa8c16"
            />
            <Text style={{ marginTop: 16, display: 'block' }} type="secondary">
              {systemStatus?.resources.disk_usage || '0%'}
            </Text>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default SecurityOverview;