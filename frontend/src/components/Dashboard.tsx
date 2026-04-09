import React, { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Row, Col, Statistic, Progress, Typography, Alert, Skeleton, Button, Modal, Checkbox, Select, Space, Divider } from 'antd';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import type { PieLabelRenderProps } from 'recharts';
import { SettingOutlined, EyeOutlined, EyeInvisibleOutlined, ReloadOutlined, DragOutlined } from '@ant-design/icons';
import Draggable from 'react-draggable';
import { ResizableBox } from 'react-resizable';
import 'react-resizable/css/styles.css';
import { fetchOverview, fetchTopTargets, fetchSystemStatus, updateWidgetPosition, updateWidgetSize, toggleWidgetVisibility, updateLayout, resetDashboard } from '../store/slices/dashboardSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import type { DashboardWidget } from '../types';

const { Title, Text } = Typography;

const Dashboard: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { overview, topTargets, systemStatus, configuration, loading, error } = useSelector((state: RootState) => state.dashboard);
  const [settingsModalVisible, setSettingsModalVisible] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    dispatch(fetchOverview());
    dispatch(fetchTopTargets());
    dispatch(fetchSystemStatus());
  }, [dispatch]);

  if (loading) {
    return (
      <div className="loading-container" style={{ padding: '24px' }}>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          {[1, 2, 3, 4].map((i) => (
            <Col span={6} key={i}>
              <Card>
                <Skeleton active paragraph={{ rows: 1 }} />
              </Card>
            </Col>
          ))}
        </Row>
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={16}>
            <Card>
              <Skeleton active paragraph={{ rows: 10 }} />
            </Card>
          </Col>
          <Col span={8}>
            <Card>
              <Skeleton active paragraph={{ rows: 10 }} />
            </Card>
          </Col>
        </Row>
        <Row gutter={16}>
          <Col span={12}>
            <Card>
              <Skeleton active paragraph={{ rows: 8 }} />
            </Card>
          </Col>
          <Col span={12}>
            <Card>
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

  // Severity distribution data for pie chart
  const severityData = overview ? [
    { name: 'Critical', value: overview.severity_distribution.critical, color: '#ff4d4f' },
    { name: 'High', value: overview.severity_distribution.high, color: '#fa8c16' },
    { name: 'Medium', value: overview.severity_distribution.medium, color: '#faad14' },
    { name: 'Low', value: overview.severity_distribution.low, color: '#52c41a' },
  ] : [];

  // Attack trend data for area chart
  const trendData = overview ? overview.attack_trend.map(item => ({
    name: new Date(item.timestamp).toLocaleTimeString(),
    attacks: item.count,
  })) : [];

  // Render widget content based on type
  const renderWidgetContent = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'summary':
        return (
          <Row gutter={16}>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Total Attacks"
                  value={overview?.total_attacks || 0}
                  suffix="events"
                  valueStyle={{ color: '#1890ff' }}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Active Attacks"
                  value={overview?.active_attacks || 0}
                  suffix="ongoing"
                  valueStyle={{ color: '#ff4d4f' }}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Top Attack Type"
                  value={overview?.top_attack_types[0]?.type || 'N/A'}
                  suffix={`${overview?.top_attack_types[0]?.count || 0} attacks`}
                  valueStyle={{ color: '#fa8c16' }}
                />
              </Card>
            </Col>
            <Col span={6}>
              <Card>
                <Statistic
                  title="Top Source IP"
                  value={overview?.top_source_ips[0]?.ip || 'N/A'}
                  suffix={`${overview?.top_source_ips[0]?.count || 0} attacks`}
                  valueStyle={{ color: '#52c41a' }}
                />
              </Card>
            </Col>
          </Row>
        );
      case 'trend':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart
              data={trendData}
              margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="attacks" stroke="#1890ff" fill="#e6f7ff" />
            </AreaChart>
          </ResponsiveContainer>
        );
      case 'severity':
        return (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
                label={(props: PieLabelRenderProps) => props.name && props.percent ? `${props.name}: ${(props.percent * 100).toFixed(0)}%` : ''}
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
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
                  <Text type="secondary">{target.count} attacks</Text>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {target.attack_types.map((type, i) => (
                    <span key={i} style={{ 
                      padding: '2px 8px', 
                      backgroundColor: '#f0f0f0', 
                      borderRadius: 4, 
                      fontSize: 12 
                    }}>
                      {type}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        );
      case 'system':
        return (
          <div className="system-status">
            <div style={{ marginBottom: 24 }}>
              <Title level={5}>Services</Title>
              {systemStatus?.services.map((service, index) => (
                <div key={index} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <Text>{service.name}</Text>
                  <Text style={{ 
                    color: service.status === 'healthy' ? '#52c41a' : '#ff4d4f' 
                  }}>
                    {service.status} ({service.uptime})
                  </Text>
                </div>
              ))}
            </div>
            <div>
              <Title level={5}>Resources</Title>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>CPU Usage</Text>
                  <Text>{systemStatus?.resources.cpu_usage}</Text>
                </div>
                <Progress percent={parseInt(systemStatus?.resources.cpu_usage || '0')} status="active" />
              </div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>Memory Usage</Text>
                  <Text>{systemStatus?.resources.memory_usage}</Text>
                </div>
                <Progress percent={parseInt(systemStatus?.resources.memory_usage || '0')} status="active" />
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text>Disk Usage</Text>
                  <Text>{systemStatus?.resources.disk_usage}</Text>
                </div>
                <Progress percent={parseInt(systemStatus?.resources.disk_usage || '0')} status="active" />
              </div>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  // Handle widget drag end
  const handleDragEnd = (widget: DashboardWidget, _e: any, data: any) => {
    dispatch(updateWidgetPosition({
      id: widget.id,
      x: Math.max(0, data.x),
      y: Math.max(0, data.y),
    }));
  };

  // Handle widget resize end
  const handleResizeEnd = (widget: DashboardWidget, _e: any, data: any) => {
    dispatch(updateWidgetSize({
      id: widget.id,
      width: Math.max(4, data.size.width / 80), // Convert pixels to grid columns (approx 80px per column)
      height: Math.max(2, data.size.height / 40), // Convert pixels to grid rows (approx 40px per row)
    }));
  };

  // Reset dashboard to default configuration
  const handleResetDashboard = () => {
    dispatch(resetDashboard());
  };

  return (
    <div className="dashboard" style={{ position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2}>Web Attack Situational Awareness</Title>
        <Space>
          <Button
            icon={<SettingOutlined />}
            onClick={() => setSettingsModalVisible(true)}
          >
            仪表盘设置
          </Button>
          <Button
            icon={<ReloadOutlined />}
            onClick={handleResetDashboard}
          >
            重置布局
          </Button>
        </Space>
      </div>

      {/* Dashboard widgets */}
      <div style={{ position: 'relative', minHeight: '600px' }}>
        {configuration.widgets
          .filter(widget => widget.visible)
          .map((widget) => (
            <Draggable
              key={widget.id}
              defaultPosition={{ x: widget.x * 80, y: widget.y * 40 }}
              onStart={() => setIsDragging(true)}
              onStop={(_e: any, data: any) => {
                handleDragEnd(widget, _e, data);
                setIsDragging(false);
              }}
            >
              <div
                style={{
                  position: 'absolute',
                  left: widget.x * 80,
                  top: widget.y * 40,
                  width: widget.width * 80,
                  height: widget.height * 40,
                  zIndex: isDragging ? 1000 : 1,
                }}
              >
                <ResizableBox
                  width={widget.width * 80}
                  height={widget.height * 40}
                  minConstraints={[320, 160]}
                  maxConstraints={[1280, 640]}
                  onResizeStop={(_e: any, data: any) => handleResizeEnd(widget, _e, data)}
                  resizeHandles={['se']}
                >
                  <Card
                    title={
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span>{widget.title}</span>
                        <Space>
                          <Button
                            type="text"
                            icon={widget.visible ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                            onClick={() => dispatch(toggleWidgetVisibility(widget.id))}
                          />
                          <DragOutlined style={{ cursor: 'move' }} />
                        </Space>
                      </div>
                    }
                    bordered={false}
                    style={{ height: '100%' }}
                  >
                    {renderWidgetContent(widget)}
                  </Card>
                </ResizableBox>
              </div>
            </Draggable>
          ))}
      </div>

      {/* Dashboard Settings Modal */}
      <Modal
        title="仪表盘设置"
        open={settingsModalVisible}
        onCancel={() => setSettingsModalVisible(false)}
        footer={[
          <Button key="cancel" onClick={() => setSettingsModalVisible(false)}>
            取消
          </Button>,
          <Button key="ok" type="primary" onClick={() => setSettingsModalVisible(false)}>
            确定
          </Button>,
        ]}
      >
        <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
          <h3>组件显示</h3>
          {configuration.widgets.map((widget) => (
            <div key={widget.id} style={{ marginBottom: 12 }}>
              <Checkbox
                checked={widget.visible}
                onChange={() => dispatch(toggleWidgetVisibility(widget.id))}
              >
                {widget.title}
              </Checkbox>
            </div>
          ))}
          <Divider />
          <h3>布局设置</h3>
          <div style={{ marginBottom: 16 }}>
            <span style={{ marginRight: 12 }}>布局类型：</span>
            <Select
              value={configuration.layout}
              onChange={(value) => dispatch(updateLayout(value))}
              style={{ width: 120 }}
            >
              <Select.Option value="grid">网格布局</Select.Option>
              <Select.Option value="custom">自定义布局</Select.Option>
            </Select>
          </div>
          <Button type="primary" onClick={handleResetDashboard}>
            重置为默认布局
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default Dashboard;
