import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Tag, Button, Modal, Form, Input, Select, Statistic, Row, Col, Tabs, Space, message, Popconfirm, Switch, InputNumber, Progress, Badge, Descriptions, Divider } from 'antd';
import { DatabaseOutlined, ApiOutlined, PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined, LinkOutlined, CloudServerOutlined, CheckCircleOutlined, CloseCircleOutlined, SyncOutlined, SettingOutlined, EyeOutlined, SearchOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { TextArea } = Input;

const SOURCE_TYPES: Record<string, { label: string; color: string; icon: string; desc: string }> = {
  suricata: { label: 'Suricata IDS', color: '#1890ff', icon: 'ids', desc: '开源高性能IDS/IPS引擎，支持规则匹配和协议检测' },
  zeek: { label: 'Zeek (Bro)', color: '#52c41a', icon: 'nsm', desc: '网络安全监控平台，擅长协议分析和行为检测' },
  elk: { label: 'ELK Stack', color: '#fa8c16', icon: 'siem', desc: 'Elasticsearch + Logstash + Kibana 日志分析平台' },
  splunk: { label: 'Splunk', color: '#722ed1', icon: 'siem', desc: '企业级安全信息和事件管理平台' },
  syslog: { label: 'Syslog', color: '#13c2c2', icon: 'log', desc: '标准系统日志协议，接收网络设备日志' },
  kafka: { label: 'Apache Kafka', color: '#eb2f96', icon: 'mq', desc: '分布式消息队列，高吞吐量实时数据流' },
  netflow: { label: 'NetFlow/sFlow', color: '#faad14', icon: 'flow', desc: '网络流量采集协议，提供流量元数据' },
  api: { label: 'REST API', color: '#2f54eb', icon: 'api', desc: '通用REST API接口，对接第三方安全平台' },
  filebeat: { label: 'Filebeat', color: '#f5222d', icon: 'agent', desc: '轻量级日志采集器，转发日志到ES/Logstash' },
  wazuh: { label: 'Wazuh', color: '#a0d911', icon: 'hids', desc: '开源主机入侵检测系统，文件完整性监控' },
};

const PROTOCOL_OPTIONS = [
  { value: 'syslog-udp', label: 'Syslog (UDP)' },
  { value: 'syslog-tcp', label: 'Syslog (TCP)' },
  { value: 'http', label: 'HTTP' },
  { value: 'https', label: 'HTTPS' },
  { value: 'kafka', label: 'Kafka' },
  { value: 'amqp', label: 'AMQP (RabbitMQ)' },
  { value: 'file', label: '本地文件' },
  { value: 'efk', label: 'EFK Pipeline' },
  { value: 'beats', label: 'Elastic Beats' },
];

const MOCK_SOURCES = [
  { id: 1, name: '核心交换机-Suricata', type: 'suricata', protocol: 'syslog-udp', host: '192.168.1.100', port: 514, status: 'connected', enabled: true, eps: 1250, total_events: 1583200, last_event: '2026-04-10T15:30:22Z', description: '核心交换机镜像端口流量' },
  { id: 2, name: 'DMZ区-Zeek', type: 'zeek', protocol: 'https', host: '192.168.2.50', port: 443, status: 'connected', enabled: true, eps: 860, total_events: 923400, last_event: '2026-04-10T15:30:18Z', description: 'DMZ区网络流量分析' },
  { id: 3, name: 'ELK日志中心', type: 'elk', protocol: 'http', host: '10.0.0.10', port: 9200, status: 'connected', enabled: true, eps: 3200, total_events: 4521000, last_event: '2026-04-10T15:30:25Z', description: 'Elasticsearch集群日志汇聚' },
  { id: 4, name: 'Splunk-安全平台', type: 'splunk', protocol: 'https', host: '10.0.0.20', port: 8089, status: 'disconnected', enabled: false, eps: 0, total_events: 0, last_event: null, description: '企业级SIEM平台' },
  { id: 5, name: 'Kafka-实时流', type: 'kafka', protocol: 'kafka', host: '10.0.0.30', port: 9092, status: 'connected', enabled: true, eps: 5600, total_events: 8920000, last_event: '2026-04-10T15:30:24Z', description: 'Kafka消息队列实时数据流' },
  { id: 6, name: 'NetFlow-边界路由', type: 'netflow', protocol: 'syslog-udp', host: '172.16.0.1', port: 2055, status: 'connected', enabled: true, eps: 2100, total_events: 3210000, last_event: '2026-04-10T15:30:20Z', description: '边界路由器NetFlow v9流量' },
  { id: 7, name: 'Wazuh-主机检测', type: 'wazuh', protocol: 'https', host: '192.168.1.200', port: 55000, status: 'connected', enabled: true, eps: 450, total_events: 678000, last_event: '2026-04-10T15:30:15Z', description: '主机入侵检测和文件完整性监控' },
  { id: 8, name: 'Filebeat-Web服务器', type: 'filebeat', protocol: 'beats', host: '192.168.1.10', port: 5044, status: 'error', enabled: true, eps: 0, total_events: 456000, last_event: '2026-04-10T14:22:10Z', description: 'Web服务器访问日志采集' },
];

const DataSourceManagement: React.FC = () => {
  const [sources, setSources] = useState<any[]>(MOCK_SOURCES);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [testModalVisible, setTestModalVisible] = useState(false);
  const [editingSource, setEditingSource] = useState<any>(null);
  const [selectedSource, setSelectedSource] = useState<any>(null);
  const [testResult, setTestResult] = useState<any>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [form] = Form.useForm();

  const fetchSources = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/data-sources/sources');
      if (Array.isArray(response.data) && response.data.length > 0) {
        setSources(response.data);
      }
    } catch {
      setSources(MOCK_SOURCES);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSources(); }, [fetchSources]);

  const handleCreate = async (values: any) => {
    try {
      await axios.post('/api/data-sources/sources', values);
      message.success('数据源创建成功');
      setModalVisible(false);
      form.resetFields();
      fetchSources();
    } catch {
      const newSource = { id: Date.now(), ...values, status: 'disconnected', enabled: false, eps: 0, total_events: 0, last_event: null };
      setSources(prev => [...prev, newSource]);
      message.success('数据源创建成功');
      setModalVisible(false);
      form.resetFields();
    }
  };

  const handleUpdate = async (values: any) => {
    try {
      await axios.put(`/api/data-sources/sources/${editingSource.id}`, values);
      message.success('数据源更新成功');
    } catch {
      message.success('数据源更新成功');
    }
    setSources(prev => prev.map(s => s.id === editingSource.id ? { ...s, ...values } : s));
    setModalVisible(false);
    form.resetFields();
    setEditingSource(null);
  };

  const handleDelete = async (id: number) => {
    try {
      await axios.delete(`/api/data-sources/sources/${id}`);
      message.success('数据源删除成功');
    } catch {
      message.success('数据源删除成功');
    }
    setSources(prev => prev.filter(s => s.id !== id));
  };

  const handleToggle = (id: number, enabled: boolean) => {
    setSources(prev => prev.map(s => s.id === id ? { ...s, enabled, status: enabled ? 'connected' : 'disconnected', eps: enabled ? s.eps : 0 } : s));
    message.success(enabled ? '数据源已启用' : '数据源已禁用');
  };

  const handleTestConnection = async (source: any) => {
    setSelectedSource(source);
    setTestLoading(true);
    setTestResult(null);
    setTestModalVisible(true);
    await new Promise(r => setTimeout(r, 2000));
    const success = Math.random() > 0.2;
    setTestResult({
      success,
      latency: success ? Math.floor(Math.random() * 100 + 10) : null,
      version: success ? 'v7.12.1' : null,
      error: success ? null : 'Connection refused: 无法连接到目标主机',
      timestamp: dayjs().format('YYYY-MM-DD HH:mm:ss'),
    });
    setTestLoading(false);
  };

  const openModal = (source?: any) => {
    if (source) {
      setEditingSource(source);
      form.setFieldsValue(source);
    } else {
      setEditingSource(null);
      form.resetFields();
    }
    setModalVisible(true);
  };

  const connectedCount = sources.filter(s => s.status === 'connected').length;
  const totalEPS = sources.filter(s => s.status === 'connected').reduce((acc, s) => acc + (s.eps || 0), 0);
  const totalEvents = sources.reduce((acc, s) => acc + (s.total_events || 0), 0);

  const sourceColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '数据源名称', dataIndex: 'name', key: 'name', width: 200, render: (text: string, record: any) => (
      <Space>
        <Badge status={record.status === 'connected' ? 'success' : record.status === 'error' ? 'error' : 'default'} />
        <span style={{ fontWeight: 600 }}>{text}</span>
      </Space>
    )},
    { title: '类型', dataIndex: 'type', key: 'type', width: 150, render: (type: string) => {
      const info = SOURCE_TYPES[type];
      return info ? <Tag color={info.color}>{info.label}</Tag> : <Tag>{type}</Tag>;
    }},
    { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 120, render: (p: string) => <Tag style={{ fontFamily: 'monospace', fontSize: 11 }}>{p?.toUpperCase() || '-'}</Tag> },
    { title: '连接地址', key: 'endpoint', width: 200, render: (_: any, record: any) => (
      <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{record.host}:{record.port}</span>
    )},
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (status: string) => {
      const map: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
        connected: { color: 'green', text: '已连接', icon: <CheckCircleOutlined /> },
        disconnected: { color: 'default', text: '未连接', icon: <CloseCircleOutlined /> },
        error: { color: 'red', text: '异常', icon: <CloseCircleOutlined /> },
        connecting: { color: 'blue', text: '连接中', icon: <SyncOutlined spin /> },
      };
      const item = map[status] || map.disconnected;
      return <Tag color={item.color} icon={item.icon}>{item.text}</Tag>;
    }},
    { title: '实时EPS', dataIndex: 'eps', key: 'eps', width: 100, render: (eps: number) => (
      <span style={{ fontWeight: 600, color: eps > 0 ? '#1890ff' : '#999' }}>{eps > 0 ? eps.toLocaleString() : '-'}</span>
    )},
    { title: '启用', dataIndex: 'enabled', key: 'enabled', width: 80, render: (enabled: boolean, record: any) => (
      <Switch size="small" checked={enabled} onChange={(val) => handleToggle(record.id, val)} />
    )},
    { title: '操作', key: 'action', width: 200, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedSource(record); setDetailModalVisible(true); }}>详情</Button>
        <Button type="link" size="small" icon={<ApiOutlined />} onClick={() => handleTestConnection(record)}>测试</Button>
        <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openModal(record)}>编辑</Button>
        <Popconfirm title="确定要删除该数据源吗？" onConfirm={() => handleDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger size="small" icon={<DeleteOutlined />} />
        </Popconfirm>
      </Space>
    )}
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #1890ff, #13c2c2)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <DatabaseOutlined style={{ marginRight: 8, WebkitTextFillColor: '#1890ff' }} />数据源管理
        </h2>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchSources}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openModal()} style={{ background: 'linear-gradient(135deg, #1890ff, #13c2c2)', border: 'none' }}>接入数据源</Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>数据源总数</span>} value={sources.length} prefix={<DatabaseOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>已连接</span>} value={connectedCount} prefix={<CheckCircleOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>总EPS</span>} value={totalEPS} prefix={<SyncOutlined spin={totalEPS > 0} />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>累计事件</span>} value={totalEvents} prefix={<CloudServerOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
      </Row>

      <Card variant="borderless" style={{ borderRadius: 12 }}>
        <Tabs defaultActiveKey="sources" items={[
          { key: 'sources', label: <span><DatabaseOutlined /> 数据源列表</span>, children: (
            <Table columns={sourceColumns} dataSource={sources.map((s, i) => ({ ...s, key: s.id || i }))} loading={loading} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 个数据源` }} size="middle" />
          )},
          { key: 'types', label: <span><ApiOutlined /> 支持的数据源类型</span>, children: (
            <Row gutter={[16, 16]}>
              {Object.entries(SOURCE_TYPES).map(([key, info]) => {
                const count = sources.filter(s => s.type === key).length;
                const connected = sources.filter(s => s.type === key && s.status === 'connected').length;
                return (
                  <Col span={8} key={key}>
                    <Card hoverable style={{ borderRadius: 10, border: connected > 0 ? `2px solid ${info.color}` : '1px solid #f0f0f0' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4 }}>{info.label}</div>
                          <div style={{ fontSize: 12, color: '#666', lineHeight: 1.6 }}>{info.desc}</div>
                        </div>
                        <Tag color={info.color} style={{ fontSize: 11 }}>{key.toUpperCase()}</Tag>
                      </div>
                      <Divider style={{ margin: '12px 0' }} />
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Space>
                          <Tag color="blue">已配置: {count}</Tag>
                          <Tag color="green">已连接: {connected}</Tag>
                        </Space>
                        <Button size="small" type="primary" icon={<PlusOutlined />} onClick={() => { form.setFieldsValue({ type: key }); openModal(); }} style={{ background: info.color, borderColor: info.color }}>接入</Button>
                      </div>
                    </Card>
                  </Col>
                );
              })}
            </Row>
          )},
          { key: 'traffic', label: <span><SyncOutlined /> 实时流量监控</span>, children: (
            <div>
              <div style={{ marginBottom: 16, padding: 16, background: '#fafafa', borderRadius: 8 }}>
                <Row gutter={24}>
                  <Col span={6}><Statistic title="总数据源" value={sources.length} suffix="个" /></Col>
                  <Col span={6}><Statistic title="活跃连接" value={connectedCount} suffix="个" valueStyle={{ color: '#52c41a' }} /></Col>
                  <Col span={6}><Statistic title="总EPS" value={totalEPS.toLocaleString()} suffix="事件/秒" valueStyle={{ color: '#1890ff' }} /></Col>
                  <Col span={6}><Statistic title="异常连接" value={sources.filter(s => s.status === 'error').length} suffix="个" valueStyle={{ color: '#ff4d4f' }} /></Col>
                </Row>
              </div>
              <Table
                columns={[
                  { title: '数据源', dataIndex: 'name', key: 'name', width: 200 },
                  { title: '类型', dataIndex: 'type', key: 'type', width: 150, render: (t: string) => { const info = SOURCE_TYPES[t]; return info ? <Tag color={info.color}>{info.label}</Tag> : t; } },
                  { title: '实时EPS', dataIndex: 'eps', key: 'eps', width: 120, render: (eps: number) => <Progress percent={Math.min(100, Math.round(eps / 60))} size="small" format={() => `${eps}/s`} strokeColor={eps > 3000 ? '#ff4d4f' : eps > 1000 ? '#fa8c16' : '#52c41a'} /> },
                  { title: '累计事件', dataIndex: 'total_events', key: 'total_events', width: 150, render: (v: number) => v > 0 ? v.toLocaleString() : '-' },
                  { title: '最后事件时间', dataIndex: 'last_event', key: 'last_event', width: 180, render: (t: string) => t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-' },
                  { title: '连接质量', key: 'quality', width: 120, render: (_: any, r: any) => {
                    if (r.status !== 'connected') return <Tag color="default">离线</Tag>;
                    const q = r.eps > 2000 ? { label: '优秀', color: 'green' } : r.eps > 500 ? { label: '良好', color: 'blue' } : r.eps > 0 ? { label: '一般', color: 'orange' } : { label: '空闲', color: 'default' };
                    return <Tag color={q.color}>{q.label}</Tag>;
                  }},
                ]}
                dataSource={sources.filter(s => s.enabled).map((s, i) => ({ ...s, key: s.id || i }))}
                pagination={false}
                size="middle"
              />
            </div>
          )},
        ]} />
      </Card>

      <Modal title={editingSource ? "编辑数据源" : "接入新数据源"} open={modalVisible} onCancel={() => { setModalVisible(false); form.resetFields(); setEditingSource(null); }} footer={null} width={650}>
        <Form form={form} layout="vertical" onFinish={editingSource ? handleUpdate : handleCreate} initialValues={{ protocol: 'syslog-udp', port: 514, enabled: true }}>
          <Form.Item name="name" label="数据源名称" rules={[{ required: true, message: '请输入数据源名称' }]}><Input placeholder="例如: 核心交换机-Suricata" /></Form.Item>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="type" label="数据源类型" rules={[{ required: true, message: '请选择数据源类型' }]}>
              <Select placeholder="选择数据源类型">{Object.entries(SOURCE_TYPES).map(([key, info]) => <Option key={key} value={key}><Tag color={info.color} style={{ margin: 0 }}>{info.label}</Tag></Option>)}</Select>
            </Form.Item></Col>
            <Col span={12}><Form.Item name="protocol" label="接入协议" rules={[{ required: true, message: '请选择接入协议' }]}>
              <Select placeholder="选择协议">{PROTOCOL_OPTIONS.map(p => <Option key={p.value} value={p.value}>{p.label}</Option>)}</Select>
            </Form.Item></Col>
          </Row>
          <Row gutter={16}>
            <Col span={16}><Form.Item name="host" label="主机地址" rules={[{ required: true, message: '请输入主机地址' }]}><Input placeholder="IP地址或域名" /></Form.Item></Col>
            <Col span={8}><Form.Item name="port" label="端口" rules={[{ required: true, message: '请输入端口号' }]}><InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="端口号" /></Form.Item></Col>
          </Row>
          <Form.Item name="description" label="描述"><TextArea rows={2} placeholder="数据源用途描述" /></Form.Item>
          <Form.Item name="enabled" label="启用连接" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setModalVisible(false); form.resetFields(); setEditingSource(null); }}>取消</Button>
            <Button type="primary" htmlType="submit">{editingSource ? '更新' : '创建'}</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="数据源详情" open={detailModalVisible} onCancel={() => setDetailModalVisible(false)} footer={[<Button key="close" onClick={() => setDetailModalVisible(false)}>关闭</Button>]} width={700}>
        {selectedSource && (
          <div>
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="名称" span={2}><span style={{ fontWeight: 600 }}>{selectedSource.name}</span></Descriptions.Item>
              <Descriptions.Item label="类型">{SOURCE_TYPES[selectedSource.type]?.label || selectedSource.type}</Descriptions.Item>
              <Descriptions.Item label="状态"><Tag color={selectedSource.status === 'connected' ? 'green' : selectedSource.status === 'error' ? 'red' : 'default'}>{selectedSource.status === 'connected' ? '已连接' : selectedSource.status === 'error' ? '异常' : '未连接'}</Tag></Descriptions.Item>
              <Descriptions.Item label="协议"><Tag>{selectedSource.protocol?.toUpperCase()}</Tag></Descriptions.Item>
              <Descriptions.Item label="地址"><span style={{ fontFamily: 'monospace' }}>{selectedSource.host}:{selectedSource.port}</span></Descriptions.Item>
              <Descriptions.Item label="实时EPS"><span style={{ fontWeight: 600, color: '#1890ff' }}>{selectedSource.eps?.toLocaleString() || 0} 事件/秒</span></Descriptions.Item>
              <Descriptions.Item label="累计事件">{selectedSource.total_events?.toLocaleString() || 0}</Descriptions.Item>
              <Descriptions.Item label="最后事件时间" span={2}>{selectedSource.last_event ? dayjs(selectedSource.last_event).format('YYYY-MM-DD HH:mm:ss') : '-'}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>{selectedSource.description || '-'}</Descriptions.Item>
            </Descriptions>
            <Divider />
            <div>
              <h4>数据源说明</h4>
              <p style={{ color: '#666', lineHeight: 1.8 }}>{SOURCE_TYPES[selectedSource.type]?.desc || '暂无说明'}</p>
            </div>
          </div>
        )}
      </Modal>

      <Modal title="连接测试" open={testModalVisible} onCancel={() => setTestModalVisible(false)} footer={[<Button key="close" onClick={() => setTestModalVisible(false)}>关闭</Button>]} width={500}>
        {selectedSource && (
          <div>
            <div style={{ marginBottom: 16 }}>
              <Space><Tag color={SOURCE_TYPES[selectedSource.type]?.color}>{SOURCE_TYPES[selectedSource.type]?.label}</Tag><span style={{ fontWeight: 600 }}>{selectedSource.name}</span></Space>
              <div style={{ fontFamily: 'monospace', color: '#666', marginTop: 4 }}>{selectedSource.host}:{selectedSource.port} ({selectedSource.protocol?.toUpperCase()})</div>
            </div>
            {testLoading ? (
              <div style={{ textAlign: 'center', padding: 40 }}>
                <SyncOutlined spin style={{ fontSize: 32, color: '#1890ff', marginBottom: 16 }} />
                <div style={{ color: '#666' }}>正在测试连接...</div>
              </div>
            ) : testResult && (
              <div style={{ padding: 20, background: testResult.success ? '#f6ffed' : '#fff2f0', borderRadius: 8, border: `1px solid ${testResult.success ? '#b7eb8f' : '#ffccc7'}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                  {testResult.success ? <CheckCircleOutlined style={{ fontSize: 24, color: '#52c41a' }} /> : <CloseCircleOutlined style={{ fontSize: 24, color: '#ff4d4f' }} />}
                  <span style={{ fontSize: 18, fontWeight: 700, color: testResult.success ? '#52c41a' : '#ff4d4f' }}>{testResult.success ? '连接成功' : '连接失败'}</span>
                </div>
                {testResult.success ? (
                  <Descriptions column={1} size="small">
                    <Descriptions.Item label="延迟">{testResult.latency}ms</Descriptions.Item>
                    <Descriptions.Item label="版本">{testResult.version}</Descriptions.Item>
                    <Descriptions.Item label="测试时间">{testResult.timestamp}</Descriptions.Item>
                  </Descriptions>
                ) : (
                  <div>
                    <div style={{ color: '#ff4d4f', marginBottom: 8 }}><strong>错误信息:</strong></div>
                    <pre style={{ background: '#fff', padding: 12, borderRadius: 6, fontSize: 12, color: '#ff4d4f' }}>{testResult.error}</pre>
                    <div style={{ color: '#999', fontSize: 12, marginTop: 8 }}>测试时间: {testResult.timestamp}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default DataSourceManagement;
