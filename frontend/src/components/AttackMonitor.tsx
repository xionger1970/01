import React, { useEffect, useState, useCallback } from 'react';
import { Card, Table, Tag, Button, Space, Modal, Descriptions, message, Input, Select, Popconfirm, Form, Row, Col, Statistic, Badge, Tabs, Steps, Divider, Tooltip, Typography } from 'antd';
import { EyeOutlined, ReloadOutlined, DeleteOutlined, EditOutlined, PlusOutlined, SearchOutlined, StopOutlined, CheckCircleOutlined, ExclamationCircleOutlined, AimOutlined, GlobalOutlined, KeyOutlined, BugOutlined, LinkOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { Text } = Typography;

interface AttackEvent {
  id: number;
  attack_type: string;
  source_ip: string;
  target_ip: string;
  target_port: number;
  severity: string;
  status: string;
  request_method: string;
  request_path: string;
  response_code: number;
  user_agent: string;
  event_time: string;
  details: any;
}

const KILL_CHAIN_STAGES = [
  { key: 'recon', name: '侦察', color: '#1890ff', types: ['Port Scan', 'Vulnerability Scan'] },
  { key: 'weaponize', name: '武器化', color: '#722ed1', types: ['Exploit Kit'] },
  { key: 'deliver', name: '投递', color: '#fa8c16', types: ['Phishing', 'Drive-by'] },
  { key: 'exploit', name: '利用', color: '#ff4d4f', types: ['SQL Injection', 'XSS', 'Command Injection', 'RCE', 'CSRF'] },
  { key: 'install', name: '安装', color: '#eb2f96', types: ['File Inclusion', 'Webshell'] },
  { key: 'c2', name: '命令控制', color: '#13c2c2', types: ['C2 Beacon', 'Backdoor'] },
  { key: 'act', name: '目标行动', color: '#52c41a', types: ['Data Exfiltration', 'DDoS', 'Brute Force', 'Path Traversal'] },
];

const IP_GEO_MAP: Record<string, { country: string; city: string; isp: string; lat: number; lon: number }> = {
  '192.168.1.100': { country: '中国', city: '北京', isp: '中国电信', lat: 39.9, lon: 116.4 },
  '10.0.0.50': { country: '美国', city: '旧金山', isp: 'Amazon AWS', lat: 37.8, lon: -122.4 },
  '172.16.0.20': { country: '俄罗斯', city: '莫斯科', isp: 'Rostelecom', lat: 55.8, lon: 37.6 },
  '192.168.2.150': { country: '中国', city: '上海', isp: '中国联通', lat: 31.2, lon: 121.5 },
  '10.1.1.80': { country: '韩国', city: '首尔', isp: 'KT Corporation', lat: 37.6, lon: 127.0 },
};

const AttackMonitor: React.FC = () => {
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<AttackEvent | null>(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [editModalVisible, setEditModalVisible] = useState(false);
  const [addModalVisible, setAddModalVisible] = useState(false);
  const [editingEvent, setEditingEvent] = useState<AttackEvent | null>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [filters, setFilters] = useState({ attack_type: '', source_ip: '', severity: '' });
  const [form] = Form.useForm();
  const [addForm] = Form.useForm();
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, blocked: 0 });

  const severityMap: Record<string, { text: string; color: string; badge: 'error' | 'warning' | 'success' | 'default' | 'processing' }> = {
    critical: { text: '严重', color: 'red', badge: 'error' }, high: { text: '高危', color: 'orange', badge: 'warning' },
    medium: { text: '中危', color: 'gold', badge: 'processing' }, low: { text: '低危', color: 'blue', badge: 'default' }, info: { text: '信息', color: 'green', badge: 'success' }
  };

  const statusMap: Record<string, { text: string; color: string; icon: React.ReactNode }> = {
    detected: { text: '已检测', color: 'orange', icon: <ExclamationCircleOutlined /> },
    blocked: { text: '已阻断', color: 'green', icon: <StopOutlined /> },
    investigating: { text: '调查中', color: 'blue', icon: <SearchOutlined /> },
    resolved: { text: '已解决', color: 'default', icon: <CheckCircleOutlined /> }
  };

  const attackTypeMap: Record<string, string> = {
    'SQL Injection': 'SQL注入', 'XSS': '跨站脚本', 'DDoS': '分布式拒绝服务',
    'Brute Force': '暴力破解', 'CSRF': '跨站请求伪造', 'Command Injection': '命令注入',
    'Path Traversal': '路径遍历', 'RCE': '远程代码执行', 'File Inclusion': '文件包含', 'Other': '其他'
  };

  const getKillChainStage = (attackType: string) => {
    for (const stage of KILL_CHAIN_STAGES) {
      if (stage.types.some(t => attackType.toLowerCase().includes(t.toLowerCase()) || t.toLowerCase().includes(attackType.toLowerCase()))) {
        return stage;
      }
    }
    return KILL_CHAIN_STAGES[3];
  };

  const extractIOC = (event: AttackEvent) => {
    const iocs: { type: string; value: string; context: string }[] = [];
    iocs.push({ type: 'IP', value: event.source_ip, context: '攻击源IP' });
    iocs.push({ type: 'IP', value: event.target_ip, context: '攻击目标IP' });
    if (event.request_path && event.request_path.length > 5) {
      iocs.push({ type: 'URL', value: event.request_path, context: '请求路径' });
    }
    if (event.user_agent) {
      iocs.push({ type: 'UA', value: event.user_agent, context: '用户代理' });
    }
    if (event.details?.payload) {
      iocs.push({ type: 'PAYLOAD', value: String(event.details.payload).substring(0, 100), context: '攻击载荷' });
    }
    return iocs;
  };

  const fetchEvents = useCallback(async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    try {
      const response = await axios.get('/api/attack-events', { params: { limit: 100, ...filters } });
      const data = Array.isArray(response.data) ? response.data : [];
      setEvents(data);
      const total = data.length;
      const critical = data.filter((e: AttackEvent) => e.severity === 'critical').length;
      const high = data.filter((e: AttackEvent) => e.severity === 'high').length;
      const blocked = data.filter((e: AttackEvent) => e.status === 'blocked').length;
      setStats({ total, critical, high, blocked });
    } catch (error) {
      console.error('获取攻击事件失败:', error);
    } finally {
      if (showLoading) setInitialLoading(false);
    }
  }, [filters]);

  useEffect(() => { fetchEvents(true); const interval = setInterval(() => fetchEvents(false), 5000); return () => clearInterval(interval); }, [fetchEvents]);

  const handleDelete = async (id: number) => { try { await axios.delete(`/api/attack-events/${id}`); message.success('删除成功'); fetchEvents(); } catch (error) { message.error('删除失败'); } };
  const handleBatchDelete = async () => { if (selectedRowKeys.length === 0) { message.warning('请先选择要删除的事件'); return; } try { await Promise.all(selectedRowKeys.map(key => axios.delete(`/api/attack-events/${key}`))); message.success(`成功删除 ${selectedRowKeys.length} 条记录`); setSelectedRowKeys([]); fetchEvents(); } catch (error) { message.error('批量删除失败'); } };
  const handleBatchBlock = async () => { if (selectedRowKeys.length === 0) { message.warning('请先选择要封锁的事件'); return; } try { await Promise.all(selectedRowKeys.map(key => axios.put(`/api/attack-events/${key}`, { status: 'blocked' }))); message.success(`成功封锁 ${selectedRowKeys.length} 条记录`); setSelectedRowKeys([]); fetchEvents(); } catch (error) { message.error('批量封锁失败'); } };
  const handleStatusChange = async (id: number, status: string) => { try { await axios.put(`/api/attack-events/${id}`, { status }); message.success('状态更新成功'); fetchEvents(); } catch (error) { message.error('状态更新失败'); } };
  const handleEdit = async (values: any) => { if (!editingEvent) return; try { await axios.put(`/api/attack-events/${editingEvent.id}`, values); message.success('编辑成功'); setEditModalVisible(false); setEditingEvent(null); form.resetFields(); fetchEvents(); } catch (error) { message.error('编辑失败'); } };
  const handleAdd = async (values: any) => { try { await axios.post('/api/attack-events', { ...values, event_time: new Date().toISOString(), details: { description: values.description || '', payload: '' }, request_params: {} }); message.success('添加成功'); setAddModalVisible(false); addForm.resetFields(); fetchEvents(); } catch (error) { message.error('添加失败'); } };

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60, sorter: (a: AttackEvent, b: AttackEvent) => a.id - b.id },
    { title: '攻击类型', dataIndex: 'attack_type', key: 'attack_type', width: 130, render: (text: string) => <Tag color="blue">{attackTypeMap[text] || text}</Tag> },
    { title: '来源IP', dataIndex: 'source_ip', key: 'source_ip', width: 140, render: (text: string) => (<Space size={4}><span style={{ fontFamily: 'monospace', color: '#ff4d4f' }}>{text}</span>{IP_GEO_MAP[text] && <Tooltip title={`${IP_GEO_MAP[text].city}, ${IP_GEO_MAP[text].country}`}><GlobalOutlined style={{ color: '#1890ff', fontSize: 11 }} /></Tooltip>}</Space>) },
    { title: '目标IP', dataIndex: 'target_ip', key: 'target_ip', width: 140, render: (text: string) => <span style={{ fontFamily: 'monospace' }}>{text}</span> },
    { title: 'Kill Chain', key: 'kill_chain', width: 100, render: (_: any, record: AttackEvent) => { const stage = getKillChainStage(record.attack_type); return <Tag color={stage.color} style={{ fontSize: 11 }}>{stage.name}</Tag>; } },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (text: string) => { const item = severityMap[text] || { text, color: 'default', badge: 'default' as const }; return <Badge status={item.badge} text={<Tag color={item.color}>{item.text}</Tag>} />; } },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (text: string) => { const item = statusMap[text] || { text, color: 'default', icon: null }; return <Tag color={item.color} icon={item.icon}>{item.text}</Tag>; } },
    { title: '时间', dataIndex: 'event_time', key: 'event_time', width: 170, render: (text: string) => dayjs(text).format('YYYY-MM-DD HH:mm:ss'), sorter: (a: AttackEvent, b: AttackEvent) => new Date(a.event_time).getTime() - new Date(b.event_time).getTime() },
    { title: '操作', key: 'action', width: 200, render: (_: any, record: AttackEvent) => (<Space size={4}><Button type="link" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedEvent(record); setModalVisible(true); }}>详情</Button><Button type="link" size="small" icon={<EditOutlined />} onClick={() => { setEditingEvent(record); form.setFieldsValue(record); setEditModalVisible(true); }}>编辑</Button><Select size="small" value={record.status} style={{ width: 90 }} onChange={(value) => handleStatusChange(record.id, value)}><Option value="detected">已检测</Option><Option value="blocked">已阻断</Option><Option value="investigating">调查中</Option><Option value="resolved">已解决</Option></Select><Popconfirm title="确定删除该事件吗？" onConfirm={() => handleDelete(record.id)} okText="确定" cancelText="取消"><Button type="link" danger size="small" icon={<DeleteOutlined />} /></Popconfirm></Space>) }
  ];

  const killChainStats = KILL_CHAIN_STAGES.map(stage => {
    const count = events.filter(e => { const s = getKillChainStage(e.attack_type); return s.key === stage.key; }).length;
    return { ...stage, count };
  });

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #ff4d4f, #fa8c16)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>实时攻击监控</h2>
        <Space>
          <Input placeholder="搜索来源IP" prefix={<SearchOutlined />} style={{ width: 180 }} value={filters.source_ip} onChange={(e) => setFilters(prev => ({ ...prev, source_ip: e.target.value }))} allowClear />
          <Select placeholder="攻击类型" style={{ width: 140 }} value={filters.attack_type || undefined} onChange={(value) => setFilters(prev => ({ ...prev, attack_type: value }))} allowClear>{Object.entries(attackTypeMap).map(([key, value]) => (<Option key={key} value={key}>{value}</Option>))}</Select>
          <Select placeholder="严重程度" style={{ width: 120 }} value={filters.severity || undefined} onChange={(value) => setFilters(prev => ({ ...prev, severity: value }))} allowClear><Option value="critical">严重</Option><Option value="high">高危</Option><Option value="medium">中危</Option><Option value="low">低危</Option></Select>
          <Button type="primary" onClick={() => fetchEvents()} icon={<ReloadOutlined />}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddModalVisible(true)} style={{ background: '#52c41a', borderColor: '#52c41a' }}>新增</Button>
          {selectedRowKeys.length > 0 && (<><Popconfirm title={`确定删除选中的 ${selectedRowKeys.length} 条记录吗？`} onConfirm={handleBatchDelete} okText="确定" cancelText="取消"><Button danger icon={<DeleteOutlined />}>批量删除 ({selectedRowKeys.length})</Button></Popconfirm><Button type="primary" icon={<StopOutlined />} onClick={handleBatchBlock} style={{ background: '#fa8c16', borderColor: '#fa8c16' }}>批量封锁</Button></>)}
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>攻击总数</span>} value={stats.total} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>严重告警</span>} value={stats.critical} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>高危告警</span>} value={stats.high} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>已阻断</span>} value={stats.blocked} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
      </Row>

      <Card variant="borderless" style={{ borderRadius: 12, marginBottom: 16 }} title={<span><BugOutlined style={{ marginRight: 8 }} />Cyber Kill Chain 攻击链映射</span>}>
        <Steps size="small" items={killChainStats.map(stage => ({
          title: <span style={{ fontSize: 12, color: stage.count > 0 ? stage.color : '#999' }}>{stage.name}</span>,
          description: <span style={{ fontSize: 11, color: stage.count > 0 ? stage.color : '#ccc', fontWeight: stage.count > 0 ? 600 : 400 }}>{stage.count}次</span>,
          status: stage.count > 0 ? 'error' as const : 'wait' as const,
        }))} />
      </Card>

      <Card variant="borderless" style={{ borderRadius: 12 }}>
        <Table columns={columns} dataSource={events} rowKey="id" loading={initialLoading} rowSelection={{ selectedRowKeys, onChange: setSelectedRowKeys }} pagination={{ pageSize: 20, showSizeChanger: true, showQuickJumper: true, showTotal: (total) => `共 ${total} 条` }} size="middle" scroll={{ x: 1400 }} />
      </Card>

      <Modal title="攻击事件详情" open={modalVisible} onCancel={() => setModalVisible(false)} footer={[<Button key="close" onClick={() => setModalVisible(false)}>关闭</Button>]} width={800}>
        {selectedEvent && (
          <Tabs defaultActiveKey="basic" items={[
            { key: 'basic', label: '基本信息', children: (
              <Descriptions column={2} bordered size="small">
                <Descriptions.Item label="ID">{selectedEvent.id}</Descriptions.Item>
                <Descriptions.Item label="攻击类型">{attackTypeMap[selectedEvent.attack_type] || selectedEvent.attack_type}</Descriptions.Item>
                <Descriptions.Item label="来源IP"><span style={{ fontFamily: 'monospace', color: '#ff4d4f' }}>{selectedEvent.source_ip}</span></Descriptions.Item>
                <Descriptions.Item label="目标IP"><span style={{ fontFamily: 'monospace' }}>{selectedEvent.target_ip}</span></Descriptions.Item>
                <Descriptions.Item label="目标端口">{selectedEvent.target_port}</Descriptions.Item>
                <Descriptions.Item label="严重程度"><Tag color={severityMap[selectedEvent.severity]?.color || 'default'}>{severityMap[selectedEvent.severity]?.text || selectedEvent.severity}</Tag></Descriptions.Item>
                <Descriptions.Item label="状态"><Tag color={statusMap[selectedEvent.status]?.color || 'default'}>{statusMap[selectedEvent.status]?.text || selectedEvent.status}</Tag></Descriptions.Item>
                <Descriptions.Item label="响应码">{selectedEvent.response_code}</Descriptions.Item>
                <Descriptions.Item label="请求方法">{selectedEvent.request_method}</Descriptions.Item>
                <Descriptions.Item label="请求路径"><span style={{ fontFamily: 'monospace' }}>{selectedEvent.request_path}</span></Descriptions.Item>
                <Descriptions.Item label="时间" span={2}>{dayjs(selectedEvent.event_time).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                <Descriptions.Item label="User-Agent" span={2}>{selectedEvent.user_agent}</Descriptions.Item>
              </Descriptions>
            )},
            { key: 'killchain', label: <span><AimOutlined /> Kill Chain</span>, children: (
              <Steps direction="vertical" size="small" items={KILL_CHAIN_STAGES.map((stage, index) => {
                const isCurrent = getKillChainStage(selectedEvent.attack_type).key === stage.key;
                return {
                  title: <span style={{ color: isCurrent ? stage.color : '#999', fontWeight: isCurrent ? 700 : 400 }}>{stage.name}</span>,
                  description: isCurrent ? <Tag color={stage.color}>{attackTypeMap[selectedEvent.attack_type] || selectedEvent.attack_type}</Tag> : <span style={{ color: '#ccc' }}>未检测到</span>,
                  status: isCurrent ? 'error' as const : 'wait' as const,
                };
              })} />
            )},
            { key: 'geo', label: <span><GlobalOutlined /> 攻击源定位</span>, children: (
              IP_GEO_MAP[selectedEvent.source_ip] ? (
                <div>
                  <Descriptions column={2} bordered size="small">
                    <Descriptions.Item label="IP地址"><span style={{ fontFamily: 'monospace', color: '#ff4d4f' }}>{selectedEvent.source_ip}</span></Descriptions.Item>
                    <Descriptions.Item label="国家">{IP_GEO_MAP[selectedEvent.source_ip].country}</Descriptions.Item>
                    <Descriptions.Item label="城市">{IP_GEO_MAP[selectedEvent.source_ip].city}</Descriptions.Item>
                    <Descriptions.Item label="ISP">{IP_GEO_MAP[selectedEvent.source_ip].isp}</Descriptions.Item>
                    <Descriptions.Item label="经度">{IP_GEO_MAP[selectedEvent.source_ip].lon}</Descriptions.Item>
                    <Descriptions.Item label="纬度">{IP_GEO_MAP[selectedEvent.source_ip].lat}</Descriptions.Item>
                  </Descriptions>
                  <div style={{ marginTop: 16, padding: 20, background: '#f5f5f5', borderRadius: 8, textAlign: 'center' }}>
                    <GlobalOutlined style={{ fontSize: 48, color: '#1890ff', marginBottom: 8 }} />
                    <div style={{ fontSize: 16, fontWeight: 600 }}>{IP_GEO_MAP[selectedEvent.source_ip].city}, {IP_GEO_MAP[selectedEvent.source_ip].country}</div>
                    <div style={{ color: '#666' }}>ISP: {IP_GEO_MAP[selectedEvent.source_ip].isp}</div>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', padding: 40, color: '#999' }}><GlobalOutlined style={{ fontSize: 48, marginBottom: 16 }} /><p>暂无该IP的地理定位信息</p></div>
              )
            )},
            { key: 'ioc', label: <span><KeyOutlined /> IOC指标</span>, children: (
              <div>
                {extractIOC(selectedEvent).map((ioc, index) => (
                  <div key={index} style={{ marginBottom: 12, padding: 12, background: '#f5f5f5', borderRadius: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <Tag color={ioc.type === 'IP' ? 'red' : ioc.type === 'URL' ? 'blue' : ioc.type === 'PAYLOAD' ? 'orange' : 'purple'}>{ioc.type}</Tag>
                      <Text type="secondary" style={{ fontSize: 12 }}>{ioc.context}</Text>
                    </div>
                    <div style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all', color: '#333' }}>{ioc.value}</div>
                  </div>
                ))}
              </div>
            )},
          ]} />
        )}
      </Modal>

      <Modal title="编辑攻击事件" open={editModalVisible} onCancel={() => { setEditModalVisible(false); setEditingEvent(null); form.resetFields(); }} footer={null} width={600}>
        <Form form={form} layout="vertical" onFinish={handleEdit}>
          <Form.Item name="attack_type" label="攻击类型" rules={[{ required: true, message: '请选择攻击类型' }]}><Select>{Object.entries(attackTypeMap).map(([key, value]) => (<Option key={key} value={key}>{value}</Option>))}</Select></Form.Item>
          <Form.Item name="source_ip" label="来源IP" rules={[{ required: true, message: '请输入来源IP' }]}><Input placeholder="请输入来源IP" /></Form.Item>
          <Form.Item name="target_ip" label="目标IP" rules={[{ required: true, message: '请输入目标IP' }]}><Input placeholder="请输入目标IP" /></Form.Item>
          <Form.Item name="target_port" label="目标端口"><Input type="number" placeholder="请输入目标端口" /></Form.Item>
          <Form.Item name="severity" label="严重程度" rules={[{ required: true, message: '请选择严重程度' }]}><Select><Option value="critical">严重</Option><Option value="high">高危</Option><Option value="medium">中危</Option><Option value="low">低危</Option></Select></Form.Item>
          <Form.Item name="status" label="当前状态"><Select><Option value="detected">已检测</Option><Option value="blocked">已阻断</Option><Option value="investigating">调查中</Option><Option value="resolved">已解决</Option></Select></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}><Button style={{ marginRight: 8 }} onClick={() => { setEditModalVisible(false); setEditingEvent(null); form.resetFields(); }}>取消</Button><Button type="primary" htmlType="submit">保存</Button></Form.Item>
        </Form>
      </Modal>

      <Modal title="新增攻击事件" open={addModalVisible} onCancel={() => { setAddModalVisible(false); addForm.resetFields(); }} footer={null} width={600}>
        <Form form={addForm} layout="vertical" onFinish={handleAdd}>
          <Form.Item name="attack_type" label="攻击类型" rules={[{ required: true, message: '请选择攻击类型' }]}><Select placeholder="请选择攻击类型">{Object.entries(attackTypeMap).map(([key, value]) => (<Option key={key} value={key}>{value}</Option>))}</Select></Form.Item>
          <Form.Item name="source_ip" label="来源IP" rules={[{ required: true, message: '请输入来源IP' }]}><Input placeholder="请输入来源IP" /></Form.Item>
          <Form.Item name="target_ip" label="目标IP" rules={[{ required: true, message: '请输入目标IP' }]}><Input placeholder="请输入目标IP" /></Form.Item>
          <Form.Item name="target_port" label="目标端口"><Input type="number" placeholder="请输入目标端口" /></Form.Item>
          <Form.Item name="severity" label="严重程度" rules={[{ required: true, message: '请选择严重程度' }]}><Select placeholder="请选择严重程度"><Option value="critical">严重</Option><Option value="high">高危</Option><Option value="medium">中危</Option><Option value="low">低危</Option></Select></Form.Item>
          <Form.Item name="request_method" label="请求方法"><Select placeholder="请选择请求方法"><Option value="GET">GET</Option><Option value="POST">POST</Option><Option value="PUT">PUT</Option><Option value="DELETE">DELETE</Option></Select></Form.Item>
          <Form.Item name="request_path" label="请求路径"><Input placeholder="例如: /api/v1/login" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}><Button style={{ marginRight: 8 }} onClick={() => { setAddModalVisible(false); addForm.resetFields(); }}>取消</Button><Button type="primary" htmlType="submit">确定</Button></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AttackMonitor;
