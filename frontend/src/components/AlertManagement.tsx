import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Tag, Button, Input, Select, Modal, Form, message, Tabs, Statistic, Row, Col, Dropdown, Popconfirm, Space, Divider, Switch, InputNumber } from 'antd';
import { ExclamationCircleOutlined, CheckCircleOutlined, ClockCircleOutlined, PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined, DownloadOutlined, BarChartOutlined, BellOutlined, SafetyCertificateOutlined, NotificationOutlined, MailOutlined, PhoneOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const { Option } = Select;

const AlertManagement: React.FC = () => {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [groups, setGroups] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [initialLoading, setInitialLoading] = useState(true);
  const [modalVisible, setModalVisible] = useState(false);
  const [ruleModalVisible, setRuleModalVisible] = useState(false);
  const [notifyModalVisible, setNotifyModalVisible] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  const [editingRule, setEditingRule] = useState<any>(null);
  const [selectedRowKeys, setSelectedRowKeys] = useState<React.Key[]>([]);
  const [filters, setFilters] = useState({ severity: '', status: '', source_ip: '' });
  const [ruleForm] = Form.useForm();
  const [notifyForm] = Form.useForm();
  const [trendData, setTrendData] = useState<any[]>([]);

  const severityColors: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff' };
  const statusColors: Record<string, string> = { new: 'red', acknowledged: 'orange', in_progress: 'blue', resolved: 'green', false_positive: 'gray', dismissed: 'gray' };
  const statusLabels: Record<string, string> = { new: '新告警', acknowledged: '已确认', in_progress: '处理中', resolved: '已解决', false_positive: '误报', dismissed: '已忽略' };
  const severityLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };

  const fetchAlertsData = useCallback(async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    try { const response = await axios.get('/api/alerts/history', { params: filters }); setAlerts(Array.isArray(response.data) ? response.data : []); }
    catch (error) { message.error('获取告警历史失败'); setAlerts([]); }
    finally { if (showLoading) setInitialLoading(false); }
  }, [filters]);

  const fetchRules = async () => {
    try { const response = await axios.get('/api/alerts/rules'); setRules(Array.isArray(response.data) ? response.data : []); }
    catch (error) { message.error('获取告警规则失败'); setRules([]); }
  };

  const fetchGroups = async () => {
    try { const response = await axios.get('/api/alerts/groups'); setGroups(Object.entries(response.data).map(([key, value]: any) => ({ key, ...value }))); }
    catch (error) { console.error('获取告警分组失败:', error); }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/alerts/stats');
      setStats(response.data);
      if (response.data.by_severity) {
        const data = Object.entries(response.data.by_severity).map(([key, value]: any) => ({
          name: severityLabels[key] || key, count: value, color: severityColors[key]
        }));
        setTrendData(data);
      }
    } catch (error) { console.error('获取告警统计失败:', error); }
  };

  useEffect(() => { const init = async () => { await Promise.all([fetchAlertsData(true), fetchRules(), fetchGroups(), fetchStats()]); }; init(); }, []);

  const handleAlertStatusUpdate = async (alertId: number, status: string, resolution?: string) => {
    try { await axios.put(`/api/alerts/history/${alertId}`, { status, resolution }); message.success('告警状态更新成功'); fetchAlertsData(); fetchStats(); }
    catch (error) { message.error('更新告警状态失败'); }
  };

  const handleAlertDelete = async (alertId: number) => {
    try { await axios.delete(`/api/alerts/history/${alertId}`); message.success('告警删除成功'); fetchAlertsData(); fetchStats(); }
    catch (error) { message.error('删除告警失败'); }
  };

  const handleBatchDelete = async () => {
    if (selectedRowKeys.length === 0) { message.warning('请先选择要删除的告警'); return; }
    try { await Promise.all(selectedRowKeys.map(key => axios.delete(`/api/alerts/history/${key}`))); message.success(`成功删除 ${selectedRowKeys.length} 条告警`); setSelectedRowKeys([]); fetchAlertsData(); fetchStats(); }
    catch (error) { message.error('批量删除失败'); }
  };

  const handleAlertAssign = async (alertId: number, user: string) => {
    try { await axios.post(`/api/alerts/history/${alertId}/assign`, { user }); message.success('告警分配成功'); fetchAlertsData(); }
    catch (error) { message.error('分配告警失败'); }
  };

  const handleRuleCreate = async (values: any) => {
    try { await axios.post('/api/alerts/rules', values); message.success('告警规则创建成功'); setRuleModalVisible(false); ruleForm.resetFields(); fetchRules(); }
    catch (error) { message.error('创建告警规则失败'); }
  };

  const handleRuleUpdate = async (values: any) => {
    try { await axios.put(`/api/alerts/rules/${editingRule.id}`, values); message.success('告警规则更新成功'); setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); fetchRules(); }
    catch (error) { message.error('更新告警规则失败'); }
  };

  const handleRuleDelete = async (ruleId: number) => {
    try { await axios.delete(`/api/alerts/rules/${ruleId}`); message.success('告警规则删除成功'); fetchRules(); }
    catch (error) { message.error('删除告警规则失败'); }
  };

  const handleExport = () => {
    const data = alerts.map(alert => ({
      id: alert.id, severity: alert.severity, status: alert.status,
      message: alert.message, source_ip: alert.details?.source_ip || '',
      created_at: alert.created_at, assigned_to: alert.assigned_to || ''
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alerts_export_${dayjs().format('YYYYMMDD_HHmmss')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    message.success('导出成功');
  };

  const handleNotifySave = async (values: any) => {
    try {
      message.success('通知渠道配置保存成功');
      setNotifyModalVisible(false);
    } catch (err) {
      message.error('保存失败');
    }
  };

  const openRuleModal = (rule?: any) => {
    if (rule) { setEditingRule(rule); ruleForm.setFieldsValue(rule); } else { setEditingRule(null); ruleForm.resetFields(); }
    setRuleModalVisible(true);
  };

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 70 },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (severity: string) => <Tag color={severityColors[severity]} style={{ margin: 0 }}>{severityLabels[severity] || severity}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (status: string) => <Tag color={statusColors[status]} style={{ margin: 0 }}>{statusLabels[status] || status}</Tag> },
    { title: '告警信息', dataIndex: 'message', key: 'message', ellipsis: true },
    { title: '来源IP', dataIndex: 'details', key: 'source_ip', width: 140, render: (details: any) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{details?.source_ip || '-'}</span> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (createdAt: string) => dayjs(createdAt).format('YYYY-MM-DD HH:mm:ss') },
    { title: '分配给', dataIndex: 'assigned_to', key: 'assigned_to', width: 100, render: (assignedTo: string) => assignedTo || <span style={{ color: '#999' }}>{'未分配'}</span> },
    { title: '操作', key: 'action', width: 180, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" size="small" onClick={() => { setSelectedAlert(record); setModalVisible(true); }}>{'详情'}</Button>
        <Dropdown menu={{ items: [
          { key: '1', label: '确认', onClick: () => handleAlertStatusUpdate(record.id, 'acknowledged') },
          { key: '2', label: '处理中', onClick: () => handleAlertStatusUpdate(record.id, 'in_progress') },
          { key: '3', label: '已解决', onClick: () => handleAlertStatusUpdate(record.id, 'resolved', '已手动解决') },
          { key: '4', label: '误报', onClick: () => handleAlertStatusUpdate(record.id, 'false_positive', '误报') },
          { key: '5', label: '忽略', onClick: () => handleAlertStatusUpdate(record.id, 'dismissed', '已忽略') },
          { key: 'divider', type: 'divider' },
          { key: '6', label: '分配给管理员', onClick: () => handleAlertAssign(record.id, 'admin') },
          { key: '7', label: '分配给分析师', onClick: () => handleAlertAssign(record.id, 'analyst') },
        ] }}>
          <Button type="link" size="small">{'处理 ▾'}</Button>
        </Dropdown>
        <Popconfirm title="确定要删除该告警吗？" onConfirm={() => handleAlertDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger size="small" icon={<DeleteOutlined />} />
        </Popconfirm>
      </Space>
    )}
  ];

  const ruleColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 70 },
    { title: '规则名称', dataIndex: 'name', key: 'name' },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (severity: string) => <Tag color={severityColors[severity]}>{severityLabels[severity] || severity}</Tag> },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80, render: (enabled: boolean) => <Tag color={enabled ? 'green' : 'gray'}>{enabled ? '启用' : '禁用'}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (createdAt: string) => dayjs(createdAt).format('YYYY-MM-DD HH:mm:ss') },
    { title: '操作', key: 'action', width: 140, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" icon={<EditOutlined />} size="small" onClick={() => openRuleModal(record)}>{'编辑'}</Button>
        <Popconfirm title="确定要删除这个规则吗？" onConfirm={() => handleRuleDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger icon={<DeleteOutlined />} size="small">{'删除'}</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const groupColumns = [
    { title: '分组ID', dataIndex: 'key', key: 'key' },
    { title: '告警数量', dataIndex: 'count', key: 'count', width: 100 },
    { title: '最高严重程度', dataIndex: 'highest_severity', key: 'highest_severity', width: 120, render: (severity: string) => <Tag color={severityColors[severity]}>{severityLabels[severity] || severity}</Tag> },
    { title: '首次出现', dataIndex: 'first_seen', key: 'first_seen', width: 170, render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss') },
    { title: '最近出现', dataIndex: 'last_seen', key: 'last_seen', width: 170, render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss') }
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #ff4d4f, #fa8c16)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <BellOutlined style={{ marginRight: 8, WebkitTextFillColor: '#ff4d4f' }} />{'告警管理'}
        </h2>
        <Space>
          <Button icon={<NotificationOutlined />} onClick={() => setNotifyModalVisible(true)}>{'通知渠道'}</Button>
          <Button icon={<ReloadOutlined />} onClick={() => { fetchAlertsData(); fetchRules(); fetchStats(); }}>{'刷新'}</Button>
          <Button icon={<DownloadOutlined />} onClick={handleExport}>{'导出'}</Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'总告警数'}</span>} value={stats.total || 0} prefix={<BellOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'未处理'}</span>} value={stats.by_status?.new || 0} prefix={<ExclamationCircleOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'处理中'}</span>} value={stats.by_status?.in_progress || 0} prefix={<ClockCircleOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{'已解决'}</span>} value={stats.by_status?.resolved || 0} prefix={<CheckCircleOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
      </Row>

      <Card variant="borderless" style={{ borderRadius: 12 }}>
        <Tabs defaultActiveKey="alerts" items={[
          { key: 'alerts', label: <span><BellOutlined /> {'告警历史'}</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Space>
                  <Select placeholder="严重程度" style={{ width: 120 }} value={filters.severity || undefined} onChange={(value) => setFilters(prev => ({ ...prev, severity: value }))} allowClear>
                    <Option value="critical">{'严重'}</Option><Option value="high">{'高'}</Option><Option value="medium">{'中'}</Option><Option value="low">{'低'}</Option><Option value="info">{'信息'}</Option>
                  </Select>
                  <Select placeholder="状态" style={{ width: 120 }} value={filters.status || undefined} onChange={(value) => setFilters(prev => ({ ...prev, status: value }))} allowClear>
                    <Option value="new">{'新告警'}</Option><Option value="acknowledged">{'已确认'}</Option><Option value="in_progress">{'处理中'}</Option><Option value="resolved">{'已解决'}</Option><Option value="false_positive">{'误报'}</Option><Option value="dismissed">{'已忽略'}</Option>
                  </Select>
                  <Input placeholder="来源IP" style={{ width: 150 }} value={filters.source_ip} onChange={(e) => setFilters(prev => ({ ...prev, source_ip: e.target.value }))} allowClear />
                  <Button icon={<ReloadOutlined />} onClick={() => { setFilters({ severity: '', status: '', source_ip: '' }); fetchAlertsData(); }}>{'重置'}</Button>
                  <Button type="primary" onClick={() => fetchAlertsData()}>{'查询'}</Button>
                </Space>
                {selectedRowKeys.length > 0 && (
                  <Popconfirm title={`确定要删除选中的 ${selectedRowKeys.length} 条告警吗？`} onConfirm={handleBatchDelete} okText="确定" cancelText="取消">
                    <Button danger icon={<DeleteOutlined />}>{'批量删除'} ({selectedRowKeys.length})</Button>
                  </Popconfirm>
                )}
              </div>
              <Table columns={columns} dataSource={alerts} rowKey="id" loading={initialLoading} rowSelection={{ selectedRowKeys, onChange: setSelectedRowKeys }} pagination={{ pageSize: 20, showSizeChanger: true, showQuickJumper: true, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            </div>
          )},
          { key: 'rules', label: <span><SafetyCertificateOutlined /> {'告警规则'}</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openRuleModal()}>{'新建规则'}</Button>
              </div>
              <Table columns={ruleColumns} dataSource={rules} rowKey="id" pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            </div>
          )},
          { key: 'groups', label: <span><BarChartOutlined /> {'告警分组'}</span>, children: (
            <Table columns={groupColumns} dataSource={groups} rowKey="key" pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
          )},
          { key: 'stats', label: <span><BarChartOutlined /> {'统计分析'}</span>, children: (
            <div>
              <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
                <Col span={6}><Card><Statistic title="总告警数" value={stats.total || 0} /></Card></Col>
                <Col span={6}><Card><Statistic title="未处理" value={stats.by_status?.new || 0} valueStyle={{ color: '#ff4d4f' }} /></Card></Col>
                <Col span={6}><Card><Statistic title="处理中" value={stats.by_status?.in_progress || 0} valueStyle={{ color: '#1890ff' }} /></Card></Col>
                <Col span={6}><Card><Statistic title="已解决" value={stats.by_status?.resolved || 0} valueStyle={{ color: '#52c41a' }} /></Card></Col>
              </Row>
              <Card title="告警严重程度分布">
                {trendData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={trendData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="count" fill="#1890ff" radius={[4, 4, 0, 0]}>
                        {trendData.map((entry: any, index: number) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column' }}>
                    <BarChartOutlined style={{ fontSize: 48, color: '#1890ff', marginBottom: 16 }} />
                    <span style={{ fontSize: 16, color: '#666' }}>{'暂无统计数据'}</span>
                  </div>
                )}
              </Card>
            </div>
          )},
        ]} />
      </Card>

      <Modal title="告警详情" open={modalVisible} onCancel={() => setModalVisible(false)} footer={[<Button key="close" onClick={() => setModalVisible(false)}>{'关闭'}</Button>]} width={800}>
        {selectedAlert && (
          <div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span><strong>{'告警信息:'}</strong> {selectedAlert.message}</span>
                <Tag color={severityColors[selectedAlert.severity]}>{severityLabels[selectedAlert.severity] || selectedAlert.severity}</Tag>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span><strong>{'状态:'}</strong> {statusLabels[selectedAlert.status] || selectedAlert.status}</span>
                <span><strong>{'创建时间:'}</strong> {dayjs(selectedAlert.created_at).format('YYYY-MM-DD HH:mm:ss')}</span>
              </div>
              {selectedAlert.assigned_to && <div style={{ marginBottom: 8 }}><span><strong>{'分配给:'}</strong> {selectedAlert.assigned_to}</span></div>}
              {selectedAlert.resolution && <div style={{ marginBottom: 8 }}><span><strong>{'解决方案:'}</strong> {selectedAlert.resolution}</span></div>}
            </div>
            <Divider />
            <div>
              <h4>{'详细信息'}</h4>
              <pre style={{ backgroundColor: '#f5f5f5', padding: 16, borderRadius: 8, overflowX: 'auto', fontSize: 12 }}>{JSON.stringify(selectedAlert.details, null, 2)}</pre>
            </div>
          </div>
        )}
      </Modal>

      <Modal title={editingRule ? "编辑告警规则" : "新建告警规则"} open={ruleModalVisible} onCancel={() => { setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); }} footer={null} width={600}>
        <Form form={ruleForm} layout="vertical" onFinish={editingRule ? handleRuleUpdate : handleRuleCreate}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true, message: '请输入规则名称' }]}><Input placeholder="请输入规则名称" /></Form.Item>
          <Form.Item name="description" label="规则描述"><Input.TextArea placeholder="请输入规则描述" rows={3} /></Form.Item>
          <Form.Item name="severity" label="严重程度" rules={[{ required: true, message: '请选择严重程度' }]}>
            <Select placeholder="请选择严重程度"><Option value="critical">{'严重'}</Option><Option value="high">{'高'}</Option><Option value="medium">{'中'}</Option><Option value="low">{'低'}</Option><Option value="info">{'信息'}</Option></Select>
          </Form.Item>
          <Form.Item name="condition" label="触发条件" rules={[{ required: true, message: '请输入触发条件' }]}><Input.TextArea placeholder="请输入触发条件 (JSON格式)" rows={3} /></Form.Item>
          <Form.Item name="enabled" label="状态"><Select><Option value={true}>{'启用'}</Option><Option value={false}>{'禁用'}</Option></Select></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); }}>{'取消'}</Button>
            <Button type="primary" htmlType="submit">{editingRule ? "更新" : "创建"}</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="通知渠道配置" open={notifyModalVisible} onCancel={() => setNotifyModalVisible(false)} footer={null} width={600}>
        <Form form={notifyForm} layout="vertical" onFinish={handleNotifySave}>
          <Divider orientation="left"><MailOutlined /> 邮件通知</Divider>
          <Form.Item name="emailEnabled" label="启用邮件通知" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="emailServer" label="SMTP服务器"><Input placeholder="smtp.example.com" /></Form.Item>
          <Form.Item name="emailPort" label="端口"><InputNumber placeholder="465" style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="emailUser" label="发件人"><Input placeholder="alert@example.com" /></Form.Item>
          <Form.Item name="emailPassword" label="授权码"><Input.Password placeholder="请输入SMTP授权码" /></Form.Item>
          <Form.Item name="emailRecipients" label="收件人（多个用逗号分隔）"><Input placeholder="admin@example.com,analyst@example.com" /></Form.Item>

          <Divider orientation="left"><PhoneOutlined /> 短信通知</Divider>
          <Form.Item name="smsEnabled" label="启用短信通知" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="smsApiUrl" label="短信API地址"><Input placeholder="https://sms-api.example.com/send" /></Form.Item>
          <Form.Item name="smsApiKey" label="API密钥"><Input.Password placeholder="请输入API密钥" /></Form.Item>
          <Form.Item name="smsPhones" label="接收手机号（多个用逗号分隔）"><Input placeholder="13800138000,13900139000" /></Form.Item>

          <Divider orientation="left"><NotificationOutlined /> Webhook通知</Divider>
          <Form.Item name="webhookEnabled" label="启用Webhook" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="webhookUrl" label="Webhook URL"><Input placeholder="https://hooks.example.com/alert" /></Form.Item>
          <Form.Item name="webhookSecret" label="签名密钥"><Input.Password placeholder="请输入签名密钥" /></Form.Item>

          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => setNotifyModalVisible(false)}>取消</Button>
            <Button type="primary" htmlType="submit">保存配置</Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AlertManagement;
