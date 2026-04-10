import React, { useState } from 'react';
import { Card, Form, Input, Button, Tabs, Switch, Select, InputNumber, message, Divider, Row, Col, Space, Tag, Table, Modal, Progress, Badge, Typography, Avatar, Statistic } from 'antd';
import { SettingOutlined, UserOutlined, BellOutlined, SafetyCertificateOutlined, CloudServerOutlined, DatabaseOutlined, MailOutlined, SaveOutlined, PlusOutlined, DeleteOutlined, EditOutlined, ApiOutlined, LaptopOutlined, GlobalOutlined, KeyOutlined, LockOutlined, CheckCircleOutlined, InfoCircleOutlined, MobileOutlined, SendOutlined, LinkOutlined, CodeOutlined, ReloadOutlined } from '@ant-design/icons';

const { Option } = Select;
const { Text, Title } = Typography;

const ASSET_DATA = [
  { key: '1', name: 'Web服务器-01', ip: '192.168.1.10', type: '服务器', os: 'CentOS 7.9', status: 'online', risk: 85, group: '生产环境' },
  { key: '2', name: '数据库-01', ip: '192.168.1.20', type: '数据库', os: 'Ubuntu 22.04', status: 'online', risk: 72, group: '生产环境' },
  { key: '3', name: 'API网关', ip: '192.168.1.30', type: '网关', os: 'Alpine Linux', status: 'online', risk: 68, group: 'DMZ区' },
  { key: '4', name: '邮件服务器', ip: '192.168.1.40', type: '服务器', os: 'Windows Server 2019', status: 'warning', risk: 55, group: '办公区' },
  { key: '5', name: '文件服务器', ip: '192.168.1.50', type: '存储', os: 'Debian 11', status: 'online', risk: 42, group: '办公区' },
  { key: '6', name: 'DNS服务器', ip: '192.168.1.60', type: '服务器', os: 'BIND9 / Ubuntu', status: 'online', risk: 30, group: 'DMZ区' },
];

const API_INTEGRATIONS = [
  { key: '1', name: 'VirusTotal', type: '威胁情报', url: 'https://www.virustotal.com/api/v3', status: 'connected', last_sync: '2025-04-10 14:30' },
  { key: '2', name: 'AlienVault OTX', type: '威胁情报', url: 'https://otx.alienvault.com/api', status: 'connected', last_sync: '2025-04-10 14:00' },
  { key: '3', name: 'Shodan', type: '资产发现', url: 'https://api.shodan.io', status: 'disconnected', last_sync: '-' },
  { key: '4', name: '企业微信', type: '消息通知', url: 'https://qyapi.weixin.qq.com/cgi-bin', status: 'connected', last_sync: '2025-04-10 13:45' },
  { key: '5', name: '钉钉机器人', type: '消息通知', url: 'https://oapi.dingtalk.com/robot', status: 'disconnected', last_sync: '-' },
];

const Settings: React.FC = () => {
  const [saving, setSaving] = useState(false);
  const [assetModalVisible, setAssetModalVisible] = useState(false);
  const [apiModalVisible, setApiModalVisible] = useState(false);
  const [assetForm] = Form.useForm();
  const [apiForm] = Form.useForm();

  const handleSave = async (formName: string) => {
    setSaving(true);
    try { await new Promise(resolve => setTimeout(resolve, 500)); message.success(`${formName}设置保存成功`); }
    catch (error) { message.error('保存失败'); }
    finally { setSaving(false); }
  };

  const assetColumns = [
    { title: '资产名称', dataIndex: 'name', key: 'name', render: (text: string) => <Text strong style={{ fontSize: 13 }}>{text}</Text> },
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', render: (text: string) => <Text code style={{ fontSize: 12 }}>{text}</Text> },
    { title: '类型', dataIndex: 'type', key: 'type', width: 90, render: (text: string) => <Tag color="blue">{text}</Tag> },
    { title: '操作系统', dataIndex: 'os', key: 'os', width: 150, render: (text: string) => <Text style={{ fontSize: 12 }}>{text}</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => <Badge status={status === 'online' ? 'success' : status === 'warning' ? 'warning' : 'error'} text={<Text style={{ fontSize: 12 }}>{status === 'online' ? '在线' : status === 'warning' ? '告警' : '离线'}</Text>} /> },
    { title: '风险', dataIndex: 'risk', key: 'risk', width: 120, render: (risk: number) => <Progress percent={risk} size="small" strokeColor={risk >= 80 ? '#ff4d4f' : risk >= 60 ? '#fa8c16' : '#52c41a'} format={(p) => `${p}`} /> },
    { title: '分组', dataIndex: 'group', key: 'group', width: 100, render: (text: string) => <Tag color="cyan">{text}</Tag> },
    { title: '操作', key: 'action', width: 100, render: () => (<Space size={4}><Button type="link" size="small" icon={<EditOutlined />}>编辑</Button><Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button></Space>) },
  ];

  const apiColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', render: (text: string, record: any) => (<Space><Avatar size="small" style={{ backgroundColor: record.status === 'connected' ? '#52c41a' : '#d9d9d9' }} icon={<ApiOutlined />} />{text}</Space>) },
    { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (text: string) => <Tag color="purple">{text}</Tag> },
    { title: 'API地址', dataIndex: 'url', key: 'url', render: (text: string) => <Text code style={{ fontSize: 11 }}>{text}</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (status: string) => <Tag color={status === 'connected' ? 'green' : 'default'} icon={status === 'connected' ? <CheckCircleOutlined /> : <InfoCircleOutlined />}>{status === 'connected' ? '已连接' : '未连接'}</Tag> },
    { title: '最后同步', dataIndex: 'last_sync', key: 'last_sync', width: 160 },
    { title: '操作', key: 'action', width: 120, render: () => (<Space size={4}><Button type="link" size="small" icon={<EditOutlined />}>配置</Button><Button type="link" size="small" icon={<ReloadOutlined />}>测试</Button></Space>) },
  ];

  const sectionStyle: React.CSSProperties = {
    background: '#fff', borderRadius: 12, padding: '24px 28px', marginBottom: 20,
    boxShadow: '0 1px 6px rgba(0,0,0,0.06)', border: '1px solid #f0f0f0',
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontSize: 15, fontWeight: 700, marginBottom: 20, paddingBottom: 12,
    borderBottom: '2px solid #f0f0f0', display: 'flex', alignItems: 'center', gap: 8,
  };

  const switchRowStyle: React.CSSProperties = {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '12px 16px', background: '#fafafa', borderRadius: 8, marginBottom: 12,
    border: '1px solid #f0f0f0',
  };

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #595959, #8c8c8c)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <SettingOutlined style={{ marginRight: 8, WebkitTextFillColor: '#595959' }} />系统设置
        </h2>
      </div>

      <Card variant="borderless" style={{ borderRadius: 12, boxShadow: '0 1px 8px rgba(0,0,0,0.06)' }}>
        <Tabs defaultActiveKey="user" tabPlacement="left" style={{ minHeight: 700 }} items={[
          {
            key: 'user', label: <span style={{ padding: '4px 0' }}><UserOutlined style={{ marginRight: 6 }} />用户设置</span>,
            children: (
              <div style={{ maxWidth: 680 }}>
                <Form layout="vertical" onFinish={() => handleSave('用户')} initialValues={{ username: 'admin', email: 'admin@example.com', role: 'admin', phone: '138****8000' }}>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><UserOutlined style={{ color: '#1890ff' }} />基本信息</div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}><Input placeholder="请输入用户名" prefix={<UserOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item></Col>
                      <Col span={12}><Form.Item name="email" label="邮箱" rules={[{ required: true, message: '请输入邮箱' }]}><Input placeholder="请输入邮箱" prefix={<MailOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item></Col>
                    </Row>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="role" label="角色"><Select><Option value="admin"><Tag color="red" style={{ margin: 0 }}>管理员</Tag></Option><Option value="analyst"><Tag color="blue" style={{ margin: 0 }}>分析师</Tag></Option><Option value="viewer"><Tag color="green" style={{ margin: 0 }}>观察者</Tag></Option></Select></Form.Item></Col>
                      <Col span={12}><Form.Item name="phone" label="手机号"><Input placeholder="请输入手机号" prefix={<MobileOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item></Col>
                    </Row>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><LockOutlined style={{ color: '#ff4d4f' }} />修改密码</div>
                    <Form.Item name="old_password" label="当前密码"><Input.Password placeholder="请输入当前密码" /></Form.Item>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="new_password" label="新密码" rules={[{ min: 8, message: '密码至少8位' }]}><Input.Password placeholder="请输入新密码（至少8位）" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="confirm_password" label="确认新密码" dependencies={['new_password']} rules={[({ getFieldValue }) => ({ validator(_, value) { if (!value || getFieldValue('new_password') === value) return Promise.resolve(); return Promise.reject(new Error('两次输入的密码不一致')); } })]}><Input.Password placeholder="请再次输入新密码" /></Form.Item></Col>
                    </Row>
                    <Form.Item><Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving} style={{ borderRadius: 8, height: 40, padding: '0 32px' }}>保存设置</Button></Form.Item>
                  </div>
                </Form>
              </div>
            ),
          },
          {
            key: 'system', label: <span style={{ padding: '4px 0' }}><CloudServerOutlined style={{ marginRight: 6 }} />系统配置</span>,
            children: (
              <div style={{ maxWidth: 680 }}>
                <Form layout="vertical" onFinish={() => handleSave('系统')} initialValues={{ data_retention_days: 90, auto_refresh_interval: 30, max_events_display: 500, log_level: 'info', enable_simulation: true, debug_mode: false, api_timeout: 30, max_concurrent_analyses: 5 }}>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><DatabaseOutlined style={{ color: '#1890ff' }} />数据设置</div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="data_retention_days" label="数据保留天数"><InputNumber min={1} max={365} style={{ width: '100%' }} addonAfter="天" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="max_events_display" label="最大事件显示数"><InputNumber min={100} max={10000} step={100} style={{ width: '100%' }} /></Form.Item></Col>
                    </Row>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="auto_refresh_interval" label="自动刷新间隔"><InputNumber min={5} max={300} style={{ width: '100%' }} addonAfter="秒" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="api_timeout" label="API超时时间"><InputNumber min={5} max={120} style={{ width: '100%' }} addonAfter="秒" /></Form.Item></Col>
                    </Row>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><CloudServerOutlined style={{ color: '#722ed1' }} />系统设置</div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="log_level" label="日志级别"><Select><Option value="debug"><Tag color="purple">Debug</Tag></Option><Option value="info"><Tag color="blue">Info</Tag></Option><Option value="warning"><Tag color="orange">Warning</Tag></Option><Option value="error"><Tag color="red">Error</Tag></Option></Select></Form.Item></Col>
                      <Col span={12}><Form.Item name="max_concurrent_analyses" label="最大并发分析数"><InputNumber min={1} max={20} style={{ width: '100%' }} /></Form.Item></Col>
                    </Row>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用数据模拟器</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>自动生成模拟攻击事件用于测试</Text></div>
                      <Form.Item name="enable_simulation" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用调试模式</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>输出详细调试信息到日志</Text></div>
                      <Form.Item name="debug_mode" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Form.Item style={{ marginTop: 20 }}><Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving} style={{ borderRadius: 8, height: 40, padding: '0 32px' }}>保存设置</Button></Form.Item>
                  </div>
                </Form>
              </div>
            ),
          },
          {
            key: 'notification', label: <span style={{ padding: '4px 0' }}><BellOutlined style={{ marginRight: 6 }} />通知设置</span>,
            children: (
              <div style={{ maxWidth: 680 }}>
                <Form layout="vertical" onFinish={() => handleSave('通知')} initialValues={{ email_enabled: true, sms_enabled: false, webhook_enabled: false, notify_on_critical: true, notify_on_high: true, notify_on_medium: false, notify_on_low: false, quiet_hours_enabled: false, quiet_start: '22:00', quiet_end: '08:00' }}>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><MailOutlined style={{ color: '#1890ff' }} />邮件通知</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用邮件通知</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>通过SMTP发送告警邮件</Text></div>
                      <Form.Item name="email_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Row gutter={24}>
                      <Col span={16}><Form.Item name="email_server" label="SMTP服务器"><Input placeholder="smtp.example.com" /></Form.Item></Col>
                      <Col span={8}><Form.Item name="email_port" label="端口" initialValue={465}><InputNumber style={{ width: '100%' }} /></Form.Item></Col>
                    </Row>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="email_user" label="发件人"><Input placeholder="alert@example.com" prefix={<MailOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item></Col>
                      <Col span={12}><Form.Item name="email_password" label="授权码"><Input.Password placeholder="请输入SMTP授权码" /></Form.Item></Col>
                    </Row>
                    <Form.Item name="email_recipients" label="收件人"><Input placeholder="多个收件人用逗号分隔" /></Form.Item>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><MobileOutlined style={{ color: '#fa8c16' }} />短信通知</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用短信通知</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>通过短信API发送告警短信</Text></div>
                      <Form.Item name="sms_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Form.Item name="sms_api_url" label="短信API地址"><Input placeholder="https://sms-api.example.com/send" prefix={<LinkOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item>
                    <Form.Item name="sms_phones" label="接收手机号"><Input placeholder="多个手机号用逗号分隔" prefix={<MobileOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><SendOutlined style={{ color: '#722ed1' }} />Webhook通知</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用Webhook</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>推送告警到自定义Webhook地址</Text></div>
                      <Form.Item name="webhook_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Form.Item name="webhook_url" label="Webhook URL"><Input placeholder="https://hooks.example.com/alert" prefix={<LinkOutlined style={{ color: '#bfbfbf' }} />} /></Form.Item>
                    <Form.Item name="webhook_secret" label="签名密钥"><Input.Password placeholder="请输入签名密钥" /></Form.Item>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><BellOutlined style={{ color: '#ff4d4f' }} />通知规则</div>
                    <Row gutter={16}>
                      {[
                        { key: 'notify_on_critical', label: '严重告警', color: '#ff4d4f' },
                        { key: 'notify_on_high', label: '高危告警', color: '#fa8c16' },
                        { key: 'notify_on_medium', label: '中危告警', color: '#faad14' },
                        { key: 'notify_on_low', label: '低危告警', color: '#52c41a' },
                      ].map(item => (
                        <Col span={12} key={item.key}>
                          <div style={{ ...switchRowStyle, borderLeft: `3px solid ${item.color}` }}>
                            <div><Tag color={item.color} style={{ margin: 0 }}>{item.label}</Tag></div>
                            <Form.Item name={item.key} valuePropName="checked" noStyle><Switch size="small" /></Form.Item>
                          </div>
                        </Col>
                      ))}
                    </Row>
                    <Divider style={{ margin: '20px 0' }} />
                    <div style={switchRowStyle}>
                      <div><Text strong>免打扰时段</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>在指定时间段内不发送通知</Text></div>
                      <Form.Item name="quiet_hours_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="quiet_start" label="开始时间"><Input placeholder="HH:mm" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="quiet_end" label="结束时间"><Input placeholder="HH:mm" /></Form.Item></Col>
                    </Row>
                    <Form.Item><Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving} style={{ borderRadius: 8, height: 40, padding: '0 32px' }}>保存设置</Button></Form.Item>
                  </div>
                </Form>
              </div>
            ),
          },
          {
            key: 'security', label: <span style={{ padding: '4px 0' }}><SafetyCertificateOutlined style={{ marginRight: 6 }} />安全设置</span>,
            children: (
              <div style={{ maxWidth: 680 }}>
                <Form layout="vertical" onFinish={() => handleSave('安全')} initialValues={{ two_factor_auth: false, session_timeout: 30, max_login_attempts: 5, ip_whitelist_enabled: false, auto_block_enabled: true, auto_block_threshold: 100, auto_block_duration: 24 }}>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><KeyOutlined style={{ color: '#1890ff' }} />认证设置</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用两步验证 (2FA)</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>登录时需要额外的验证码验证</Text></div>
                      <Form.Item name="two_factor_auth" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="session_timeout" label="会话超时时间"><InputNumber min={5} max={480} style={{ width: '100%' }} addonAfter="分钟" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="max_login_attempts" label="最大登录尝试次数"><InputNumber min={3} max={10} style={{ width: '100%' }} addonAfter="次" /></Form.Item></Col>
                    </Row>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><GlobalOutlined style={{ color: '#722ed1' }} />访问控制</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用IP白名单</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>仅允许白名单中的IP访问系统</Text></div>
                      <Form.Item name="ip_whitelist_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Form.Item name="ip_whitelist" label="IP白名单"><Input.TextArea rows={4} placeholder={"每行一个IP地址或CIDR\n例如：\n192.168.1.0/24\n10.0.0.1"} style={{ fontFamily: 'monospace', fontSize: 13 }} /></Form.Item>
                  </div>
                  <div style={sectionStyle}>
                    <div style={sectionTitleStyle}><SafetyCertificateOutlined style={{ color: '#ff4d4f' }} />自动防护</div>
                    <div style={switchRowStyle}>
                      <div><Text strong>启用自动封锁</Text><br /><Text type="secondary" style={{ fontSize: 12 }}>当攻击次数超过阈值时自动封锁来源IP</Text></div>
                      <Form.Item name="auto_block_enabled" valuePropName="checked" noStyle><Switch /></Form.Item>
                    </div>
                    <Row gutter={24}>
                      <Col span={12}><Form.Item name="auto_block_threshold" label="自动封锁阈值"><InputNumber min={10} max={1000} style={{ width: '100%' }} addonAfter="次攻击" /></Form.Item></Col>
                      <Col span={12}><Form.Item name="auto_block_duration" label="封锁持续时间"><InputNumber min={1} max={720} style={{ width: '100%' }} addonAfter="小时" /></Form.Item></Col>
                    </Row>
                    <Form.Item><Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving} style={{ borderRadius: 8, height: 40, padding: '0 32px' }}>保存设置</Button></Form.Item>
                  </div>
                </Form>
              </div>
            ),
          },
          {
            key: 'assets', label: <span style={{ padding: '4px 0' }}><LaptopOutlined style={{ marginRight: 6 }} />资产管理</span>,
            children: (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <Space>
                    <Badge count={ASSET_DATA.length} style={{ backgroundColor: '#1890ff' }}><Avatar icon={<LaptopOutlined />} style={{ backgroundColor: '#1890ff' }} /></Badge>
                    <Text strong style={{ fontSize: 16 }}>资产总数</Text>
                  </Space>
                  <Space>
                    <Button icon={<PlusOutlined />} type="primary" onClick={() => setAssetModalVisible(true)} style={{ borderRadius: 8 }}>添加资产</Button>
                    <Button icon={<ReloadOutlined />} style={{ borderRadius: 8 }}>扫描发现</Button>
                  </Space>
                </div>
                <Table columns={assetColumns} dataSource={ASSET_DATA} pagination={{ pageSize: 10, showTotal: (total) => `共 ${total} 个资产` }} size="middle" style={{ borderRadius: 8, overflow: 'hidden' }} />
              </div>
            ),
          },
          {
            key: 'integration', label: <span style={{ padding: '4px 0' }}><ApiOutlined style={{ marginRight: 6 }} />API集成</span>,
            children: (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <Space>
                    <Badge count={API_INTEGRATIONS.filter(a => a.status === 'connected').length} style={{ backgroundColor: '#52c41a' }}><Avatar icon={<ApiOutlined />} style={{ backgroundColor: '#722ed1' }} /></Badge>
                    <Text strong style={{ fontSize: 16 }}>已连接 {API_INTEGRATIONS.filter(a => a.status === 'connected').length}/{API_INTEGRATIONS.length}</Text>
                  </Space>
                  <Button icon={<PlusOutlined />} type="primary" onClick={() => setApiModalVisible(true)} style={{ borderRadius: 8 }}>添加集成</Button>
                </div>
                <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
                  <Col span={8}><Card size="small" variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 10 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>已连接</span>} value={API_INTEGRATIONS.filter(a => a.status === 'connected').length} valueStyle={{ color: '#fff', fontWeight: 700 }} prefix={<CheckCircleOutlined />} /></Card></Col>
                  <Col span={8}><Card size="small" variant="borderless" style={{ background: 'linear-gradient(135deg, #d9d9d9, #bfbfbf)', borderRadius: 10 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>未连接</span>} value={API_INTEGRATIONS.filter(a => a.status !== 'connected').length} valueStyle={{ color: '#fff', fontWeight: 700 }} prefix={<InfoCircleOutlined />} /></Card></Col>
                  <Col span={8}><Card size="small" variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 10 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>集成总数</span>} value={API_INTEGRATIONS.length} valueStyle={{ color: '#fff', fontWeight: 700 }} prefix={<ApiOutlined />} /></Card></Col>
                </Row>
                <Table columns={apiColumns} dataSource={API_INTEGRATIONS} pagination={{ pageSize: 10, showTotal: (total) => `共 ${total} 个集成` }} size="middle" style={{ borderRadius: 8, overflow: 'hidden' }} />
              </div>
            ),
          },
          {
            key: 'about', label: <span style={{ padding: '4px 0' }}><InfoCircleOutlined style={{ marginRight: 6 }} />关于系统</span>,
            children: (
              <div style={{ maxWidth: 680 }}>
                <div style={sectionStyle}>
                  <div style={{ textAlign: 'center', padding: '24px 0 32px' }}>
                    <SafetyCertificateOutlined style={{ fontSize: 56, color: '#1890ff', marginBottom: 16 }} />
                    <Title level={3} style={{ margin: 0 }}>网络攻击态势感知系统</Title>
                    <Text type="secondary" style={{ fontSize: 13 }}>Cyber Attack Situational Awareness System</Text>
                    <div style={{ marginTop: 8 }}><Tag color="blue" style={{ fontSize: 13, padding: '2px 12px' }}>v2.0.0</Tag></div>
                  </div>
                </div>
                <div style={sectionStyle}>
                  <div style={sectionTitleStyle}><CodeOutlined style={{ color: '#722ed1' }} />技术栈</div>
                  <Row gutter={[16, 12]}>
                    {[
                      { label: '前端框架', value: 'React 19 + TypeScript', color: '#61dafb' },
                      { label: 'UI组件库', value: 'Ant Design 5', color: '#1890ff' },
                      { label: '后端框架', value: 'FastAPI + Python', color: '#009688' },
                      { label: '可视化引擎', value: 'ECharts + Recharts', color: '#fa8c16' },
                      { label: '状态管理', value: 'Redux Toolkit', color: '#764abc' },
                      { label: '构建工具', value: 'Vite', color: '#646cff' },
                    ].map(item => (
                      <Col span={12} key={item.label}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', background: '#fafafa', borderRadius: 8, border: '1px solid #f0f0f0' }}>
                          <div style={{ width: 4, height: 28, borderRadius: 2, background: item.color }} />
                          <div><Text type="secondary" style={{ fontSize: 11 }}>{item.label}</Text><br /><Text strong style={{ fontSize: 13 }}>{item.value}</Text></div>
                        </div>
                      </Col>
                    ))}
                  </Row>
                </div>
                <div style={sectionStyle}>
                  <div style={sectionTitleStyle}><SafetyCertificateOutlined style={{ color: '#52c41a' }} />功能模块</div>
                  <Row gutter={[8, 8]}>
                    {['仪表盘', '攻击监控', '安全态势', '态势大屏', '威胁情报', '异常检测', '告警管理', '攻击回溯', '协同联动', '数据源管理', 'AI智能研判'].map((m, i) => (
                      <Col key={m}><Tag color={['blue', 'red', 'green', 'orange', 'purple', 'cyan', 'gold', 'magenta', 'lime', 'geekblue', 'volcano'][i]} style={{ padding: '4px 12px', fontSize: 13, borderRadius: 6 }}>{m}</Tag></Col>
                    ))}
                  </Row>
                </div>
              </div>
            ),
          },
        ]} />
      </Card>

      <Modal title="添加资产" open={assetModalVisible} onCancel={() => setAssetModalVisible(false)} footer={null} width={600}>
        <Form form={assetForm} layout="vertical" onFinish={() => { message.success('资产添加成功'); setAssetModalVisible(false); assetForm.resetFields(); }}>
          <Row gutter={24}>
            <Col span={12}><Form.Item name="name" label="资产名称" rules={[{ required: true, message: '请输入资产名称' }]}><Input placeholder="例如: Web服务器-01" /></Form.Item></Col>
            <Col span={12}><Form.Item name="ip" label="IP地址" rules={[{ required: true, message: '请输入IP地址' }]}><Input placeholder="例如: 192.168.1.10" /></Form.Item></Col>
          </Row>
          <Row gutter={24}>
            <Col span={12}><Form.Item name="type" label="资产类型" rules={[{ required: true, message: '请选择资产类型' }]}><Select placeholder="请选择"><Option value="服务器">服务器</Option><Option value="数据库">数据库</Option><Option value="网关">网关</Option><Option value="存储">存储</Option><Option value="网络设备">网络设备</Option><Option value="终端">终端</Option></Select></Form.Item></Col>
            <Col span={12}><Form.Item name="group" label="资产分组"><Select placeholder="请选择分组"><Option value="生产环境">生产环境</Option><Option value="DMZ区">DMZ区</Option><Option value="办公区">办公区</Option><Option value="开发测试">开发测试</Option></Select></Form.Item></Col>
          </Row>
          <Form.Item name="os" label="操作系统"><Input placeholder="例如: CentOS 7.9" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}><Button style={{ marginRight: 8 }} onClick={() => setAssetModalVisible(false)}>取消</Button><Button type="primary" htmlType="submit">添加</Button></Form.Item>
        </Form>
      </Modal>

      <Modal title="添加API集成" open={apiModalVisible} onCancel={() => setApiModalVisible(false)} footer={null} width={600}>
        <Form form={apiForm} layout="vertical" onFinish={() => { message.success('API集成添加成功'); setApiModalVisible(false); apiForm.resetFields(); }}>
          <Row gutter={24}>
            <Col span={12}><Form.Item name="name" label="集成名称" rules={[{ required: true, message: '请输入名称' }]}><Input placeholder="例如: VirusTotal" /></Form.Item></Col>
            <Col span={12}><Form.Item name="type" label="集成类型" rules={[{ required: true, message: '请选择类型' }]}><Select placeholder="请选择"><Option value="威胁情报">威胁情报</Option><Option value="资产发现">资产发现</Option><Option value="消息通知">消息通知</Option><Option value="SIEM">SIEM</Option><Option value="其他">其他</Option></Select></Form.Item></Col>
          </Row>
          <Form.Item name="url" label="API地址" rules={[{ required: true, message: '请输入API地址' }]}><Input placeholder="https://api.example.com/v1" /></Form.Item>
          <Form.Item name="api_key" label="API密钥"><Input.Password placeholder="请输入API密钥" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}><Button style={{ marginRight: 8 }} onClick={() => setApiModalVisible(false)}>取消</Button><Button type="primary" htmlType="submit">添加</Button></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default Settings;
