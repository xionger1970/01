import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Tag, Button, Modal, Form, Input, Select, Statistic, Row, Col, Tabs, Space, message, Popconfirm, Switch, InputNumber, Divider, Badge, Descriptions, Progress } from 'antd';
import { ApiOutlined, PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined, ThunderboltOutlined, PlayCircleOutlined, CheckCircleOutlined, NodeIndexOutlined, SafetyCertificateOutlined, LockOutlined, CloudOutlined, SecurityScanOutlined, BugOutlined, GlobalOutlined, SettingOutlined, SearchOutlined, StopOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { TextArea } = Input;

const FIREWALL_RULES = [
  { id: 1, name: '阻断已知恶意IP', action: 'deny', direction: 'inbound', source: '103.224.182.0/24', dest: 'any', port: '*', protocol: 'TCP', enabled: true, hits: 15234, priority: 1, description: '已知C2服务器IP段' },
  { id: 2, name: '允许内网SSH访问', action: 'allow', direction: 'inbound', source: '192.168.0.0/16', dest: '192.168.1.10', port: '22', protocol: 'TCP', enabled: true, hits: 8920, priority: 10, description: '内网管理员SSH访问' },
  { id: 3, name: '阻断异常端口扫描', action: 'deny', direction: 'inbound', source: 'any', dest: 'any', port: '1-1024', protocol: 'TCP', enabled: true, hits: 45230, priority: 5, description: '阻断外部端口扫描行为' },
  { id: 4, name: '允许HTTP/HTTPS入站', action: 'allow', direction: 'inbound', source: 'any', dest: '192.168.1.10', port: '80,443', protocol: 'TCP', enabled: true, hits: 892100, priority: 20, description: 'Web服务入站流量' },
  { id: 5, name: '阻断Tor出口节点', action: 'deny', direction: 'inbound', source: 'tor-exit-nodes', dest: 'any', port: '*', protocol: 'ALL', enabled: true, hits: 3456, priority: 3, description: '阻断Tor匿名网络出口节点' },
  { id: 6, name: '限制DNS查询', action: 'rate-limit', direction: 'outbound', source: '192.168.0.0/16', dest: 'any', port: '53', protocol: 'UDP', enabled: true, hits: 23400, priority: 15, description: '限制DNS查询频率防DNS隧道' },
  { id: 7, name: '阻断勒索软件C2', action: 'deny', direction: 'both', source: '185.220.101.0/24', dest: 'any', port: '*', protocol: 'ALL', enabled: true, hits: 892, priority: 2, description: '已知勒索软件C2通信IP' },
  { id: 8, name: '允许VPN隧道', action: 'allow', direction: 'inbound', source: '10.10.0.0/16', dest: '192.168.1.1', port: '1194', protocol: 'UDP', enabled: true, hits: 12300, priority: 12, description: 'OpenVPN隧道流量' },
];

const IDS_RULES = [
  { id: 1, name: 'SQL注入检测', category: 'web-attack', severity: 'high', sid: '1000001', action: 'alert', enabled: true, hits: 234, description: '检测SQL注入攻击特征' },
  { id: 2, name: 'XSS跨站脚本', category: 'web-attack', severity: 'high', sid: '1000002', action: 'alert', enabled: true, hits: 156, description: '检测跨站脚本攻击' },
  { id: 3, name: '暴力破解SSH', category: 'brute-force', severity: 'medium', sid: '1000003', action: 'alert', enabled: true, hits: 892, description: '检测SSH暴力破解尝试' },
  { id: 4, name: 'DDoS SYN Flood', category: 'ddos', severity: 'critical', sid: '1000004', action: 'block', enabled: true, hits: 45, description: '检测SYN洪泛攻击' },
  { id: 5, name: '恶意文件下载', category: 'malware', severity: 'high', sid: '1000005', action: 'block', enabled: true, hits: 67, description: '检测已知恶意文件哈希' },
  { id: 6, name: 'C2心跳通信', category: 'c2', severity: 'critical', sid: '1000006', action: 'block', enabled: true, hits: 23, description: '检测C2服务器心跳通信模式' },
  { id: 7, name: '端口扫描检测', category: 'recon', severity: 'medium', sid: '1000007', action: 'alert', enabled: true, hits: 1567, description: '检测网络端口扫描行为' },
  { id: 8, name: 'DNS隧道检测', category: 'exfiltration', severity: 'high', sid: '1000008', action: 'alert', enabled: false, hits: 0, description: '检测DNS隧道数据外传' },
];

const WAF_RULES = [
  { id: 1, name: 'SQL注入防护', type: 'sqli', mode: 'block', enabled: true, hits: 456, severity: 'critical', description: '拦截SQL注入攻击载荷' },
  { id: 2, name: 'XSS防护', type: 'xss', mode: 'block', enabled: true, hits: 234, severity: 'high', description: '拦截跨站脚本攻击' },
  { id: 3, name: '命令注入防护', type: 'rce', mode: 'block', enabled: true, hits: 89, severity: 'critical', description: '拦截操作系统命令注入' },
  { id: 4, name: '文件包含防护', type: 'lfi', mode: 'block', enabled: true, hits: 34, severity: 'high', description: '拦截本地/远程文件包含' },
  { id: 5, name: 'CC攻击防护', type: 'cc', mode: 'rate-limit', enabled: true, hits: 12300, severity: 'medium', description: '限制恶意请求频率' },
  { id: 6, name: '爬虫防护', type: 'bot', mode: 'challenge', enabled: true, hits: 8900, severity: 'low', description: '人机验证拦截恶意爬虫' },
  { id: 7, name: '路径遍历防护', type: 'traversal', mode: 'block', enabled: true, hits: 56, severity: 'high', description: '拦截目录遍历攻击' },
  { id: 8, name: 'CSRF防护', type: 'csrf', mode: 'detect', enabled: true, hits: 12, severity: 'medium', description: '检测跨站请求伪造' },
];

const SECURITY_DEVICES = [
  { id: 1, name: '边界防火墙-PF-01', type: 'firewall', ip: '172.16.0.1', model: 'Palo Alto PA-5260', firmware: '10.2.3', status: 'online', rules_count: 156, cpu: 45, memory: 62, throughput: '8.5 Gbps', uptime: '45天12小时' },
  { id: 2, name: '内网防火墙-PF-02', type: 'firewall', ip: '192.168.1.1', model: 'FortiGate 600E', firmware: '7.2.1', status: 'online', rules_count: 89, cpu: 32, memory: 48, throughput: '3.2 Gbps', uptime: '30天8小时' },
  { id: 3, name: 'IDS-01', type: 'ids', ip: '192.168.1.100', model: 'Suricata 7.0', firmware: '7.0.3', status: 'online', rules_count: 23456, cpu: 58, memory: 71, throughput: '5.1 Gbps', uptime: '60天3小时' },
  { id: 4, name: 'IPS-01', type: 'ips', ip: '192.168.1.101', model: 'Snort 3', firmware: '3.1.12', status: 'online', rules_count: 18900, cpu: 62, memory: 75, throughput: '4.8 Gbps', uptime: '55天7小时' },
  { id: 5, name: 'WAF-01', type: 'waf', ip: '192.168.1.50', model: 'ModSecurity + OWASP CRS', firmware: '3.0.8', status: 'online', rules_count: 890, cpu: 41, memory: 55, throughput: '2.1 Gbps', uptime: '90天1小时' },
  { id: 6, name: 'VPN网关-01', type: 'vpn', ip: '192.168.1.2', model: 'OpenVPN Access Server', firmware: '2.11.1', status: 'online', rules_count: 12, cpu: 15, memory: 30, throughput: '500 Mbps', uptime: '120天5小时' },
];

const Orchestration: React.FC = () => {
  const [devices, setDevices] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [quickActions, setQuickActions] = useState<any[]>([]);
  const [workflows, setWorkflows] = useState<any[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [deviceModalVisible, setDeviceModalVisible] = useState(false);
  const [ruleModalVisible, setRuleModalVisible] = useState(false);
  const [workflowModalVisible, setWorkflowModalVisible] = useState(false);
  const [fwRuleModalVisible, setFwRuleModalVisible] = useState(false);
  const [idsRuleModalVisible, setIdsRuleModalVisible] = useState(false);
  const [wafRuleModalVisible, setWafRuleModalVisible] = useState(false);
  const [deviceDetailVisible, setDeviceDetailVisible] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<any>(null);
  const [editingDevice, setEditingDevice] = useState<any>(null);
  const [editingRule, setEditingRule] = useState<any>(null);
  const [editingWorkflow, setEditingWorkflow] = useState<any>(null);
  const [firewallRules, setFirewallRules] = useState(FIREWALL_RULES);
  const [idsRules, setIdsRules] = useState(IDS_RULES);
  const [wafRules, setWafRules] = useState(WAF_RULES);
  const [securityDevices, setSecurityDevices] = useState(SECURITY_DEVICES);
  const [deviceForm] = Form.useForm();
  const [ruleForm] = Form.useForm();
  const [workflowForm] = Form.useForm();
  const [fwRuleForm] = Form.useForm();
  const [idsRuleForm] = Form.useForm();
  const [wafRuleForm] = Form.useForm();

  const fetchOrchestrationData = useCallback(async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    try {
      const [devicesRes, rulesRes, actionsRes] = await Promise.all([
        axios.get('/api/orchestration/devices'),
        axios.get('/api/orchestration/rules'),
        axios.get('/api/orchestration/quick-actions')
      ]);
      setDevices(Array.isArray(devicesRes.data) ? devicesRes.data : []);
      setRules(Array.isArray(rulesRes.data) ? rulesRes.data : []);
      setQuickActions(Array.isArray(actionsRes.data) ? actionsRes.data : []);
    } catch (error) {
      message.error('获取协同联动数据失败');
    } finally {
      if (showLoading) setInitialLoading(false);
    }
  }, []);

  useEffect(() => { fetchOrchestrationData(true); }, [fetchOrchestrationData]);

  const handleDeviceCreate = async (values: any) => {
    try { await axios.post('/api/orchestration/devices', values); message.success('设备创建成功'); setDeviceModalVisible(false); deviceForm.resetFields(); fetchOrchestrationData(); }
    catch (error) { message.error('创建设备失败'); }
  };
  const handleDeviceUpdate = async (values: any) => {
    try { await axios.put(`/api/orchestration/devices/${editingDevice.id}`, values); message.success('设备更新成功'); setDeviceModalVisible(false); deviceForm.resetFields(); setEditingDevice(null); fetchOrchestrationData(); }
    catch (error) { message.error('更新设备失败'); }
  };
  const handleDeviceDelete = async (deviceId: number) => {
    try { await axios.delete(`/api/orchestration/devices/${deviceId}`); message.success('设备删除成功'); fetchOrchestrationData(); }
    catch (error) { message.error('删除设备失败'); }
  };
  const handleRuleCreate = async (values: any) => {
    try { await axios.post('/api/orchestration/rules', values); message.success('规则创建成功'); setRuleModalVisible(false); ruleForm.resetFields(); fetchOrchestrationData(); }
    catch (error) { message.error('创建规则失败'); }
  };
  const handleRuleUpdate = async (values: any) => {
    try { await axios.put(`/api/orchestration/rules/${editingRule.id}`, values); message.success('规则更新成功'); setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); fetchOrchestrationData(); }
    catch (error) { message.error('更新规则失败'); }
  };
  const handleRuleDelete = async (ruleId: number) => {
    try { await axios.delete(`/api/orchestration/rules/${ruleId}`); message.success('规则删除成功'); fetchOrchestrationData(); }
    catch (error) { message.error('删除规则失败'); }
  };
  const handleQuickAction = async (actionId: string) => {
    try { await axios.post(`/api/orchestration/quick-actions/${actionId}/execute`); message.success('操作执行成功'); }
    catch (error) { message.error('操作执行失败'); }
  };
  const handleWorkflowCreate = async (values: any) => {
    const newWorkflow = { id: Date.now(), name: values.name, description: values.description || '', steps: values.steps ? values.steps.split('\n').filter((s: string) => s.trim()) : [], status: 'draft', created_at: new Date().toISOString() };
    setWorkflows(prev => [...prev, newWorkflow]);
    message.success('工作流创建成功');
    setWorkflowModalVisible(false);
    workflowForm.resetFields();
  };
  const handleWorkflowDelete = (workflowId: number) => {
    setWorkflows(prev => prev.filter(w => w.id !== workflowId));
    message.success('工作流删除成功');
  };
  const handleWorkflowExecute = (workflow: any) => {
    setWorkflows(prev => prev.map(w => w.id === workflow.id ? { ...w, status: 'running' } : w));
    message.success(`工作流 "${workflow.name}" 已开始执行`);
    setTimeout(() => { setWorkflows(prev => prev.map(w => w.id === workflow.id ? { ...w, status: 'completed' } : w)); message.success(`工作流 "${workflow.name}" 执行完成`); }, 3000);
  };

  const openDeviceModal = (device?: any) => {
    if (device) { setEditingDevice(device); deviceForm.setFieldsValue(device); } else { setEditingDevice(null); deviceForm.resetFields(); }
    setDeviceModalVisible(true);
  };
  const openRuleModal = (rule?: any) => {
    if (rule) { setEditingRule(rule); ruleForm.setFieldsValue(rule); } else { setEditingRule(null); ruleForm.resetFields(); }
    setRuleModalVisible(true);
  };
  const openWorkflowModal = (workflow?: any) => {
    if (workflow) { setEditingWorkflow(workflow); workflowForm.setFieldsValue({ ...workflow, steps: workflow.steps?.join('\n') || '' }); } else { setEditingWorkflow(null); workflowForm.resetFields(); }
    setWorkflowModalVisible(true);
  };

  const toggleFwRule = (id: number, enabled: boolean) => {
    setFirewallRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r));
    message.success(enabled ? '规则已启用' : '规则已禁用');
  };
  const toggleIdsRule = (id: number, enabled: boolean) => {
    setIdsRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r));
    message.success(enabled ? '规则已启用' : '规则已禁用');
  };
  const toggleWafRule = (id: number, enabled: boolean) => {
    setWafRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r));
    message.success(enabled ? '规则已启用' : '规则已禁用');
  };

  const deviceColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '设备名称', dataIndex: 'name', key: 'name' },
    { title: '类型', dataIndex: 'type', key: 'type', width: 120, render: (type: string) => <Tag color="blue">{type || '-'}</Tag> },
    { title: 'IP地址', dataIndex: 'ip', key: 'ip', width: 140, render: (ip: string) => <span style={{ fontFamily: 'monospace' }}>{ip || '-'}</span> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => <Tag color={status === 'online' ? 'green' : status === 'offline' ? 'red' : 'orange'}>{status === 'online' ? '在线' : status === 'offline' ? '离线' : status || '未知'}</Tag> },
    { title: '操作', key: 'action', width: 140, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" icon={<EditOutlined />} size="small" onClick={() => openDeviceModal(record)}>编辑</Button>
        <Popconfirm title="确定要删除这个设备吗？" onConfirm={() => handleDeviceDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const ruleColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '规则名称', dataIndex: 'name', key: 'name' },
    { title: '触发条件', dataIndex: 'trigger', key: 'trigger', ellipsis: true, render: (trigger: string) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{trigger || '-'}</span> },
    { title: '执行动作', dataIndex: 'action', key: 'action', width: 120, render: (action: string) => <Tag color="green">{action || '-'}</Tag> },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 80, render: (enabled: boolean) => <Tag color={enabled ? 'green' : 'gray'}>{enabled ? '启用' : '禁用'}</Tag> },
    { title: '操作', key: 'action_col', width: 140, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" icon={<EditOutlined />} size="small" onClick={() => openRuleModal(record)}>编辑</Button>
        <Popconfirm title="确定要删除这个规则吗？" onConfirm={() => handleRuleDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const workflowColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '工作流名称', dataIndex: 'name', key: 'name' },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    { title: '步骤数', key: 'steps', width: 80, render: (_: any, record: any) => (record.steps || []).length },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (status: string) => <Tag color={status === 'running' ? 'blue' : status === 'completed' ? 'green' : 'orange'}>{status === 'running' ? '运行中' : status === 'completed' ? '已完成' : '草稿'}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss') },
    { title: '操作', key: 'action', width: 200, render: (_: any, record: any) => (
      <Space size={4}>
        {record.status !== 'running' && <Button type="link" size="small" icon={<PlayCircleOutlined />} onClick={() => handleWorkflowExecute(record)}>执行</Button>}
        <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openWorkflowModal(record)}>编辑</Button>
        <Popconfirm title="确定要删除这个工作流吗？" onConfirm={() => handleWorkflowDelete(record.id)} okText="确定" cancelText="取消">
          <Button type="link" danger size="small" icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const secDeviceColumns = [
    { title: '设备名称', dataIndex: 'name', key: 'name', width: 200, render: (text: string, r: any) => <Space><Badge status={r.status === 'online' ? 'success' : 'error'} /><span style={{ fontWeight: 600 }}>{text}</span></Space> },
    { title: '类型', dataIndex: 'type', key: 'type', width: 100, render: (t: string) => {
      const m: Record<string, { label: string; color: string }> = { firewall: { label: '防火墙', color: '#ff4d4f' }, ids: { label: 'IDS', color: '#1890ff' }, ips: { label: 'IPS', color: '#fa8c16' }, waf: { label: 'WAF', color: '#722ed1' }, vpn: { label: 'VPN', color: '#13c2c2' } };
      const info = m[t] || { label: t, color: 'default' };
      return <Tag color={info.color}>{info.label}</Tag>;
    }},
    { title: '型号', dataIndex: 'model', key: 'model', width: 200, render: (t: string) => <span style={{ fontSize: 12 }}>{t}</span> },
    { title: 'IP', dataIndex: 'ip', key: 'ip', width: 130, render: (t: string) => <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{t}</span> },
    { title: 'CPU', dataIndex: 'cpu', key: 'cpu', width: 100, render: (v: number) => <Progress percent={v} size="small" strokeColor={v > 80 ? '#ff4d4f' : v > 60 ? '#fa8c16' : '#52c41a'} /> },
    { title: '内存', dataIndex: 'memory', key: 'memory', width: 100, render: (v: number) => <Progress percent={v} size="small" strokeColor={v > 80 ? '#ff4d4f' : v > 60 ? '#fa8c16' : '#52c41a'} /> },
    { title: '吞吐量', dataIndex: 'throughput', key: 'throughput', width: 110 },
    { title: '规则数', dataIndex: 'rules_count', key: 'rules_count', width: 80, render: (v: number) => <span style={{ fontWeight: 600 }}>{v?.toLocaleString()}</span> },
    { title: '操作', key: 'action', width: 80, render: (_: any, r: any) => <Button type="link" size="small" icon={<SearchOutlined />} onClick={() => { setSelectedDevice(r); setDeviceDetailVisible(true); }}>详情</Button> },
  ];

  const fwRuleColumns = [
    { title: '优先级', dataIndex: 'priority', key: 'priority', width: 70, sorter: (a: any, b: any) => a.priority - b.priority },
    { title: '规则名称', dataIndex: 'name', key: 'name', width: 180 },
    { title: '动作', dataIndex: 'action', key: 'action', width: 100, render: (a: string) => <Tag color={a === 'deny' ? 'red' : a === 'allow' ? 'green' : 'orange'}>{a === 'deny' ? '阻断' : a === 'allow' ? '放行' : '限速'}</Tag> },
    { title: '方向', dataIndex: 'direction', key: 'direction', width: 80, render: (d: string) => <Tag>{d === 'inbound' ? '入站' : d === 'outbound' ? '出站' : '双向'}</Tag> },
    { title: '源地址', dataIndex: 'source', key: 'source', width: 150, render: (t: string) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{t}</span> },
    { title: '目标地址', dataIndex: 'dest', key: 'dest', width: 130, render: (t: string) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{t}</span> },
    { title: '端口', dataIndex: 'port', key: 'port', width: 80, render: (t: string) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{t}</span> },
    { title: '命中次数', dataIndex: 'hits', key: 'hits', width: 100, render: (v: number) => <span style={{ fontWeight: 600 }}>{v?.toLocaleString()}</span> },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', width: 70, render: (e: boolean, r: any) => <Switch size="small" checked={e} onChange={(v) => toggleFwRule(r.id, v)} /> },
  ];

  const idsRuleColumns = [
    { title: 'SID', dataIndex: 'sid', key: 'sid', width: 90, render: (t: string) => <span style={{ fontFamily: 'monospace', fontSize: 11 }}>{t}</span> },
    { title: '规则名称', dataIndex: 'name', key: 'name', width: 180 },
    { title: '分类', dataIndex: 'category', key: 'category', width: 120, render: (t: string) => <Tag color="blue">{t}</Tag> },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (s: string) => <Tag color={s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'gold' : 'blue'}>{s === 'critical' ? '严重' : s === 'high' ? '高' : s === 'medium' ? '中' : '低'}</Tag> },
    { title: '响应动作', dataIndex: 'action', key: 'action', width: 90, render: (a: string) => <Tag color={a === 'block' ? 'red' : 'orange'}>{a === 'block' ? '阻断' : '告警'}</Tag> },
    { title: '命中次数', dataIndex: 'hits', key: 'hits', width: 90, render: (v: number) => <span style={{ fontWeight: 600 }}>{v?.toLocaleString()}</span> },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', width: 70, render: (e: boolean, r: any) => <Switch size="small" checked={e} onChange={(v) => toggleIdsRule(r.id, v)} /> },
  ];

  const wafRuleColumns = [
    { title: '规则名称', dataIndex: 'name', key: 'name', width: 180 },
    { title: '攻击类型', dataIndex: 'type', key: 'type', width: 110, render: (t: string) => <Tag color="purple">{t.toUpperCase()}</Tag> },
    { title: '防护模式', dataIndex: 'mode', key: 'mode', width: 100, render: (m: string) => <Tag color={m === 'block' ? 'red' : m === 'rate-limit' ? 'orange' : m === 'challenge' ? 'blue' : 'default'}>{m === 'block' ? '阻断' : m === 'rate-limit' ? '限速' : m === 'challenge' ? '验证' : '检测'}</Tag> },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (s: string) => <Tag color={s === 'critical' ? 'red' : s === 'high' ? 'orange' : s === 'medium' ? 'gold' : 'blue'}>{s === 'critical' ? '严重' : s === 'high' ? '高' : s === 'medium' ? '中' : '低'}</Tag> },
    { title: '命中次数', dataIndex: 'hits', key: 'hits', width: 90, render: (v: number) => <span style={{ fontWeight: 600 }}>{v?.toLocaleString()}</span> },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', width: 70, render: (e: boolean, r: any) => <Switch size="small" checked={e} onChange={(v) => toggleWafRule(r.id, v)} /> },
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #13c2c2, #36cfc9)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <ApiOutlined style={{ marginRight: 8, WebkitTextFillColor: '#13c2c2' }} />协同联动
        </h2>
        <Button icon={<ReloadOutlined />} onClick={() => fetchOrchestrationData()}>刷新</Button>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #13c2c2, #36cfc9)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>安全设备</span>} value={securityDevices.length} prefix={<SafetyCertificateOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>防火墙规则</span>} value={firewallRules.length} prefix={<SecurityScanOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>IDS/IPS规则</span>} value={idsRules.length} prefix={<BugOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>WAF规则</span>} value={wafRules.length} prefix={<GlobalOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
      </Row>

      <Card variant="borderless" style={{ borderRadius: 12 }}>
        <Tabs defaultActiveKey="security-devices" items={[
          { key: 'security-devices', label: <span><SafetyCertificateOutlined /> 安全设备</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openDeviceModal()}>添加设备</Button>
              </div>
              <Table columns={secDeviceColumns} dataSource={securityDevices.map((d, i) => ({ ...d, key: d.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 台设备` }} size="middle" />
            </div>
          )},
          { key: 'firewall', label: <span><SecurityScanOutlined /> 防火墙规则</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Space>
                  <Tag color="red">阻断: {firewallRules.filter(r => r.action === 'deny').length}</Tag>
                  <Tag color="green">放行: {firewallRules.filter(r => r.action === 'allow').length}</Tag>
                  <Tag color="orange">限速: {firewallRules.filter(r => r.action === 'rate-limit').length}</Tag>
                </Space>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => setFwRuleModalVisible(true)}>新增规则</Button>
              </div>
              <Table columns={fwRuleColumns} dataSource={firewallRules.map((r, i) => ({ ...r, key: r.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条规则` }} size="middle" />
            </div>
          )},
          { key: 'ids-ips', label: <span><BugOutlined /> IDS/IPS规则</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Space>
                  <Tag color="red">阻断: {idsRules.filter(r => r.action === 'block').length}</Tag>
                  <Tag color="orange">告警: {idsRules.filter(r => r.action === 'alert').length}</Tag>
                  <Tag color="blue">启用: {idsRules.filter(r => r.enabled).length}/{idsRules.length}</Tag>
                </Space>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => setIdsRuleModalVisible(true)}>新增规则</Button>
              </div>
              <Table columns={idsRuleColumns} dataSource={idsRules.map((r, i) => ({ ...r, key: r.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条规则` }} size="middle" />
            </div>
          )},
          { key: 'waf', label: <span><GlobalOutlined /> WAF规则</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <Space>
                  <Tag color="red">阻断: {wafRules.filter(r => r.mode === 'block').length}</Tag>
                  <Tag color="orange">限速: {wafRules.filter(r => r.mode === 'rate-limit').length}</Tag>
                  <Tag color="blue">验证: {wafRules.filter(r => r.mode === 'challenge').length}</Tag>
                  <Tag color="default">检测: {wafRules.filter(r => r.mode === 'detect').length}</Tag>
                </Space>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => setWafRuleModalVisible(true)}>新增规则</Button>
              </div>
              <Table columns={wafRuleColumns} dataSource={wafRules.map((r, i) => ({ ...r, key: r.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条规则` }} size="middle" />
            </div>
          )},
          { key: 'devices', label: <span><ApiOutlined /> 联动设备</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openDeviceModal()}>添加设备</Button>
              </div>
              <Table columns={deviceColumns} dataSource={devices.map((d, i) => ({ ...d, key: d.id || i }))} loading={initialLoading} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            </div>
          )},
          { key: 'rules', label: <span><ThunderboltOutlined /> 联动规则</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openRuleModal()}>新建规则</Button>
              </div>
              <Table columns={ruleColumns} dataSource={rules.map((r, i) => ({ ...r, key: r.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            </div>
          )},
          { key: 'workflows', label: <span><NodeIndexOutlined /> 工作流编排</span>, children: (
            <div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 16 }}>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openWorkflowModal()}>新建工作流</Button>
              </div>
              <Table columns={workflowColumns} dataSource={workflows.map((w, i) => ({ ...w, key: w.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
            </div>
          )},
        ]} />
      </Card>

      <Modal title={editingDevice ? "编辑设备" : "添加设备"} open={deviceModalVisible} onCancel={() => { setDeviceModalVisible(false); deviceForm.resetFields(); setEditingDevice(null); }} footer={null} width={500}>
        <Form form={deviceForm} layout="vertical" onFinish={editingDevice ? handleDeviceUpdate : handleDeviceCreate}>
          <Form.Item name="name" label="设备名称" rules={[{ required: true, message: '请输入设备名称' }]}><Input placeholder="请输入设备名称" /></Form.Item>
          <Form.Item name="type" label="设备类型" rules={[{ required: true, message: '请选择设备类型' }]}>
            <Select placeholder="请选择设备类型"><Option value="firewall">防火墙</Option><Option value="ids">IDS</Option><Option value="ips">IPS</Option><Option value="waf">WAF</Option><Option value="siem">SIEM</Option><Option value="vpn">VPN网关</Option><Option value="proxy">代理服务器</Option><Option value="other">其他</Option></Select>
          </Form.Item>
          <Form.Item name="ip" label="IP地址" rules={[{ required: true, message: '请输入IP地址' }]}><Input placeholder="请输入IP地址" /></Form.Item>
          <Form.Item name="port" label="端口"><Input placeholder="请输入端口号" /></Form.Item>
          <Form.Item name="status" label="状态"><Select><Option value="online">在线</Option><Option value="offline">离线</Option></Select></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setDeviceModalVisible(false); deviceForm.resetFields(); setEditingDevice(null); }}>取消</Button>
            <Button type="primary" htmlType="submit">{editingDevice ? '更新' : '创建'}</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title={editingRule ? "编辑联动规则" : "新建联动规则"} open={ruleModalVisible} onCancel={() => { setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); }} footer={null} width={600}>
        <Form form={ruleForm} layout="vertical" onFinish={editingRule ? handleRuleUpdate : handleRuleCreate}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true, message: '请输入规则名称' }]}><Input placeholder="请输入规则名称" /></Form.Item>
          <Form.Item name="trigger" label="触发条件" rules={[{ required: true, message: '请输入触发条件' }]}><TextArea rows={3} placeholder="请输入触发条件 (JSON格式)" /></Form.Item>
          <Form.Item name="action" label="执行动作" rules={[{ required: true, message: '请输入执行动作' }]}><Input placeholder="请输入执行动作" /></Form.Item>
          <Form.Item name="target_device" label="目标设备"><Select placeholder="请选择目标设备" allowClear>{devices.map((d, i) => <Select.Option key={i} value={d.name}>{d.name} ({d.ip})</Select.Option>)}</Select></Form.Item>
          <Form.Item name="enabled" label="状态"><Select><Option value={true}>启用</Option><Option value={false}>禁用</Option></Select></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setRuleModalVisible(false); ruleForm.resetFields(); setEditingRule(null); }}>取消</Button>
            <Button type="primary" htmlType="submit">{editingRule ? '更新' : '创建'}</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="新建工作流" open={workflowModalVisible} onCancel={() => { setWorkflowModalVisible(false); workflowForm.resetFields(); setEditingWorkflow(null); }} footer={null} width={600}>
        <Form form={workflowForm} layout="vertical" onFinish={editingWorkflow ? undefined : handleWorkflowCreate}>
          <Form.Item name="name" label="工作流名称" rules={[{ required: true, message: '请输入工作流名称' }]}><Input placeholder="请输入工作流名称" /></Form.Item>
          <Form.Item name="description" label="描述"><TextArea rows={2} placeholder="请输入工作流描述" /></Form.Item>
          <Form.Item name="steps" label="工作流步骤（每行一个步骤）" rules={[{ required: true, message: '请输入工作流步骤' }]}>
            <TextArea rows={8} placeholder={"请输入工作流步骤，每行一个\n例如：\n1. 检测到攻击事件\n2. 自动封锁攻击源IP\n3. 生成告警通知\n4. 启动取证分析"} />
          </Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setWorkflowModalVisible(false); workflowForm.resetFields(); setEditingWorkflow(null); }}>取消</Button>
            <Button type="primary" htmlType="submit">{editingWorkflow ? '更新' : '创建'}</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="新增防火墙规则" open={fwRuleModalVisible} onCancel={() => { setFwRuleModalVisible(false); fwRuleForm.resetFields(); }} footer={null} width={650}>
        <Form form={fwRuleForm} layout="vertical" onFinish={(v) => { setFirewallRules(prev => [...prev, { ...v, id: Date.now(), hits: 0 }]); message.success('防火墙规则创建成功'); setFwRuleModalVisible(false); fwRuleForm.resetFields(); }}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true }]}><Input placeholder="规则名称" /></Form.Item>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="action" label="动作" rules={[{ required: true }]}><Select><Option value="deny">阻断</Option><Option value="allow">放行</Option><Option value="rate-limit">限速</Option></Select></Form.Item></Col>
            <Col span={12}><Form.Item name="direction" label="方向" rules={[{ required: true }]}><Select><Option value="inbound">入站</Option><Option value="outbound">出站</Option><Option value="both">双向</Option></Select></Form.Item></Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="source" label="源地址" rules={[{ required: true }]}><Input placeholder="IP/CIDR/any" /></Form.Item></Col>
            <Col span={12}><Form.Item name="dest" label="目标地址" rules={[{ required: true }]}><Input placeholder="IP/CIDR/any" /></Form.Item></Col>
          </Row>
          <Row gutter={16}>
            <Col span={8}><Form.Item name="port" label="端口" rules={[{ required: true }]}><Input placeholder="80,443 或 *" /></Form.Item></Col>
            <Col span={8}><Form.Item name="protocol" label="协议" rules={[{ required: true }]}><Select><Option value="TCP">TCP</Option><Option value="UDP">UDP</Option><Option value="ICMP">ICMP</Option><Option value="ALL">ALL</Option></Select></Form.Item></Col>
            <Col span={8}><Form.Item name="priority" label="优先级" rules={[{ required: true }]}><InputNumber min={1} max={65535} style={{ width: '100%' }} /></Form.Item></Col>
          </Row>
          <Form.Item name="description" label="描述"><TextArea rows={2} placeholder="规则描述" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setFwRuleModalVisible(false); fwRuleForm.resetFields(); }}>取消</Button>
            <Button type="primary" htmlType="submit">创建</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="新增IDS/IPS规则" open={idsRuleModalVisible} onCancel={() => { setIdsRuleModalVisible(false); idsRuleForm.resetFields(); }} footer={null} width={600}>
        <Form form={idsRuleForm} layout="vertical" onFinish={(v) => { setIdsRules(prev => [...prev, { ...v, id: Date.now(), sid: `10${Date.now()}`, hits: 0 }]); message.success('IDS/IPS规则创建成功'); setIdsRuleModalVisible(false); idsRuleForm.resetFields(); }}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true }]}><Input placeholder="规则名称" /></Form.Item>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="category" label="分类" rules={[{ required: true }]}><Select><Option value="web-attack">Web攻击</Option><Option value="brute-force">暴力破解</Option><Option value="ddos">DDoS</Option><Option value="malware">恶意软件</Option><Option value="c2">C2通信</Option><Option value="recon">侦察</Option><Option value="exfiltration">数据外传</Option></Select></Form.Item></Col>
            <Col span={12}><Form.Item name="severity" label="严重程度" rules={[{ required: true }]}><Select><Option value="critical">严重</Option><Option value="high">高</Option><Option value="medium">中</Option><Option value="low">低</Option></Select></Form.Item></Col>
          </Row>
          <Form.Item name="action" label="响应动作" rules={[{ required: true }]}><Select><Option value="alert">告警</Option><Option value="block">阻断</Option></Select></Form.Item>
          <Form.Item name="description" label="描述"><TextArea rows={2} placeholder="规则描述" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setIdsRuleModalVisible(false); idsRuleForm.resetFields(); }}>取消</Button>
            <Button type="primary" htmlType="submit">创建</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="新增WAF规则" open={wafRuleModalVisible} onCancel={() => { setWafRuleModalVisible(false); wafRuleForm.resetFields(); }} footer={null} width={600}>
        <Form form={wafRuleForm} layout="vertical" onFinish={(v) => { setWafRules(prev => [...prev, { ...v, id: Date.now(), hits: 0 }]); message.success('WAF规则创建成功'); setWafRuleModalVisible(false); wafRuleForm.resetFields(); }}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true }]}><Input placeholder="规则名称" /></Form.Item>
          <Row gutter={16}>
            <Col span={12}><Form.Item name="type" label="攻击类型" rules={[{ required: true }]}><Select><Option value="sqli">SQL注入</Option><Option value="xss">XSS</Option><Option value="rce">命令注入</Option><Option value="lfi">文件包含</Option><Option value="cc">CC攻击</Option><Option value="bot">爬虫</Option><Option value="traversal">路径遍历</Option><Option value="csrf">CSRF</Option></Select></Form.Item></Col>
            <Col span={12}><Form.Item name="mode" label="防护模式" rules={[{ required: true }]}><Select><Option value="block">阻断</Option><Option value="detect">检测</Option><Option value="rate-limit">限速</Option><Option value="challenge">人机验证</Option></Select></Form.Item></Col>
          </Row>
          <Form.Item name="severity" label="严重程度" rules={[{ required: true }]}><Select><Option value="critical">严重</Option><Option value="high">高</Option><Option value="medium">中</Option><Option value="low">低</Option></Select></Form.Item>
          <Form.Item name="description" label="描述"><TextArea rows={2} placeholder="规则描述" /></Form.Item>
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button style={{ marginRight: 8 }} onClick={() => { setWafRuleModalVisible(false); wafRuleForm.resetFields(); }}>取消</Button>
            <Button type="primary" htmlType="submit">创建</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="设备详情" open={deviceDetailVisible} onCancel={() => setDeviceDetailVisible(false)} footer={[<Button key="close" onClick={() => setDeviceDetailVisible(false)}>关闭</Button>]} width={700}>
        {selectedDevice && (
          <Descriptions column={2} bordered size="small">
            <Descriptions.Item label="设备名称" span={2}><span style={{ fontWeight: 600 }}>{selectedDevice.name}</span></Descriptions.Item>
            <Descriptions.Item label="类型"><Tag color={selectedDevice.type === 'firewall' ? 'red' : selectedDevice.type === 'ids' ? 'blue' : selectedDevice.type === 'ips' ? 'orange' : selectedDevice.type === 'waf' ? 'purple' : 'cyan'}>{selectedDevice.type === 'firewall' ? '防火墙' : selectedDevice.type === 'ids' ? 'IDS' : selectedDevice.type === 'ips' ? 'IPS' : selectedDevice.type === 'waf' ? 'WAF' : selectedDevice.type === 'vpn' ? 'VPN' : selectedDevice.type}</Tag></Descriptions.Item>
            <Descriptions.Item label="状态"><Badge status={selectedDevice.status === 'online' ? 'success' : 'error'} text={selectedDevice.status === 'online' ? '在线' : '离线'} /></Descriptions.Item>
            <Descriptions.Item label="型号" span={2}>{selectedDevice.model}</Descriptions.Item>
            <Descriptions.Item label="IP地址"><span style={{ fontFamily: 'monospace' }}>{selectedDevice.ip}</span></Descriptions.Item>
            <Descriptions.Item label="固件版本">{selectedDevice.firmware}</Descriptions.Item>
            <Descriptions.Item label="CPU使用率"><Progress percent={selectedDevice.cpu} size="small" strokeColor={selectedDevice.cpu > 80 ? '#ff4d4f' : '#52c41a'} /></Descriptions.Item>
            <Descriptions.Item label="内存使用率"><Progress percent={selectedDevice.memory} size="small" strokeColor={selectedDevice.memory > 80 ? '#ff4d4f' : '#52c41a'} /></Descriptions.Item>
            <Descriptions.Item label="吞吐量"><span style={{ fontWeight: 600 }}>{selectedDevice.throughput}</span></Descriptions.Item>
            <Descriptions.Item label="规则数"><span style={{ fontWeight: 600 }}>{selectedDevice.rules_count?.toLocaleString()}</span></Descriptions.Item>
            <Descriptions.Item label="运行时间" span={2}>{selectedDevice.uptime}</Descriptions.Item>
          </Descriptions>
        )}
      </Modal>
    </div>
  );
};

export default Orchestration;
