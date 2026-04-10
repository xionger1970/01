import React, { useEffect, useState, useCallback } from 'react';
import { Card, Row, Col, Table, Tabs, Button, Input, Modal, Form, Alert, Spin, Tag, Statistic, Popconfirm, message, Space, Descriptions, Divider, Select } from 'antd';
import { AreaChartOutlined, UserOutlined, DatabaseOutlined, SettingOutlined, ReloadOutlined, DeleteOutlined, SearchOutlined, EyeOutlined, PlusOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import axios from 'axios';

interface Anomaly {
  type: string;
  description: string;
  severity: string;
  details: any;
  timestamp: number;
}

interface AnomalyStats {
  total_traffic_data: number;
  total_connection_data: number;
  total_user_login_data: number;
  total_user_access_data: number;
  total_data_transfer_data: number;
  total_process_data: number;
  total_resource_data: number;
  thresholds: any;
  last_updated: string;
}

const severityLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
const severityColors: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff' };
const typeLabels: Record<string, string> = { traffic_anomaly: '流量异常', large_packet: '大数据包', connection_flood: '连接洪泛', login_attempts: '登录尝试异常', geo_location: '地理位置异常', access_frequency: '访问频率异常', data_transfer_rate: '数据传输异常', sensitive_data_access: '敏感数据访问', process_count: '进程数量异常', cpu_usage: 'CPU使用率异常', memory_usage: '内存使用率异常', disk_usage: '磁盘使用率异常' };

const AnomalyDetection: React.FC = () => {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [stats, setStats] = useState<AnomalyStats | null>(null);
  const [thresholds, setThresholds] = useState<any>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('all');
  const [modalVisible, setModalVisible] = useState(false);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null);
  const [searchText, setSearchText] = useState('');
  const [form] = Form.useForm();
  const [whitelist, setWhitelist] = useState<{ type: string; value: string; reason: string }[]>([]);
  const [whitelistModalVisible, setWhitelistModalVisible] = useState(false);
  const [whitelistForm] = Form.useForm();

  const fetchAnomalyData = useCallback(async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    setError(null);
    try {
      const [anomaliesRes, statsRes, thresholdsRes] = await Promise.all([
        axios.get(`/api/anomalies/detect?anomaly_type=${activeTab === 'all' ? '' : activeTab}`),
        axios.get('/api/anomalies/stats'),
        axios.get('/api/anomalies/thresholds')
      ]);
      setAnomalies(Array.isArray(anomaliesRes.data) ? anomaliesRes.data : []);
      setStats(statsRes.data);
      setThresholds(thresholdsRes.data);
    } catch (err) {
      setError('获取异常检测数据失败');
      console.error('获取异常检测数据失败:', err);
    } finally {
      if (showLoading) setInitialLoading(false);
    }
  }, [activeTab]);

  useEffect(() => { fetchAnomalyData(true); }, [activeTab]);

  const handleUpdateThresholds = async (values: any) => {
    try {
      await axios.post('/api/anomalies/thresholds', values);
      message.success('阈值更新成功');
      setModalVisible(false);
      form.resetFields();
      fetchAnomalyData();
    } catch (err) {
      message.error('更新阈值失败，请重试');
    }
  };

  const handleDeleteAnomaly = async (index: number) => {
    try {
      const newAnomalies = anomalies.filter((_, i) => i !== index);
      setAnomalies(newAnomalies);
      message.success('删除成功');
    } catch (err) {
      message.error('删除失败');
    }
  };

  const handleAddWhitelist = async (values: any) => {
    try {
      setWhitelist(prev => [...prev, { type: values.type, value: values.value, reason: values.reason || '' }]);
      message.success('白名单添加成功');
      setWhitelistModalVisible(false);
      whitelistForm.resetFields();
    } catch (err) {
      message.error('添加白名单失败');
    }
  };

  const handleDeleteWhitelist = (index: number) => {
    setWhitelist(prev => prev.filter((_, i) => i !== index));
    message.success('白名单删除成功');
  };

  const columns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: '异常类型', dataIndex: 'type', key: 'type', width: 150, render: (type: string) => <Tag color="blue">{typeLabels[type] || type}</Tag> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 100, render: (severity: string) => <Tag color={severityColors[severity] || 'blue'}>{severityLabels[severity] || severity}</Tag> },
    { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 170, render: (timestamp: number) => new Date(timestamp * 1000).toLocaleString() },
    { title: '操作', key: 'action', width: 140, render: (_: any, record: Anomaly, index: number) => (
      <Space size={4}>
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedAnomaly(record); setDetailModalVisible(true); }}>详情</Button>
        <Popconfirm title="确定要删除该异常记录吗？" onConfirm={() => handleDeleteAnomaly(index)} okText="确定" cancelText="取消">
          <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
        </Popconfirm>
      </Space>
    )}
  ];

  const filteredAnomalies = anomalies.filter(a => {
    if (!searchText) return true;
    const label = typeLabels[a.type] || a.type;
    return label.toLowerCase().includes(searchText.toLowerCase()) || a.description.toLowerCase().includes(searchText.toLowerCase());
  });

  const whitelistColumns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: '类型', dataIndex: 'type', key: 'type', width: 120, render: (type: string) => <Tag color="blue">{typeLabels[type] || type}</Tag> },
    { title: '白名单值', dataIndex: 'value', key: 'value', render: (value: string) => <span style={{ fontFamily: 'monospace' }}>{value}</span> },
    { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
    { title: '操作', key: 'action', width: 80, render: (_: any, __: any, index: number) => (
      <Popconfirm title="确定要删除该白名单吗？" onConfirm={() => handleDeleteWhitelist(index)} okText="确定" cancelText="取消">
        <Button type="link" danger icon={<DeleteOutlined />} size="small">删除</Button>
      </Popconfirm>
    )}
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #fa8c16, #faad14)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          异常行为检测
        </h2>
        <Space>
          <Input placeholder="搜索异常类型..." prefix={<SearchOutlined />} value={searchText} onChange={(e) => setSearchText(e.target.value)} style={{ width: 200 }} allowClear />
          <Button icon={<ReloadOutlined />} onClick={() => fetchAnomalyData()}>刷新</Button>
          <Button icon={<SafetyCertificateOutlined />} onClick={() => setWhitelistModalVisible(true)}>白名单管理</Button>
          <Button type="primary" icon={<SettingOutlined />} onClick={() => setModalVisible(true)} style={{ background: 'linear-gradient(135deg, #fa8c16, #faad14)', border: 'none' }}>阈值设置</Button>
        </Space>
      </div>

      {error && <Alert message={error} type="error" style={{ marginBottom: 24 }} closable onClose={() => setError(null)} />}

      <Spin spinning={initialLoading} description="加载中...">
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>流量数据</span>} value={stats?.total_traffic_data || 0} prefix={<AreaChartOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>用户数据</span>} value={(stats?.total_user_login_data || 0) + (stats?.total_user_access_data || 0)} prefix={<UserOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>数据传输</span>} value={stats?.total_data_transfer_data || 0} prefix={<DatabaseOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
          <Col span={6}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>系统数据</span>} value={(stats?.total_process_data || 0) + (stats?.total_resource_data || 0)} prefix={<SettingOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        </Row>

        <Card variant="borderless" style={{ borderRadius: 12 }}>
          <Tabs activeKey={activeTab} onChange={setActiveTab} style={{ marginBottom: 16 }} items={[
            { key: 'all', label: '全部异常' },
            { key: 'traffic', label: '流量异常' },
            { key: 'user', label: '用户异常' },
            { key: 'data', label: '数据异常' },
            { key: 'system', label: '系统异常' },
          ]} />
          <Table columns={columns} dataSource={filteredAnomalies.map((anomaly, index) => ({ ...anomaly, key: index }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条异常` }} size="middle" />
        </Card>

        {stats?.last_updated && (
          <div style={{ marginTop: 16, textAlign: 'right', color: '#999', fontSize: 12 }}>
            最后更新: {new Date(stats.last_updated).toLocaleString()}
          </div>
        )}
      </Spin>

      <Modal title="异常检测阈值设置" open={modalVisible} onCancel={() => setModalVisible(false)} footer={null} width={800}>
        <Form form={form} layout="vertical" onFinish={handleUpdateThresholds} initialValues={thresholds}>
          <Tabs items={[
            { key: 'traffic', label: '流量阈值', children: (
              <>
                <Form.Item name={['traffic', 'rate_change']} label="流量变化率阈值"><Input type="number" placeholder="输入流量变化率阈值" /></Form.Item>
                <Form.Item name={['traffic', 'connection_rate']} label="每分钟连接数阈值"><Input type="number" placeholder="输入每分钟连接数阈值" /></Form.Item>
                <Form.Item name={['traffic', 'packet_size']} label="数据包大小阈值"><Input type="number" placeholder="输入数据包大小阈值" /></Form.Item>
              </>
            )},
            { key: 'user', label: '用户阈值', children: (
              <>
                <Form.Item name={['user', 'login_attempts']} label="每分钟登录尝试次数阈值"><Input type="number" placeholder="输入登录尝试次数阈值" /></Form.Item>
                <Form.Item name={['user', 'access_frequency']} label="每分钟访问频率阈值"><Input type="number" placeholder="输入访问频率阈值" /></Form.Item>
                <Form.Item name={['user', 'geo_distance']} label="地理位置距离阈值（公里）"><Input type="number" placeholder="输入地理位置距离阈值" /></Form.Item>
              </>
            )},
            { key: 'data', label: '数据阈值', children: (
              <>
                <Form.Item name={['data', 'transfer_rate']} label="数据传输速率阈值（字节/秒）"><Input type="number" placeholder="输入数据传输速率阈值" /></Form.Item>
                <Form.Item name={['data', 'sensitive_access']} label="敏感数据访问频率阈值"><Input type="number" placeholder="输入敏感数据访问频率阈值" /></Form.Item>
              </>
            )},
            { key: 'system', label: '系统阈值', children: (
              <>
                <Form.Item name={['system', 'process_count']} label="进程数量阈值"><Input type="number" placeholder="输入进程数量阈值" /></Form.Item>
                <Form.Item name={['system', 'cpu_usage']} label="CPU使用率阈值（%）"><Input type="number" placeholder="输入CPU使用率阈值" /></Form.Item>
                <Form.Item name={['system', 'memory_usage']} label="内存使用率阈值（%）"><Input type="number" placeholder="输入内存使用率阈值" /></Form.Item>
                <Form.Item name={['system', 'disk_usage']} label="磁盘使用率阈值（%）"><Input type="number" placeholder="输入磁盘使用率阈值" /></Form.Item>
              </>
            )},
          ]} />
          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Button onClick={() => setModalVisible(false)} style={{ marginRight: 8 }}>取消</Button>
            <Button type="primary" htmlType="submit">保存设置</Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal title="异常详情" open={detailModalVisible} onCancel={() => setDetailModalVisible(false)} footer={[<Button key="close" onClick={() => setDetailModalVisible(false)}>关闭</Button>]} width={700}>
        {selectedAnomaly && (
          <div>
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="异常类型"><Tag color="blue">{typeLabels[selectedAnomaly.type] || selectedAnomaly.type}</Tag></Descriptions.Item>
              <Descriptions.Item label="严重程度"><Tag color={severityColors[selectedAnomaly.severity] || 'blue'}>{severityLabels[selectedAnomaly.severity] || selectedAnomaly.severity}</Tag></Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>{selectedAnomaly.description}</Descriptions.Item>
              <Descriptions.Item label="检测时间" span={2}>{new Date(selectedAnomaly.timestamp * 1000).toLocaleString()}</Descriptions.Item>
            </Descriptions>
            <Divider />
            <div>
              <h4>详细信息</h4>
              <pre style={{ backgroundColor: '#f5f5f5', padding: 16, borderRadius: 8, overflowX: 'auto', fontSize: 12, maxHeight: 300 }}>
                {JSON.stringify(selectedAnomaly.details, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>

      <Modal title="白名单管理" open={whitelistModalVisible} onCancel={() => setWhitelistModalVisible(false)} footer={[<Button key="close" onClick={() => setWhitelistModalVisible(false)}>关闭</Button>]} width={800}>
        <Form form={whitelistForm} layout="inline" onFinish={handleAddWhitelist} style={{ marginBottom: 16 }}>
          <Form.Item name="type" rules={[{ required: true, message: '请选择类型' }]}>
            <Select placeholder="选择类型" style={{ width: 150 }}>
              {Object.entries(typeLabels).map(([key, label]) => (
                <Select.Option key={key} value={key}>{label}</Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item name="value" rules={[{ required: true, message: '请输入值' }]}>
            <Input placeholder="白名单值（如IP、用户名等）" style={{ width: 200 }} />
          </Form.Item>
          <Form.Item name="reason">
            <Input placeholder="原因（可选）" style={{ width: 150 }} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" icon={<PlusOutlined />}>添加</Button>
          </Form.Item>
        </Form>
        <Table
          columns={whitelistColumns}
          dataSource={whitelist.map((item, i) => ({ ...item, key: i }))}
          pagination={{ pageSize: 10, showTotal: (total) => `共 ${total} 条` }}
          size="small"
          locale={{ emptyText: '暂无白名单数据' }}
        />
      </Modal>
    </div>
  );
};

export default AnomalyDetection;
