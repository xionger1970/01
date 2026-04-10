import React, { useState, useEffect, useRef } from 'react';
import { Card, Table, Tag, Button, Modal, Statistic, Row, Col, Tabs, Space, Descriptions, Spin, message, Empty, Timeline } from 'antd';
import { HistoryOutlined, DeleteOutlined, ReloadOutlined, NodeIndexOutlined, BranchesOutlined, EyeOutlined, AimOutlined } from '@ant-design/icons';
import * as echarts from 'echarts';
import axios from 'axios';
import dayjs from 'dayjs';

const severityColors: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff' };
const severityLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };

const AttackTracking: React.FC = () => {
  const [attackChains, setAttackChains] = useState<any[]>([]);
  const [statistics, setStatistics] = useState<any>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [detailModalVisible, setDetailModalVisible] = useState(false);
  const [selectedChain, setSelectedChain] = useState<any>(null);
  const [graphModalVisible, setGraphModalVisible] = useState(false);
  const [timelineModalVisible, setTimelineModalVisible] = useState(false);
  const chartRef = useRef<echarts.ECharts | null>(null);

  const fetchAttackTrackingData = async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    try {
      const [chainsRes, statsRes] = await Promise.all([
        axios.get('/api/attack-tracking/chains'),
        axios.get('/api/attack-tracking/statistics')
      ]);
      setAttackChains(Array.isArray(chainsRes.data) ? chainsRes.data : []);
      setStatistics(statsRes.data);
    } catch (error) {
      message.error('获取攻击追踪数据失败');
      setAttackChains([]);
    } finally {
      if (showLoading) setInitialLoading(false);
    }
  };

  useEffect(() => { fetchAttackTrackingData(true); }, []);

  const handleDeleteChain = async (chainId: string) => {
    try {
      await axios.delete(`/api/attack-tracking/chains/${chainId}`);
      message.success('删除成功');
      fetchAttackTrackingData();
    } catch (error) {
      message.error('删除失败');
    }
  };

  const showAttackGraph = (chain: any) => {
    setSelectedChain(chain);
    setGraphModalVisible(true);
    setTimeout(() => initAttackGraph(chain), 100);
  };

  const showTimeline = (chain: any) => {
    setSelectedChain(chain);
    setTimelineModalVisible(true);
  };

  const initAttackGraph = (chain: any) => {
    const dom = document.getElementById('attack-graph-container');
    if (!dom) return;
    if (chartRef.current) chartRef.current.dispose();
    const chart = echarts.init(dom);
    chartRef.current = chart;

    const nodes: any[] = [];
    const links: any[] = [];
    const steps = chain.steps || chain.attack_steps || [];

    if (steps.length === 0) {
      nodes.push({ name: chain.source_ip || '未知来源', x: 300, y: 200, symbolSize: 50, itemStyle: { color: '#ff4d4f' } });
      nodes.push({ name: chain.target_ip || '未知目标', x: 500, y: 200, symbolSize: 50, itemStyle: { color: '#fa8c16' } });
      links.push({ source: chain.source_ip || '未知来源', target: chain.target_ip || '未知目标' });
    } else {
      steps.forEach((step: any, index: number) => {
        const stepName = step.action || step.type || `步骤${index + 1}`;
        nodes.push({
          name: stepName, x: 100 + index * 180, y: 200 + (index % 2) * 80,
          symbolSize: 45, itemStyle: { color: index === 0 ? '#ff4d4f' : index === steps.length - 1 ? '#52c41a' : '#1890ff' },
          label: { show: true, fontSize: 10, formatter: stepName.length > 8 ? stepName.substring(0, 8) + '...' : stepName }
        });
        if (index > 0) {
          links.push({ source: steps[index - 1].action || steps[index - 1].type || `步骤${index}`, target: stepName, lineStyle: { color: '#999', curveness: 0.2 } });
        }
      });
    }

    chart.setOption({
      title: { text: '攻击链路图', left: 'center', top: 10, textStyle: { fontSize: 14 } },
      tooltip: { trigger: 'item', formatter: (params: any) => params.dataType === 'node' ? params.name : `${params.data.source} → ${params.data.target}` },
      series: [{ type: 'graph', layout: 'none', data: nodes, links: links, roam: true, label: { show: true, position: 'bottom' }, edgeSymbol: ['none', 'arrow'], edgeSymbolSize: [4, 10], lineStyle: { opacity: 0.9, width: 2, curveness: 0 } }]
    });
  };

  const chainColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 80, render: (id: any) => String(id).substring(0, 8) },
    { title: '攻击源', dataIndex: 'source_ip', key: 'source_ip', width: 140, render: (ip: string) => <span style={{ fontFamily: 'monospace', color: '#ff4d4f' }}>{ip || '-'}</span> },
    { title: '攻击目标', dataIndex: 'target_ip', key: 'target_ip', width: 140, render: (ip: string) => <span style={{ fontFamily: 'monospace', color: '#fa8c16' }}>{ip || '-'}</span> },
    { title: '攻击类型', dataIndex: 'attack_type', key: 'attack_type', width: 120, render: (type: string) => <Tag color="blue">{type || '-'}</Tag> },
    { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 90, render: (severity: string) => <Tag color={severityColors[severity] || 'blue'}>{severityLabels[severity] || severity || '-'}</Tag> },
    { title: '步骤数', key: 'steps', width: 80, render: (_: any, record: any) => (record.steps || record.attack_steps || []).length },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (status: string) => <Tag color={status === 'active' ? 'red' : status === 'completed' ? 'green' : 'blue'}>{status === 'active' ? '进行中' : status === 'completed' ? '已完成' : status || '未知'}</Tag> },
    { title: '操作', key: 'action', width: 200, render: (_: any, record: any) => (
      <Space size={4}>
        <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedChain(record); setDetailModalVisible(true); }}>详情</Button>
        <Button type="link" size="small" icon={<NodeIndexOutlined />} onClick={() => showAttackGraph(record)}>攻击图</Button>
        <Button type="link" size="small" icon={<BranchesOutlined />} onClick={() => showTimeline(record)}>时间线</Button>
        <Button type="link" danger size="small" icon={<DeleteOutlined />} onClick={() => handleDeleteChain(record.id)}>删除</Button>
      </Space>
    )}
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #eb2f96, #ff85c0)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <HistoryOutlined style={{ marginRight: 8, WebkitTextFillColor: '#eb2f96' }} />
          攻击回溯
        </h2>
        <Button icon={<ReloadOutlined />} onClick={() => fetchAttackTrackingData()}>刷新</Button>
      </div>

      <Spin spinning={initialLoading} description="加载中...">
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}>
            <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #ff4d4f, #ff7875)', borderRadius: 12 }}>
              <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>攻击链总数</span>} value={statistics?.total_chains || attackChains.length} prefix={<HistoryOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #fa8c16, #ffc53d)', borderRadius: 12 }}>
              <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>活跃攻击链</span>} value={statistics?.active_chains || attackChains.filter(c => c.status === 'active').length} prefix={<AimOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}>
              <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>平均步骤数</span>} value={statistics?.avg_steps || (attackChains.length > 0 ? Math.round(attackChains.reduce((acc, c) => acc + (c.steps || c.attack_steps || []).length, 0) / attackChains.length) : 0)} prefix={<BranchesOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} />
            </Card>
          </Col>
          <Col span={6}>
            <Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}>
              <Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>已追踪攻击源</span>} value={statistics?.unique_sources || new Set(attackChains.map(c => c.source_ip)).size} prefix={<NodeIndexOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} />
            </Card>
          </Col>
        </Row>

        <Card variant="borderless" style={{ borderRadius: 12 }}>
          <Table columns={chainColumns} dataSource={attackChains.map((c, i) => ({ ...c, key: c.id || i }))} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
        </Card>
      </Spin>

      <Modal title="攻击链详情" open={detailModalVisible} onCancel={() => setDetailModalVisible(false)} footer={[<Button key="close" onClick={() => setDetailModalVisible(false)}>关闭</Button>]} width={800}>
        {selectedChain && (
          <div>
            <Descriptions column={2} bordered size="small">
              <Descriptions.Item label="攻击源"><span style={{ fontFamily: 'monospace', color: '#ff4d4f' }}>{selectedChain.source_ip || '-'}</span></Descriptions.Item>
              <Descriptions.Item label="攻击目标"><span style={{ fontFamily: 'monospace', color: '#fa8c16' }}>{selectedChain.target_ip || '-'}</span></Descriptions.Item>
              <Descriptions.Item label="攻击类型"><Tag color="blue">{selectedChain.attack_type || '-'}</Tag></Descriptions.Item>
              <Descriptions.Item label="严重程度"><Tag color={severityColors[selectedChain.severity] || 'blue'}>{severityLabels[selectedChain.severity] || selectedChain.severity || '-'}</Tag></Descriptions.Item>
              <Descriptions.Item label="状态"><Tag color={selectedChain.status === 'active' ? 'red' : 'green'}>{selectedChain.status === 'active' ? '进行中' : '已完成'}</Tag></Descriptions.Item>
              <Descriptions.Item label="步骤数">{(selectedChain.steps || selectedChain.attack_steps || []).length}</Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 16 }}>
              <h4>攻击步骤</h4>
              {(selectedChain.steps || selectedChain.attack_steps || []).length > 0 ? (
                <Timeline items={(selectedChain.steps || selectedChain.attack_steps).map((step: any, index: number) => ({
                  color: index === 0 ? 'red' : index === (selectedChain.steps || selectedChain.attack_steps).length - 1 ? 'green' : 'blue',
                  children: (
                    <div>
                      <div><Tag color={index === 0 ? 'red' : 'blue'}>步骤 {index + 1}</Tag> <strong>{step.action || step.type || '-'}</strong></div>
                      {step.description && <div style={{ color: '#666', marginTop: 4 }}>{step.description}</div>}
                      {step.timestamp && <div style={{ color: '#999', fontSize: 12, marginTop: 4 }}>{dayjs(step.timestamp * 1000).format('YYYY-MM-DD HH:mm:ss')}</div>}
                    </div>
                  )
                }))} />
              ) : <Empty description="暂无步骤数据" />}
            </div>
          </div>
        )}
      </Modal>

      <Modal title="攻击链路图" open={graphModalVisible} onCancel={() => { setGraphModalVisible(false); if (chartRef.current) { chartRef.current.dispose(); chartRef.current = null; } }} footer={[<Button key="close" onClick={() => { setGraphModalVisible(false); if (chartRef.current) { chartRef.current.dispose(); chartRef.current = null; } }}>关闭</Button>]} width={900}>
        <div id="attack-graph-container" style={{ height: 450, width: '100%' }} />
      </Modal>

      <Modal title="攻击时间线" open={timelineModalVisible} onCancel={() => setTimelineModalVisible(false)} footer={[<Button key="close" onClick={() => setTimelineModalVisible(false)}>关闭</Button>]} width={700}>
        {selectedChain && (
          <div>
            <div style={{ marginBottom: 16 }}>
              <Tag color="red">{selectedChain.source_ip || '未知'}</Tag>
              <span style={{ margin: '0 8px' }}>→</span>
              <Tag color="orange">{selectedChain.target_ip || '未知'}</Tag>
            </div>
            {(selectedChain.steps || selectedChain.attack_steps || []).length > 0 ? (
              <Timeline items={(selectedChain.steps || selectedChain.attack_steps).map((step: any, index: number) => ({
                color: index === 0 ? 'red' : index === (selectedChain.steps || selectedChain.attack_steps).length - 1 ? 'green' : 'blue',
                children: (
                  <Card size="small" style={{ marginBottom: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <strong>步骤 {index + 1}: {step.action || step.type || '-'}</strong>
                      {step.timestamp && <span style={{ color: '#999', fontSize: 12 }}>{dayjs(step.timestamp * 1000).format('HH:mm:ss')}</span>}
                    </div>
                    {step.description && <div style={{ color: '#666', marginTop: 4, fontSize: 13 }}>{step.description}</div>}
                  </Card>
                )
              }))} />
            ) : <Empty description="暂无时间线数据" />}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default AttackTracking;
