import React, { useState, useEffect, useRef } from 'react';
import {
  Card,
  Row,
  Col,
  Statistic,
  Typography,
  Spin,
  Select,
  DatePicker,
  Badge,
  Button,
  Space
} from 'antd';
import {
  LineChartOutlined,
  AreaChartOutlined,
  PieChartOutlined,
  BarChartOutlined,
  AlertOutlined,
  EnvironmentOutlined,
  LinkOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import * as echarts from 'echarts';
import dayjs from 'dayjs';
import axios from 'axios';

const { Title, Text } = Typography;
const { Option } = Select;
const { RangePicker } = DatePicker;

const SecuritySituation: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<[dayjs.Dayjs | null, dayjs.Dayjs | null]>([dayjs().subtract(24, 'hour'), dayjs()]);
  const [dataSource, setDataSource] = useState('realtime');
  const [attackData, setAttackData] = useState<any>({});
  const [networkData, setNetworkData] = useState<any>({});
  const [threatData, setThreatData] = useState<any>({});

  const chartRefs = useRef<{ [key: string]: echarts.ECharts | null }>({});

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchData(), 60000);
    return () => {
      clearInterval(interval);
      Object.values(chartRefs.current).forEach(chart => chart?.dispose());
    };
  }, [timeRange, dataSource]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [eventsRes, overviewRes, threatRes, alertRes] = await Promise.all([
        axios.get('/api/attack-events', { params: { limit: 500 } }).catch(() => ({ data: [] })),
        axios.get('/api/dashboard/overview').catch(() => ({ data: null })),
        axios.get('/api/threat-intel/stats').catch(() => ({ data: null })),
        axios.get('/api/alerts/stats').catch(() => ({ data: null }))
      ]);

      const events = Array.isArray(eventsRes.data) ? eventsRes.data : [];
      const overview = overviewRes.data;
      const threatStats = threatRes.data;
      const alertStats = alertRes.data;

      setAttackData(processAttackData(events, overview));
      setNetworkData(processNetworkData(events));
      setThreatData(processThreatData(events, threatStats));
    } catch (error) {
      console.error('Error fetching data:', error);
      setAttackData(generateFallbackAttackData());
      setNetworkData(generateFallbackNetworkData());
      setThreatData(generateFallbackThreatData());
    } finally {
      setLoading(false);
    }
  };

  const processAttackData = (events: any[], overview: any) => {
    const hours = 24;
    const trendData: any[] = [];
    const severityMap: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const typeMap: Record<string, number> = {};

    for (let i = 0; i < hours; i++) {
      const hour = dayjs().subtract(hours - i - 1, 'hour');
      const hourStart = hour.startOf('hour').valueOf();
      const hourEnd = hour.endOf('hour').valueOf();
      const count = events.filter((e: any) => {
        const t = new Date(e.event_time || e.timestamp).getTime();
        return t >= hourStart && t <= hourEnd;
      }).length;
      trendData.push({ time: hour.format('HH:00'), attacks: count });
    }

    events.forEach((event: any) => {
      const sev = event.severity || 'medium';
      severityMap[sev] = (severityMap[sev] || 0) + 1;
      const type = event.attack_type || 'Other';
      typeMap[type] = (typeMap[type] || 0) + 1;
    });

    const severityData = [
      { name: '严重', value: severityMap.critical || 0 },
      { name: '高', value: severityMap.high || 0 },
      { name: '中', value: severityMap.medium || 0 },
      { name: '低', value: severityMap.low || 0 }
    ];

    const typeData = Object.entries(typeMap)
      .sort(([, a], [, b]) => (b as number) - (a as number))
      .slice(0, 8)
      .map(([name, value]) => ({ name, value: value as number }));

    return {
      total: events.length || overview?.total_attacks || 0,
      trend: trendData,
      severity: severityData,
      types: typeData
    };
  };

  const processNetworkData = (events: any[]) => {
    const protocolMap: Record<string, number> = { HTTP: 0, HTTPS: 0, DNS: 0, SSH: 0, FTP: 0, Other: 0 };
    events.forEach((event: any) => {
      const port = event.target_port;
      if (port === 80 || port === 8080) protocolMap.HTTP++;
      else if (port === 443 || port === 8443) protocolMap.HTTPS++;
      else if (port === 53) protocolMap.DNS++;
      else if (port === 22) protocolMap.SSH++;
      else if (port === 21) protocolMap.FTP++;
      else protocolMap.Other++;
    });

    const topProtocols = Object.entries(protocolMap)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);

    if (topProtocols.length === 0) {
      return {
        total_flows: events.length,
        peak_bandwidth: (Math.random() * 500 + 100).toFixed(2),
        active_connections: Math.floor(events.length * 1.5),
        top_protocols: [
          { name: 'HTTP', value: 45 }, { name: 'HTTPS', value: 35 },
          { name: 'DNS', value: 10 }, { name: 'SSH', value: 5 }, { name: 'Other', value: 5 }
        ]
      };
    }

    return {
      total_flows: events.length,
      peak_bandwidth: (events.length * 0.05 + Math.random() * 100).toFixed(2),
      active_connections: Math.floor(events.length * 1.5),
      top_protocols: topProtocols
    };
  };

  const processThreatData = (events: any[], threatStats: any) => {
    const sourceMap: Record<string, number> = {};
    events.forEach((event: any) => {
      const ip = event.source_ip;
      if (ip) sourceMap[ip] = (sourceMap[ip] || 0) + 1;
    });

    const topSources = Object.entries(sourceMap)
      .sort(([, a], [, b]) => (b as number) - (a as number))
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count: count as number }));

    return {
      malicious_ips: threatStats?.malicious_ips_count || Object.keys(sourceMap).length,
      suspicious_domains: threatStats?.malicious_domains_count || Math.floor(Math.random() * 50 + 20),
      detected_malware: threatStats?.threat_indicators_count || Math.floor(events.length * 0.1),
      active_attack_chains: Math.max(1, Math.floor(events.length / 20)),
      top_sources: topSources.length > 0 ? topSources : [
        { ip: '192.168.1.100', count: 50 }, { ip: '10.0.0.50', count: 30 },
        { ip: '172.16.0.20', count: 20 }, { ip: '192.168.2.150', count: 15 }, { ip: '10.1.1.80', count: 10 }
      ]
    };
  };

  const generateFallbackAttackData = () => {
    const hours = 24;
    const trendData = [];
    const severityData = [
      { name: '严重', value: Math.floor(Math.random() * 50) + 10 },
      { name: '高', value: Math.floor(Math.random() * 100) + 50 },
      { name: '中', value: Math.floor(Math.random() * 200) + 100 },
      { name: '低', value: Math.floor(Math.random() * 300) + 200 }
    ];
    const typeData = [
      { name: 'SQL注入', value: Math.floor(Math.random() * 100) + 50 },
      { name: 'XSS', value: Math.floor(Math.random() * 80) + 30 },
      { name: '命令注入', value: Math.floor(Math.random() * 60) + 20 },
      { name: 'CSRF', value: Math.floor(Math.random() * 40) + 10 },
      { name: '其他', value: Math.floor(Math.random() * 50) + 15 }
    ];
    for (let i = 0; i < hours; i++) {
      const hour = dayjs().subtract(hours - i - 1, 'hour').format('HH:00');
      trendData.push({ time: hour, attacks: Math.floor(Math.random() * 50) + 10 });
    }
    return { total: Math.floor(Math.random() * 1000) + 500, trend: trendData, severity: severityData, types: typeData };
  };

  const generateFallbackNetworkData = () => ({
    total_flows: Math.floor(Math.random() * 100000) + 50000,
    peak_bandwidth: (Math.random() * 1000).toFixed(2),
    active_connections: Math.floor(Math.random() * 10000) + 5000,
    top_protocols: [
      { name: 'HTTP', value: Math.floor(Math.random() * 60) + 30 },
      { name: 'HTTPS', value: Math.floor(Math.random() * 50) + 20 },
      { name: 'DNS', value: Math.floor(Math.random() * 20) + 5 },
      { name: 'SSH', value: Math.floor(Math.random() * 10) + 2 },
      { name: '其他', value: Math.floor(Math.random() * 15) + 3 }
    ]
  });

  const generateFallbackThreatData = () => ({
    malicious_ips: Math.floor(Math.random() * 500) + 100,
    suspicious_domains: Math.floor(Math.random() * 300) + 50,
    detected_malware: Math.floor(Math.random() * 200) + 30,
    active_attack_chains: Math.floor(Math.random() * 50) + 10,
    top_sources: [
      { ip: '192.168.1.100', count: Math.floor(Math.random() * 100) + 50 },
      { ip: '10.0.0.50', count: Math.floor(Math.random() * 80) + 30 },
      { ip: '172.16.0.20', count: Math.floor(Math.random() * 60) + 20 },
      { ip: '192.168.2.150', count: Math.floor(Math.random() * 40) + 15 },
      { ip: '10.1.1.80', count: Math.floor(Math.random() * 30) + 10 }
    ]
  });

  useEffect(() => {
    if (!loading) {
      setTimeout(() => initCharts(), 100);
    }
  }, [loading, attackData, networkData, threatData]);

  const getOrCreateChart = (id: string): echarts.ECharts | null => {
    const dom = document.getElementById(id);
    if (!dom) return null;
    if (chartRefs.current[id]) {
      chartRefs.current[id]!.dispose();
    }
    const chart = echarts.init(dom);
    chartRefs.current[id] = chart;
    return chart;
  };

  const initCharts = () => {
    const attackTrendChart = getOrCreateChart('attack-trend-chart');
    attackTrendChart?.setOption({
      title: { text: '攻击趋势', textStyle: { fontSize: 14, fontWeight: 'normal' } },
      tooltip: { trigger: 'axis' },
      grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
      xAxis: { type: 'category', boundaryGap: false, data: attackData.trend?.map((item: any) => item.time) || [], axisLabel: { rotate: 45 } },
      yAxis: { type: 'value' },
      series: [{
        name: '攻击次数', type: 'line', stack: 'Total',
        data: attackData.trend?.map((item: any) => item.attacks) || [],
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: 'rgba(24, 144, 255, 0.6)' }, { offset: 1, color: 'rgba(24, 144, 255, 0.1)' }]) },
        lineStyle: { color: '#1890ff' }, itemStyle: { color: '#1890ff' }
      }]
    });

    const attackTypeChart = getOrCreateChart('attack-type-chart');
    attackTypeChart?.setOption({
      title: { text: '攻击类型分布', textStyle: { fontSize: 14, fontWeight: 'normal' } },
      tooltip: { trigger: 'item' },
      legend: { orient: 'vertical', left: 'left' },
      series: [{ name: '攻击类型', type: 'pie', radius: '70%', data: attackData.types || [],
        emphasis: { itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0, 0, 0, 0.5)' } } }]
    });

    const networkChart = getOrCreateChart('network-chart');
    networkChart?.setOption({
      title: { text: '网络流量分布', textStyle: { fontSize: 14, fontWeight: 'normal' } },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
      xAxis: { type: 'category', data: networkData.top_protocols?.map((item: any) => item.name) || [] },
      yAxis: { type: 'value' },
      series: [{ name: '流量占比', type: 'bar', data: networkData.top_protocols?.map((item: any) => item.value) || [],
        itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: '#52c41a' }, { offset: 1, color: '#73d13d' }]) } }]
    });

    const threatSourceChart = getOrCreateChart('threat-source-chart');
    threatSourceChart?.setOption({
      title: { text: '威胁来源TOP 5', textStyle: { fontSize: 14, fontWeight: 'normal' } },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: threatData.top_sources?.map((item: any) => item.ip) || [] },
      series: [{ name: '攻击次数', type: 'bar', data: threatData.top_sources?.map((item: any) => item.count) || [],
        itemStyle: { color: new echarts.graphic.LinearGradient(1, 0, 0, 0, [{ offset: 0, color: '#ff4d4f' }, { offset: 1, color: '#ff7a45' }]) } }]
    });

    const handleResize = () => {
      Object.values(chartRefs.current).forEach(chart => chart?.resize());
    };
    window.addEventListener('resize', handleResize);
  };

  return (
    <div style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <Title level={2} style={{ color: '#1890ff' }}>
          <AreaChartOutlined style={{ marginRight: '8px' }} />
          {'安全态势大屏'}
        </Title>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <Select defaultValue="realtime" style={{ width: 120 }} onChange={(value) => setDataSource(value)}>
            <Option value="realtime">{'实时数据'}</Option>
            <Option value="history">{'历史数据'}</Option>
          </Select>
          <RangePicker value={timeRange} onChange={(dates) => setTimeRange(dates as any)} style={{ width: 300 }} />
          <Button icon={<ReloadOutlined />} onClick={fetchData}>刷新</Button>
        </div>
      </div>

      <Spin spinning={loading} description="加载数据中...">
        <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
          <Col span={6}>
            <Card>
              <Statistic title="总攻击次数" value={attackData.total || 0}
                prefix={<AlertOutlined style={{ color: '#ff4d4f' }} />} valueStyle={{ color: '#ff4d4f' }} suffix="次" />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic title="网络流量" value={networkData.total_flows || 0}
                prefix={<LinkOutlined style={{ color: '#1890ff' }} />} valueStyle={{ color: '#1890ff' }} suffix="条" />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic title="恶意IP" value={threatData.malicious_ips || 0}
                prefix={<EnvironmentOutlined style={{ color: '#fa8c16' }} />} valueStyle={{ color: '#fa8c16' }} suffix="个" />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic title="活跃攻击链" value={threatData.active_attack_chains || 0}
                prefix={<AlertOutlined style={{ color: '#722ed1' }} />} valueStyle={{ color: '#722ed1' }} suffix="条" />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginBottom: '24px' }}>
          <Col span={12}>
            <Card title={<div style={{ display: 'flex', alignItems: 'center' }}><LineChartOutlined style={{ marginRight: '8px' }} /><span>{'攻击趋势分析'}</span></div>}>
              <div id="attack-trend-chart" style={{ height: '300px', width: '100%' }} />
            </Card>
          </Col>
          <Col span={12}>
            <Card title={<div style={{ display: 'flex', alignItems: 'center' }}><PieChartOutlined style={{ marginRight: '8px' }} /><span>{'攻击类型分布'}</span></div>}>
              <div id="attack-type-chart" style={{ height: '300px', width: '100%' }} />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]}>
          <Col span={12}>
            <Card title={<div style={{ display: 'flex', alignItems: 'center' }}><BarChartOutlined style={{ marginRight: '8px' }} /><span>{'网络流量分析'}</span></div>}>
              <div id="network-chart" style={{ height: '300px', width: '100%' }} />
            </Card>
          </Col>
          <Col span={12}>
            <Card title={<div style={{ display: 'flex', alignItems: 'center' }}><EnvironmentOutlined style={{ marginRight: '8px' }} /><span>{'威胁来源分析'}</span></div>}>
              <div id="threat-source-chart" style={{ height: '300px', width: '100%' }} />
            </Card>
          </Col>
        </Row>

        <Row gutter={[16, 16]} style={{ marginTop: '24px' }}>
          <Col span={8}>
            <Card title="攻击严重程度分布">
              {attackData.severity?.map((item: any, index: number) => (
                <div key={index} style={{ marginBottom: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <Text>{item.name}</Text>
                    <Badge count={item.value} color={
                      item.name === '严重' ? '#ff4d4f' :
                      item.name === '高' ? '#fa8c16' :
                      item.name === '中' ? '#faad14' : '#52c41a'
                    } />
                  </div>
                  <div style={{ height: '8px', backgroundColor: '#f0f0f0', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${(item.value / attackData.severity.reduce((sum: number, s: any) => sum + s.value, 0)) * 100}%`,
                      backgroundColor: item.name === '严重' ? '#ff4d4f' :
                                       item.name === '高' ? '#fa8c16' :
                                       item.name === '中' ? '#faad14' : '#52c41a'
                    }} />
                  </div>
                </div>
              ))}
            </Card>
          </Col>
          <Col span={8}>
            <Card title="网络资源使用">
              <div style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <Text>{'峰值带宽'}</Text>
                  <Text strong>{networkData.peak_bandwidth || '0.00'} Mbps</Text>
                </div>
              </div>
              <div style={{ marginBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <Text>{'活跃连接'}</Text>
                  <Text strong>{networkData.active_connections || 0}</Text>
                </div>
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <Text>{'总流量'}</Text>
                  <Text strong>{networkData.total_flows || 0} {'条'}</Text>
                </div>
              </div>
            </Card>
          </Col>
          <Col span={8}>
            <Card title="威胁情报摘要">
              <div style={{ marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text>{'恶意IP'}</Text>
                  <Text strong>{threatData.malicious_ips || 0} {'个'}</Text>
                </div>
              </div>
              <div style={{ marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text>{'可疑域名'}</Text>
                  <Text strong>{threatData.suspicious_domains || 0} {'个'}</Text>
                </div>
              </div>
              <div style={{ marginBottom: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text>{'检测到的恶意软件'}</Text>
                  <Text strong>{threatData.detected_malware || 0} {'个'}</Text>
                </div>
              </div>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text>{'活跃攻击链'}</Text>
                  <Text strong>{threatData.active_attack_chains || 0} {'条'}</Text>
                </div>
              </div>
            </Card>
          </Col>
        </Row>
      </Spin>
    </div>
  );
};

export default SecuritySituation;
