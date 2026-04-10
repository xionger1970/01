import React, { useState, useEffect } from 'react';
import { Card, Spin, Statistic, Row, Col, Tabs, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'antd';
import { MonitorOutlined, CpuOutlined, DatabaseOutlined, WifiOutlined, ApiOutlined } from '@ant-design/icons';

const { TabPane } = Tabs;

const PerformanceMonitor: React.FC = () => {
  const [summary, setSummary] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('summary');

  useEffect(() => {
    // 启动性能监控
    fetch('http://localhost:8000/api/performance/start-monitoring', {
      method: 'POST'
    });

    // 定期获取性能数据
    const interval = setInterval(() => {
      fetchSummary();
      fetchMetrics();
    }, 5000);

    // 初始加载
    fetchSummary();
    fetchMetrics();

    return () => {
      clearInterval(interval);
      // 停止性能监控
      fetch('http://localhost:8000/api/performance/stop-monitoring', {
        method: 'POST'
      });
    };
  }, []);

  const fetchSummary = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/performance/summary');
      const data = await response.json();
      setSummary(data);
    } catch (error) {
      console.error('获取性能摘要失败:', error);
    }
  };

  const fetchMetrics = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/performance/metrics?limit=60');
      const data = await response.json();
      setMetrics(data);
    } catch (error) {
      console.error('获取性能指标失败:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold mb-6 text-gray-900">性能监控</h1>

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <Spin size="large" />
          </div>
        ) : (
          <>
            {/* 性能摘要 */}
            <div className="mb-6">
              <Row gutter={[16, 16]}>
                <Col xs={24} sm={12} md={8} lg={6}>
                  <Card>
                    <Statistic 
                      title="CPU使用率" 
                      value={summary?.cpu?.average_percent?.toFixed(2) || 0} 
                      suffix="%"
                      prefix={<CpuOutlined />}
                      valueStyle={{ color: summary?.cpu?.average_percent > 80 ? '#f5222d' : '#52c41a' }}
                    />
                    <div className="text-xs text-gray-500 mt-2">
                      核心数: {summary?.cpu?.count || 0}
                    </div>
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={6}>
                  <Card>
                    <Statistic 
                      title="内存使用率" 
                      value={summary?.memory?.average_percent?.toFixed(2) || 0} 
                      suffix="%"
                      prefix={<DatabaseOutlined />}
                      valueStyle={{ color: summary?.memory?.average_percent > 80 ? '#f5222d' : '#52c41a' }}
                    />
                    <div className="text-xs text-gray-500 mt-2">
                      总内存: {(summary?.memory?.total_gb || 0).toFixed(2)} GB
                    </div>
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={6}>
                  <Card>
                    <Statistic 
                      title="磁盘使用率" 
                      value={summary?.disk?.average_percent?.toFixed(2) || 0} 
                      suffix="%"
                      prefix={<DatabaseOutlined />}
                      valueStyle={{ color: summary?.disk?.average_percent > 80 ? '#f5222d' : '#52c41a' }}
                    />
                    <div className="text-xs text-gray-500 mt-2">
                      总磁盘: {(summary?.disk?.total_gb || 0).toFixed(2)} GB
                    </div>
                  </Card>
                </Col>
                <Col xs={24} sm={12} md={8} lg={6}>
                  <Card>
                    <Statistic 
                      title="API响应时间" 
                      value={summary?.api?.average_response_time_ms?.toFixed(2) || 0} 
                      suffix="ms"
                      prefix={<ApiOutlined />}
                      valueStyle={{ color: summary?.api?.average_response_time_ms > 1000 ? '#f5222d' : '#52c41a' }}
                    />
                    <div className="text-xs text-gray-500 mt-2">
                      请求数: {summary?.api?.request_count || 0}
                    </div>
                  </Card>
                </Col>
              </Row>
            </div>

            {/* 详细指标 */}
            <Card className="mb-6">
              <Tabs activeKey={activeTab} onChange={setActiveTab}>
                <TabPane tab="CPU" key="cpu">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics.cpu || []}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTime} />
                        <YAxis domain={[0, 100]} />
                        <Tooltip formatter={(value) => [`${value}%`, 'CPU使用率']} />
                        <Line type="monotone" dataKey="percent" stroke="#8884d8" activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </TabPane>
                <TabPane tab="内存" key="memory">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics.memory || []}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTime} />
                        <YAxis domain={[0, 100]} />
                        <Tooltip formatter={(value) => [`${value}%`, '内存使用率']} />
                        <Line type="monotone" dataKey="percent" stroke="#82ca9d" activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </TabPane>
                <TabPane tab="磁盘" key="disk">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics.disk || []}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTime} />
                        <YAxis domain={[0, 100]} />
                        <Tooltip formatter={(value) => [`${value}%`, '磁盘使用率']} />
                        <Line type="monotone" dataKey="percent" stroke="#ffc658" activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </TabPane>
                <TabPane tab="网络" key="network">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics.network || []}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTime} />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="sent" stroke="#8884d8" name="发送 (MB)" />
                        <Line type="monotone" dataKey="recv" stroke="#82ca9d" name="接收 (MB)" />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </TabPane>
                <TabPane tab="API响应" key="response">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics.response_times || []}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTime} />
                        <YAxis />
                        <Tooltip formatter={(value) => [`${(value * 1000).toFixed(2)} ms`, '响应时间']} />
                        <Line type="monotone" dataKey="response_time" stroke="#ff7300" activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </TabPane>
              </Tabs>
            </Card>

            {/* API请求统计 */}
            {metrics.request_counts && metrics.request_counts.length > 0 && (
              <Card className="mb-6">
                <h3 className="text-lg font-medium mb-4">API请求统计</h3>
                <div className="space-y-4">
                  {metrics.request_counts.slice(-20).reverse().map((req: any, index: number) => (
                    <div key={index} className="flex justify-between items-center p-2 border rounded">
                      <div>
                        <div className="font-medium">{req.method} {req.endpoint}</div>
                        <div className="text-xs text-gray-500">{formatTime(req.timestamp)}</div>
                      </div>
                      <span 
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          req.status_code >= 400 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                        }`}
                      >
                        {req.status_code}
                      </span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default PerformanceMonitor;