import React, { useState, useEffect } from 'react';
import { Card, Tabs, Button, Input, Select, Table, Tag, Statistic, Row, Col, Form, message, Space, Progress, Modal, Divider, Typography, Spin, Descriptions } from 'antd';
import { RobotOutlined, ThunderboltOutlined, HistoryOutlined, DeleteOutlined, ReloadOutlined, BulbOutlined, BarChartOutlined, FileTextOutlined, CopyOutlined, DownloadOutlined, AlertOutlined, LockOutlined, TrademarkOutlined, EyeOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { TextArea } = Input;

const threatTypeLabels: Record<string, string> = {
  web_attack: 'Web攻击', apt: 'APT攻击', ransomware: '勒索软件',
  phishing: '钓鱼攻击', ddos: 'DDoS攻击', anomaly: '异常行为',
  code_execution: '代码执行', insider_threat: '内部威胁'
};
const severityColors: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff' };
const severityLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };

const AIAnalysis: React.FC = () => {
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [models, setModels] = useState<any[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [formData, setFormData] = useState({ event_type: 'attack_event', event_data: '', model: 'default' });
  const [reportModalVisible, setReportModalVisible] = useState(false);
  const [reportContent, setReportContent] = useState('');

  const fetchHistory = async (showLoading = false) => {
    if (showLoading) setInitialLoading(true);
    try { const response = await axios.get('/api/ai-analysis/history'); setHistory(Array.isArray(response.data) ? response.data : []); }
    catch (error) { setHistory([]); } finally { if (showLoading) setInitialLoading(false); }
  };

  const fetchModels = async () => {
    try { const response = await axios.get('/api/ai-analysis/models'); setModels(Array.isArray(response.data) ? response.data : []); }
    catch (error) { setModels([]); }
  };

  useEffect(() => { const init = async () => { await Promise.all([fetchHistory(true), fetchModels()]); }; init(); }, []);

  const handleAnalyze = async () => {
    if (!formData.event_data.trim()) { message.warning('请输入事件数据'); return; }
    setAnalyzing(true);
    try { const response = await axios.post('/api/ai-analysis/analyze', { event_type: formData.event_type, event_data: formData.event_data, model: formData.model }); setAnalysisResult(response.data); message.success('分析完成'); fetchHistory(); }
    catch (error) { message.error('分析失败'); } finally { setAnalyzing(false); }
  };

  const handleDeleteHistory = async (id: number) => { try { await axios.delete(`/api/ai-analysis/history/${id}`); message.success('删除成功'); fetchHistory(); } catch (error) { message.error('删除失败'); } };

  const handleGenerateReport = () => {
    if (!analysisResult) { message.warning('请先完成一次分析'); return; }
    const report = generateReport(analysisResult);
    setReportContent(report); setReportModalVisible(true);
  };

  const generateReport = (result: any) => {
    const now = dayjs().format('YYYY-MM-DD HH:mm:ss');
    let report = `=== AI智能分析报告 ===\n生成时间: ${now}\n分析模型: ${formData.model}\n\n`;
    if (result.result) {
      report += `--- 分析结果 ---\n威胁类型: ${threatTypeLabels[result.result.threat_type as string] || result.result.threat_type || '未知'}\n严重程度: ${severityLabels[result.result.severity] || result.result.severity || '未知'}\n置信度: ${Math.round((result.result.confidence || 0) * 100)}%\n`;
      if (result.result.description) report += `\n描述:\n${result.result.description}\n`;
      if (result.result.recommendations?.length > 0) { report += `\n--- 处置建议 ---\n`; result.result.recommendations.forEach((rec: string, i: number) => { report += `${i + 1}. ${rec}\n`; }); }
      if (result.result.indicators?.length > 0) { report += `\n--- 检测指标 ---\n`; result.result.indicators.forEach((ind: string) => { report += `- ${ind}\n`; }); }
    }
    report += `\n=== 报告结束 ===\n`;
    return report;
  };

  const historyColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '威胁类型', key: 'threat_type', width: 120, render: (_: any, record: any) => <Tag color={record.result?.threat_type === 'apt' ? 'red' : 'blue'}>{threatTypeLabels[record.result?.threat_type] || '-'}</Tag> },
    { title: '置信度', key: 'confidence', width: 100, render: (_: any, record: any) => <Progress percent={Math.round((record.result?.confidence || 0) * 100)} size="small" /> },
    { title: '分析时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss') },
    { title: '操作', key: 'action', width: 120, render: (_: any, record: any) => (<Space size={4}><Button type="link" size="small" onClick={() => setAnalysisResult(record)}>查看</Button><Button type="link" danger size="small" icon={<DeleteOutlined />} onClick={() => handleDeleteHistory(record.id)}>删除</Button></Space>) }
  ];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5', minHeight: '100vh' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: 24, fontWeight: 700, background: 'linear-gradient(135deg, #722ed1, #b37feb)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          <RobotOutlined style={{ marginRight: 8, WebkitTextFillColor: '#722ed1' }} />AI智能分析
        </h2>
        <Space>
          <Button icon={<FileTextOutlined />} onClick={handleGenerateReport}>生成报告</Button>
          <Button icon={<ReloadOutlined />} onClick={() => { fetchHistory(); fetchModels(); }}>刷新</Button>
        </Space>
      </div>

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>分析模型</span>} value={models.length} prefix={<RobotOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={8}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #1890ff, #69c0ff)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>分析次数</span>} value={history.length} prefix={<BarChartOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
        <Col span={8}><Card variant="borderless" style={{ background: 'linear-gradient(135deg, #52c41a, #95de64)', borderRadius: 12 }}><Statistic title={<span style={{ color: 'rgba(255,255,255,0.85)' }}>平均置信度</span>} value={history.length > 0 ? Math.round(history.reduce((acc: number, h: any) => acc + (h.result?.confidence || 0), 0) / history.length * 100) : 0} suffix="%" prefix={<BulbOutlined />} valueStyle={{ color: '#fff', fontWeight: 700 }} /></Card></Col>
      </Row>

      <Card variant="borderless" style={{ borderRadius: 12 }}>
        <Tabs defaultActiveKey="analyze" items={[
          { key: 'analyze', label: <span><ThunderboltOutlined /> 智能分析</span>, children: (
            <Row gutter={24}>
              <Col span={12}>
                <Card title="输入事件数据" variant="borderless" style={{ borderRadius: 8 }}>
                  <Form layout="vertical">
                    <Form.Item label="事件类型"><Select value={formData.event_type} onChange={(value) => setFormData(prev => ({ ...prev, event_type: value }))}><Option value="attack_event">攻击事件</Option><Option value="anomaly">异常事件</Option><Option value="alert">告警事件</Option></Select></Form.Item>
                    <Form.Item label="事件数据"><TextArea rows={8} value={formData.event_data} onChange={(e) => setFormData(prev => ({ ...prev, event_data: e.target.value }))} placeholder="请输入事件数据（JSON格式）" /></Form.Item>
                    <Form.Item label="分析模型"><Select value={formData.model} onChange={(value) => setFormData(prev => ({ ...prev, model: value }))}><Option value="default">默认模型</Option>{models.map((model: any) => (<Option key={model.id} value={model.id}>{model.name}</Option>))}</Select></Form.Item>
                    <Form.Item><Button type="primary" icon={<ThunderboltOutlined />} loading={analyzing} onClick={handleAnalyze} style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', border: 'none' }}>开始分析</Button></Form.Item>
                  </Form>
                </Card>
              </Col>
              <Col span={12}>
                <Card title="分析结果" variant="borderless" style={{ borderRadius: 8 }} extra={analysisResult && <Button size="small" icon={<FileTextOutlined />} onClick={handleGenerateReport}>报告</Button>}>
                  {analysisResult ? (
                    <div>
                      {analysisResult.result && (<>
                        <div style={{ marginBottom: 16 }}><Tag color={severityColors[analysisResult.result.severity || 'medium']}>{severityLabels[analysisResult.result.severity || 'medium']}</Tag><Tag color={analysisResult.result.threat_type === 'apt' ? 'red' : 'blue'}>{threatTypeLabels[analysisResult.result.threat_type as string] || analysisResult.result.threat_type}</Tag><Progress percent={Math.round((analysisResult.result.confidence || 0) * 100)} style={{ width: 150, marginLeft: 16 }} size="small" /></div>
                        
                        {/* 威胁评分 */}
                        {analysisResult.threat_score !== undefined && (
                          <div style={{ marginBottom: 16 }}>
                            <strong>威胁评分:</strong>
                            <Progress percent={Math.round(analysisResult.threat_score * 100)} 
                              status={analysisResult.threat_score > 0.8 ? 'exception' : analysisResult.threat_score > 0.5 ? 'warning' : 'normal'}
                              style={{ marginTop: 4 }}
                            />
                          </div>
                        )}
                        
                        {analysisResult.result.description && <div style={{ marginBottom: 12 }}><strong>描述:</strong><p style={{ marginTop: 4 }}>{analysisResult.result.description}</p></div>}
                        
                        {/* 攻击模式 */}
                        {analysisResult.result.attack_patterns && analysisResult.result.attack_patterns.length > 0 && (
                          <div style={{ marginBottom: 12 }}>
                            <strong>攻击模式:</strong>
                            <div style={{ marginTop: 4 }}>
                              {analysisResult.result.attack_patterns.map((pattern: string, i: number) => (
                                <Tag key={i} color="purple" style={{ marginBottom: 4 }}>
                                  {pattern === 'lateral_movement' ? '横向移动' : 
                                   pattern === 'privilege_escalation' ? '权限提升' : 
                                   pattern === 'data_exfiltration' ? '数据泄露' : pattern}
                                </Tag>
                              ))}
                            </div>
                          </div>
                        )}
                        
                        {/* 预测性分析 */}
                        {analysisResult.result.predictive_analysis && (
                          <div style={{ marginBottom: 12 }}>
                            <strong>预测分析:</strong>
                            <Descriptions size="small" style={{ marginTop: 4 }} column={2}>
                              <Descriptions.Item label="可能结果">{analysisResult.result.predictive_analysis.outcome}</Descriptions.Item>
                              <Descriptions.Item label="影响程度">{analysisResult.result.predictive_analysis.impact}</Descriptions.Item>
                              <Descriptions.Item label="可能性">{Math.round(analysisResult.result.predictive_analysis.probability * 100)}%</Descriptions.Item>
                              <Descriptions.Item label="建议处理时间">{analysisResult.result.predictive_analysis.mitigation_time}</Descriptions.Item>
                            </Descriptions>
                          </div>
                        )}
                        
                        {analysisResult.result.recommendations?.length > 0 && <div style={{ marginBottom: 12 }}><strong>建议:</strong><ul style={{ marginTop: 4, paddingLeft: 20 }}>{analysisResult.result.recommendations.map((rec: string, i: number) => <li key={i}>{rec}</li>)}</ul></div>}
                        {analysisResult.result.indicators?.length > 0 && <div><strong>检测指标:</strong><div style={{ marginTop: 4 }}>{analysisResult.result.indicators.map((ind: string, i: number) => <Tag key={i} color="orange" style={{ marginBottom: 4 }}>{ind}</Tag>)}</div></div>}
                      </>)}
                    </div>
                  ) : (<div style={{ textAlign: 'center', padding: '60px 0', color: '#999' }}><RobotOutlined style={{ fontSize: 48, marginBottom: 16 }} /><p>输入事件数据并点击分析按钮开始分析</p></div>)}
                </Card>
              </Col>
            </Row>
          )},
          { key: 'history', label: <span><HistoryOutlined /> 分析历史</span>, children: (
            <Table columns={historyColumns} dataSource={history.map((h, i) => ({ ...h, key: h.id || i }))} loading={initialLoading} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
          )},
        ]} />
      </Card>

      <Modal title="分析报告" open={reportModalVisible} onCancel={() => setReportModalVisible(false)} footer={[
        <Button key="copy" icon={<CopyOutlined />} onClick={() => { navigator.clipboard.writeText(reportContent).then(() => message.success('已复制')); }}>复制</Button>,
        <Button key="download" icon={<DownloadOutlined />} onClick={() => { const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `ai_report_${dayjs().format('YYYYMMDD_HHmmss')}.txt`; a.click(); URL.revokeObjectURL(url); message.success('导出成功'); }}>导出</Button>,
        <Button key="close" onClick={() => setReportModalVisible(false)}>关闭</Button>
      ]} width={700}>
        <pre style={{ backgroundColor: '#f5f5f5', padding: 16, borderRadius: 8, overflowX: 'auto', fontSize: 13, lineHeight: 1.6, maxHeight: 500, whiteSpace: 'pre-wrap' }}>{reportContent}</pre>
      </Modal>
    </div>
  );
};

export default AIAnalysis;
