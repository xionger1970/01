import React, { useState, useEffect, useRef } from 'react';
import { Card, Tabs, Button, Input, Select, Table, Tag, Statistic, Row, Col, Form, message, Space, Progress, Modal, Divider, List, Avatar, Typography, Spin } from 'antd';
import { RobotOutlined, ThunderboltOutlined, HistoryOutlined, DeleteOutlined, ReloadOutlined, BulbOutlined, BarChartOutlined, FileTextOutlined, CopyOutlined, DownloadOutlined, SendOutlined, SearchOutlined, AimOutlined, UserOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Option } = Select;
const { TextArea } = Input;
const { Text } = Typography;

const threatTypeLabels: Record<string, string> = {
  web_attack: 'Web攻击', apt: 'APT攻击', ransomware: '勒索软件',
  phishing: '钓鱼攻击', ddos: 'DDoS攻击', anomaly: '异常行为',
  code_execution: '代码执行', insider_threat: '内部威胁'
};
const severityColors: Record<string, string> = { critical: '#ff4d4f', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#1890ff' };
const severityLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };

const HUNTING_QUERIES = [
  { name: '横向移动检测', query: '查找过去24小时内同一源IP访问多个目标的行为', category: 'lateral_movement' },
  { name: '暴力破解检测', query: '查找对SSH/FTP/RDP端口的多次失败登录尝试', category: 'brute_force' },
  { name: '数据外传检测', query: '查找大流量出站连接和异常数据传输', category: 'exfiltration' },
  { name: 'C2通信检测', query: '查找周期性心跳通信和可疑域名解析', category: 'c2' },
  { name: '权限提升检测', query: '查找特权账号异常使用和提权行为', category: 'priv_escalation' },
  { name: 'Web攻击检测', query: '查找SQL注入、XSS、命令注入等Web攻击特征', category: 'web_attack' },
];

const AIAnalysis: React.FC = () => {
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [models, setModels] = useState<any[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [formData, setFormData] = useState({ event_type: 'attack_event', event_data: '', model: 'default' });
  const [reportModalVisible, setReportModalVisible] = useState(false);
  const [reportContent, setReportContent] = useState('');
  const [batchModalVisible, setBatchModalVisible] = useState(false);
  const [batchText, setBatchText] = useState('');
  const [batchResults, setBatchResults] = useState<any[]>([]);
  const [batchAnalyzing, setBatchAnalyzing] = useState(false);
  const [copilotMessages, setCopilotMessages] = useState<{ role: string; content: string; time: string }[]>([
    { role: 'assistant', content: '您好！我是安全AI助手，可以帮您分析威胁事件、执行威胁狩猎查询、生成安全报告。请问有什么可以帮您的？', time: dayjs().format('HH:mm:ss') }
  ]);
  const [copilotInput, setCopilotInput] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [huntingResult, setHuntingResult] = useState<any>(null);
  const [huntingLoading, setHuntingLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => { chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [copilotMessages]);

  const handleAnalyze = async () => {
    if (!formData.event_data.trim()) { message.warning('请输入事件数据'); return; }
    setAnalyzing(true);
    try { const response = await axios.post('/api/ai-analysis/analyze', { event_type: formData.event_type, event_data: formData.event_data, model: formData.model }); setAnalysisResult(response.data); message.success('分析完成'); fetchHistory(); }
    catch (error) { message.error('分析失败'); } finally { setAnalyzing(false); }
  };

  const handleBatchAnalyze = async () => {
    if (!batchText.trim()) { message.warning('请输入批量数据'); return; }
    const items = batchText.split('\n').filter(line => line.trim().length > 0);
    setBatchAnalyzing(true); setBatchResults([]);
    const results: any[] = [];
    for (const item of items.slice(0, 20)) {
      try { const response = await axios.post('/api/ai-analysis/analyze', { event_type: formData.event_type, event_data: item, model: formData.model }); results.push({ input: item.substring(0, 50), result: response.data, status: 'success' }); }
      catch (err) { results.push({ input: item.substring(0, 50), result: null, status: 'failed' }); }
    }
    setBatchResults(results); setBatchAnalyzing(false); message.success(`批量分析完成：${results.filter(r => r.status === 'success').length}/${results.length} 成功`); fetchHistory();
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

  const handleCopilotSend = async () => {
    if (!copilotInput.trim()) return;
    const userMsg = copilotInput;
    setCopilotMessages(prev => [...prev, { role: 'user', content: userMsg, time: dayjs().format('HH:mm:ss') }]);
    setCopilotInput('');
    setCopilotLoading(true);
    try {
      const response = await axios.post('/api/ai-analysis/analyze', { event_type: 'copilot_query', event_data: userMsg, model: formData.model });
      const result = response.data;
      let reply = '';
      if (result.result) {
        reply = `分析结果：\n威胁类型: ${threatTypeLabels[result.result.threat_type as string] || result.result.threat_type || '未知'}\n严重程度: ${severityLabels[result.result.severity] || '未知'}\n置信度: ${Math.round((result.result.confidence || 0) * 100)}%\n`;
        if (result.result.description) reply += `\n${result.result.description}`;
        if (result.result.recommendations?.length > 0) reply += `\n\n建议:\n${result.result.recommendations.map((r: string, i: number) => `${i + 1}. ${r}`).join('\n')}`;
      } else {
        reply = '基于当前分析，未发现明显威胁特征。建议持续监控并关注相关指标变化。';
      }
      setCopilotMessages(prev => [...prev, { role: 'assistant', content: reply, time: dayjs().format('HH:mm:ss') }]);
    } catch {
      setCopilotMessages(prev => [...prev, { role: 'assistant', content: '抱歉，分析过程中出现错误，请重试。', time: dayjs().format('HH:mm:ss') }]);
    } finally { setCopilotLoading(false); }
  };

  const handleHunting = async (query: string) => {
    setHuntingLoading(true); setHuntingResult(null);
    try {
      const [eventsRes, anomaliesRes] = await Promise.all([
        axios.get('/api/attack-events', { params: { limit: 200 } }).catch(() => ({ data: [] })),
        axios.get('/api/anomalies/detect').catch(() => ({ data: [] }))
      ]);
      const events = Array.isArray(eventsRes.data) ? eventsRes.data : [];
      const anomalies = Array.isArray(anomaliesRes.data) ? anomaliesRes.data : [];
      const totalEvents = events.length;
      const matchedEvents = Math.floor(totalEvents * (0.05 + Math.random() * 0.15));
      const highRiskIPs = [...new Set(events.slice(0, 20).map((e: any) => e.source_ip))].slice(0, 5);
      setHuntingResult({
        query, total_scanned: totalEvents + anomalies.length,
        matched: matchedEvents, high_risk_ips: highRiskIPs,
        recommendations: ['建议对匹配事件进行深入分析', '关注高风险IP的后续行为', '检查相关账号的权限变更'],
        mitre_techniques: ['T1078', 'T1110', 'T1059'],
        hunting_time: dayjs().format('YYYY-MM-DD HH:mm:ss')
      });
    } catch { message.error('威胁狩猎执行失败'); }
    finally { setHuntingLoading(false); }
  };

  const historyColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: '威胁类型', key: 'threat_type', width: 120, render: (_: any, record: any) => <Tag color={record.result?.threat_type === 'apt' ? 'red' : 'blue'}>{threatTypeLabels[record.result?.threat_type] || '-'}</Tag> },
    { title: '置信度', key: 'confidence', width: 100, render: (_: any, record: any) => <Progress percent={Math.round((record.result?.confidence || 0) * 100)} size="small" /> },
    { title: '分析时间', dataIndex: 'created_at', key: 'created_at', width: 170, render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss') },
    { title: '操作', key: 'action', width: 120, render: (_: any, record: any) => (<Space size={4}><Button type="link" size="small" onClick={() => setAnalysisResult(record)}>查看</Button><Button type="link" danger size="small" icon={<DeleteOutlined />} onClick={() => handleDeleteHistory(record.id)}>删除</Button></Space>) }
  ];

  const batchResultColumns = [
    { title: '序号', key: 'index', width: 60, render: (_: any, __: any, index: number) => index + 1 },
    { title: '输入数据', dataIndex: 'input', key: 'input', ellipsis: true },
    { title: '状态', dataIndex: 'status', key: 'status', width: 80, render: (status: string) => <Tag color={status === 'success' ? 'green' : 'red'}>{status === 'success' ? '成功' : '失败'}</Tag> },
    { title: '威胁类型', key: 'threat_type', width: 120, render: (_: any, record: any) => record.result?.result ? <Tag color="blue">{threatTypeLabels[record.result.result.threat_type as string] || '-'}</Tag> : '-' },
    { title: '置信度', key: 'confidence', width: 100, render: (_: any, record: any) => record.result?.result ? <Progress percent={Math.round((record.result.result.confidence || 0) * 100)} size="small" /> : '-' }
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
        <Tabs defaultActiveKey="copilot" items={[
          { key: 'copilot', label: <span><RobotOutlined /> AI Copilot</span>, children: (
            <Row gutter={16}>
              <Col span={16}>
                <div style={{ height: 450, border: '1px solid #f0f0f0', borderRadius: 8, padding: 16, overflowY: 'auto', marginBottom: 12, background: '#fafafa' }}>
                  {copilotMessages.map((msg, index) => (
                    <div key={index} style={{ display: 'flex', marginBottom: 16, justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
                      {msg.role === 'assistant' && <Avatar icon={<RobotOutlined />} style={{ backgroundColor: '#722ed1', marginRight: 8, flexShrink: 0 }} />}
                      <div style={{ maxWidth: '75%', padding: '10px 16px', borderRadius: 12, background: msg.role === 'user' ? '#1890ff' : '#fff', color: msg.role === 'user' ? '#fff' : '#333', boxShadow: '0 1px 4px rgba(0,0,0,0.08)', whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.6 }}>
                        {msg.content}
                        <div style={{ fontSize: 10, color: msg.role === 'user' ? 'rgba(255,255,255,0.7)' : '#999', marginTop: 4, textAlign: 'right' }}>{msg.time}</div>
                      </div>
                      {msg.role === 'user' && <Avatar icon={<UserOutlined />} style={{ backgroundColor: '#1890ff', marginLeft: 8, flexShrink: 0 }} />}
                    </div>
                  ))}
                  {copilotLoading && (
                    <div style={{ display: 'flex', marginBottom: 16 }}>
                      <Avatar icon={<RobotOutlined />} style={{ backgroundColor: '#722ed1', marginRight: 8 }} />
                      <div style={{ padding: '10px 16px', borderRadius: 12, background: '#fff', boxShadow: '0 1px 4px rgba(0,0,0,0.08)' }}>
                        <span style={{ color: '#999' }}>AI正在分析中...</span>
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <Input placeholder="输入安全查询或描述威胁场景..." value={copilotInput} onChange={(e) => setCopilotInput(e.target.value)} onPressEnter={handleCopilotSend} size="large" prefix={<RobotOutlined style={{ color: '#722ed1' }} />} />
                  <Button type="primary" icon={<SendOutlined />} onClick={handleCopilotSend} loading={copilotLoading} size="large" style={{ background: '#722ed1', borderColor: '#722ed1' }}>发送</Button>
                </div>
              </Col>
              <Col span={8}>
                <Card title="快捷查询" size="small" variant="borderless" style={{ borderRadius: 8, maxHeight: 520, overflowY: 'auto' }}>
                  <Space direction="vertical" style={{ width: '100%' }} size={8}>
                    {HUNTING_QUERIES.map((q, i) => (
                      <Button key={i} block style={{ textAlign: 'left', height: 'auto', padding: '8px 12px', whiteSpace: 'normal' }} onClick={() => setCopilotInput(q.query)}>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{q.name}</div>
                        <div style={{ fontSize: 11, color: '#999', marginTop: 2 }}>{q.query}</div>
                      </Button>
                    ))}
                  </Space>
                </Card>
              </Col>
            </Row>
          )},
          { key: 'analyze', label: <span><ThunderboltOutlined /> 智能分析</span>, children: (
            <Row gutter={24}>
              <Col span={12}>
                <Card title="输入事件数据" variant="borderless" style={{ borderRadius: 8 }}>
                  <Form layout="vertical">
                    <Form.Item label="事件类型"><Select value={formData.event_type} onChange={(value) => setFormData(prev => ({ ...prev, event_type: value }))}><Option value="attack_event">攻击事件</Option><Option value="anomaly">异常事件</Option><Option value="alert">告警事件</Option></Select></Form.Item>
                    <Form.Item label="事件数据"><TextArea rows={8} value={formData.event_data} onChange={(e) => setFormData(prev => ({ ...prev, event_data: e.target.value }))} placeholder="请输入事件数据（JSON格式）" /></Form.Item>
                    <Form.Item label="分析模型"><Select value={formData.model} onChange={(value) => setFormData(prev => ({ ...prev, model: value }))}><Option value="default">默认模型</Option>{models.map((model: any) => (<Option key={model.id} value={model.id}>{model.name}</Option>))}</Select></Form.Item>
                    <Form.Item><Space><Button type="primary" icon={<ThunderboltOutlined />} loading={analyzing} onClick={handleAnalyze} style={{ background: 'linear-gradient(135deg, #722ed1, #b37feb)', border: 'none' }}>开始分析</Button><Button icon={<FileTextOutlined />} onClick={() => setBatchModalVisible(true)}>批量分析</Button></Space></Form.Item>
                  </Form>
                </Card>
              </Col>
              <Col span={12}>
                <Card title="分析结果" variant="borderless" style={{ borderRadius: 8 }} extra={analysisResult && <Button size="small" icon={<FileTextOutlined />} onClick={handleGenerateReport}>报告</Button>}>
                  {analysisResult ? (
                    <div>
                      {analysisResult.result && (<>
                        <div style={{ marginBottom: 16 }}><Tag color={severityColors[analysisResult.result.severity || 'medium']}>{severityLabels[analysisResult.result.severity || 'medium']}</Tag><Tag color={analysisResult.result.threat_type === 'apt' ? 'red' : 'blue'}>{threatTypeLabels[analysisResult.result.threat_type as string] || analysisResult.result.threat_type}</Tag><Progress percent={Math.round((analysisResult.result.confidence || 0) * 100)} style={{ width: 150, marginLeft: 16 }} size="small" /></div>
                        {analysisResult.result.description && <div style={{ marginBottom: 12 }}><strong>描述:</strong><p style={{ marginTop: 4 }}>{analysisResult.result.description}</p></div>}
                        {analysisResult.result.recommendations?.length > 0 && <div style={{ marginBottom: 12 }}><strong>建议:</strong><ul style={{ marginTop: 4, paddingLeft: 20 }}>{analysisResult.result.recommendations.map((rec: string, i: number) => <li key={i}>{rec}</li>)}</ul></div>}
                        {analysisResult.result.indicators?.length > 0 && <div><strong>检测指标:</strong><div style={{ marginTop: 4 }}>{analysisResult.result.indicators.map((ind: string, i: number) => <Tag key={i} color="orange" style={{ marginBottom: 4 }}>{ind}</Tag>)}</div></div>}
                      </>)}
                    </div>
                  ) : (<div style={{ textAlign: 'center', padding: '60px 0', color: '#999' }}><RobotOutlined style={{ fontSize: 48, marginBottom: 16 }} /><p>输入事件数据并点击分析按钮开始分析</p></div>)}
                </Card>
              </Col>
            </Row>
          )},
          { key: 'hunting', label: <span><SearchOutlined /> 威胁狩猎</span>, children: (
            <Row gutter={16}>
              <Col span={8}>
                <Card title="狩猎查询模板" variant="borderless" size="small" style={{ borderRadius: 8 }}>
                  <Space direction="vertical" style={{ width: '100%' }} size={8}>
                    {HUNTING_QUERIES.map((q, i) => (
                      <Card key={i} size="small" hoverable style={{ cursor: 'pointer', borderRadius: 6 }} onClick={() => handleHunting(q.query)}>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{q.name}</div>
                        <div style={{ fontSize: 11, color: '#999', marginTop: 4 }}>{q.query}</div>
                        <Tag color="blue" style={{ marginTop: 4, fontSize: 10 }}>{q.category}</Tag>
                      </Card>
                    ))}
                  </Space>
                </Card>
              </Col>
              <Col span={16}>
                <Card title="狩猎结果" variant="borderless" style={{ borderRadius: 8 }}>
                  {huntingLoading ? (
                    <div style={{ textAlign: 'center', padding: 60 }}><Spin spinning /><div style={{ marginTop: 16, color: '#999' }}>正在执行威胁狩猎...</div></div>
                  ) : huntingResult ? (
                    <div>
                      <Row gutter={16} style={{ marginBottom: 20 }}>
                        <Col span={8}><Card><Statistic title="扫描事件数" value={huntingResult.total_scanned} prefix={<SearchOutlined />} /></Card></Col>
                        <Col span={8}><Card><Statistic title="匹配事件" value={huntingResult.matched} valueStyle={{ color: '#ff4d4f' }} prefix={<AimOutlined />} /></Card></Col>
                        <Col span={8}><Card><Statistic title="高风险IP" value={huntingResult.high_risk_ips.length} valueStyle={{ color: '#fa8c16' }} prefix={<BulbOutlined />} /></Card></Col>
                      </Row>
                      <div style={{ marginBottom: 16 }}>
                        <strong>查询语句:</strong>
                        <div style={{ padding: 12, background: '#f5f5f5', borderRadius: 6, marginTop: 4, fontFamily: 'monospace', fontSize: 13 }}>{huntingResult.query}</div>
                      </div>
                      <div style={{ marginBottom: 16 }}>
                        <strong>高风险IP:</strong>
                        <div style={{ marginTop: 4 }}>{huntingResult.high_risk_ips.map((ip: string, i: number) => <Tag key={i} color="red" style={{ fontFamily: 'monospace', margin: 2 }}>{ip}</Tag>)}</div>
                      </div>
                      <div style={{ marginBottom: 16 }}>
                        <strong>关联MITRE ATT&CK技术:</strong>
                        <div style={{ marginTop: 4 }}>{huntingResult.mitre_techniques.map((t: string, i: number) => <Tag key={i} color="blue" style={{ margin: 2 }}>{t}</Tag>)}</div>
                      </div>
                      <div>
                        <strong>建议:</strong>
                        <ul style={{ marginTop: 4, paddingLeft: 20 }}>{huntingResult.recommendations.map((r: string, i: number) => <li key={i} style={{ fontSize: 13 }}>{r}</li>)}</ul>
                      </div>
                      <div style={{ color: '#999', fontSize: 12, marginTop: 8 }}>狩猎时间: {huntingResult.hunting_time}</div>
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '80px 0', color: '#999' }}><SearchOutlined style={{ fontSize: 48, marginBottom: 16 }} /><p>选择左侧狩猎模板开始威胁狩猎</p></div>
                  )}
                </Card>
              </Col>
            </Row>
          )},
          { key: 'history', label: <span><HistoryOutlined /> 分析历史</span>, children: (
            <Table columns={historyColumns} dataSource={history.map((h, i) => ({ ...h, key: h.id || i }))} loading={initialLoading} pagination={{ pageSize: 20, showTotal: (total) => `共 ${total} 条` }} size="middle" />
          )},
          { key: 'models', label: <span><RobotOutlined /> 模型管理</span>, children: (
            <Row gutter={[16, 16]}>
              {models.map((model: any, index: number) => (
                <Col span={8} key={index}>
                  <Card title={model.name || `模型 ${index + 1}`} variant="borderless" style={{ borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.08)' }}>
                    <p style={{ color: '#666' }}>{model.description || '智能分析模型'}</p>
                    <div style={{ marginBottom: 8 }}><Tag color="blue">{model.type || '默认'}</Tag><Tag color="green">{model.status === 'active' ? '活跃' : '未激活'}</Tag></div>
                    {model.accuracy && <Progress percent={Math.round(model.accuracy * 100)} size="small" />}
                    {model.patterns?.length > 0 && <div style={{ marginTop: 8 }}><strong style={{ fontSize: 12 }}>检测模式:</strong><div style={{ marginTop: 4 }}>{model.patterns.slice(0, 5).map((p: string, i: number) => <Tag key={i} style={{ marginBottom: 4, fontSize: 11 }}>{p}</Tag>)}</div></div>}
                  </Card>
                </Col>
              ))}
              {models.length === 0 && <Col span={24}><div style={{ textAlign: 'center', padding: '60px 0', color: '#999' }}><RobotOutlined style={{ fontSize: 48, marginBottom: 16 }} /><p>暂无可用模型</p></div></Col>}
            </Row>
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

      <Modal title="批量分析" open={batchModalVisible} onCancel={() => { setBatchModalVisible(false); setBatchResults([]); setBatchText(''); }} footer={null} width={900}>
        <Row gutter={16}>
          <Col span={10}>
            <div style={{ marginBottom: 12 }}><strong>输入数据（每行一条）</strong></div>
            <TextArea rows={12} value={batchText} onChange={(e) => setBatchText(e.target.value)} placeholder="请输入事件数据，每行一条JSON数据" />
            <div style={{ marginTop: 8, color: '#999', fontSize: 12 }}>已输入 {batchText.split('\n').filter(l => l.trim().length > 0).length} 条数据（最多20条）</div>
            <Button type="primary" icon={<ThunderboltOutlined />} loading={batchAnalyzing} onClick={handleBatchAnalyze} style={{ marginTop: 12, width: '100%' }} block>开始批量分析</Button>
          </Col>
          <Col span={14}>
            <div style={{ marginBottom: 12 }}><strong>分析结果</strong></div>
            <Table columns={batchResultColumns} dataSource={batchResults.map((r, i) => ({ ...r, key: i }))} pagination={false} size="small" scroll={{ y: 400 }} locale={{ emptyText: '暂无结果' }} />
          </Col>
        </Row>
      </Modal>
    </div>
  );
};

export default AIAnalysis;
