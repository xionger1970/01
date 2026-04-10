import React from 'react';
import { Provider } from 'react-redux';
import { ConfigProvider, Layout, Menu, Switch, Space, Tooltip } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import './index.css';
import { DashboardOutlined, AlertOutlined, MonitorOutlined, SettingOutlined, MoonOutlined, SunOutlined, ApiOutlined, AreaChartOutlined, TeamOutlined, HistoryOutlined, BarChartOutlined, LinkOutlined, FileSearchOutlined, SafetyCertificateOutlined, RobotOutlined, ThunderboltOutlined, DatabaseOutlined } from '@ant-design/icons';
import store from './store';
import Dashboard from './components/Dashboard';
import AttackMonitor from './components/AttackMonitor';
import SecurityOverview from './components/SecurityOverview';
import Settings from './components/Settings';
import ThreatIntel from './components/ThreatIntel';
import AnomalyDetection from './components/AnomalyDetection';
import AlertManagement from './components/AlertManagement';
import AttackTracking from './components/AttackTracking';
import SecuritySituation from './components/SecuritySituation';
import Orchestration from './components/Orchestration';
import AIAnalysis from './components/AIAnalysis';
import DataSourceManagement from './components/DataSourceManagement';

const { Header, Content, Sider } = Layout;

const App: React.FC = () => {
  const [selectedKey, setSelectedKey] = React.useState('dashboard');
  const [darkMode, setDarkMode] = React.useState(false);
  const [collapsed, setCollapsed] = React.useState(false);

  const theme = {
    token: {
      colorPrimary: '#1890ff',
      colorBgLayout: darkMode ? '#141414' : '#f0f2f5',
      colorBgContainer: darkMode ? '#1f1f1f' : '#ffffff',
      colorTextBase: darkMode ? '#f0f0f0' : '#000000',
      colorTextSecondary: darkMode ? '#a0a0a0' : '#666666',
      borderRadius: 8,
    },
  };

  const renderContent = () => {
    const map: Record<string, React.ReactNode> = {
      'dashboard': <Dashboard />,
      'attack-monitor': <AttackMonitor />,
      'security-overview': <SecurityOverview />,
      'security-situation': <SecuritySituation />,
      'threat-intel': <ThreatIntel />,
      'anomaly-detection': <AnomalyDetection />,
      'alert-management': <AlertManagement />,
      'attack-tracking': <AttackTracking />,
      'orchestration': <Orchestration />,
      'data-sources': <DataSourceManagement />,
      'ai-analysis': <AIAnalysis />,
      'settings': <Settings />,
    };
    return <div style={{ width: '100%' }} className="animate-fade-in">{map[selectedKey] || <Dashboard />}</div>;
  };

  return (
    <Provider store={store}>
      <ConfigProvider locale={zhCN} theme={theme}>
        <Layout style={{ minHeight: '100vh' }} className={darkMode ? 'dark-mode' : ''}>
          <Header style={{
            background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '0 24px', boxShadow: '0 2px 8px rgba(0,0,0,0.15)', zIndex: 10,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <SafetyCertificateOutlined style={{ fontSize: 28, color: '#1890ff' }} />
              <div>
                <h1 style={{ color: '#fff', margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: 1 }}>网络攻击态势感知系统</h1>
                <div style={{ color: 'rgba(255,255,255,0.45)', fontSize: 11, marginTop: 1 }}>Cyber Attack Situational Awareness System</div>
              </div>
            </div>
            <Space size={16}>
              <Tooltip title={darkMode ? '切换浅色模式' : '切换深色模式'}>
                <Switch checked={darkMode} onChange={setDarkMode}
                  checkedChildren={<MoonOutlined style={{ color: 'white' }} />}
                  unCheckedChildren={<SunOutlined style={{ color: 'white' }} />}
                />
              </Tooltip>
            </Space>
          </Header>
          <Layout>
            <Sider
              width={220}
              collapsible
              collapsed={collapsed}
              onCollapse={setCollapsed}
              style={{
                background: darkMode ? '#1a1a2e' : 'linear-gradient(180deg, #f8f9fc 0%, #eef1f6 100%)',
                borderRight: darkMode ? '1px solid #2a2a3e' : '1px solid #e8ecf1',
                boxShadow: '2px 0 8px rgba(0,0,0,0.04)',
              }}
              theme={darkMode ? 'dark' : 'light'}
            >
              <Menu
                mode="inline"
                selectedKeys={[selectedKey]}
                style={{
                  height: '100%', borderRight: 0,
                  background: 'transparent',
                  paddingTop: 8,
                }}
                onSelect={({ key }) => setSelectedKey(key)}
                items={[
                  { key: 'dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
                  { key: 'attack-monitor', icon: <AlertOutlined />, label: '攻击监控' },
                  { key: 'security-overview', icon: <MonitorOutlined />, label: '安全态势' },
                  { key: 'security-situation', icon: <BarChartOutlined />, label: '态势大屏' },
                  { type: 'divider' },
                  { key: 'threat-intel', icon: <ApiOutlined />, label: '威胁情报' },
                  { key: 'anomaly-detection', icon: <AreaChartOutlined />, label: '异常检测' },
                  { key: 'alert-management', icon: <TeamOutlined />, label: '告警管理' },
                  { type: 'divider' },
                  { key: 'attack-tracking', icon: <HistoryOutlined />, label: '攻击回溯' },
                  { key: 'orchestration', icon: <LinkOutlined />, label: '协同联动' },
                  { key: 'data-sources', icon: <DatabaseOutlined />, label: '数据源管理' },
                  { key: 'ai-analysis', icon: <RobotOutlined />, label: 'AI智能研判' },
                  { type: 'divider' },
                  { key: 'settings', icon: <SettingOutlined />, label: '系统设置' },
                ]}
              />
            </Sider>
            <Content style={{
              background: darkMode ? '#141414' : '#f0f2f5',
              overflow: 'auto',
              minHeight: 'calc(100vh - 64px)',
            }}>
              {renderContent()}
            </Content>
          </Layout>
        </Layout>
      </ConfigProvider>
    </Provider>
  );
};

export default App;
