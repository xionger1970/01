import React from 'react';
import { Provider } from 'react-redux';
import { ConfigProvider, Layout, Menu, Space } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import './index.css';
import { DashboardOutlined, AlertOutlined, SettingOutlined, ApiOutlined, AreaChartOutlined, TeamOutlined, HistoryOutlined, BarChartOutlined, LinkOutlined, RobotOutlined, DatabaseOutlined, SafetyOutlined } from '@ant-design/icons';
import store from './store';
import Dashboard from './components/Dashboard';
import AttackMonitor from './components/AttackMonitor';
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
  const [collapsed, setCollapsed] = React.useState(false);

  const theme = {
    token: {
      colorPrimary: '#00b894',
      colorBgLayout: '#1a1a2e',
      colorBgContainer: '#16213e',
      colorTextBase: '#e4e6eb',
      colorTextSecondary: '#b8bbbf',
      borderRadius: 8,
    },
  };

  const renderContent = () => {
    const map: Record<string, React.ReactNode> = {
      'dashboard': <Dashboard />,
      'attack-monitor': <AttackMonitor />,
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

  const menuItems = [
    { key: 'dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
    { key: 'attack-monitor', icon: <AlertOutlined />, label: '攻击监控' },
    { key: 'security-situation', icon: <BarChartOutlined />, label: '安全态势' },
    { type: 'divider' },
    { key: 'threat-intel', icon: <ApiOutlined />, label: '威胁情报' },
    { key: 'anomaly-detection', icon: <AreaChartOutlined />, label: '异常检测' },
    { key: 'alert-management', icon: <TeamOutlined />, label: '告警管理' },
    { type: 'divider' },
    { key: 'attack-tracking', icon: <HistoryOutlined />, label: '攻击回溯' },
    { key: 'orchestration', icon: <LinkOutlined />, label: '协同联动' },
    { key: 'data-sources', icon: <DatabaseOutlined />, label: '数据源管理' },
    { key: 'ai-analysis', icon: <RobotOutlined />, label: 'AI智能分析' },
    { type: 'divider' },
    { key: 'settings', icon: <SettingOutlined />, label: '系统设置' },
  ];

  return (
    <Provider store={store}>
      <ConfigProvider locale={zhCN} theme={theme}>
        <Layout style={{ minHeight: '100vh' }}>
          <Header style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '0 24px', height: 56, position: 'sticky', top: 0, zIndex: 100,
            background: 'linear-gradient(135deg, #16213e 0%, #1a1a2e 100%)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <SafetyOutlined style={{ fontSize: 26, color: '#00b894' }} />
              <div>
                <h1 style={{ color: '#ffffff', margin: 0, fontSize: 17, fontWeight: 700, lineHeight: '22px' }}>网络攻击态势感知系统</h1>
                <div style={{ color: '#b8bbbf', fontSize: 11, lineHeight: '14px' }}>Cyber Attack Situational Awareness</div>
              </div>
            </div>
          </Header>
          <Layout>
            <Sider
              width={200}
              collapsible
              collapsed={collapsed}
              onCollapse={setCollapsed}
              style={{
                overflow: 'auto',
                position: 'sticky',
                top: 56,
                height: 'calc(100vh - 56px)',
              }}
              theme="dark"
            >
              <Menu
                mode="inline"
                selectedKeys={[selectedKey]}
                style={{ 
                  height: '100%', 
                  borderRight: 0, 
                  background: 'transparent', 
                  paddingTop: 8,
                  paddingBottom: 16
                }}
                onSelect={({ key }) => setSelectedKey(key)}
                items={menuItems}
              />
            </Sider>
            <Content style={{
              overflow: 'auto',
              minHeight: 'calc(100vh - 56px)',
              background: '#1a1a2e',
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
