import React from 'react';
import { Provider } from 'react-redux';
import { ConfigProvider, Layout, Menu, Switch, Space, Tooltip } from 'antd';
import { CSSTransition, TransitionGroup } from 'react-transition-group';
import zhCN from 'antd/locale/zh_CN';
import 'antd/dist/reset.css';
import { DashboardOutlined, AlertOutlined, MonitorOutlined, SettingOutlined, MoonOutlined, SunOutlined } from '@ant-design/icons';
import store from './store';
import Dashboard from './components/Dashboard';
import AttackMonitor from './components/AttackMonitor';
import SecurityOverview from './components/SecurityOverview';
import Settings from './components/Settings';

const { Header, Content, Sider } = Layout;

const App: React.FC = () => {
  const [selectedKey, setSelectedKey] = React.useState('dashboard');
  const [darkMode, setDarkMode] = React.useState(false);

  // 深色模式主题配置
  const theme = {
    token: {
      colorPrimary: '#1890ff',
      colorBgLayout: darkMode ? '#141414' : '#ffffff',
      colorBgContainer: darkMode ? '#1f1f1f' : '#ffffff',
      colorTextBase: darkMode ? '#f0f0f0' : '#000000',
      colorTextSecondary: darkMode ? '#a0a0a0' : '#666666',
    },
  };

  const renderContent = () => {
    return (
      <TransitionGroup>
        <CSSTransition
          key={selectedKey}
          timeout={300}
          classNames="page-transition"
        >
          <div style={{ width: '100%' }}>
            {selectedKey === 'dashboard' && <Dashboard />}
            {selectedKey === 'attack-monitor' && <AttackMonitor />}
            {selectedKey === 'security-overview' && <SecurityOverview />}
            {selectedKey === 'settings' && <Settings />}
            {selectedKey !== 'dashboard' && selectedKey !== 'attack-monitor' && selectedKey !== 'security-overview' && selectedKey !== 'settings' && <Dashboard />}
          </div>
        </CSSTransition>
      </TransitionGroup>
    );
  };

  return (
    <Provider store={store}>
      <ConfigProvider locale={zhCN} theme={theme}>
        <Layout style={{ minHeight: '100vh', backgroundColor: darkMode ? '#141414' : '#ffffff' }} className={darkMode ? 'dark-mode' : ''}>
          <Header style={{ backgroundColor: '#1890ff', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h1 style={{ color: 'white', margin: 0, fontSize: 18 }}>Web攻击态势感知系统</h1>
            <Space style={{ marginRight: 24 }}>
              <Tooltip title={darkMode ? '切换到浅色模式' : '切换到深色模式'}>
                <Switch
                  checked={darkMode}
                  onChange={setDarkMode}
                  checkedChildren={<MoonOutlined style={{ color: 'white' }} />}
                  unCheckedChildren={<SunOutlined style={{ color: 'white' }} />}
                />
              </Tooltip>
            </Space>
          </Header>
          <Layout>
            <Sider width={200} style={{ backgroundColor: darkMode ? '#1f1f1f' : '#f0f2f5' }}>
              <Menu
                mode="inline"
                selectedKeys={[selectedKey]}
                style={{ height: '100%', borderRight: 0 }}
                onSelect={({ key }) => setSelectedKey(key)}
                items={[
                  {
                    key: 'dashboard',
                    icon: <DashboardOutlined />,
                    label: '仪表盘',
                  },
                  {
                    key: 'attack-monitor',
                    icon: <AlertOutlined />,
                    label: '攻击监控',
                  },
                  {
                    key: 'security-overview',
                    icon: <MonitorOutlined />,
                    label: '安全态势',
                  },
                  {
                    key: 'settings',
                    icon: <SettingOutlined />,
                    label: '系统设置',
                  },
                ]}
              />
            </Sider>
            <Content style={{ padding: 24, background: darkMode ? '#1f1f1f' : 'white' }}>
              {renderContent()}
            </Content>
          </Layout>
        </Layout>
      </ConfigProvider>
    </Provider>
  );
};

export default App;

// 添加页面过渡动画样式
const style = document.createElement('style');
style.textContent = `
  .page-transition-enter {
    opacity: 0;
    transform: translateX(20px);
  }
  .page-transition-enter-active {
    opacity: 1;
    transform: translateX(0);
    transition: opacity 300ms, transform 300ms;
  }
  .page-transition-exit {
    opacity: 1;
    transform: translateX(0);
  }
  .page-transition-exit-active {
    opacity: 0;
    transform: translateX(-20px);
    transition: opacity 300ms, transform 300ms;
  }
  
  /* 深色模式样式 */
  .dark-mode {
    background-color: #141414;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-card {
    background-color: #1f1f1f;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-table {
    background-color: #1f1f1f;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-table-thead > tr > th {
    background-color: #2a2a2a;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-table-tbody > tr > td {
    background-color: #1f1f1f;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-modal-content {
    background-color: #1f1f1f;
    color: #f0f0f0;
  }
  
  .dark-mode .ant-modal-header {
    background-color: #2a2a2a;
    color: #f0f0f0;
  }
`;
document.head.appendChild(style);
