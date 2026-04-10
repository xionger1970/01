import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ResponsePanel = () => {
  const [activeTab, setActiveTab] = useState('priority');
  const [blacklist, setBlacklist] = useState([]);
  const [assets, setAssets] = useState({});
  const [deviceStatus, setDeviceStatus] = useState({});
  const [responseHistory, setResponseHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  // 加载数据
  useEffect(() => {
    if (activeTab === 'priority') {
      loadPriorityData();
    } else if (activeTab === 'device') {
      loadDeviceData();
    } else if (activeTab === 'history') {
      loadResponseHistory();
    }
  }, [activeTab]);

  const loadPriorityData = async () => {
    setLoading(true);
    try {
      const blacklistResponse = await axios.get('/api/response/prioritizer/blacklist');
      setBlacklist(blacklistResponse.data.blacklist);
    } catch (error) {
      console.error('Error loading priority data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadDeviceData = async () => {
    setLoading(true);
    try {
      const statusResponse = await axios.get('/api/response/device/status');
      setDeviceStatus(statusResponse.data);
    } catch (error) {
      console.error('Error loading device data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadResponseHistory = async () => {
    setLoading(true);
    try {
      const historyResponse = await axios.get('/api/response/device/response_history');
      setResponseHistory(historyResponse.data.history);
    } catch (error) {
      console.error('Error loading response history:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddToBlacklist = async (ip) => {
    try {
      await axios.post('/api/response/prioritizer/blacklist/add', null, { params: { ip } });
      loadPriorityData();
    } catch (error) {
      console.error('Error adding to blacklist:', error);
    }
  };

  const handleRemoveFromBlacklist = async (ip) => {
    try {
      await axios.delete('/api/response/prioritizer/blacklist/remove', { params: { ip } });
      loadPriorityData();
    } catch (error) {
      console.error('Error removing from blacklist:', error);
    }
  };

  const handleBlockIP = async (ip, duration = 3600, reason = '检测到恶意活动') => {
    try {
      await axios.post('/api/response/device/block', null, { params: { ip, duration, reason } });
      loadDeviceData();
    } catch (error) {
      console.error('Error blocking IP:', error);
    }
  };

  const handleUnblockIP = async (ip) => {
    try {
      await axios.post('/api/response/device/unblock', null, { params: { ip } });
      loadDeviceData();
    } catch (error) {
      console.error('Error unblocking IP:', error);
    }
  };

  const renderPriorityTab = () => {
    if (loading) return <div>加载数据中...</div>;
    
    return (
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold mb-3">威胁情报黑名单</h3>
          <div className="mb-4">
            <input
              type="text"
              placeholder="输入IP地址"
              className="px-3 py-2 border rounded mr-2"
              id="newBlacklistIP"
            />
            <button
              onClick={() => {
                const input = document.getElementById('newBlacklistIP');
                if (input.value) {
                  handleAddToBlacklist(input.value);
                  input.value = '';
                }
              }}
              className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
            >
              添加
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full bg-white border border-gray-200">
              <thead>
                <tr>
                  <th className="py-2 px-4 border-b">IP地址</th>
                  <th className="py-2 px-4 border-b">操作</th>
                </tr>
              </thead>
              <tbody>
                {blacklist.map((ip, index) => (
                  <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                    <td className="py-2 px-4 border-b">{ip}</td>
                    <td className="py-2 px-4 border-b">
                      <button
                        onClick={() => handleRemoveFromBlacklist(ip)}
                        className="px-3 py-1 bg-red-100 text-red-800 rounded hover:bg-red-200"
                      >
                        移除
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  const renderDeviceTab = () => {
    if (loading) return <div>加载设备状态中...</div>;
    
    return (
      <div className="space-y-6">
        <div className="mb-4">
          <input
            type="text"
            placeholder="输入要阻止的IP地址"
            className="px-3 py-2 border rounded mr-2"
            id="blockIPInput"
          />
          <input
            type="number"
            placeholder="持续时间(秒)"
            defaultValue="3600"
            className="px-3 py-2 border rounded mr-2 w-32"
            id="blockDurationInput"
          />
          <input
            type="text"
            placeholder="阻止原因"
            defaultValue="检测到恶意活动"
            className="px-3 py-2 border rounded mr-2"
            id="blockReasonInput"
          />
          <button
            onClick={() => {
              const ipInput = document.getElementById('blockIPInput');
              const durationInput = document.getElementById('blockDurationInput');
              const reasonInput = document.getElementById('blockReasonInput');
              if (ipInput.value) {
                handleBlockIP(ipInput.value, parseInt(durationInput.value), reasonInput.value);
                ipInput.value = '';
              }
            }}
            className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
          >
            阻止IP
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* 防火墙状态 */}
          <div className="p-4 border rounded-lg">
            <h4 className="font-semibold mb-2">防火墙</h4>
            <p className="text-sm text-gray-600 mb-2">
              已阻止: <span className="font-bold">{deviceStatus.firewall?.count || 0}</span>
            </p>
            <div className="flex flex-wrap gap-1">
              {deviceStatus.firewall?.blocked_ips?.slice(0, 5).map((ip, i) => (
                <span key={i} className="px-2 py-1 bg-red-100 text-red-800 rounded text-xs">
                  {ip}
                  <button
                    onClick={() => handleUnblockIP(ip)}
                    className="ml-1 text-red-500"
                  >
                    ×
                  </button>
                </span>
              ))}
              {(deviceStatus.firewall?.blocked_ips?.length || 0) > 5 && (
                <span className="px-2 py-1 text-xs text-gray-500">
                  +{(deviceStatus.firewall?.blocked_ips?.length || 0) - 5}更多
                </span>
              )}
            </div>
          </div>

          {/* Nginx状态 */}
          <div className="p-4 border rounded-lg">
            <h4 className="font-semibold mb-2">Nginx</h4>
            <p className="text-sm text-gray-600 mb-2">
              已阻止: <span className="font-bold">{deviceStatus.nginx?.count || 0}</span>
            </p>
            <div className="flex flex-wrap gap-1">
              {deviceStatus.nginx?.blocked_ips?.slice(0, 5).map((ip, i) => (
                <span key={i} className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded text-xs">
                  {ip}
                  <button
                    onClick={() => handleUnblockIP(ip)}
                    className="ml-1 text-yellow-500"
                  >
                    ×
                  </button>
                </span>
              ))}
              {(deviceStatus.nginx?.blocked_ips?.length || 0) > 5 && (
                <span className="px-2 py-1 text-xs text-gray-500">
                  +{(deviceStatus.nginx?.blocked_ips?.length || 0) - 5}更多
                </span>
              )}
            </div>
          </div>

          {/* ModSecurity状态 */}
          <div className="p-4 border rounded-lg">
            <h4 className="font-semibold mb-2">ModSecurity</h4>
            <p className="text-sm text-gray-600 mb-2">
              自定义规则: <span className="font-bold">{deviceStatus.modsecurity?.rules_count || 0}</span>
            </p>
            <div className="text-xs text-gray-500">
              查看规则详情请访问ModSecurity管理页面
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderHistoryTab = () => {
    if (loading) return <div>加载响应历史中...</div>;
    
    return (
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">响应操作历史</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-200">
            <thead>
              <tr>
                <th className="py-2 px-4 border-b">时间</th>
                <th className="py-2 px-4 border-b">IP地址</th>
                <th className="py-2 px-4 border-b">原因</th>
                <th className="py-2 px-4 border-b">操作详情</th>
              </tr>
            </thead>
            <tbody>
              {responseHistory.map((item, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                  <td className="py-2 px-4 border-b">
                    {new Date(item.timestamp).toLocaleString()}
                  </td>
                  <td className="py-2 px-4 border-b font-mono">{item.ip}</td>
                  <td className="py-2 px-4 border-b">{item.reason}</td>
                  <td className="py-2 px-4 border-b">
                    <div className="flex flex-wrap gap-1">
                      {item.actions?.map((action, i) => (
                        <span
                          key={i}
                          className={`px-2 py-1 rounded text-xs ${
                            action.success
                              ? 'bg-green-100 text-green-800'
                              : 'bg-red-100 text-red-800'
                          }`}
                        >
                          {action.device}: {action.success ? '成功' : '失败'}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  return (
    <div className="p-4 bg-white rounded-lg shadow">
      <h2 className="text-xl font-bold mb-4">响应管理面板</h2>
      
      <div className="border-b border-gray-200 mb-4">
        <nav className="flex space-x-4">
          <button
            onClick={() => setActiveTab('priority')}
            className={`px-4 py-2 border-b-2 ${
              activeTab === 'priority'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            告警优先级
          </button>
          <button
            onClick={() => setActiveTab('device')}
            className={`px-4 py-2 border-b-2 ${
              activeTab === 'device'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            设备联动
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`px-4 py-2 border-b-2 ${
              activeTab === 'history'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            响应历史
          </button>
        </nav>
      </div>
      
      <div className="mt-4">
        {activeTab === 'priority' && renderPriorityTab()}
        {activeTab === 'device' && renderDeviceTab()}
        {activeTab === 'history' && renderHistoryTab()}
      </div>
    </div>
  );
};

export default ResponsePanel;