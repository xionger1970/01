import React, { useState, useEffect } from 'react';
import axios from 'axios';

const DetectionPanel = () => {
  const [activeTab, setActiveTab] = useState('mitre');
  const [mitreTechniques, setMitreTechniques] = useState([]);
  const [mitreTactics, setMitreTactics] = useState([]);
  const [aggregatedAlerts, setAggregatedAlerts] = useState([]);
  const [whitelist, setWhitelist] = useState({ ips: [], domains: [], ip_ranges: [] });
  const [timeWindowEvents, setTimeWindowEvents] = useState({});
  const [frequencyStatus, setFrequencyStatus] = useState({});
  const [blockedEntities, setBlockedEntities] = useState([]);
  const [loading, setLoading] = useState(false);

  // 加载MITRE ATT&CK数据
  useEffect(() => {
    if (activeTab === 'mitre') {
      loadMitreData();
    }
  }, [activeTab]);

  // 加载聚合告警
  useEffect(() => {
    if (activeTab === 'alerts') {
      loadAggregatedAlerts();
    }
  }, [activeTab]);

  // 加载白名单
  useEffect(() => {
    if (activeTab === 'whitelist') {
      loadWhitelist();
    }
  }, [activeTab]);

  // 加载频率检测数据
  useEffect(() => {
    if (activeTab === 'frequency') {
      loadBlockedEntities();
    }
  }, [activeTab]);

  const loadMitreData = async () => {
    setLoading(true);
    try {
      const [techniquesResponse, tacticsResponse] = await Promise.all([
        axios.get('/api/detection/mitre/techniques'),
        axios.get('/api/detection/mitre/tactics')
      ]);
      setMitreTechniques(techniquesResponse.data);
      setMitreTactics(tacticsResponse.data);
    } catch (error) {
      console.error('Error loading MITRE data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadAggregatedAlerts = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/detection/alerts/aggregated');
      setAggregatedAlerts(response.data);
    } catch (error) {
      console.error('Error loading aggregated alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadWhitelist = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/detection/whitelist/list');
      setWhitelist(response.data);
    } catch (error) {
      console.error('Error loading whitelist:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadBlockedEntities = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/detection/frequency/blocked');
      setBlockedEntities(response.data);
    } catch (error) {
      console.error('Error loading blocked entities:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddToWhitelist = async (type, value) => {
    try {
      if (type === 'ip') {
        await axios.post('/api/detection/whitelist/ip', { ip: value });
      } else if (type === 'domain') {
        await axios.post('/api/detection/whitelist/domain', { domain: value });
      } else if (type === 'ip_range') {
        await axios.post('/api/detection/whitelist/ip_range', { ip_range: value });
      }
      loadWhitelist();
    } catch (error) {
      console.error('Error adding to whitelist:', error);
    }
  };

  const handleRemoveFromWhitelist = async (type, value) => {
    try {
      if (type === 'ip') {
        await axios.delete('/api/detection/whitelist/ip', { params: { ip: value } });
      } else if (type === 'domain') {
        await axios.delete('/api/detection/whitelist/domain', { params: { domain: value } });
      } else if (type === 'ip_range') {
        await axios.delete('/api/detection/whitelist/ip_range', { params: { ip_range: value } });
      }
      loadWhitelist();
    } catch (error) {
      console.error('Error removing from whitelist:', error);
    }
  };

  const handleUnblockEntity = async (entity) => {
    try {
      await axios.post('/api/detection/frequency/unblock', { entity });
      loadBlockedEntities();
    } catch (error) {
      console.error('Error unblocking entity:', error);
    }
  };

  const renderMITRETAB = () => {
    if (loading) return <div>Loading MITRE ATT&CK data...</div>;
    
    return (
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">MITRE ATT&CK Techniques</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-200">
            <thead>
              <tr>
                <th className="py-2 px-4 border-b">Attack Type</th>
                <th className="py-2 px-4 border-b">Technique ID</th>
                <th className="py-2 px-4 border-b">Technique Name</th>
                <th className="py-2 px-4 border-b">Tactic</th>
                <th className="py-2 px-4 border-b">Description</th>
              </tr>
            </thead>
            <tbody>
              {mitreTechniques.map((technique, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                  <td className="py-2 px-4 border-b">{technique.attack_type}</td>
                  <td className="py-2 px-4 border-b">{technique.technique_id}</td>
                  <td className="py-2 px-4 border-b">{technique.technique_name}</td>
                  <td className="py-2 px-4 border-b">{technique.tactic}</td>
                  <td className="py-2 px-4 border-b">{technique.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <h3 className="text-lg font-semibold mt-6">MITRE ATT&CK Tactics</h3>
        <div className="flex flex-wrap gap-2">
          {mitreTactics.map((tactic, index) => (
            <span key={index} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
              {tactic}
            </span>
          ))}
        </div>
      </div>
    );
  };

  const renderAlertsTab = () => {
    if (loading) return <div>Loading aggregated alerts...</div>;
    
    return (
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Aggregated Alerts</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-200">
            <thead>
              <tr>
                <th className="py-2 px-4 border-b">Source IP</th>
                <th className="py-2 px-4 border-b">Alert Type</th>
                <th className="py-2 px-4 border-b">Count</th>
                <th className="py-2 px-4 border-b">First Seen</th>
                <th className="py-2 px-4 border-b">Last Seen</th>
                <th className="py-2 px-4 border-b">Severity</th>
                <th className="py-2 px-4 border-b">Targets</th>
              </tr>
            </thead>
            <tbody>
              {aggregatedAlerts.map((alert, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                  <td className="py-2 px-4 border-b">{alert.source_ip}</td>
                  <td className="py-2 px-4 border-b">{alert.alert_type}</td>
                  <td className="py-2 px-4 border-b">{alert.count}</td>
                  <td className="py-2 px-4 border-b">{new Date(alert.first_seen).toLocaleString()}</td>
                  <td className="py-2 px-4 border-b">{new Date(alert.last_seen).toLocaleString()}</td>
                  <td className="py-2 px-4 border-b">
                    <span className={`px-2 py-1 rounded ${alert.severity >= 3 ? 'bg-red-100 text-red-800' : alert.severity >= 2 ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-2 px-4 border-b">{alert.targets.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  };

  const renderWhitelistTab = () => {
    if (loading) return <div>Loading whitelist...</div>;
    
    return (
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold mb-2">IP Whitelist</h3>
          <div className="flex flex-wrap gap-2">
            {whitelist.ips.map((ip, index) => (
              <div key={index} className="flex items-center gap-2">
                <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm">
                  {ip}
                </span>
                <button 
                  onClick={() => handleRemoveFromWhitelist('ip', ip)}
                  className="text-red-500 hover:text-red-700"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
        
        <div>
          <h3 className="text-lg font-semibold mb-2">IP Range Whitelist</h3>
          <div className="flex flex-wrap gap-2">
            {whitelist.ip_ranges.map((range, index) => (
              <div key={index} className="flex items-center gap-2">
                <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm">
                  {range}
                </span>
                <button 
                  onClick={() => handleRemoveFromWhitelist('ip_range', range)}
                  className="text-red-500 hover:text-red-700"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
        
        <div>
          <h3 className="text-lg font-semibold mb-2">Domain Whitelist</h3>
          <div className="flex flex-wrap gap-2">
            {whitelist.domains.map((domain, index) => (
              <div key={index} className="flex items-center gap-2">
                <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm">
                  {domain}
                </span>
                <button 
                  onClick={() => handleRemoveFromWhitelist('domain', domain)}
                  className="text-red-500 hover:text-red-700"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderFrequencyTab = () => {
    if (loading) return <div>Loading frequency detection data...</div>;
    
    return (
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Blocked Entities</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-200">
            <thead>
              <tr>
                <th className="py-2 px-4 border-b">Entity</th>
                <th className="py-2 px-4 border-b">Unblock Time</th>
                <th className="py-2 px-4 border-b">Actions</th>
              </tr>
            </thead>
            <tbody>
              {blockedEntities.map((entity, index) => (
                <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                  <td className="py-2 px-4 border-b">{entity.entity}</td>
                  <td className="py-2 px-4 border-b">{new Date(entity.unblock_time).toLocaleString()}</td>
                  <td className="py-2 px-4 border-b">
                    <button 
                      onClick={() => handleUnblockEntity(entity.entity)}
                      className="px-3 py-1 bg-blue-100 text-blue-800 rounded hover:bg-blue-200"
                    >
                      Unblock
                    </button>
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
      <h2 className="text-xl font-bold mb-4">Detection Panel</h2>
      
      <div className="border-b border-gray-200 mb-4">
        <nav className="flex space-x-4">
          <button
            onClick={() => setActiveTab('mitre')}
            className={`px-4 py-2 border-b-2 ${activeTab === 'mitre' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            MITRE ATT&CK
          </button>
          <button
            onClick={() => setActiveTab('alerts')}
            className={`px-4 py-2 border-b-2 ${activeTab === 'alerts' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            Aggregated Alerts
          </button>
          <button
            onClick={() => setActiveTab('whitelist')}
            className={`px-4 py-2 border-b-2 ${activeTab === 'whitelist' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            Whitelist
          </button>
          <button
            onClick={() => setActiveTab('frequency')}
            className={`px-4 py-2 border-b-2 ${activeTab === 'frequency' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            Frequency Detection
          </button>
        </nav>
      </div>
      
      <div className="mt-4">
        {activeTab === 'mitre' && renderMITRETAB()}
        {activeTab === 'alerts' && renderAlertsTab()}
        {activeTab === 'whitelist' && renderWhitelistTab()}
        {activeTab === 'frequency' && renderFrequencyTab()}
      </div>
    </div>
  );
};

export default DetectionPanel;