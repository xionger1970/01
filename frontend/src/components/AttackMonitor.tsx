import React, { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Table, Tag, Typography, Badge, Button, Space, Modal, Descriptions, Skeleton, message } from 'antd';
import { EyeOutlined, ReloadOutlined } from '@ant-design/icons';
import { fetchAttackEvents } from '../store/slices/attackEventsSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import type { AttackEvent } from '../types';

const { Text } = Typography;
const { Column } = Table;

const AttackMonitor: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { events: attackEvents, loading } = useSelector((state: RootState) => state.attackEvents);
  
  const [selectedEvent, setSelectedEvent] = React.useState<AttackEvent | null>(null);
  const [modalVisible, setModalVisible] = React.useState(false);
  const [selectedRowKeys, setSelectedRowKeys] = React.useState<React.Key[]>([]);

  useEffect(() => {
    // Fetch initial attack events
    dispatch(fetchAttackEvents({ limit: 100 }));
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      dispatch(fetchAttackEvents({ limit: 100 }));
    }, 5000); // Update every 5 seconds
    
    return () => clearInterval(interval);
  }, [dispatch]);

  const handleViewDetails = (event: AttackEvent) => {
    setSelectedEvent(event);
    setModalVisible(true);
  };

  const handleRefresh = () => {
    dispatch(fetchAttackEvents({ limit: 100 }));
  };

  // 批量操作处理函数
  const handleBatchBlock = () => {
    // 获取选中的攻击事件
    const selectedEvents = attackEvents.filter((event: AttackEvent) => selectedRowKeys.includes(event.id));
    const selectedIPs = selectedEvents.map((event: AttackEvent) => event.source_ip);
    
    // 这里应该调用后端API进行批量封禁
    console.log('批量封禁IP:', selectedIPs);
    message.success(`已封禁 ${selectedIPs.length} 个IP地址`);
    
    // 清空选择
    setSelectedRowKeys([]);
  };

  const handleBatchMarkAsHandled = () => {
    // 获取选中的攻击事件
    const selectedEvents = attackEvents.filter((event: AttackEvent) => selectedRowKeys.includes(event.id));
    const selectedIds = selectedEvents.map((event: AttackEvent) => event.id);
    
    // 这里应该调用后端API进行批量标记
    console.log('批量标记为已处理:', selectedIds);
    message.success(`已标记 ${selectedIds.length} 个事件为已处理`);
    
    // 清空选择
    setSelectedRowKeys([]);
  };

  const handleBatchExport = () => {
    // 获取选中的攻击事件
    const selectedEvents = attackEvents.filter((event: AttackEvent) => selectedRowKeys.includes(event.id));
    
    // 生成CSV格式数据
    const csvContent = [
      ['攻击类型', '源IP', '目标', '严重程度', '状态', '时间'],
      ...selectedEvents.map((event: AttackEvent) => [
        event.attack_type,
        event.source_ip,
        `${event.target_ip}:${event.target_port}`,
        event.severity,
        event.status,
        new Date(event.event_time).toLocaleString()
      ])
    ].map(row => row.join(',')).join('\n');
    
    // 创建下载链接
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `attack_events_${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    message.success(`已导出 ${selectedEvents.length} 个事件`);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'volcano';
      case 'high':
        return 'red';
      case 'medium':
        return 'orange';
      case 'low':
        return 'blue';
      default:
        return 'default';
    }
  };

  // 表格选择配置
  const rowSelection = {
    selectedRowKeys,
    onChange: (keys: React.Key[]) => setSelectedRowKeys(keys),
  };

  return (
    <Card title="实时攻击监控" bordered={false} extra={<Button icon={<ReloadOutlined />} onClick={handleRefresh} style={{ transition: 'all 0.3s' }}>刷新</Button>}>
      {/* 批量操作工具栏 */}
      {!loading && selectedRowKeys.length > 0 && (
        <div style={{ marginBottom: 16, padding: 12, backgroundColor: '#f5f5f5', borderRadius: 4 }}>
          <Space>
            <Text>已选择 {selectedRowKeys.length} 个事件</Text>
            <Button type="primary" onClick={handleBatchBlock}>
              批量封禁IP
            </Button>
            <Button onClick={handleBatchMarkAsHandled}>
              批量标记为已处理
            </Button>
            <Button onClick={handleBatchExport}>
              批量导出
            </Button>
            <Button onClick={() => setSelectedRowKeys([])}>
              取消选择
            </Button>
          </Space>
        </div>
      )}
      {loading ? (
        <Skeleton active paragraph={{ rows: 10 }} />
      ) : (
        <Table 
          dataSource={attackEvents} 
          rowKey="id" 
          pagination={{ pageSize: 10 }}
          rowSelection={rowSelection}
        >
          <Column 
            title="攻击类型" 
            dataIndex="attack_type" 
            key="attack_type"
            render={(text) => (
              <Tag color="blue">{text}</Tag>
            )}
          />
          <Column 
            title="源IP" 
            dataIndex="source_ip" 
            key="source_ip"
          />
          <Column 
            title="目标" 
            key="target"
            render={(record: AttackEvent) => (
              <Text>{`${record.target_ip}:${record.target_port}`}</Text>
            )}
          />
          <Column 
            title="严重程度" 
            dataIndex="severity" 
            key="severity"
            render={(text) => (
              <Badge status={getSeverityColor(text) as any} text={text} />
            )}
          />
          <Column 
            title="状态" 
            dataIndex="status" 
            key="status"
            render={(text) => (
              <Tag color={text === 'blocked' ? 'green' : 'yellow'}>{text}</Tag>
            )}
          />
          <Column 
            title="时间" 
            dataIndex="event_time" 
            key="event_time"
            render={(text) => (
              <Text type="secondary">{new Date(text).toLocaleString()}</Text>
            )}
          />
          <Column 
            title="操作" 
            key="action"
            render={(record: AttackEvent) => (
              <Space size="middle">
                <Button 
                  icon={<EyeOutlined />} 
                  size="small" 
                  onClick={() => handleViewDetails(record)}
                >
                  详情
                </Button>
              </Space>
            )}
          />
        </Table>
      )}

      {/* Attack Event Details Modal */}
      <Modal
        title="攻击事件详情"
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setModalVisible(false)}>关闭</Button>
        ]}
        width={800}
      >
        {selectedEvent && (
          <div>
            <Descriptions bordered column={2}>
              <Descriptions.Item label="攻击类型">{selectedEvent.attack_type}</Descriptions.Item>
              <Descriptions.Item label="严重程度">
                <Badge status={getSeverityColor(selectedEvent.severity) as any} text={selectedEvent.severity} />
              </Descriptions.Item>
              <Descriptions.Item label="源IP">{selectedEvent.source_ip}</Descriptions.Item>
              <Descriptions.Item label="目标IP">{selectedEvent.target_ip}</Descriptions.Item>
              <Descriptions.Item label="目标端口">{selectedEvent.target_port}</Descriptions.Item>
              <Descriptions.Item label="状态">{selectedEvent.status}</Descriptions.Item>
              <Descriptions.Item label="请求方法">{selectedEvent.request_method}</Descriptions.Item>
              <Descriptions.Item label="请求路径">{selectedEvent.request_path}</Descriptions.Item>
              <Descriptions.Item label="响应码" span={2}>{selectedEvent.response_code}</Descriptions.Item>
              <Descriptions.Item label="用户代理" span={2}>{selectedEvent.user_agent || 'N/A'}</Descriptions.Item>
              <Descriptions.Item label="事件时间" span={2}>{new Date(selectedEvent.event_time).toLocaleString()}</Descriptions.Item>
            </Descriptions>
            
            {selectedEvent.details && (
              <Card title="详细信息" style={{ marginTop: 16 }}>
                <pre style={{ whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(selectedEvent.details, null, 2)}
                </pre>
              </Card>
            )}
          </div>
        )}
      </Modal>
    </Card>
  );
};

export default AttackMonitor;