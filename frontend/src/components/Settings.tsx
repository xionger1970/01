import React, { useState, useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Card, Tabs, Form, Input, Select, Switch, Button, message, Space, Divider } from 'antd';
import { fetchConfigurations, updateConfiguration } from '../store/slices/configurationsSlice';
import type { RootState } from '../store';
import type { AppDispatch } from '../store';
import type { UserConfiguration, SystemConfiguration, NotificationConfiguration } from '../types';

const { Option } = Select;
const { TabPane } = Tabs;

const Settings: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { configurations, loading, error } = useSelector((state: RootState) => state.configurations);
  const [form] = Form.useForm();
  const [activeTab, setActiveTab] = useState('user');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    dispatch(fetchConfigurations());
  }, [dispatch]);

  useEffect(() => {
    if (configurations.length > 0) {
      const userConfig = configurations.find(config => config.key === 'user');
      const systemConfig = configurations.find(config => config.key === 'system');
      const notificationConfig = configurations.find(config => config.key === 'notification');

      if (userConfig && typeof userConfig.value !== 'string') {
        const userValue = userConfig.value as UserConfiguration;
        form.setFieldsValue({
          language: userValue.language || 'zh-CN',
          timezone: userValue.timezone || 'Asia/Shanghai',
        });
      }

      if (systemConfig && typeof systemConfig.value !== 'string') {
        const systemValue = systemConfig.value as SystemConfiguration;
        form.setFieldsValue({
          autoRefresh: systemValue.autoRefresh || false,
          refreshInterval: systemValue.refreshInterval || 30,
          maxEvents: systemValue.maxEvents || 100,
        });
      }

      if (notificationConfig && typeof notificationConfig.value !== 'string') {
        const notificationValue = notificationConfig.value as NotificationConfiguration;
        form.setFieldsValue({
          emailNotifications: notificationValue.emailNotifications || false,
          smsNotifications: notificationValue.smsNotifications || false,
          email: notificationValue.email || '',
          phone: notificationValue.phone || '',
        });
      }
    }
  }, [configurations, form]);

  const handleSubmit = async () => {
    try {
      setSubmitting(true);
      const values = await form.validateFields();

      // Update user configuration
      const userConfig = configurations.find(config => config.key === 'user');
      if (userConfig) {
        await dispatch(updateConfiguration({
          id: userConfig.id,
          config: {
            key: 'user',
            value: {
              language: values.language,
              timezone: values.timezone,
            },
            description: '用户配置',
          },
        }));
      }

      // Update system configuration
      const systemConfig = configurations.find(config => config.key === 'system');
      if (systemConfig) {
        await dispatch(updateConfiguration({
          id: systemConfig.id,
          config: {
            key: 'system',
            value: {
              autoRefresh: values.autoRefresh,
              refreshInterval: values.refreshInterval,
              maxEvents: values.maxEvents,
            },
            description: '系统配置',
          },
        }));
      }

      // Update notification configuration
      const notificationConfig = configurations.find(config => config.key === 'notification');
      if (notificationConfig) {
        await dispatch(updateConfiguration({
          id: notificationConfig.id,
          config: {
            key: 'notification',
            value: {
              emailNotifications: values.emailNotifications,
              smsNotifications: values.smsNotifications,
              email: values.email,
              phone: values.phone,
            },
            description: '通知配置',
          },
        }));
      }

      message.success('配置保存成功');
    } catch (error) {
      message.error('配置保存失败');
      console.error('保存配置时出错:', error);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return <div style={{ textAlign: 'center', padding: '40px' }}>加载中...</div>;
  }

  if (error) {
    return <div style={{ textAlign: 'center', padding: '40px', color: 'red' }}>加载失败: {error}</div>;
  }

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <Card title="系统设置" style={{ marginBottom: '24px' }}>
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
        >
          <Tabs activeKey={activeTab} onChange={setActiveTab}>
            <TabPane tab="用户配置" key="user">
              <Form.Item
                label="语言"
                name="language"
                rules={[{ required: true, message: '请选择语言' }]}
              >
                <Select placeholder="选择语言">
                  <Option value="zh-CN">简体中文</Option>
                  <Option value="en-US">English</Option>
                </Select>
              </Form.Item>
              <Form.Item
                label="时区"
                name="timezone"
                rules={[{ required: true, message: '请选择时区' }]}
              >
                <Select placeholder="选择时区">
                  <Option value="Asia/Shanghai">中国标准时间</Option>
                  <Option value="America/New_York">美国东部时间</Option>
                  <Option value="Europe/London">格林威治标准时间</Option>
                </Select>
              </Form.Item>
            </TabPane>

            <TabPane tab="系统配置" key="system">
              <Form.Item
                label="自动刷新"
                name="autoRefresh"
              >
                <Switch />
              </Form.Item>
              <Form.Item
                label="刷新间隔（秒）"
                name="refreshInterval"
                rules={[{ required: true, message: '请输入刷新间隔' }]}
              >
                <Input type="number" min={10} max={300} />
              </Form.Item>
              <Form.Item
                label="最大事件数"
                name="maxEvents"
                rules={[{ required: true, message: '请输入最大事件数' }]}
              >
                <Input type="number" min={10} max={1000} />
              </Form.Item>
            </TabPane>

            <TabPane tab="通知设置" key="notification">
              <Form.Item
                label="邮件通知"
                name="emailNotifications"
              >
                <Switch />
              </Form.Item>
              <Form.Item
                label="邮箱地址"
                name="email"
                rules={[
                  {
                    required: form.getFieldValue('emailNotifications'),
                    message: '请输入邮箱地址',
                  },
                  {
                    type: 'email',
                    message: '请输入有效的邮箱地址',
                  },
                ]}
              >
                <Input placeholder="请输入邮箱地址" />
              </Form.Item>
              <Divider />
              <Form.Item
                label="短信通知"
                name="smsNotifications"
              >
                <Switch />
              </Form.Item>
              <Form.Item
                label="手机号码"
                name="phone"
                rules={[
                  {
                    required: form.getFieldValue('smsNotifications'),
                    message: '请输入手机号码',
                  },
                  {
                    pattern: /^1[3-9]\d{9}$/,
                    message: '请输入有效的手机号码',
                  },
                ]}
              >
                <Input placeholder="请输入手机号码" />
              </Form.Item>
            </TabPane>
          </Tabs>

          <Divider />
          <Form.Item>
            <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button type="primary" htmlType="submit" loading={submitting}>
                保存配置
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default Settings;