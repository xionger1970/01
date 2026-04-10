import React, { useState } from 'react';
import { Card, Form, Input, Button, Alert, Typography, Space, Divider } from 'antd';
import { LockOutlined, UserOutlined, LogoutOutlined, TeamOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import authService from '../services/authService';

const { Title, Text } = Typography;

const Login: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isRegister, setIsRegister] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (values: { username: string; password: string; confirmPassword?: string }) => {
    setLoading(true);
    setError(null);
    
    try {
      if (isRegister) {
        // 注册
        if (values.password !== values.confirmPassword) {
          throw new Error('两次输入的密码不一致');
        }
        await authService.register(values.username, values.password);
        // 注册成功后自动登录
        await authService.login(values.username, values.password);
        navigate('/');
      } else {
        // 登录
        await authService.login(values.username, values.password);
        navigate('/');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败，请重试');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      minHeight: '100vh', 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      background: 'linear-gradient(135deg, #16213e 0%, #1a1a2e 100%)'
    }}>
      <Card 
        style={{ 
          width: 400, 
          borderRadius: 12, 
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
          border: 'none'
        }}
        title={
          <div style={{ textAlign: 'center' }}>
            <Title level={4} style={{ margin: 0, color: '#00b894' }}>
              {isRegister ? '注册账户' : '用户登录'}
            </Title>
            <Text style={{ color: '#b8bbbf' }}>
              网络攻击态势感知系统
            </Text>
          </div>
        }
      >
        {error && (
          <Alert 
            message="错误" 
            description={error} 
            type="error" 
            showIcon 
            style={{ marginBottom: 20 }}
            closable 
            onClose={() => setError(null)}
          />
        )}
        
        <Form
          name={isRegister ? 'register' : 'login'}
          initialValues={{ remember: true }}
          onFinish={handleSubmit}
          layout="vertical"
        >
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input 
              prefix={<UserOutlined style={{ color: 'rgba(0, 184, 148, 0.6)' }} />} 
              placeholder="请输入用户名"
              size="large"
            />
          </Form.Item>
          
          <Form.Item
            name="password"
            label="密码"
            rules={[{ required: true, message: '请输入密码' }]}
          >
            <Input.Password 
              prefix={<LockOutlined style={{ color: 'rgba(0, 184, 148, 0.6)' }} />} 
              placeholder="请输入密码"
              size="large"
            />
          </Form.Item>
          
          {isRegister && (
            <Form.Item
              name="confirmPassword"
              label="确认密码"
              rules={[{ required: true, message: '请确认密码' }]}
            >
              <Input.Password 
                prefix={<LockOutlined style={{ color: 'rgba(0, 184, 148, 0.6)' }} />} 
                placeholder="请确认密码"
                size="large"
              />
            </Form.Item>
          )}
          
          <Form.Item style={{ marginTop: 32 }}>
            <Button 
              type="primary" 
              htmlType="submit" 
              size="large" 
              loading={loading}
              style={{ 
                width: '100%', 
                background: 'linear-gradient(135deg, #00b894, #00d2b0)', 
                border: 'none',
                height: 44,
                fontSize: 16
              }}
            >
              {isRegister ? '注册' : '登录'}
            </Button>
          </Form.Item>
        </Form>
        
        <Divider style={{ margin: '24px 0' }} />
        
        <Space style={{ width: '100%', justifyContent: 'center' }}>
          <Text style={{ color: '#b8bbbf' }}>
            {isRegister ? '已有账户？' : '还没有账户？'}
          </Text>
          <Button 
            type="link" 
            onClick={() => setIsRegister(!isRegister)}
            style={{ color: '#00b894' }}
          >
            {isRegister ? '去登录' : '去注册'}
          </Button>
        </Space>
        
        <div style={{ marginTop: 16, textAlign: 'center' }}>
          <Text style={{ color: '#666' }}>
            测试账号: admin / admin123 或 user / user123
          </Text>
        </div>
      </Card>
    </div>
  );
};

export default Login;