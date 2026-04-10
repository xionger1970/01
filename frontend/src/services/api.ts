import axios from 'axios';
import type { AttackEvent, AlertRule, AlertHistory, DashboardOverview, TopTarget, SystemStatus, Configuration, User, Token } from '../types';

// 创建请求缓存
const requestCache = new Map();

// Create axios instance
const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 生成缓存键
    const cacheKey = `${config.method}:${config.url}:${JSON.stringify(config.params)}`;
    
    // 检查是否有缓存
    if (config.method === 'get' && requestCache.has(cacheKey)) {
      const cachedResponse = requestCache.get(cacheKey);
      // 如果缓存存在且未过期（5分钟）
      if (cachedResponse && Date.now() - cachedResponse.timestamp < 5 * 60 * 1000) {
        return Promise.resolve(cachedResponse.data);
      }
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    // 缓存 GET 请求的响应
    if (response.config.method === 'get') {
      const cacheKey = `${response.config.method}:${response.config.url}:${JSON.stringify(response.config.params)}`;
      requestCache.set(cacheKey, {
        data: response,
        timestamp: Date.now(),
      });
    }
    return response;
  },
  (error) => {
    // 统一错误处理
    if (error.response) {
      switch (error.response.status) {
        case 401:
          // 未授权处理
          break;
        case 404:
          console.error('API 端点不存在');
          break;
        case 500:
          console.error('服务器内部错误');
          break;
        default:
          console.error('请求失败:', error.response.data);
      }
    } else if (error.request) {
      console.error('网络错误，无法连接到服务器');
    } else {
      console.error('请求配置错误:', error.message);
    }
    return Promise.reject(error);
  }
);

// Authentication endpoints
export const authService = {
  login: async (username: string, password: string): Promise<Token> => {
    const response = await api.post<Token>('/auth/token', {
      username,
      password,
    });
    return response.data;
  },
  getCurrentUser: async (): Promise<User> => {
    const response = await api.get<User>('/auth/me');
    return response.data;
  },
};

// Attack events endpoints
export const attackEventsService = {
  getAttackEvents: async (attack_type?: string, source_ip?: string, limit: number = 100): Promise<AttackEvent[]> => {
    const params = new URLSearchParams();
    if (attack_type) params.append('attack_type', attack_type);
    if (source_ip) params.append('source_ip', source_ip);
    params.append('limit', limit.toString());
    
    const response = await api.get<AttackEvent[]>(`/attack-events?${params.toString()}`);
    return response.data;
  },
  getAttackStats: async () => {
    const response = await api.get('/attack-events/stats');
    return response.data;
  },
};

// Alerts endpoints
export const alertsService = {
  getAlertRules: async (): Promise<AlertRule[]> => {
    const response = await api.get<AlertRule[]>('/alerts/rules');
    return response.data;
  },
  createAlertRule: async (rule: Omit<AlertRule, 'id' | 'created_at' | 'updated_at'>): Promise<AlertRule> => {
    const response = await api.post<AlertRule>('/alerts/rules', rule);
    return response.data;
  },
  getAlertHistory: async (): Promise<AlertHistory[]> => {
    const response = await api.get<AlertHistory[]>('/alerts/history');
    return response.data;
  },
};

// Dashboard endpoints
export const dashboardService = {
  getOverview: async (): Promise<DashboardOverview> => {
    const response = await api.get<DashboardOverview>('/dashboard/overview');
    return response.data;
  },
  getTopTargets: async (): Promise<TopTarget[]> => {
    const response = await api.get<TopTarget[]>('/dashboard/top-targets');
    return response.data;
  },
  getSystemStatus: async (): Promise<SystemStatus> => {
    const response = await api.get<SystemStatus>('/dashboard/system-status');
    return response.data;
  },
};

// Configurations endpoints
export const configurationsService = {
  getConfigurations: async (): Promise<Configuration[]> => {
    const response = await api.get<Configuration[]>('/configurations');
    return response.data;
  },
  createConfiguration: async (config: Omit<Configuration, 'id' | 'created_at' | 'updated_at'>): Promise<Configuration> => {
    const response = await api.post<Configuration>('/configurations', config);
    return response.data;
  },
  updateConfiguration: async (id: number, config: Omit<Configuration, 'id' | 'created_at' | 'updated_at'>): Promise<Configuration> => {
    const response = await api.put<Configuration>(`/configurations/${id}`, config);
    return response.data;
  },
  deleteConfiguration: async (id: number): Promise<void> => {
    await api.delete(`/configurations/${id}`);
  },
};

export default api;
