import api from './api';
import type { User, Token } from '../types';

// 存储令牌的键
const TOKEN_KEY = 'auth_token';
const USER_KEY = 'auth_user';

/**
 * 身份验证服务
 */
export const authService = {
  /**
   * 登录
   * @param username 用户名
   * @param password 密码
   * @returns 令牌和用户信息
   */
  login: async (username: string, password: string): Promise<{ token: Token; user: User }> => {
    try {
      const response = await api.post<Token>('/auth/token', new URLSearchParams({
        username,
        password,
        grant_type: 'password'
      }), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      const token = response.data;
      
      // 保存令牌到本地存储
      localStorage.setItem(TOKEN_KEY, token.access_token);
      
      // 获取用户信息
      const user = await authService.getCurrentUser();
      
      // 保存用户信息到本地存储
      localStorage.setItem(USER_KEY, JSON.stringify(user));
      
      // 更新 api 实例的默认 headers
      api.defaults.headers.common['Authorization'] = `Bearer ${token.access_token}`;
      
      return { token, user };
    } catch (error) {
      throw new Error('登录失败，请检查用户名和密码');
    }
  },

  /**
   * 注册
   * @param username 用户名
   * @param password 密码
   * @param role 角色
   * @returns 注册结果
   */
  register: async (username: string, password: string, role: string = 'user'): Promise<{ message: string }> => {
    try {
      const response = await api.post('/auth/register', null, {
        params: { username, password, role }
      });
      return response.data;
    } catch (error) {
      throw new Error('注册失败，用户名可能已存在');
    }
  },

  /**
   * 获取当前用户信息
   * @returns 用户信息
   */
  getCurrentUser: async (): Promise<User> => {
    try {
      const response = await api.get<User>('/auth/me');
      return response.data;
    } catch (error) {
      throw new Error('获取用户信息失败');
    }
  },

  /**
   * 登出
   */
  logout: (): void => {
    // 清除本地存储
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    
    // 清除 api 实例的 Authorization header
    delete api.defaults.headers.common['Authorization'];
  },

  /**
   * 检查是否已登录
   * @returns 是否已登录
   */
  isAuthenticated: (): boolean => {
    return !!localStorage.getItem(TOKEN_KEY);
  },

  /**
   * 获取存储的用户信息
   * @returns 用户信息或 null
   */
  getStoredUser: (): User | null => {
    const userStr = localStorage.getItem(USER_KEY);
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch (error) {
      return null;
    }
  },

  /**
   * 初始化身份验证
   * 从本地存储中恢复令牌和用户信息
   */
  initializeAuth: (): void => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
  }
};

export default authService;