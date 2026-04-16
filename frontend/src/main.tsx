import React from 'react';
import ReactDOM from 'react-dom/client';
import { Provider } from 'react-redux';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import App from './App';
import Login from './components/Login';
import store from './store';
import authService from './services/authService';
import './index.css';

// 初始化身份验证
authService.initializeAuth();

// 暂时禁用受保护的路由，方便测试
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  // 暂时禁用身份验证检查，直接允许访问
  return children;
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Provider store={store}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><App /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </Provider>
  </React.StrictMode>,
);
