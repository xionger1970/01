// Attack event types
export interface AttackEvent {
  id: number;
  attack_type: string;
  source_ip: string;
  target_ip: string;
  target_port: number;
  user_agent: string | null;
  status: string;
  request_method: string;
  request_path: string;
  request_params: Record<string, any> | null;
  response_code: number;
  severity: string;
  details: Record<string, any> | null;
  event_time: string;
}

// Alert types
export interface AlertRule {
  id: number;
  name: string;
  description: string | null;
  severity: string;
  condition: Record<string, any>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertHistory {
  id: number;
  rule_id: number;
  severity: string;
  message: string;
  details: Record<string, any> | null;
  status: string;
  created_at: string;
  updated_at: string;
}

// Dashboard types
export interface DashboardOverview {
  total_attacks: number;
  active_attacks: number;
  top_attack_types: Array<{ type: string; count: number }>;
  top_source_ips: Array<{ ip: string; count: number }>;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  attack_trend: Array<{ timestamp: string; count: number }>;
}

export interface TopTarget {
  target: string;
  count: number;
  attack_types: string[];
}

export interface SystemStatus {
  services: Array<{ name: string; status: string; uptime: string }>;
  resources: {
    cpu_usage: string;
    memory_usage: string;
    disk_usage: string;
    network_in: string;
    network_out: string;
  };
}

// Configuration types
export interface UserConfiguration {
  language: string;
  timezone: string;
}

export interface SystemConfiguration {
  autoRefresh: boolean;
  refreshInterval: number;
  maxEvents: number;
}

export interface NotificationConfiguration {
  emailNotifications: boolean;
  smsNotifications: boolean;
  email: string;
  phone: string;
}

export interface Configuration {
  id: number;
  key: string;
  value: UserConfiguration | SystemConfiguration | NotificationConfiguration | string;
  description: string | null;
  created_at: string;
  updated_at: string;
}

// User types
export interface User {
  username: string;
  role: string;
}

export interface Token {
  access_token: string;
  token_type: string;
}

// Dashboard configuration types
export interface DashboardWidget {
  id: string;
  type: 'summary' | 'trend' | 'severity' | 'targets' | 'system';
  title: string;
  x: number;
  y: number;
  width: number;
  height: number;
  visible: boolean;
}

export interface DashboardConfiguration {
  widgets: DashboardWidget[];
  layout: 'grid' | 'custom';
  theme: 'light' | 'dark';
}
