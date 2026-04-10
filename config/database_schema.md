# 数据库Schema设计

## 1. PostgreSQL 数据库设计

### 1.1 用户表（users）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 用户ID |
| username | VARCHAR(50) | UNIQUE NOT NULL | 用户名 |
| password_hash | VARCHAR(255) | NOT NULL | 哈希后的密码 |
| email | VARCHAR(100) | UNIQUE NOT NULL | 邮箱 |
| role | VARCHAR(20) | NOT NULL DEFAULT 'user' | 角色（admin/user） |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.2 配置表（configurations）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 配置ID |
| key | VARCHAR(50) | UNIQUE NOT NULL | 配置键 |
| value | TEXT | NOT NULL | 配置值 |
| description | TEXT | | 配置描述 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.3 告警规则表（alert_rules）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 规则ID |
| name | VARCHAR(100) | NOT NULL | 规则名称 |
| description | TEXT | | 规则描述 |
| severity | VARCHAR(20) | NOT NULL | 严重程度（low/medium/high/critical） |
| condition | JSONB | NOT NULL | 规则条件（JSON格式） |
| enabled | BOOLEAN | DEFAULT TRUE | 是否启用 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.4 告警通知渠道表（notification_channels）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 渠道ID |
| name | VARCHAR(100) | NOT NULL | 渠道名称 |
| type | VARCHAR(50) | NOT NULL | 渠道类型（email/sms/webhook） |
| config | JSONB | NOT NULL | 渠道配置（JSON格式） |
| enabled | BOOLEAN | DEFAULT TRUE | 是否启用 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.5 告警历史表（alert_history）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 告警ID |
| rule_id | INTEGER | REFERENCES alert_rules(id) | 关联的规则ID |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| message | TEXT | NOT NULL | 告警消息 |
| details | JSONB | | 详细信息 |
| status | VARCHAR(20) | DEFAULT 'new' | 状态（new/processed/closed） |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.6 攻击类型表（attack_types）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 攻击类型ID |
| name | VARCHAR(100) | UNIQUE NOT NULL | 攻击类型名称 |
| description | TEXT | | 攻击类型描述 |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

## 2. InfluxDB 数据库设计

### 2.1 攻击事件测量（attack_events）
**标签（Tags）：**
- attack_type: 攻击类型
- source_ip: 源IP地址
- target_ip: 目标IP地址
- target_port: 目标端口
- user_agent: 用户代理
- status: 攻击状态（attempted/successful）

**字段（Fields）：**
- request_method: 请求方法
- request_path: 请求路径
- request_params: 请求参数
- response_code: 响应代码
- severity: 严重程度
- details: 详细信息（JSON格式）

**时间戳（Timestamp）：**
- event_time: 事件发生时间

### 2.2 网络流量测量（network_traffic）
**标签（Tags）：**
- protocol: 协议（TCP/UDP/ICMP）
- source_ip: 源IP地址
- target_ip: 目标IP地址
- source_port: 源端口
- target_port: 目标端口
- direction: 方向（inbound/outbound）

**字段（Fields）：**
- bytes_sent: 发送字节数
- bytes_received: 接收字节数
- packet_count: 数据包数量
- duration: 连接持续时间（秒）

**时间戳（Timestamp）：**
- event_time: 事件发生时间

### 2.3 WAF日志测量（waf_logs）
**标签（Tags）：**
- action: WAF动作（block/allow/log）
- rule_id: 规则ID
- source_ip: 源IP地址
- target_host: 目标主机

**字段（Fields）：**
- request_method: 请求方法
- request_uri: 请求URI
- request_headers: 请求头（JSON格式）
- request_body: 请求体
- response_code: 响应代码
- rule_message: 规则消息

**时间戳（Timestamp）：**
- event_time: 事件发生时间

### 2.4 系统性能测量（system_metrics）
**标签（Tags）：**
- host: 主机名
- service: 服务名称

**字段（Fields）：**
- cpu_usage: CPU使用率（%）
- memory_usage: 内存使用率（%）
- disk_usage: 磁盘使用率（%）
- network_in: 网络入流量（字节/秒）
- network_out: 网络出流量（字节/秒）

**时间戳（Timestamp）：**
- event_time: 事件发生时间
