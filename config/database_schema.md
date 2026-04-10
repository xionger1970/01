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
| type | VARCHAR(50) | NOT NULL | 渠道类型（email/sms/webhook/slack/telegram/dingtalk） |
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

### 1.7 网络流量会话表（network_sessions）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 会话ID |
| source_ip | INET | NOT NULL | 源IP地址 |
| source_port | INTEGER | | 源端口 |
| target_ip | INET | NOT NULL | 目标IP地址 |
| target_port | INTEGER | | 目标端口 |
| protocol | VARCHAR(10) | NOT NULL | 协议（TCP/UDP/ICMP） |
| bytes_sent | BIGINT | DEFAULT 0 | 发送字节数 |
| bytes_received | BIGINT | DEFAULT 0 | 接收字节数 |
| packet_count | INTEGER | DEFAULT 0 | 数据包数量 |
| duration | INTEGER | | 持续时间（秒） |
| start_time | TIMESTAMP | NOT NULL | 开始时间 |
| end_time | TIMESTAMP | | 结束时间 |
| flags | VARCHAR(50) | | TCP标志 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.8 HTTP流量表（http_traffic）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | HTTP流量ID |
| session_id | INTEGER | REFERENCES network_sessions(id) | 关联会话ID |
| source_ip | INET | NOT NULL | 源IP地址 |
| target_ip | INET | NOT NULL | 目标IP地址 |
| method | VARCHAR(10) | NOT NULL | HTTP方法 |
| host | VARCHAR(255) | | 主机名 |
| url | TEXT | NOT NULL | 请求URL |
| uri | TEXT | | URI |
| status_code | INTEGER | | 响应状态码 |
| user_agent | TEXT | | User-Agent |
| referer | TEXT | | Referer |
| request_headers | JSONB | | 请求头 |
| response_headers | JSONB | | 响应头 |
| request_body | TEXT | | 请求体 |
| response_body | TEXT | | 响应体 |
| content_type | VARCHAR(100) | | 内容类型 |
| content_length | INTEGER | | 内容长度 |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.9 DNS查询表（dns_queries）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | DNS查询ID |
| session_id | INTEGER | REFERENCES network_sessions(id) | 关联会话ID |
| source_ip | INET | NOT NULL | 源IP地址 |
| target_ip | INET | | DNS服务器IP |
| query_type | VARCHAR(10) | NOT NULL | 查询类型（A/AAAA/MX/NS等） |
| query_name | VARCHAR(255) | NOT NULL | 查询域名 |
| answers | JSONB | | 应答结果 |
| response_code | INTEGER | | 响应码 |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.10 FTP会话表（ftp_sessions）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | FTP会话ID |
| session_id | INTEGER | REFERENCES network_sessions(id) | 关联会话ID |
| source_ip | INET | NOT NULL | 源IP地址 |
| target_ip | INET | NOT NULL | 目标IP地址 |
| username | VARCHAR(100) | | 用户名 |
| command | VARCHAR(50) | | FTP命令 |
| argument | TEXT | | 命令参数 |
| response_code | INTEGER | | 响应码 |
| response_message | TEXT | | 响应消息 |
| file_size | BIGINT | | 文件大小 |
| file_name | VARCHAR(255) | | 文件名 |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.11 防火墙日志表（firewall_logs）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 防火墙日志ID |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| device_name | VARCHAR(100) | | 设备名称 |
| action | VARCHAR(20) | NOT NULL | 动作（allow/deny/drop） |
| source_ip | INET | | 源IP地址 |
| source_port | INTEGER | | 源端口 |
| source_zone | VARCHAR(50) | | 源区域 |
| target_ip | INET | | 目标IP地址 |
| target_port | INTEGER | | 目标端口 |
| target_zone | VARCHAR(50) | | 目标区域 |
| protocol | VARCHAR(10) | | 协议 |
| rule_name | VARCHAR(100) | | 规则名称 |
| rule_id | INTEGER | | 规则ID |
| bytes_sent | BIGINT | | 发送字节数 |
| bytes_received | BIGINT | | 接收字节数 |
| packet_count | INTEGER | | 数据包数量 |
| nat_source_ip | INET | | NAT源IP |
| nat_source_port | INTEGER | | NAT源端口 |
| nat_target_ip | INET | | NAT目标IP |
| nat_target_port | INTEGER | | NAT目标端口 |
| raw_log | TEXT | | 原始日志 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.12 WAF日志表（waf_logs）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | WAF日志ID |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| device_name | VARCHAR(100) | | 设备名称 |
| action | VARCHAR(20) | NOT NULL | 动作（block/allow/challenge） |
| rule_id | VARCHAR(50) | | 规则ID |
| rule_name | VARCHAR(255) | | 规则名称 |
| rule_category | VARCHAR(100) | | 规则类别 |
| severity | VARCHAR(20) | | 严重程度 |
| source_ip | INET | NOT NULL | 源IP地址 |
| source_port | INTEGER | | 源端口 |
| country | VARCHAR(100) | | 国家 |
| target_host | VARCHAR(255) | | 目标主机 |
| method | VARCHAR(10) | | HTTP方法 |
| uri | TEXT | | 请求URI |
| query_string | TEXT | | 查询字符串 |
| user_agent | TEXT | | User-Agent |
| referer | TEXT | | Referer |
| request_headers | JSONB | | 请求头 |
| request_body | TEXT | | 请求体 |
| response_code | INTEGER | | 响应码 |
| attack_type | VARCHAR(100) | | 攻击类型 |
| matched_location | VARCHAR(100) | | 匹配位置 |
| matched_value | TEXT | | 匹配值 |
| session_id | VARCHAR(100) | | 会话ID |
| raw_log | TEXT | | 原始日志 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.13 系统日志表（system_logs）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 系统日志ID |
| timestamp | TIMESTAMP | NOT NULL | 时间戳 |
| hostname | VARCHAR(100) | | 主机名 |
| os_type | VARCHAR(50) | | 操作系统类型（Linux/Windows） |
| facility | VARCHAR(50) | | 设施（syslog facility） |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| program | VARCHAR(100) | | 程序名称 |
| pid | INTEGER | | 进程ID |
| message | TEXT | NOT NULL | 日志消息 |
| username | VARCHAR(100) | | 用户名 |
| process_name | VARCHAR(100) | | 进程名称 |
| command_line | TEXT | | 命令行 |
| event_id | VARCHAR(50) | | 事件ID（Windows） |
| event_code | INTEGER | | 事件代码 |
| source_ip | INET | | 源IP（远程登录等） |
| raw_log | TEXT | | 原始日志 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |

### 1.14 数据源配置表（data_sources）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 数据源ID |
| name | VARCHAR(100) | NOT NULL | 数据源名称 |
| type | VARCHAR(50) | NOT NULL | 类型（suricata/zeek/firewall/waf/system/web） |
| config | JSONB | NOT NULL | 配置（JSON格式） |
| status | VARCHAR(20) | DEFAULT 'inactive' | 状态（active/inactive/error） |
| last_seen | TIMESTAMP | | 最后活动时间 |
| error_message | TEXT | | 错误信息 |
| enabled | BOOLEAN | DEFAULT TRUE | 是否启用 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.15 CVE漏洞规则表（cve_rules）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 规则ID |
| cve_id | VARCHAR(20) | UNIQUE NOT NULL | CVE编号 |
| name | VARCHAR(255) | NOT NULL | 漏洞名称 |
| description | TEXT | | 漏洞描述 |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| cvss_score | DECIMAL(3,1) | | CVSS评分 |
| affected_software | JSONB | | 受影响软件 |
| detection_pattern | TEXT | | 检测模式（正则表达式） |
| mitigation | TEXT | | 缓解措施 |
| published_date | DATE | | 发布日期 |
| last_updated | DATE | | 最后更新日期 |
| enabled | BOOLEAN | DEFAULT TRUE | 是否启用 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.16 MITRE ATT&CK映射表（mitre_attack_mappings）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 映射ID |
| technique_id | VARCHAR(20) | NOT NULL | 技术ID（如 T1059.007） |
| technique_name | VARCHAR(255) | NOT NULL | 技术名称 |
| tactic | VARCHAR(100) | NOT NULL | 战术（如 Initial Access） |
| description | TEXT | | 技术描述 |
| attack_type | VARCHAR(100) | | 攻击类型关联 |
| severity | VARCHAR(20) | | 严重程度 |
| mitigation | TEXT | | 缓解措施 |
| detection | TEXT | | 检测方法 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.17 白名单表（whitelist）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 白名单ID |
| type | VARCHAR(20) | NOT NULL | 类型（ip/domain/url/user/process） |
| value | VARCHAR(255) | NOT NULL | 白名单值 |
| description | TEXT | | 描述 |
| source | VARCHAR(100) | | 来源（如 internal/thirdparty） |
| expires_at | TIMESTAMP | | 过期时间 |
| enabled | BOOLEAN | DEFAULT TRUE | 是否启用 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.18 告警聚合表（alert_aggregations）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 聚合ID |
| source_ip | INET | NOT NULL | 源IP地址 |
| attack_type | VARCHAR(100) | NOT NULL | 攻击类型 |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| count | INTEGER | DEFAULT 1 | 攻击次数 |
| first_seen | TIMESTAMP | NOT NULL | 首次出现时间 |
| last_seen | TIMESTAMP | NOT NULL | 最后出现时间 |
| status | VARCHAR(20) | DEFAULT 'active' | 状态（active/processed/closed） |
| details | JSONB | | 详细信息 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

### 1.19 时间窗口分析表（time_window_analysis）
| 字段名 | 数据类型 | 约束 | 描述 |
|-------|---------|------|------|
| id | SERIAL | PRIMARY KEY | 分析ID |
| type | VARCHAR(50) | NOT NULL | 分析类型（login_failure/brute_force/port_scan） |
| target | VARCHAR(255) | NOT NULL | 目标（如 IP/用户名） |
| source_ip | INET | | 源IP地址 |
| count | INTEGER | DEFAULT 1 | 事件次数 |
| window_start | TIMESTAMP | NOT NULL | 窗口开始时间 |
| window_end | TIMESTAMP | NOT NULL | 窗口结束时间 |
| threshold | INTEGER | NOT NULL | 阈值 |
| severity | VARCHAR(20) | NOT NULL | 严重程度 |
| status | VARCHAR(20) | DEFAULT 'active' | 状态（active/processed/closed） |
| details | JSONB | | 详细信息 |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 创建时间 |
| updated_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | 更新时间 |

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
