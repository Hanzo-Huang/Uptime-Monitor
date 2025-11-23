# Uptime Monitor 需求与功能规格说明书

## 1. 项目概述
本项目是一个基于 **Cloudflare Workers** (后端) 和 **Cloudflare Pages** (前端) 的网站监控系统。
主要用于实时监控网站的连通性、SSL 证书有效期及域名过期时间。支持多渠道通知（钉钉机器人）、故障重试机制、以及可视化的管理后台和公开状态页。

## 2. 系统架构
- **后端**: Cloudflare Workers (Hono 框架) + D1 Database (SQLite)
- **前端**: Cloudflare Pages (Vue 3 + TailwindCSS + FontAwesome)
- **代码托管**: GitHub
- **通知服务**: 钉钉群机器人 (Webhook + 加签安全验证)
- **外部 API**: `crt.sh` (SSL查询), `rdap.org` (域名查询)

## 3. 功能特性

### 3.1 核心监控 (Worker)
- **连通性监测**: 每 1 分钟触发一次 Cron 任务，检查所有站点的 HTTP 状态码。
- **重试机制**:
    - 首次检测失败，状态标记为 `RETRYING`，重试计数器 +1。
    - 连续失败 3 次后，状态标记为 `DOWN`，并触发告警。
    - 恢复正常时，状态更新为 `UP`，并发送恢复通知。
- **SSL 证书监控**:
    - 自动获取 SSL 证书过期时间（支持泛域名证书自动识别）。
    - 每日自动刷新证书信息。
- **域名过期监控**:
    - 自动获取域名注册过期时间。
- **自定义 User-Agent**:
    - 支持为每个监控项单独设置 UA，模拟不同客户端访问。

### 3.2 告警通知 (钉钉)
- **Markdown 格式通知**:
    - 告警标题醒目（红色/绿色）。
    - 包含详细信息：故障 URL、状态码、耗时、失败原因。
    - 包含 SSL 和域名过期提醒。
- **安全验证**: 支持钉钉机器人的加签 (HMAC-SHA256) 验证。

### 3.3 公开状态页 (Public Status Page)
- **免登录访问**: 任何人均可查看。
- **现代 UI 设计**:
    - 深色模式 (Dark Mode) / 浅色模式自适应。
    - 霓虹光效与磨砂玻璃质感。
    - 移动端适配优化（响应式布局）。
- **信息展示**:
    - 整体系统状态 (Operational / Disruption)。
    - 每个站点的在线状态、SSL 有效期（剩余天数）、上次检查时间。
- **自定义域名**: 支持绑定自定义域名访问 API。

### 3.4 管理后台 (Admin Dashboard)
- **安全认证**:
    - 基于密码的简单认证机制。
    - 登录状态持久化 (SessionStorage)。
- **监控管理**:
    - 添加监控：支持设置名称、URL、关键词、自定义 UA。
    - 删除监控：连带删除相关日志。
- **日志查看**:
    - 侧滑抽屉式查看最近的检测日志（状态码、耗时、结果）。
- **界面设计**:
    - 现代化 Dashboard 风格。
    - 响应式设计，支持移动端管理。

## 4. 数据库设计 (Cloudflare D1)

### monitors 表
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| id | INTEGER PK | 自增 ID |
| name | TEXT | 网站名称 |
| url | TEXT | 监控 URL |
| method | TEXT | 请求方法 (默认 GET) |
| interval | INTEGER | 监控间隔 (秒) |
| status | TEXT | 当前状态 (UP/DOWN/RETRYING) |
| retry_count | INTEGER | 当前重试次数 |
| last_check | DATETIME | 上次检查时间 |
| keyword | TEXT | 关键词验证 (可选) |
| user_agent | TEXT | 自定义 UA (可选) |
| domain_expiry| DATETIME | 域名过期时间 |
| cert_expiry | DATETIME | SSL 证书过期时间 |
| check_info_status | TEXT | 证书更新任务状态 |
| created_at | DATETIME | 创建时间 |

### logs 表
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| id | INTEGER PK | 自增 ID |
| monitor_id | INTEGER FK | 关联 monitor.id |
| status_code | INTEGER | HTTP 状态码 |
| latency | INTEGER | 响应耗时 (ms) |
| is_fail | BOOLEAN | 是否失败 |
| reason | TEXT | 失败原因 |
| created_at | DATETIME | 记录时间 |

## 5. API 接口 (RESTful)

- `GET /monitors/public`: 获取公开监控数据 (无需认证)。
- `GET /monitors`: 获取所有监控详情 (需认证)。
- `POST /monitors`: 添加新监控 (需认证)。
- `DELETE /monitors/:id`: 删除监控 (需认证)。
- `GET /monitors/:id/logs`: 获取指定监控日志 (需认证)。
- `POST /test-alert`: 测试钉钉通知 (调试用)。
