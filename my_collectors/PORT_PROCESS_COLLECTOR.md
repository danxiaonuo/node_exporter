# 端口进程采集器配置说明

本文档描述了端口进程采集器的所有配置选项。

## 环境变量配置

### 核心配置

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT_LABEL_INTERVAL` | `8h` | 端口和进程发现扫描间隔（多久刷新一次端口及其关联进程的列表） |
| `PROC_PREFIX` | 自动检测 | /proc 文件系统路径前缀（自动检测 Docker/Kubernetes 容器） |

### 端口状态检测

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT_STATUS_INTERVAL` | `1m` | TCP 端口状态检查缓存间隔 |
| `PORT_UDP_STATUS_INTERVAL` | 与 `PORT_STATUS_INTERVAL` 相同 | UDP 端口状态检查缓存间隔 |
| `PORT_CHECK_TIMEOUT` | `3s` | 单个端口连接尝试的超时时间 |
| `MAX_PARALLEL_IP_CHECKS` | `8` | 每个端口并发检查 IP 地址的最大数量 |

### HTTP 检测

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `ENABLE_HTTP_DETECTION` | `true` | 是否启用 HTTP 端口检测 |
| `PORT_HTTP_STATUS_INTERVAL` | `5m` | HTTP 端口状态检查缓存间隔 |
| `HTTP_DETECTION_INTERVAL` | `1m` | HTTP 检测工作器处理间隔 |
| `HTTP_DETECTION_CONCURRENCY` | `10` | HTTP 检测并发工作器数量 |

### 进程监控

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PROCESS_ALIVE_STATUS_INTERVAL` | `1m` | 进程存活状态检查缓存间隔 |

## 配置示例

### Docker/Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
spec:
  template:
    spec:
      containers:
      - name: node-exporter
        image: your-registry/node-exporter:latest
        env:
        # 核心配置
        - name: PORT_LABEL_INTERVAL
          value: "8h"
        - name: PROC_PREFIX
          value: "/host/proc"
        
        # 端口检测
        - name: PORT_STATUS_INTERVAL
          value: "1m"
        - name: PORT_CHECK_TIMEOUT
          value: "3s"
        - name: MAX_PARALLEL_IP_CHECKS
          value: "8"
        
        # HTTP 检测
        - name: ENABLE_HTTP_DETECTION
          value: "true"
        - name: PORT_HTTP_STATUS_INTERVAL
          value: "5m"
        - name: HTTP_DETECTION_INTERVAL
          value: "1m"
        - name: HTTP_DETECTION_CONCURRENCY
          value: "10"
        
        # 进程监控
        - name: PROCESS_ALIVE_STATUS_INTERVAL
          value: "1m"
        
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
```

### Docker Compose

```yaml
version: '3.8'
services:
  node-exporter:
    image: your-registry/node-exporter:latest
    privileged: true
    environment:
      # 核心配置
      - PORT_LABEL_INTERVAL=8h
      - PROC_PREFIX=/host/proc
      
      # 端口检测
      - PORT_STATUS_INTERVAL=1m
      - PORT_CHECK_TIMEOUT=3s
      - MAX_PARALLEL_IP_CHECKS=8
      
      # HTTP 检测
      - ENABLE_HTTP_DETECTION=true
      - PORT_HTTP_STATUS_INTERVAL=5m
      - HTTP_DETECTION_INTERVAL=1m
      - HTTP_DETECTION_CONCURRENCY=10
      
      # 进程监控
      - PROCESS_ALIVE_STATUS_INTERVAL=1m
    volumes:
      - /proc:/host/proc:ro
```

### Systemd 服务

```ini
[Unit]
Description=Node Exporter with Custom Collectors
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/node_exporter
Environment="PORT_LABEL_INTERVAL=8h"
Environment="PORT_STATUS_INTERVAL=1m"
Environment="PORT_CHECK_TIMEOUT=3s"
Environment="MAX_PARALLEL_IP_CHECKS=8"
Environment="ENABLE_HTTP_DETECTION=true"
Environment="PORT_HTTP_STATUS_INTERVAL=5m"
Environment="HTTP_DETECTION_INTERVAL=1m"
Environment="HTTP_DETECTION_CONCURRENCY=10"
Environment="PROCESS_ALIVE_STATUS_INTERVAL=1m"

[Install]
WantedBy=multi-user.target
```

## 性能调优

### 高流量环境

```bash
# 减少扫描频率以最小化资源使用
export PORT_LABEL_INTERVAL=12h
export PORT_STATUS_INTERVAL=2m
export PORT_HTTP_STATUS_INTERVAL=10m
export HTTP_DETECTION_INTERVAL=2m

# 增加并发数以加快检测速度
export MAX_PARALLEL_IP_CHECKS=16
export HTTP_DETECTION_CONCURRENCY=20

# 减少超时时间以加快失败检测
export PORT_CHECK_TIMEOUT=1s
```

### 低资源环境

```bash
# 增加间隔时间以减少资源使用
export PORT_LABEL_INTERVAL=24h
export PORT_STATUS_INTERVAL=5m
export PORT_HTTP_STATUS_INTERVAL=15m
export HTTP_DETECTION_INTERVAL=5m

# 减少并发数以最小化资源使用
export MAX_PARALLEL_IP_CHECKS=4
export HTTP_DETECTION_CONCURRENCY=5

# 增加超时时间以适应较慢的网络
export PORT_CHECK_TIMEOUT=5s
```

### 禁用 HTTP 检测

```bash
# 完全禁用 HTTP 检测以节省资源
export ENABLE_HTTP_DETECTION=false
```

## 指标说明

采集器提供以下指标：

- `node_tcp_port_alive`: TCP 端口存活状态 (1=存活, 0=死亡)
- `node_tcp_port_response_seconds`: TCP 端口响应时间（秒）
- `node_udp_port_alive`: UDP 端口存活状态 (1=存在, 0=不存在)
- `node_http_port_alive`: HTTP 端口存活状态 (1=存活, 0=死亡)
- `node_process_alive`: 进程存活状态 (1=存活, 0=死亡)

所有指标都包含标签：`process_name`, `exe_path`, `port`（除了 `node_process_alive` 使用 `process_name` 和 `exe_path`）。

## 故障排除

### 常见问题

1. **"Unsolicited response received on idle HTTP channel"**: 这表示 HTTP 检测遇到了非 HTTP 服务（如 VNC）。检测逻辑已经改进，更加严格。

2. **资源使用过高**: 考虑增加间隔时间并减少并发数。

3. **缺少进程信息**: 确保容器可以访问主机的 `/proc` 文件系统。

4. **权限被拒绝错误**: 使用 `--privileged` 运行容器或适当的权限。

### 调试模式

要启用调试日志，设置 `DEBUG` 环境变量：

```bash
export DEBUG=true
```

这将提供关于端口检测、HTTP 检测和缓存操作的详细信息。

## 功能特性

### 自动发现机制
- 自动发现主机上所有监听的 TCP 和 UDP 端口及其关联进程
- 支持 IPv4 和 IPv6 地址
- 智能缓存机制，减少系统负载

### HTTP 检测优化
- 异步检测，不阻塞指标暴露
- 严格的 HTTP 协议验证，避免误报
- 智能缓存和历史记录机制

### 性能优化
- 并发检测，提高检测效率
- 可配置的超时和并发控制
- 多级缓存机制

### 容器支持
- 自动检测 Docker/Kubernetes 环境
- 支持挂载主机 /proc 文件系统
- 灵活的配置选项

## 使用建议

1. **生产环境**: 建议使用默认配置，根据实际负载调整并发数
2. **开发环境**: 可以增加检测频率以获得更实时的数据
3. **资源受限环境**: 建议增加间隔时间并减少并发数
4. **高安全环境**: 考虑禁用 HTTP 检测以减少网络活动