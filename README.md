# Prometheus node_exporter 插件化增强版

本项目基于官方 [Prometheus node_exporter](https://github.com/prometheus/node_exporter) 扩展，支持**自定义采集器插件**的自动注册与高性能指标采集，适用于物理机、容器、Kubernetes 等多种场景。

---

## 主要特性

- **插件化采集器机制**：支持在 `my_collectors/` 目录下编写自定义采集器（Collector），一键自动注册，无需手动修改主程序。
- **高性能端口-进程采集器**：自动发现监听端口与进程，检测端口/HTTP存活、响应时间，支持大规模主机高并发采集。
- **硬件、网卡、登录失败等多种插件**：开箱即用，支持硬件信息、物理网卡、登录失败次数等常见运维指标。
- **环境变量灵活配置**：所有检测周期、超时、并发、排除进程等均可通过环境变量灵活调整。
- **官方兼容性**：构建流程、版本信息注入、产物命名等与官方 node_exporter 保持一致。
- **CI/CD 自动化**：支持 GitHub Actions 自动注册插件、构建多平台产物、发布 Release。

---

## 目录结构

```
node_exporter/
├── collector/                  # 官方采集器主目录
├── my_collectors/              # 自定义采集器插件目录
│   ├── port_process_collector.go
│   ├── hardware_info_collector.go
│   ├── network_interface_collector.go
│   ├── login_failed_collector.go
│   └── auto_register_collectors.sh  # 自动注册脚本
└── ...
```

---

## 编写自定义插件（Collector）

### 1. 新建插件源码

- 在 `my_collectors/` 目录下新建 `xxx_collector.go`，包名为 `my_collectors`。
- 导出构造函数 `NewXxxCollector()`，如 `port_process_collector.go` → `NewPortProcessCollector()`。
- 实现 Prometheus 的 `Collector` 接口（`Describe`/`Collect` 或 `Update` 方法）。
- 指标命名、标签、help 建议参照官方风格。

**示例：**
```go
package my_collectors

import "github.com/prometheus/client_golang/prometheus"

type MyCollector struct {
    myMetric *prometheus.Desc
}

func NewMyCollector() *MyCollector {
    return &MyCollector{
        myMetric: prometheus.NewDesc(
            "node_my_metric",
            "自定义指标说明",
            []string{"label1"}, nil,
        ),
    }
}

func (c *MyCollector) Describe(ch chan<- *prometheus.Desc) {
    ch <- c.myMetric
}

func (c *MyCollector) Collect(ch chan<- prometheus.Metric) {
    // 采集逻辑
    ch <- prometheus.MustNewConstMetric(c.myMetric, prometheus.GaugeValue, 1, "value1")
}
```

### 2. 自动注册插件

- 运行自动注册脚本：
  ```sh
  bash my_collectors/auto_register_collectors.sh
  ```
- 脚本会自动：
  - 扫描 `my_collectors/` 下所有 `*_collector.go` 文件
  - 生成 import 和注册代码，插入 `collector/collector.go`（幂等安全）
  - 支持多插件批量注册

### 3. 编译与运行

- 依赖拉取：
  ```sh
  cd node_exporter
  go mod tidy
  ```
- 编译：
  ```sh
  go build -o node_exporter
  ```
- 运行：
  ```sh
  ./node_exporter
  # 访问 http://localhost:9100/metrics 查看自定义指标
  ```

---

## 主要内置插件说明

- **端口-进程采集器（port_process_collector.go）**
  - 自动发现监听端口与进程，检测 TCP/UDP/HTTP 存活、响应时间
  - 支持高并发、超时、排除进程、容器兼容等
  - HTTP检测采用异步机制，严格协议验证，避免误报
  - 所有检测周期、超时、并发数均可通过环境变量配置
  - 详见 [`my_collectors/PORT_PROCESS_COLLECTOR.md`](my_collectors/PORT_PROCESS_COLLECTOR.md)
- **硬件信息采集器（hardware_info_collector.go）**
  - 自动采集主板、CPU、内存、磁盘、操作系统等信息
  - 详见 [`my_collectors/hardware_info_collector.md`](my_collectors/hardware_info_collector.md)
- **物理网卡采集器（network_interface_collector.go）**
  - 自动采集物理网卡及 IPv4 地址
  - 详见 [`my_collectors/network_interface_collector.md`](my_collectors/network_interface_collector.md)
- **登录失败次数采集器（login_failed_collector.go）**
  - 自动采集主机登录失败次数
  - 详见 [`my_collectors/login_failed_collector.md`](my_collectors/login_failed_collector.md)

---

## 环境变量与配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `PORT_CHECK_TIMEOUT` | `3s` | 端口检测超时时间 |
| `PORT_STATUS_INTERVAL` | `30s` | TCP端口状态检测间隔 |
| `PORT_HTTP_STATUS_INTERVAL` | `5m` | HTTP端口状态检测间隔（完全异步检测） |
| `PORT_UDP_STATUS_INTERVAL` | `30s` | UDP端口状态检测间隔 |
| `PROCESS_ALIVE_STATUS_INTERVAL` | `1m` | 进程存活状态检测间隔 |
| `PORT_LABEL_INTERVAL` | `8h` | 端口和进程发现扫描间隔 |
| `MAX_PARALLEL_IP_CHECKS` | `8` | 最大并发端口检测数 |
| `ENABLE_HTTP_DETECTION` | `true` | 是否启用HTTP检测 |
| `HTTP_DETECTION_CONCURRENCY` | `10` | HTTP检测并发数 |
| `HTTP_DETECTION_INTERVAL` | `30s` | HTTP检测工作器处理间隔（完全异步） |
| `FAST_MODE` | `true` | 快速模式（减少TCP检测超时） |
| `PROC_PREFIX` | 自动检测 | 容器环境下的/proc路径前缀 |

---

## Docker/Kubernetes 部署示例

**Docker 采集宿主机进程/端口：**
```sh
docker run --rm \
  --privileged \
  -v /proc:/host/proc:ro \
  -e PROC_PREFIX=/host/proc \
  -e PORT_CHECK_TIMEOUT=3s \
  -e PORT_HTTP_STATUS_INTERVAL=5m \
  -e HTTP_DETECTION_INTERVAL=1m \
  -e HTTP_DETECTION_CONCURRENCY=10 \
  -e ENABLE_HTTP_DETECTION=true \
  -e EXCLUDED_PROCESS_NAMES=nginx,redis \
  --user root \
  your_image_name
```

**Kubernetes DaemonSet 采集宿主机：**
```yaml
containers:
  - name: node-exporter
    image: your_image_name
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
      - name: proc
        mountPath: /host/proc
        readOnly: true
    env:
      - name: PROC_PREFIX
        value: /host/proc
      - name: PORT_CHECK_TIMEOUT
        value: "3s"
      - name: PORT_HTTP_STATUS_INTERVAL
        value: "5m"
      - name: HTTP_DETECTION_INTERVAL
        value: "1m"
      - name: HTTP_DETECTION_CONCURRENCY
        value: "10"
      - name: ENABLE_HTTP_DETECTION
        value: "true"
      - name: EXCLUDED_PROCESS_NAMES
        value: nginx,redis
volumes:
  - name: proc
    hostPath:
      path: /proc
      type: Directory
```

---

## CI/CD 与版本信息注入

- GitHub Actions 自动注册插件、构建多平台产物、发布 Release
- 自动注入版本号、commit、分支、构建时间、构建用户等信息，保持与官方一致
- 详见 `.github/workflows/main.yml`

---

## 常见问题

- **插件注册无效？**
  - 请确认已运行 `auto_register_collectors.sh` 并重新编译
- **/metrics 加载慢？**
  - 检查端口检测超时、并发数、主机端口数量，合理调整环境变量
- **容器采集不到宿主机进程？**
  - 请确保挂载 `/proc` 并以 root/特权模式运行，`PROC_PREFIX` 配置正确
- **如何只采集/排除特定进程？**
  - 配置 `EXCLUDED_PROCESS_NAMES` 环境变量
- **HTTP检测遇到"Unsolicited response received on idle HTTP channel"报错？**
  - 说明：HTTP检测遇到非HTTP协议端口（如VNC/RFB）时会报此错，已通过严格协议判断优化，建议升级到最新版
- **遇到"write: broken pipe"错误？**
  - 说明：客户端在指标暴露过程中断开了连接，建议启用快速模式：`export FAST_MODE=true`，或减少超时时间：`export PORT_CHECK_TIMEOUT=1s`
- **更多问题**：详见各插件 `*.md` 文档

---

## 贡献与支持

- 欢迎提交自定义采集器插件，建议遵循官方 Collector 接口和命名规范
- 有问题请提交 issue 或联系维护者

---

## License

本项目遵循 [Apache 2.0 License](LICENSE) 