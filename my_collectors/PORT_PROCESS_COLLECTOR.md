# 端口与进程自动发现及监控插件说明

## 功能简介

本插件用于自动发现主机（支持物理机和容器）上的所有监听TCP和UDP端口及其关联进程，并监控端口存活、进程存活、端口响应时间等关键指标。适用于 Prometheus 监控体系，便于故障告警和运维分析。

- 自动发现主机所有监听**TCP/UDP端口**及其进程（标签内容每8小时刷新一次，周期可配置）
- 检测TCP端口是否存活（可访问/假死检测，检测周期可配置，默认每1分钟检测一次）
- 检测UDP端口是否存在（只判断端口存在性）
- 检测TCP端口响应时间（秒，UDP不采集响应时间，检测周期同上）
- 检测进程是否存活
- 支持排除常见系统和监控进程，避免无意义采集
- 适用于物理机和容器环境
- **TCP/UDP端口指标名称区分，UDP端口只采集存在性，不采集响应时间**

## 检测周期说明

- **端口状态检测周期**（PORT_STATUS_INTERVAL）：
  - 控制 TCP 端口存活状态（1/0）和响应时间的检测频率。
  - 可通过环境变量 `PORT_STATUS_INTERVAL` 配置，支持 Go duration 格式（如 `1m`, `30s`）。
  - 默认值为 `1m`（每1分钟检测一次）。

- **标签内容检测周期**（PORT_LABEL_INTERVAL）：
  - 控制端口-进程映射（即指标标签内容，如 process_name、exe_path、port）的刷新频率。
  - 可通过环境变量 `PORT_LABEL_INTERVAL` 配置，支持 Go duration 格式。
  - 默认值为 `8h`（每8小时刷新一次标签内容）。

### 配置示例

```sh
export PORT_STATUS_INTERVAL=1m
export PORT_LABEL_INTERVAL=8h
```

这样配置后，端口状态和响应时间每1分钟检测一次，标签内容每8小时刷新一次。

## 指标说明

### 1. TCP端口存活状态
```
node_tcp_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 1
```
- 1 表示TCP端口可建立连接，0 表示端口不可访问。
- labels:
  - process_name：进程名
  - exe_path：可执行文件路径
  - port：端口号
- **此指标只检测TCP连接是否可达，不做HTTP请求。**

### 2. TCP端口响应时间
```
node_tcp_port_response_seconds{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 0.0015
```
- 数值为TCP端口连接耗时（单位：秒）。
- labels 同上。
- **此指标只反映TCP连接耗时，不包含HTTP响应时间。**

### 3. HTTP端口存活状态（假死检测）
```
node_http_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 1
```
- 1 表示HTTP服务可访问（有响应头），0 表示HTTP服务不可用或假死。
- labels 同上。
- **此指标专门检测HTTP服务可用性，适合做Web服务假死/异常监控。**

### 4. UDP端口存活状态
```
node_udp_port_alive{process_name="dnsmasq", exe_path="/usr/sbin/dnsmasq", port="53"} 1
```
- 1 表示UDP端口存在。
- labels 同上。
- **UDP端口不采集响应时间。**

### 5. 进程存活状态
```
node_process_alive{process_name="nginx", exe_path="/usr/sbin/nginx"} 1
```
- 1 表示进程存活，0 表示进程不存在。
- labels:
  - process_name：进程名
  - exe_path：可执行文件路径

## 工作原理

1. **端口与进程自动发现**：
   - 每隔 `PORT_LABEL_INTERVAL`（默认8小时）扫描一次 `/proc` 目录，发现所有监听**TCP/UDP端口**及其关联进程。
   - 只采集 LISTEN 状态的TCP端口和所有UDP端口。
   - TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
   - 排除常见系统进程和监控进程（如 systemd、zabbix、prometheus、node_exporter 等）。
   - **TCP端口采集 /proc/net/tcp 和 /proc/net/tcp6，UDP端口采集 /proc/net/udp 和 /proc/net/udp6。**
2. **端口状态与响应时间检测**：
   - 每隔 `PORT_STATUS_INTERVAL`（默认1分钟）检测一次所有已发现TCP端口的存活状态和响应时间。
   - `node_tcp_port_alive` 只检测TCP连接是否可达。
   - `node_tcp_port_response_seconds` 只反映TCP连接耗时。
   - `node_http_port_alive` 检测HTTP服务可用性（假死检测，检测周期同上）。
   - UDP端口只判断端口存在，不检测连通性和响应时间。
   - 进程检测只要 `/proc/<pid>` 存在即认为存活。

## 使用方法

1. 将 `port_process_collector.go` 添加到 `my_collectors/` 目录。
2. 在 node_exporter 的采集器注册机制中注册该 Collector（如自动注册脚本）。
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到相关指标。

## 注意事项

- 端口/进程发现周期和端口状态检测周期均可通过环境变量配置，详见上文。
- 只采集 LISTEN 状态的TCP端口和所有UDP端口。
- TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
- 排除列表可在 `isExcludedProcess` 函数中自定义。
- 插件对服务器性能影响极小，适合生产环境使用。
- **UDP端口只采集存在性，不采集响应时间。**
- **本采集器已适配 node_exporter 的本地 Collector 接口，实现了 Update 方法，兼容 Prometheus 和 node_exporter 框架。**
- **node_process_alive 指标只会为每个唯一进程采集和上报一次，避免重复指标冲突。**
- **{process_name, exe_path} 的对象池是在首次启动和每次标签刷新周期时更新，采集指标时遍历的是上次发现的那一批对象。**

## 常见问题

- **Q: 为什么有些端口/进程没有被采集？**
  - 可能被排除列表过滤，或进程未监听TCP/UDP端口。
- **Q: 如何调整检测周期？**
  - 通过环境变量 `PORT_STATUS_INTERVAL` 和 `PORT_LABEL_INTERVAL` 配置。
- **Q: 如何只采集特定端口或进程？**
  - 可在 `discoverPortProcess` 中增加白名单逻辑。

## 联系与支持

如有更多需求或问题，请联系开发者或提交 issue。

---

## 编译与运行

### 1. 安装 Go 环境

请确保已安装 Go（建议 1.18 及以上版本）。
可通过命令检查：
```sh
go version
```

### 2. 拉取依赖

在 node_exporter 项目根目录下执行：
```sh
go mod tidy
```
这会自动拉取和整理所有依赖。

### 3. 编译 node_exporter

在项目根目录下执行：
```sh
go build -o node_exporter
```
编译成功后，会在当前目录生成 `node_exporter` 可执行文件（Windows 下为 `node_exporter.exe`）。

### 4. 运行

直接运行即可：
```sh
./node_exporter
```
或在 Windows 下：
```sh
node_exporter.exe
```

默认会监听 `:9100` 端口，访问 `http://localhost:9100/metrics` 可查看所有 Prometheus 指标，包括自定义的端口/进程相关指标。

### 5. 常见问题

- 如果遇到依赖缺失、编译报错，请确保 go.mod/go.sum 文件完整，并已执行 `go mod tidy`。
- 如需交叉编译（如在 Linux 上编译 Windows 可执行文件），可用：
  ```sh
  GOOS=windows GOARCH=amd64 go build -o node_exporter.exe
  ```
- 如需打包 Docker 镜像或有其它平台编译需求，请联系开发者。

## 目录结构

```
node_exporter/
├── collector/
│   └── collector.go
├── my_collectors/
│   ├── port_process_collector.go
│   ├── auto_register_collectors.sh
│   └── ...（更多 *_collector.go 插件）
└── ...
```

## 自动注册插件机制

本项目支持自动注册 `my_collectors/` 目录下的所有自定义采集器，无需手动修改 `collector/collector.go`。

### 自动注册脚本

- 脚本位置：`my_collectors/auto_register_collectors.sh`
- 适用平台：Linux（Bash）
- 功能：
  - 自动扫描 `my_collectors/` 下所有 `*_collector.go` 文件
  - 自动生成 import 和注册代码，插入到 `collector/collector.go`
  - 幂等安全，重复运行不会产生重复注册或脏数据
  - 自动将插件源码复制到 `node_exporter/my_collectors/` 目录下

#### 使用方法

1. **添加新插件**
   - 在 `my_collectors/` 目录下新建如 `foo_bar_collector.go`，包名为 `my_collectors`，导出构造函数 `NewFooBarCollector()`。
   - **注意：文件名中的下划线会自动转为驼峰，构造函数名需与之对应。**
     - 例如：`port_process_collector.go` → `NewPortProcessCollector()`
     - 例如：`foo_bar_collector.go` → `NewFooBarCollector()`
2. **运行自动注册脚本**
   ```sh
   bash my_collectors/auto_register_collectors.sh
   ```
   - 脚本会自动：
     - 复制所有插件到 `node_exporter/my_collectors/`
     - 修改 `collector/collector.go`，插入 import 和注册代码
     - 保证 import 块和 init 注册块不会重复、不会破坏原有内容

3. **编译 node_exporter**
   ```sh
   cd node_exporter
   go build -o node_exporter
   ```

4. **运行并验证**
   - 启动 node_exporter，访问 `/metrics`，即可看到自定义插件的指标。

#### 构造函数命名规范

- 插件文件名需为 `xxx_collector.go`，注册名为 `xxx`（下划线分隔）。
- 构造函数必须导出，命名为 `NewXxxCollector`，其中 `Xxx` 为下划线转驼峰（首字母大写）。
  - 例如：
    - `port_process_collector.go` → `NewPortProcessCollector()`
    - `foo_bar_collector.go` → `NewFooBarCollector()`
    - `my_custom_collector.go` → `NewMyCustomCollector()`
- 注册时自动调用，无需手动修改 `