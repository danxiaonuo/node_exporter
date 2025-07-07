# 端口与进程自动发现及监控插件说明

## 功能简介

本插件用于自动发现主机（支持物理机和容器）上的所有监听TCP和UDP端口及其关联进程，并实时监控端口存活、进程存活、端口响应时间等关键指标。适用于 Prometheus 监控体系，便于故障告警和运维分析。

- 自动发现主机所有监听**TCP/UDP端口**及其进程（每8小时刷新一次，首次运行立即发现）
- 实时检测TCP端口是否存活（可访问/假死检测）
- 实时检测UDP端口是否存在（只判断端口存在性）
- 实时检测TCP端口响应时间（秒，UDP不采集响应时间）
- 实时检测进程是否存活
- 支持排除常见系统和监控进程，避免无意义采集
- 适用于物理机和容器环境
- **TCP/UDP端口指标名称区分，UDP端口只采集存在性，不采集响应时间**

## 指标说明

### 1. TCP端口存活状态
```
node_tcp_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80", pid="1234"} 1
```
- 1 表示TCP端口可建立连接，0 表示端口不可访问。
- labels:
  - process_name：进程名
  - exe_path：可执行文件路径
  - port：端口号
  - pid：进程号
- **此指标只检测TCP连接是否可达，不做HTTP请求。**

### 2. TCP端口响应时间
```
node_tcp_port_response_seconds{process_name="nginx", exe_path="/usr/sbin/nginx", port="80", pid="1234"} 0.0015
```
- 数值为TCP端口连接耗时（单位：秒）。
- labels 同上。
- **此指标只反映TCP连接耗时，不包含HTTP响应时间。**

### 3. HTTP端口存活状态（假死检测）
```
node_http_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80", pid="1234"} 1
```
- 1 表示HTTP服务可访问（有响应头），0 表示HTTP服务不可用或假死。
- labels 同上。
- **此指标专门检测HTTP服务可用性，适合做Web服务假死/异常监控。**

### 4. UDP端口存活状态
```
node_udp_port_alive{process_name="dnsmasq", exe_path="/usr/sbin/dnsmasq", port="53", pid="2345"} 1
```
- 1 表示UDP端口存在。
- labels 同上。
- **UDP端口不采集响应时间。**

### 5. 进程存活状态
```
node_process_alive{process_name="nginx", exe_path="/usr/sbin/nginx", pid="1234"} 1
```
- 1 表示进程存活，0 表示进程不存在。
- labels:
  - process_name：进程名
  - exe_path：可执行文件路径
  - pid：进程号

## 工作原理

1. **端口与进程自动发现**：
   - 每8小时扫描一次 `/proc` 目录，发现所有监听**TCP/UDP端口**及其关联进程。
   - TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
   - 排除常见系统进程和监控进程（如 systemd、zabbix、prometheus、node_exporter 等）。
   - **TCP端口采集 /proc/net/tcp 和 /proc/net/tcp6，UDP端口采集 /proc/net/udp 和 /proc/net/udp6。**
2. **实时检测**：
   - 每次 Prometheus 拉取 `/metrics` 时，实时检测所有已发现TCP/UDP端口和进程的存活状态。
   - `node_tcp_port_alive` 只检测TCP连接是否可达。
   - `node_tcp_port_response_seconds` 只反映TCP连接耗时。
   - `node_http_port_alive` 检测HTTP服务可用性（假死检测）。
   - UDP端口只判断端口存在，不检测连通性和响应时间。
   - 进程检测只要 `/proc/<pid>` 存在即认为存活。

## 使用方法

1. 将 `port_process_collector.go` 添加到 `collector` 目录。
2. 在 `collector.go` 中注册该 Collector：
   ```go
   import "./collector"
   func init() {
       registerCollector("port_process", defaultEnabled, func(logger *slog.Logger) (Collector, error) {
           return NewPortProcessCollector(), nil
       })
   }
   ```
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到相关指标。

## 注意事项

- 端口/进程发现每8小时刷新一次，采集时实时检测存活和响应时间。
- 只采集 LISTEN 状态的TCP端口和所有UDP端口。
- TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
- 排除列表可在 `isExcludedProcess` 函数中自定义。
- 插件对服务器性能影响极小，适合生产环境使用。
- **UDP端口只采集存在性，不采集响应时间。**
- **本采集器已适配 node_exporter 的本地 Collector 接口，实现了 Update 方法，兼容 Prometheus 和 node_exporter 框架。**
- **node_process_alive 指标只会为每个唯一进程（pid）采集和上报一次，避免重复指标冲突。**
- **{process_name, exe_path, pid} 的对象池是在首次启动和每8小时刷新一次时更新，采集指标时遍历的是上次发现的那一批对象。**

## 常见问题

- **Q: 为什么有些端口/进程没有被采集？**
  - 可能被排除列表过滤，或进程未监听TCP/UDP端口。
- **Q: 如何调整扫描周期？**
  - 修改 `scanInterval` 常量即可。
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
- 注册时自动调用，无需手动修改 `collector.go`。

## 端口进程采集器功能简介

（此处保留原有采集器功能、指标、配置等说明）

## 子模块集成说明

本插件支持以 Git 子模块方式集成到 node_exporter 项目，便于统一管理和自动同步自定义采集器。

### 1. 添加 my_collectors 作为子模块

在 node_exporter 项目根目录下执行：
```sh
# 添加 my_collectors 子模块（假设你的 my_collectors 仓库地址为 git@xxx:yourrepo/my_collectors.git）
git submodule add <your_my_collectors_repo_url> my_collectors
# 初始化并拉取子模块内容
git submodule update --init --recursive
```

### 2. 拉取/更新子模块

每次更新 my_collectors 子模块时，需同步拉取最新内容：
```sh
git submodule update --remote my_collectors
```

### 3. 自动注册插件

my_collectors 目录下的 `auto_register_collectors.sh` 脚本会自动：
- 复制所有插件到 `node_exporter/my_collectors/`
- 自动修改 `node_exporter/collector/collector.go`，插入 import 和注册代码
- 保证 import 块和 init 注册块不会重复、不会破坏原有内容

#### 使用方法
1. 在 my_collectors 目录下新建或修改插件（如 `foo_bar_collector.go`）。
2. 运行自动注册脚本：
   ```sh
   bash my_collectors/auto_register_collectors.sh
   ```
3. 重新编译 node_exporter：
   ```sh
   cd node_exporter
   go build -o node_exporter
   ```

--- 