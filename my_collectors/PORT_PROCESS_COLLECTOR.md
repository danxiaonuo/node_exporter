# 端口与进程自动发现及监控插件说明

## 功能简介

本插件用于自动发现主机（支持物理机和容器）上的所有监听TCP和UDP端口及其关联进程，并监控端口存活、进程存活、端口响应时间等关键指标。适用于 Prometheus 监控体系，便于故障告警和运维分析。

- 自动发现主机所有监听**TCP/UDP端口**及其进程（标签内容每8小时刷新一次，周期可配置）
- 检测TCP端口是否存活（带检测缓存，周期可配置，默认每1分钟检测一次）
- 检测UDP端口是否存在（带检测缓存，周期可配置，默认每1分钟检测一次）
- 检测HTTP端口存活（异步检测，全量端口覆盖，智能缓存，避免阻塞指标暴露）
- 检测TCP端口响应时间（带检测缓存，周期同上）
- 检测进程是否存活（带检测缓存，周期可配置，默认每1分钟检测一次）
- 支持排除常见系统和监控进程，避免无意义采集
- 适用于物理机和容器环境
- **TCP/UDP/HTTP端口指标名称区分，UDP端口只采集存在性（带检测缓存），不采集响应时间**

## 检测周期与缓存机制

| 指标类型                | 检测缓存 | 环境变量                      | 默认周期   | 说明 |
|------------------------|----------|-------------------------------|------------|------|
| TCP端口存活/响应时间    | 有       | PORT_STATUS_INTERVAL, PORT_CHECK_TIMEOUT, MAX_PARALLEL_IP_CHECKS | 1分钟      | 端口可达性/响应时间，周期缓存，支持IPv4/IPv6，超时/并发可配 |
| HTTP端口存活           | 异步     | PORT_HTTP_STATUS_INTERVAL, PORT_CHECK_TIMEOUT, HTTP_DETECTION_CONCURRENCY | 异步检测   | 全量端口覆盖，异步检测不阻塞指标暴露，智能缓存，支持IPv4/IPv6 |
| UDP端口存在性          | 有       | PORT_UDP_STATUS_INTERVAL      | 1分钟      | 仅判断fd存在，周期缓存 |
| 进程存活               | 有       | PROCESS_ALIVE_STATUS_INTERVAL | 1分钟      | 进程是否存活，周期缓存 |
| 端口-进程标签发现      | 有       | PORT_LABEL_INTERVAL           | 8小时      | 端口-进程映射，周期缓存 |

### 环境变量说明
- `PORT_STATUS_INTERVAL`：TCP端口存活/响应时间检测周期，默认1分钟。
- `PORT_HTTP_STATUS_INTERVAL`：HTTP端口存活检测周期，默认与TCP一致。
- `PORT_UDP_STATUS_INTERVAL`：UDP端口存在性检测周期，默认与TCP一致。
- `PROCESS_ALIVE_STATUS_INTERVAL`：进程存活检测缓存刷新周期，默认1分钟。
- `PORT_LABEL_INTERVAL`：端口-进程标签发现周期，默认8小时。
- `PORT_CHECK_TIMEOUT`：TCP/HTTP检测超时时间，默认1秒，避免长时间阻塞。
- `MAX_PARALLEL_IP_CHECKS`：检测所有本地IP时的最大并发数，默认8，防止极端大规模主机拖垮性能。
- `HTTP_DETECTION_CONCURRENCY`：HTTP检测并发数，默认10，控制异步检测负载。
- `ENABLE_HTTP_DETECTION`：是否启用HTTP检测，默认true。
- `EXCLUDED_PROCESS_NAMES`：自定义排除进程名，逗号分隔。
- `PROC_PREFIX`：容器环境下指定proc路径前缀。

### 配置示例
```sh
export PORT_STATUS_INTERVAL=1m
export PORT_HTTP_STATUS_INTERVAL=1m
export PORT_UDP_STATUS_INTERVAL=1m
export PROCESS_ALIVE_STATUS_INTERVAL=1m
export PORT_LABEL_INTERVAL=8h
export PORT_CHECK_TIMEOUT=1s
export MAX_PARALLEL_IP_CHECKS=8
export HTTP_DETECTION_CONCURRENCY=10
export ENABLE_HTTP_DETECTION=true
export EXCLUDED_PROCESS_NAMES=nginx,redis,customapp
```

## 指标说明

### 1. TCP端口存活状态
```
node_tcp_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 1
```
- 1 表示TCP端口可建立连接，0 表示端口不可访问。
- 检测结果有缓存，刷新周期由 `PORT_STATUS_INTERVAL` 控制。
- 支持IPv4和IPv6监听端口。
- 检测超时时间可通过 `PORT_CHECK_TIMEOUT` 配置，默认2秒。
- 检测所有本地IP时最大并发数可通过 `MAX_PARALLEL_IP_CHECKS` 配置，默认8。

### 2. TCP端口响应时间
```
node_tcp_port_response_seconds{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 0.0015
```
- 数值为TCP端口连接耗时（单位：秒）。
- 检测结果有缓存，刷新周期同上。

### 3. HTTP端口存活状态（假死检测）
```
node_http_port_alive{process_name="nginx", exe_path="/usr/sbin/nginx", port="80"} 1
```
- 1 表示HTTP服务可访问（有响应头），0 表示HTTP服务不可用或假死。
- **异步检测机制**：HTTP检测在后台异步进行，不阻塞指标暴露，首次访问时可能无HTTP指标。
- **智能检测策略**：
  - **首次全量检测**：程序启动后对所有TCP端口进行HTTP检测，发现所有HTTP服务
  - **后续精准检测**：只对曾经HTTP检测成功的端口进行持续检测，避免无意义检测
- **智能缓存**：检测结果有缓存，刷新周期由 `PORT_HTTP_STATUS_INTERVAL` 控制。
- **历史记录**：曾经HTTP检测通过的端口会持续暴露指标（即使后续检测失败）。
- 支持IPv4和IPv6监听端口。
- 检测超时时间可通过 `PORT_CHECK_TIMEOUT` 配置，默认1秒。
- HTTP检测并发数可通过 `HTTP_DETECTION_CONCURRENCY` 配置，默认10。

### 4. UDP端口存活状态
```
node_udp_port_alive{process_name="dnsmasq", exe_path="/usr/sbin/dnsmasq", port="53"} 1
```
- 1 表示UDP端口存在（进程fd存在）。
- 检测结果有缓存，刷新周期由 `PORT_UDP_STATUS_INTERVAL` 控制。
- UDP端口不采集响应时间。

### 5. 进程存活状态
```
node_process_alive{process_name="nginx", exe_path="/usr/sbin/nginx"} 1
```
- 1 表示进程存活，0 表示进程不存在。
- 检测结果有缓存，刷新周期由 `PROCESS_ALIVE_STATUS_INTERVAL` 控制。
- **去重机制：每个唯一进程（进程名+路径组合）只采集一次，避免重复上报。**

## 工作原理

1. **端口与进程自动发现**：
   - 每隔 `PORT_LABEL_INTERVAL`（默认8小时）扫描一次 `/proc` 目录，发现所有监听**TCP/UDP端口**及其关联进程。
   - 只采集 LISTEN 状态的TCP端口和所有UDP端口。
   - TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
   - 排除常见系统进程和监控进程（如 systemd、zabbix、prometheus、node_exporter 等），可通过环境变量扩展。
   - **TCP/HTTP检测流程：先串行检测常用地址（127.0.0.1、0.0.0.0、::1、::），全部不通再对所有本地IP做有限并发检测（最大并发数可配），一旦有一个成功立即返回，极端大规模主机下也能兼顾性能和准确性。**
   - **TCP端口采集 /proc/net/tcp 和 /proc/net/tcp6，UDP端口采集 /proc/net/udp 和 /proc/net/udp6。**
2. **端口状态与响应时间检测**：
   - 每隔 `PORT_STATUS_INTERVAL`（默认1分钟）检测一次所有已发现TCP端口的存活状态和响应时间，结果有缓存。
   - `node_tcp_port_alive` 只检测TCP连接是否可达，支持IPv4/IPv6，超时/并发可配。
   - `node_tcp_port_response_seconds` 只反映TCP连接耗时。
   - `node_http_port_alive` 检测HTTP服务可用性（智能检测策略：首次全量检测发现所有HTTP服务，后续只对成功端口进行持续检测，异步处理不阻塞指标暴露，检测结果有缓存，支持IPv4/IPv6，超时/并发可配）。
   - UDP端口只判断端口存在（进程fd存在），检测结果有缓存，周期可配置。
   - 进程检测只要 `/proc/<pid>` 存在即认为存活，检测结果有缓存，周期可配置。

## 使用方法

1. 将 `port_process_collector.go` 添加到 `my_collectors/` 目录。
2. 运行自动注册脚本（见下文自动注册机制）。
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到相关指标。

## 注意事项

- 所有检测缓存周期均可通过环境变量配置，详见上文。
- 只采集 LISTEN 状态的TCP端口和所有UDP端口。
- TCP/UDP端口分别去重（同一协议下同一端口只采集一次）。
- 排除列表可通过 `EXCLUDED_PROCESS_NAMES` 环境变量自定义。
- 插件对服务器性能影响极小，适合生产环境使用。
- **UDP端口只采集存在性（带检测缓存，周期可配置），不采集响应时间。**
- **本采集器已适配 node_exporter 的本地 Collector 接口，实现了 Update 方法，兼容 Prometheus 和 node_exporter 框架。**
- **node_process_alive 指标只会为每个唯一进程（进程名+路径组合）采集和上报一次，检测结果有缓存，周期可配置，避免重复指标冲突。**
- **{process_name, exe_path} 的对象池是在首次启动和每次标签刷新周期时更新，采集指标时遍历的是上次发现的那一批对象。**

## 常见问题

- **Q: 为什么有些端口/进程没有被采集？**
  - 可能被排除列表过滤，或进程未监听TCP/UDP端口。
- **Q: 如何调整检测周期？**
  - 通过环境变量 `PORT_STATUS_INTERVAL`、`PORT_HTTP_STATUS_INTERVAL`、`PORT_UDP_STATUS_INTERVAL`、`PORT_LABEL_INTERVAL` 配置。
- **Q: 如何只采集特定端口或进程？**
  - 可在 `discoverPortProcess` 中增加白名单逻辑，或通过排除环境变量控制。
- **Q: HTTP端口指标为什么有的端口不暴露？**
  - HTTP检测采用异步机制，首次访问时可能无HTTP指标，后续访问会逐步出现。
  - 首次全量检测会尝试发现所有HTTP服务，后续只对成功端口进行持续检测。
  - 只有曾经HTTP检测通过的端口才会持续暴露该指标，且端口消失后指标消失。
- **Q: 为什么会出现"broken pipe"错误？**
  - 通常是因为指标暴露速度过慢，客户端主动断开连接。
  - 已通过异步HTTP检测、减少超时时间、智能缓存等机制优化，大幅减少此类错误。
- **Q: HTTP检测是否会影响指标暴露速度？**
  - 不会，HTTP检测完全异步进行，不阻塞指标暴露。
  - 采集时只返回缓存结果，无缓存时加入异步队列，后台处理。
- **Q: UDP端口存活是怎么判断的？**
  - 只要进程fd存在该端口即认为存在，检测结果有缓存。
- **Q: 进程存活是怎么判断的？**
  - 只要 `/proc/<pid>` 存在即认为存活，检测结果有缓存，周期可配置。
- **Q: TCP/HTTP检测超时时间和并发数能否调整？**
  - 可以，通过 `PORT_CHECK_TIMEOUT` 和 `MAX_PARALLEL_IP_CHECKS` 环境变量配置，默认2秒和8，适合慢服务、网络抖动和极端大规模主机场景。
- **Q: TCP/HTTP检测能否支持IPv6监听端口？**
  - 已支持，自动遍历所有本地IPv4和IPv6地址。

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

### 自动注册脚本原理

- 脚本位置：`my_collectors/auto_register_collectors.sh`
- 适用平台：Linux（Bash）
- 主要功能：
  1. 自动扫描 `my_collectors/` 下所有 `*_collector.go` 文件。
  2. 自动将所有插件源码复制到 `node_exporter/my_collectors/` 目录下（保持同步）。
  3. 自动生成 import 语句和注册代码（调用 `registerCollector`），插入到 `node_exporter/collector/collector.go` 的 import 块和 init 块中。
  4. import 块和 init 块均为自动生成，重复运行脚本不会产生重复注册或脏数据（幂等安全）。
  5. 构造函数命名规范：文件名如 `foo_bar_collector.go`，则需导出 `NewFooBarCollector()`。
  6. 注册名为文件名前缀（去掉 `_collector`），如 `foo_bar_collector.go` 注册名为 `foo_bar`。
  7. import 路径统一为 `github.com/prometheus/node_exporter/my_collectors`。
  8. 注册代码格式：
     ```go
     registerCollector("foo_bar", defaultEnabled, func(logger *slog.Logger) (Collector, error) {
         return my_collectors.NewFooBarCollector(), nil
     })
     ```

### 使用方法

1. **添加新插件**
   - 在 `my_collectors/` 目录下新建如 `foo_bar_collector.go`，包名为 `my_collectors`，导出构造函数 `NewFooBarCollector()`。
   - 文件名中的下划线会自动转为驼峰，构造函数名需与之对应。
     - 例如：`port_process_collector.go` → `NewPortProcessCollector()`
     - 例如：`foo_bar_collector.go` → `NewFooBarCollector()`
2. **运行自动注册脚本**
   ```sh
   bash my_collectors/auto_register_collectors.sh
   ```
   - 脚本会自动：
     - 复制所有插件到 `node_exporter/my_collectors/`
     - 修改 `collector/collector.go`，插入 import 和注册代码（import块和init块自动生成，原有内容保留）
     - 幂等安全，重复运行不会重复注册
3. **编译 node_exporter**
   ```sh
   cd node_exporter
   go build -o node_exporter
   ```
4. **运行并验证**
   - 启动 node_exporter，访问 `/metrics`，即可看到自定义插件的指标。

### 注意事项

- 插件文件名需为 `xxx_collector.go`，注册名为 `xxx`（下划线分隔）。
- 构造函数必须导出，命名为 `NewXxxCollector`，其中 `Xxx` 为下划线转驼峰（首字母大写）。
- 注册时自动调用，无需手动修改 `collector.go`。
- import 路径和注册代码均由脚本自动生成。
- 支持多插件自动注册，适合批量管理和持续集成。

## Docker 和 Kubernetes 环境运行说明

### 一、Docker 运行示例

#### 1. 采集宿主机进程/端口（推荐配置）

```sh
docker run --rm \
  --privileged \
  -v /proc:/host/proc:ro \
  -e PROC_PREFIX=/host/proc \
  -e EXCLUDED_PROCESS_NAMES=nginx,redis,customapp \
  --user root \
  your_image_name
```

- `--privileged`：容器拥有所有宿主机能力，能访问 /proc 下所有进程。
- `-v /proc:/host/proc:ro`：挂载宿主机 /proc 到容器内 /host/proc。
- `-e PROC_PREFIX=/host/proc`：让采集器访问宿主机 /proc。
- `-e EXCLUDED_PROCESS_NAMES=nginx,redis,customapp`：传入要排除的进程名。
- `--user root`：以 root 用户运行，避免权限不足。

#### 2. docker-compose 示例

```yaml
services:
  node_exporter:
    image: your_image_name
    privileged: true
    user: root
    volumes:
      - /proc:/host/proc:ro
    environment:
      - PROC_PREFIX=/host/proc
      - EXCLUDED_PROCESS_NAMES=nginx,redis,customapp
    restart: always
```

### 二、Kubernetes 运行示例

#### 1. 采集宿主机进程/端口（Pod/DaemonSet）

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node-exporter
spec:
  containers:
    - name: node-exporter
      image: your_image_name
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
      volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
      env:
        - name: PROC_PREFIX
          value: /host/proc
        - name: EXCLUDED_PROCESS_NAMES
          value: nginx,redis,customapp
  volumes:
    - name: proc
      hostPath:
        path: /proc
        type: Directory
```

#### 2. DaemonSet 示例（每台节点部署一个）

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
          image: your_image_name
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
          volumeMounts:
            - name: proc
              mountPath: /host/proc
              readOnly: true
          env:
            - name: PROC_PREFIX
              value: /host/proc
            - name: EXCLUDED_PROCESS_NAMES
              value: nginx,redis,customapp
      volumes:
        - name: proc
          hostPath:
            path: /proc
            type: Directory
```

### 注意事项

- 容器内如需采集宿主机进程/端口，必须以 root 用户、特权模式运行，并挂载宿主机 /proc。
- 如果宿主机 /proc 挂载了 hidepid=1/2，则即使 root 也无法访问其他用户进程的 fd，需宿主机 /proc 为 hidepid=0。
- 生产环境下，特权容器有安全风险，请根据实际需求权衡。

## 进程排除自定义说明

本插件支持通过环境变量 `EXCLUDED_PROCESS_NAMES`（逗号分隔）自定义排除进程名，容器和 K8s 环境可灵活配置。

- 默认排除列表内置常见系统和监控进程。
- 通过 `EXCLUDED_PROCESS_NAMES` 传入的进程名会与默认排除列表合并。
- 匹配方式为"包含关系"，如 `nginx` 会排除所有包含 `nginx` 的进程名。

### 用法示例

**Docker 运行：**

```sh
docker run --rm \
  --privileged \
  -v /proc:/host/proc:ro \
  -e PROC_PREFIX=/host/proc \
  -e EXCLUDED_PROCESS_NAMES=nginx,redis,customapp \
  --user root \
  your_image_name
```

**docker-compose 示例：**

```yaml
services:
  node_exporter:
    image: your_image_name
    privileged: true
    user: root
    volumes:
      - /proc:/host/proc:ro
    environment:
      - PROC_PREFIX=/host/proc
      - EXCLUDED_PROCESS_NAMES=nginx,redis,customapp
    restart: always
```

**Kubernetes 示例（Pod/DaemonSet）：**

```yaml
env:
  - name: PROC_PREFIX
    value: /host/proc
  - name: EXCLUDED_PROCESS_NAMES
    value: nginx,redis,customapp
```

这样配置后，所有进程名包含 `nginx`、`redis`、`customapp` 的进程都会被排除，不会被采集。

### 端口检测超时时间（PORT_CHECK_TIMEOUT）

- 作用：控制每个端口检测的最大等待时间，防止慢服务或网络异常拖慢整体采集。
- 配置方式：
  - 环境变量 `PORT_CHECK_TIMEOUT`，如 `1s`、`2s`、`5s` 等。
  - **默认值：1秒**（1s）。
- 建议：
  - 绝大多数生产环境建议保持1秒或更低。
  - 仅在极端慢服务排查时临时调大。
  - 超时时间过大（如1分钟）会极大拖慢 /metrics 暴露速度，尤其在端口未监听或IP不可达时。

示例：
```sh
export PORT_CHECK_TIMEOUT=1s
```