# 物理网卡与IP地址自动采集插件说明

## 功能简介

本插件用于自动采集主机（支持物理机和容器）上的所有物理网卡及其 IPv4 地址信息，并以 Prometheus 指标方式暴露，便于资产盘点、网络合规和运维管理。

- 自动采集所有物理网卡及其 IPv4 地址（排除虚拟网卡如 docker、veth、br-、virbr、lo 等）
- 每8小时自动刷新一次，首次启动时立即采集
- 指标 help 说明为中文，便于理解
- 采集失败时不暴露该网卡
- 适用于物理机和容器环境

## 采集内容

- 物理网卡名称（如 eth0、ens33、enp3s0 等）
- 物理网卡的 IPv4 地址（如 192.168.1.10）
- 每个物理网卡的每个 IPv4 地址单独暴露为一条指标

## 检测周期说明

- **网卡信息采集周期**（NETWORK_INTERFACE_INTERVAL）：
  - 控制所有物理网卡信息的刷新频率。
  - 可通过环境变量 `NETWORK_INTERFACE_INTERVAL` 配置，支持 Go duration 格式（如 `8h`, `1h`）。
  - 默认值为 `8h`（每8小时刷新一次）。

### 配置示例

```sh
export NETWORK_INTERFACE_INTERVAL=8h
```

## 指标说明

### 1. 物理网卡与IP地址信息
```
node_network_interface_info{interface="eth0", ip="192.168.1.10"} 1
```
- labels:
  - interface：物理网卡名称
  - ip：该网卡的 IPv4 地址
- value: 固定为 1
- help: 物理网卡及其IPv4地址信息（每8小时刷新一次）

## 工作原理

1. **物理网卡自动采集**：
   - 每隔 `NETWORK_INTERFACE_INTERVAL`（默认8小时）自动刷新一次所有物理网卡及其 IPv4 地址，首次启动时立即采集。
   - 只采集物理网卡，自动排除常见虚拟网卡（如 docker、veth、br-、virbr、lo、vmnet、tap、tun、wlx、enx 等）。
   - 只采集 IPv4 地址。
2. **指标暴露**：
   - 每个物理网卡的每个 IPv4 地址暴露为一条 Prometheus 指标。

## 使用方法

1. 将 `network_interface_collector.go` 添加到 `my_collectors/` 目录。
2. 运行 `my_collectors/auto_register_collectors.sh` 自动注册插件。
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到相关网卡与IP地址指标。

## 注意事项

- 采集周期可通过环境变量 `NETWORK_INTERFACE_INTERVAL` 配置，默认8小时。
- 插件对服务器性能影响极小，适合生产环境使用。
- 只采集物理网卡及其 IPv4 地址，虚拟网卡和 IPv6 地址不会暴露。
- 适配 node_exporter 的本地 Collector 接口，实现了 Update/Collect 方法，兼容 Prometheus。

## 目录结构

```
node_exporter/
├── collector/
│   └── collector.go
├── my_collectors/
│   ├── network_interface_collector.go
│   ├── port_process_collector.go
│   ├── hardware_info_collector.go
│   ├── auto_register_collectors.sh
│   └── ...（更多 *_collector.go 插件）
└── ...
```

## 常见问题

- **Q: 为什么有些网卡没有被采集？**
  - 可能是虚拟网卡（如 docker、veth、lo 等），或网卡未启用（down 状态）。
- **Q: 如何调整采集周期？**
  - 通过环境变量 `NETWORK_INTERFACE_INTERVAL` 配置。
- **Q: 如何只采集特定网卡？**
  - 可在 `isVirtualInterface` 函数中自定义白名单/黑名单逻辑。

## 构建与运行

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

### 3. 自动注册插件

在项目根目录下执行：
```sh
bash my_collectors/auto_register_collectors.sh
```
该脚本会自动将所有 `my_collectors/*.go` 插件注册到 node_exporter。

### 4. 编译 node_exporter

在项目根目录下执行：
```sh
go build -o node_exporter
```
编译成功后，会在当前目录生成 `node_exporter` 可执行文件（Windows 下为 `node_exporter.exe`）。

### 5. 运行

直接运行即可：
```sh
./node_exporter
```
或在 Windows 下：
```sh
node_exporter.exe
```

默认会监听 `:9100` 端口，访问 `http://localhost:9100/metrics` 可查看所有 Prometheus 指标，包括自定义的网卡/IP相关指标。

### 6. 常见问题

- 如果遇到依赖缺失、编译报错，请确保 go.mod/go.sum 文件完整，并已执行 `go mod tidy`。
- 如需交叉编译（如在 Linux 上编译 Windows 可执行文件），可用：
  ```sh
  GOOS=windows GOARCH=amd64 go build -o node_exporter.exe
  ```
- 如需打包 Docker 镜像或有其它平台编译需求，请联系开发者。

## 联系与支持

如有更多需求或问题，请联系开发者或提交 issue。 