# 登录失败次数自动采集插件说明

## 功能简介

本插件用于自动采集主机（支持物理机和容器）上的登录失败次数，并以 Prometheus 指标方式暴露，便于安全监控、入侵检测和运维告警。

- 自动采集主机登录失败次数（优先用 lastb，失败则查日志）
- 每1分钟自动刷新一次，首次启动时立即采集
- 指标 help 说明为中文，便于理解
- 采集失败时指标值为 0
- 适用于物理机和容器环境

## 采集内容

- 主机登录失败次数（近1小时内，防止计数过大）
- 优先使用 lastb 命令获取，失败则查找 /var/log/secure、auth.log、messages 等日志

## 检测周期说明

- **登录失败次数采集周期**（LOGIN_FAILED_INTERVAL）：
  - 控制登录失败次数的刷新频率。
  - 可通过环境变量 `LOGIN_FAILED_INTERVAL` 配置，支持 Go duration 格式（如 `1m`, `30s`）。
  - 默认值为 `1m`（每1分钟刷新一次）。

### 配置示例

```sh
export LOGIN_FAILED_INTERVAL=1m
```

## 指标说明

### 1. 登录失败次数
```
node_login_failed_count 3
```
- value: 近1小时内主机登录失败次数（整数）
- help: 主机登录失败次数（每分钟刷新一次）

## 工作原理

1. **登录失败次数自动采集**：
   - 每隔 `LOGIN_FAILED_INTERVAL`（默认1分钟）自动刷新一次登录失败次数，首次启动时立即采集。
   - 优先使用 lastb 命令获取失败次数，若命令不可用则查找常见日志文件。
   - 只统计近1小时内的失败次数，防止计数过大。
2. **指标暴露**：
   - 登录失败次数以 Prometheus 指标方式暴露。

## 使用方法

1. 将 `login_failed_collector.go` 添加到 `my_collectors/` 目录。
2. 运行 `my_collectors/auto_register_collectors.sh` 自动注册插件。
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到登录失败次数指标。

## 注意事项

- 采集周期可通过环境变量 `LOGIN_FAILED_INTERVAL` 配置，默认1分钟。
- 插件对服务器性能影响极小，适合生产环境使用。
- 需确保主机有 lastb 命令或常见安全日志文件。
- 适配 node_exporter 的本地 Collector 接口，实现了 Update/Collect 方法，兼容 Prometheus。

## 目录结构

```
node_exporter/
├── collector/
│   └── collector.go
├── my_collectors/
│   ├── login_failed_collector.go
│   ├── network_interface_collector.go
│   ├── port_process_collector.go
│   ├── hardware_info_collector.go
│   ├── auto_register_collectors.sh
│   └── ...（更多 *_collector.go 插件）
└── ...
```

## 常见问题

- **Q: 为什么指标值为0？**
  - 可能主机没有 lastb 命令，且日志文件不存在或无权限读取。
- **Q: 如何调整采集周期？**
  - 通过环境变量 `LOGIN_FAILED_INTERVAL` 配置。
- **Q: 如何兼容不同 Linux 发行版？**
  - 可在采集函数中扩展日志路径或命令。

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

默认会监听 `:9100` 端口，访问 `http://localhost:9100/metrics` 可查看所有 Prometheus 指标，包括自定义的登录失败次数指标。

### 6. 常见问题

- 如果遇到依赖缺失、编译报错，请确保 go.mod/go.sum 文件完整，并已执行 `go mod tidy`。
- 如需交叉编译（如在 Linux 上编译 Windows 可执行文件），可用：
  ```sh
  GOOS=windows GOARCH=amd64 go build -o node_exporter.exe
  ```
- 如需打包 Docker 镜像或有其它平台编译需求，请联系开发者。

## 联系与支持

如有更多需求或问题，请联系开发者或提交 issue。 