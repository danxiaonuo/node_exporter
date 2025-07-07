# 硬件信息自动采集插件说明

## 功能简介

本插件用于自动采集主机（支持物理机和容器）上的主要硬件和操作系统信息，并以 Prometheus 指标方式暴露，便于资产盘点、合规检查和运维管理。

- 自动采集主板、系统、CPU、内存、磁盘、操作系统等关键信息
- 每8小时自动刷新一次，首次启动时立即采集
- 指标 help 说明为中文，便于理解
- 采集失败时，label 标记为"未知"，数值型指标为 0
- 适用于物理机和容器环境

## 采集内容

- 主板信息：厂商、型号、序列号、版本
- 系统信息：厂商、型号、序列号、UUID
- CPU 信息：型号、核心数
- 内存总容量（单位：字节，自动转换为 GB/TB 显示）
- 磁盘总容量（单位：字节，自动转换为 GB/TB 显示）
- 操作系统信息：名称、类型、版本

## 检测周期说明

- **硬件信息采集周期**（HARDWARE_INFO_INTERVAL）：
  - 控制所有硬件信息的刷新频率。
  - 可通过环境变量 `HARDWARE_INFO_INTERVAL` 配置，支持 Go duration 格式（如 `8h`, `1h`）。
  - 默认值为 `8h`（每8小时刷新一次）。

### 配置示例

```sh
export HARDWARE_INFO_INTERVAL=8h
```

## 指标说明

### 1. 主板信息
```
node_hardware_board_info{vendor="ASUS", product="PRIME Z390-A", serial="123456", version="1.0"} 1
```
- labels:
  - vendor：主板厂商
  - product：主板型号
  - serial：主板序列号
  - version：主板版本
- value: 固定为 1

### 2. 系统信息
```
node_hardware_system_info{vendor="Dell", product="PowerEdge R730", serial="ABCDEF", uuid="..."} 1
```
- labels:
  - vendor：系统厂商
  - product：系统型号
  - serial：系统序列号
  - uuid：系统 UUID
- value: 固定为 1

### 3. CPU 信息
```
node_hardware_cpu_info{model="Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz"} 12
```
- labels:
  - model：CPU 型号
- value: CPU 核心数

### 4. 内存总容量
```
node_hardware_memory_total_bytes{display="128 GB"} 137438953472
```
- labels:
  - display：自动转换单位后的容量（如 "128 GB"）
- value: 内存总字节数

### 5. 磁盘总容量
```
node_hardware_disk_total_bytes{display="2 TB"} 2199023255552
```
- labels:
  - display：自动转换单位后的容量（如 "2 TB"）
- value: 磁盘总字节数

### 6. 操作系统信息
```
node_hardware_os_info{name="centos", type="linux", version="7.9.2009"} 1
```
- labels:
  - name：操作系统名称
  - type：操作系统类型
  - version：操作系统版本
- value: 固定为 1

## 工作原理

1. **硬件信息自动采集**：
   - 每隔 `HARDWARE_INFO_INTERVAL`（默认8小时）自动刷新一次所有硬件信息，首次启动时立即采集。
   - 采集失败时，label 标记为"未知"，数值型指标为 0。
2. **指标暴露**：
   - 每项硬件信息暴露为一个 Prometheus 指标，字符串信息用 label，容量等用 value。
   - 内存、磁盘容量自动转换为 GB/TB 显示（label），原始字节数作为 value。

## 使用方法

1. 将 `hardware_info_collector.go` 添加到 `my_collectors/` 目录。
2. 运行 `my_collectors/auto_register_collectors.sh` 自动注册插件。
3. 重新编译并运行 node_exporter。
4. 访问 `/metrics`，即可看到相关硬件信息指标。

## 注意事项

- 采集周期可通过环境变量 `HARDWARE_INFO_INTERVAL` 配置，默认8小时。
- 插件对服务器性能影响极小，适合生产环境使用。
- 采集内容如需扩展，可在 `collectHardwareInfo` 函数中补充。
- 适配 node_exporter 的本地 Collector 接口，实现了 Update/Collect 方法，兼容 Prometheus。

## 目录结构

```
node_exporter/
├── collector/
│   └── collector.go
├── my_collectors/
│   ├── hardware_info_collector.go
│   ├── port_process_collector.go
│   ├── auto_register_collectors.sh
│   └── ...（更多 *_collector.go 插件）
└── ...
```

## 常见问题

- **Q: 为什么有些信息显示为"未知"？**
  - 可能因权限不足、容器环境限制或硬件信息未导出导致。
- **Q: 如何调整采集周期？**
  - 通过环境变量 `HARDWARE_INFO_INTERVAL` 配置。
- **Q: 如何扩展采集内容？**
  - 可在 `collectHardwareInfo` 函数中补充采集逻辑。

## 联系与支持

如有更多需求或问题，请联系开发者或提交 issue。 