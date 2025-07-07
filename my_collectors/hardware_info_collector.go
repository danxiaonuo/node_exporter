package my_collectors

import (
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/jaypipes/ghw"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

// 硬件信息缓存结构体
var hardwareInfoCache = struct {
	LastScan time.Time
	Data     *HardwareInfo
	Mutex    sync.RWMutex
}{Data: nil}

// 缓存刷新周期，默认8小时，可通过环境变量 HARDWARE_INFO_INTERVAL 配置
var hardwareInfoInterval = func() time.Duration {
	if v := os.Getenv("HARDWARE_INFO_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return 8 * time.Hour
}()

// 硬件信息结构体
// 字符串信息用 string，容量等用 float64
// 所有字段均为最终暴露内容
// 采集失败时填 "未知" 或 0
type HardwareInfo struct {
	BoardVendor   string
	BoardProduct  string
	BoardSerial   string
	BoardVersion  string
	SystemVendor  string
	SystemProduct string
	SystemSerial  string
	SystemUUID    string
	CPUModel      string
	CPUCores      int
	MemoryTotal   float64 // 单位: 字节
	DiskTotal     float64 // 单位: 字节
	OSName        string
	OSType        string
	OSVersion     string
}

// 获取硬件信息，带缓存，每8小时刷新一次
func getHardwareInfo() *HardwareInfo {
	hardwareInfoCache.Mutex.RLock()
	expired := time.Since(hardwareInfoCache.LastScan) > hardwareInfoInterval || hardwareInfoCache.Data == nil
	hardwareInfoCache.Mutex.RUnlock()
	if expired {
		hardwareInfoCache.Mutex.Lock()
		if time.Since(hardwareInfoCache.LastScan) > hardwareInfoInterval || hardwareInfoCache.Data == nil {
			hardwareInfoCache.Data = collectHardwareInfo()
			hardwareInfoCache.LastScan = time.Now()
		}
		hardwareInfoCache.Mutex.Unlock()
	}
	hardwareInfoCache.Mutex.RLock()
	defer hardwareInfoCache.Mutex.RUnlock()
	return hardwareInfoCache.Data
}

// 真正采集硬件信息的函数
func collectHardwareInfo() *HardwareInfo {
	info := &HardwareInfo{
		BoardVendor:   "未知",
		BoardProduct:  "未知",
		BoardSerial:   "未知",
		BoardVersion:  "未知",
		SystemVendor:  "未知",
		SystemProduct: "未知",
		SystemSerial:  "未知",
		SystemUUID:    "未知",
		CPUModel:      "未知",
		CPUCores:      0,
		MemoryTotal:   0,
		DiskTotal:     0,
		OSName:        "未知",
		OSType:        "未知",
		OSVersion:     "未知",
	}
	if p, err := ghw.Product(); err == nil {
		if p.Vendor != "" {
			info.SystemVendor = p.Vendor
		}
		if p.Name != "" {
			info.SystemProduct = p.Name
		}
		if p.SerialNumber != "" {
			info.SystemSerial = p.SerialNumber
		}
		if p.UUID != "" {
			info.SystemUUID = p.UUID
		}
	}
	if b, err := ghw.Baseboard(); err == nil {
		if b.Vendor != "" {
			info.BoardVendor = b.Vendor
		}
		if b.Product != "" {
			info.BoardProduct = b.Product
		}
		if b.SerialNumber != "" {
			info.BoardSerial = b.SerialNumber
		}
		if b.Version != "" {
			info.BoardVersion = b.Version
		}
	}
	if c, err := cpu.Info(); err == nil && len(c) > 0 {
		if c[0].ModelName != "" {
			info.CPUModel = c[0].ModelName
		}
		info.CPUCores = len(c)
	}
	if m, err := mem.VirtualMemory(); err == nil {
		info.MemoryTotal = float64(m.Total)
	}
	if d, err := disk.Usage("/"); err == nil {
		info.DiskTotal = float64(d.Total)
	}
	if h, err := host.Info(); err == nil {
		if h.Platform != "" {
			info.OSName = h.Platform
		}
		if h.PlatformFamily != "" {
			info.OSType = h.PlatformFamily
		}
		if h.PlatformVersion != "" {
			info.OSVersion = h.PlatformVersion
		}
	}
	return info
}

// 单位自动转换
func convertSize(size float64) (float64, string) {
	var unit string
	var convertedSize float64
	switch {
	case size >= 1024*1024*1024*1024:
		convertedSize = size / (1024 * 1024 * 1024 * 1024)
		unit = "TB"
	case size >= 1024*1024*1024:
		convertedSize = size / (1024 * 1024 * 1024)
		unit = "GB"
	case size >= 1024*1024:
		convertedSize = size / (1024 * 1024)
		unit = "MB"
	default:
		convertedSize = size / 1024
		unit = "KB"
	}
	return convertedSize, unit
}

// 硬件信息采集器
// 每项信息一个指标，help 用中文
// 字符串信息用 label，数值信息为 value
// 采集失败时 value=0，label=未知

type HardwareInfoCollector struct {
	boardInfoDesc   *prometheus.Desc
	systemInfoDesc  *prometheus.Desc
	cpuInfoDesc     *prometheus.Desc
	memoryTotalDesc *prometheus.Desc
	diskTotalDesc   *prometheus.Desc
	osInfoDesc      *prometheus.Desc
}

func NewHardwareInfoCollector() *HardwareInfoCollector {
	return &HardwareInfoCollector{
		boardInfoDesc: prometheus.NewDesc(
			"node_hardware_board_info",
			"主板信息（厂商、型号、序列号、版本）",
			[]string{"vendor", "product", "serial", "version"}, nil,
		),
		systemInfoDesc: prometheus.NewDesc(
			"node_hardware_system_info",
			"系统信息（厂商、型号、序列号、UUID）",
			[]string{"vendor", "product", "serial", "uuid"}, nil,
		),
		cpuInfoDesc: prometheus.NewDesc(
			"node_hardware_cpu_info",
			"CPU信息（型号、核心数）",
			[]string{"model"}, nil,
		),
		memoryTotalDesc: prometheus.NewDesc(
			"node_hardware_memory_total_bytes",
			"内存总容量（单位：字节）",
			[]string{"display"}, nil,
		),
		diskTotalDesc: prometheus.NewDesc(
			"node_hardware_disk_total_bytes",
			"磁盘总容量（单位：字节）",
			[]string{"display"}, nil,
		),
		osInfoDesc: prometheus.NewDesc(
			"node_hardware_os_info",
			"操作系统信息（名称、类型、版本）",
			[]string{"name", "type", "version"}, nil,
		),
	}
}

func (c *HardwareInfoCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.boardInfoDesc
	ch <- c.systemInfoDesc
	ch <- c.cpuInfoDesc
	ch <- c.memoryTotalDesc
	ch <- c.diskTotalDesc
	ch <- c.osInfoDesc
}

func (c *HardwareInfoCollector) Collect(ch chan<- prometheus.Metric) {
	info := getHardwareInfo()
	// 主板信息
	ch <- prometheus.MustNewConstMetric(
		c.boardInfoDesc, prometheus.GaugeValue, 1,
		info.BoardVendor, info.BoardProduct, info.BoardSerial, info.BoardVersion,
	)
	// 系统信息
	ch <- prometheus.MustNewConstMetric(
		c.systemInfoDesc, prometheus.GaugeValue, 1,
		info.SystemVendor, info.SystemProduct, info.SystemSerial, info.SystemUUID,
	)
	// CPU信息
	ch <- prometheus.MustNewConstMetric(
		c.cpuInfoDesc, prometheus.GaugeValue, float64(info.CPUCores),
		info.CPUModel,
	)
	// 内存总容量
	memVal, memUnit := convertSize(info.MemoryTotal)
	ch <- prometheus.MustNewConstMetric(
		c.memoryTotalDesc, prometheus.GaugeValue, info.MemoryTotal,
		fmt.Sprintf("%.0f %s", math.Round(memVal), memUnit),
	)
	// 磁盘总容量
	diskVal, diskUnit := convertSize(info.DiskTotal)
	ch <- prometheus.MustNewConstMetric(
		c.diskTotalDesc, prometheus.GaugeValue, info.DiskTotal,
		fmt.Sprintf("%.0f %s", math.Round(diskVal), diskUnit),
	)
	// 操作系统信息
	ch <- prometheus.MustNewConstMetric(
		c.osInfoDesc, prometheus.GaugeValue, 1,
		info.OSName, info.OSType, info.OSVersion,
	)
}

// 实现 node_exporter Collector 接口的 Update 方法
func (c *HardwareInfoCollector) Update(ch chan<- prometheus.Metric) error {
	c.Collect(ch)
	return nil
}
