package my_collectors

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// 操作调用超时，默认10秒，可通过环境变量 HARDWARE_INFO_TIMEOUT 配置
var hardwareInfoTimeout = func() time.Duration {
	if v := os.Getenv("HARDWARE_INFO_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 10 * time.Second
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

// 静默执行 ghw 函数调用，抑制标准错误输出
func silentGhwCall(fn func() error) error {
	// 保存原始标准错误
	originalStderr := os.Stderr
	// 创建管道来丢弃错误输出
	r, w, _ := os.Pipe()

	// 临时重定向标准错误到管道写入端
	os.Stderr = w

	// 启动 goroutine 从管道读取并丢弃数据
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r)
		close(done)
	}()

	// 执行函数
	err := fn()

	// 关闭写入端，触发读取端 EOF
	w.Close()

	// 等待读取 goroutine 完成（最多等待 100ms）
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}

	// 关闭读取端并恢复原始标准错误
	r.Close()
	os.Stderr = originalStderr

	return err
}

// 静默获取 Product 信息
func silentProduct() (*ghw.ProductInfo, error) {
	var p *ghw.ProductInfo
	var err error
	silentErr := silentGhwCall(func() error {
		p, err = ghw.Product()
		return err
	})
	if silentErr != nil {
		err = silentErr
	}
	return p, err
}

// 静默获取 Baseboard 信息
func silentBaseboard() (*ghw.BaseboardInfo, error) {
	var b *ghw.BaseboardInfo
	var err error
	silentErr := silentGhwCall(func() error {
		b, err = ghw.Baseboard()
		return err
	})
	if silentErr != nil {
		err = silentErr
	}
	return b, err
}

// 静默获取 Block 信息
func silentBlock() (*ghw.BlockInfo, error) {
	var blk *ghw.BlockInfo
	var err error
	silentErr := silentGhwCall(func() error {
		blk, err = ghw.Block()
		return err
	})
	if silentErr != nil {
		err = silentErr
	}
	return blk, err
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
	// 系统产品信息，增加超时保护
	type productResult struct {
		p   *ghw.ProductInfo
		err error
	}
	productCh := make(chan productResult, 1)
	go func() {
		p, err := silentProduct()
		productCh <- productResult{p: p, err: err}
	}()
	select {
	case res := <-productCh:
		if res.err == nil && res.p != nil {
			if res.p.Vendor != "" {
				info.SystemVendor = res.p.Vendor
			}
			if res.p.Name != "" {
				info.SystemProduct = res.p.Name
			}
			if res.p.SerialNumber != "" {
				info.SystemSerial = res.p.SerialNumber
			}
			if res.p.UUID != "" {
				info.SystemUUID = res.p.UUID
			}
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
	}
	// 主板信息，增加超时保护
	type baseboardResult struct {
		b   *ghw.BaseboardInfo
		err error
	}
	baseboardCh := make(chan baseboardResult, 1)
	go func() {
		b, err := silentBaseboard()
		baseboardCh <- baseboardResult{b: b, err: err}
	}()
	select {
	case res := <-baseboardCh:
		if res.err == nil && res.b != nil {
			if res.b.Vendor != "" {
				info.BoardVendor = res.b.Vendor
			}
			if res.b.Product != "" {
				info.BoardProduct = res.b.Product
			}
			if res.b.SerialNumber != "" {
				info.BoardSerial = res.b.SerialNumber
			}
			if res.b.Version != "" {
				info.BoardVersion = res.b.Version
			}
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
	}
	// CPU 信息，增加超时保护
	type cpuResult struct {
		infos []cpu.InfoStat
		err   error
	}
	cpuCh := make(chan cpuResult, 1)
	go func() {
		infos, err := cpu.Info()
		cpuCh <- cpuResult{infos: infos, err: err}
	}()
	select {
	case res := <-cpuCh:
		if res.err == nil && len(res.infos) > 0 {
			if res.infos[0].ModelName != "" {
				info.CPUModel = res.infos[0].ModelName
			}
			info.CPUCores = len(res.infos)
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
	}
	// 内存信息，增加超时保护
	type memResult struct {
		vm  *mem.VirtualMemoryStat
		err error
	}
	memCh := make(chan memResult, 1)
	go func() {
		vm, err := mem.VirtualMemory()
		memCh <- memResult{vm: vm, err: err}
	}()
	select {
	case res := <-memCh:
		if res.err == nil && res.vm != nil {
			info.MemoryTotal = float64(res.vm.Total)
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
	}
	// 磁盘信息，增加超时保护
	type diskResult struct {
		totalBytes float64
		err        error
	}
	diskCh := make(chan diskResult, 1)
	go func() {
		var total float64
		// 方法一：lsblk（TYPE=disk）
		ctx1, cancel1 := context.WithTimeout(context.Background(), hardwareInfoTimeout)
		defer cancel1()
		cmd := exec.CommandContext(ctx1, "lsblk", "-b", "-dn", "-o", "NAME,SIZE,TYPE")
		if out, e := cmd.Output(); e == nil {
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 3 && fields[2] == "disk" {
					if sz, perr := strconv.ParseUint(fields[1], 10, 64); perr == nil {
						total += float64(sz)
					}
				}
			}
		}
		// 方法二：按分区汇总本地固定磁盘（跳过远程/光驱/可移动），带超时
		if total == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), hardwareInfoTimeout)
			defer cancel()
			if parts, perr := disk.PartitionsWithContext(ctx, false); perr == nil {
				for _, part := range parts {
					if ctx.Err() != nil {
						break
					}
					opts := strings.ToLower(part.Opts)
					if strings.Contains(opts, "remote") || strings.Contains(opts, "cdrom") || strings.Contains(opts, "removable") {
						continue
					}
					if du, derr := disk.UsageWithContext(ctx, part.Mountpoint); derr == nil && du != nil {
						total += float64(du.Total)
					}
				}
			}
		}
		// 方法三：ghw 汇总物理磁盘（若前两者无结果）
		if total == 0 {
			if blk, gerr := silentBlock(); gerr == nil && blk != nil {
				for _, d := range blk.Disks {
					name := d.Name
					if name == "" {
						continue
					}
					if strings.HasPrefix(name, "loop") ||
						strings.HasPrefix(name, "ram") ||
						strings.HasPrefix(name, "zram") ||
						strings.HasPrefix(name, "dm-") ||
						strings.HasPrefix(name, "sr") ||
						strings.HasPrefix(name, "md") {
						continue
					}
					if d.SizeBytes > 0 {
						total += float64(d.SizeBytes)
					}
				}
			}
		}
		// 方法四：根分区兜底，避免返回 0
		if total == 0 {
			if du, derr := disk.Usage("/"); derr == nil && du != nil {
				total = float64(du.Total)
			}
		}
		diskCh <- diskResult{totalBytes: total, err: nil}
	}()
	select {
	case res := <-diskCh:
		if res.totalBytes > 0 {
			info.DiskTotal = res.totalBytes
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
	}
	// 获取操作系统信息（避免调用 Info() 触发进程枚举，改用 PlatformInformation，并增加超时保护）
	type osResult struct {
		platform string
		family   string
		version  string
		err      error
	}
	osCh := make(chan osResult, 1)
	go func() {
		platform, family, version, err := host.PlatformInformation()
		osCh <- osResult{platform: platform, family: family, version: version, err: err}
	}()
	select {
	case res := <-osCh:
		if res.err == nil {
			if res.platform != "" {
				info.OSName = res.platform
			}
			if res.family != "" {
				info.OSType = res.family
			}
			if res.version != "" {
				info.OSVersion = res.version
			}
		}
	case <-time.After(hardwareInfoTimeout):
		// 超时则保留默认值
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
