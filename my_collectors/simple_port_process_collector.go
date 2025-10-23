package my_collectors

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PortProcessInfo 结构体：用于存储端口与进程的关联信息
type PortProcessInfo struct {
	ProcessName string // 进程名
	ExePath     string // 可执行文件路径
	Port        int    // 端口号
	Pid         int    // 进程号
	WorkDir     string // 工作目录
	Username    string // 运行用户
	Protocol    string // 协议类型：tcp/udp
}

// portProcessCacheStruct 结构体：用于缓存端口与进程的发现结果
type portProcessCacheStruct struct {
	LastScan time.Time
	Data     []PortProcessInfo
	RWMutex  sync.RWMutex
}

var portProcessCache = &portProcessCacheStruct{}

// 标签缓存周期可配置
var scanInterval = func() time.Duration {
	if v := os.Getenv("PORT_LABEL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return 8 * time.Hour
}()

var procPrefix = func() string {
	if p := os.Getenv("PROC_PREFIX"); p != "" {
		return p
	}
	// 自动判断容器环境
	cgroupFile := "/proc/1/cgroup"
	content, err := os.ReadFile(cgroupFile)
	if err == nil {
		s := string(content)
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") {
			return "/host/proc"
		}
	}
	return ""
}()

func procPath(path string) string {
	return procPrefix + path
}

// SimplePortProcessCollector 结构体：实现 Prometheus Collector 接口
type SimplePortProcessCollector struct {
	portTCPAliveDesc      *prometheus.Desc // TCP端口存活指标描述符
	processAliveDesc      *prometheus.Desc // 进程存活指标描述符（包含进程状态）
	processCPUPercentDesc *prometheus.Desc // 进程CPU使用率指标描述符
	processMemPercentDesc *prometheus.Desc // 进程内存使用率指标描述符
	processVMRSSDesc      *prometheus.Desc // 进程物理内存指标描述符
	processVMSizeDesc     *prometheus.Desc // 进程虚拟内存指标描述符
	processThreadsDesc    *prometheus.Desc // 进程线程数指标描述符
	processIOReadDesc     *prometheus.Desc // 进程IO读取指标描述符
	processIOWriteDesc    *prometheus.Desc // 进程IO写入指标描述符
}

// NewSimplePortProcessCollector 构造函数：创建并返回一个新的简化端口进程采集器
func NewSimplePortProcessCollector() *SimplePortProcessCollector {
	return &SimplePortProcessCollector{
		portTCPAliveDesc: prometheus.NewDesc(
			"node_tcp_port_alive",                    // 指标名称
			"TCP端口存活状态 (1=存活, 0=死亡)",           // 指标描述
			[]string{"process_name", "exe_path", "port"}, nil,
		),
		processAliveDesc: prometheus.NewDesc(
			"node_process_alive",                     // 指标名称
			"进程存活状态 (1=存活, 0=死亡) 包含进程状态",  // 指标描述
			[]string{"process_name", "exe_path", "state"}, nil,
		),
		processCPUPercentDesc: prometheus.NewDesc(
			"node_process_cpu_percent",               // 指标名称
			"进程CPU使用率百分比",                      // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processMemPercentDesc: prometheus.NewDesc(
			"node_process_memory_percent",            // 指标名称
			"进程物理内存使用率百分比",                  // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processVMRSSDesc: prometheus.NewDesc(
			"node_process_memory_rss_bytes",          // 指标名称
			"进程使用的物理内存大小(字节)",              // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processVMSizeDesc: prometheus.NewDesc(
			"node_process_memory_vms_bytes",          // 指标名称
			"进程使用的虚拟内存大小(字节)",              // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processThreadsDesc: prometheus.NewDesc(
			"node_process_threads",                   // 指标名称
			"进程中的线程总数",                         // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processIOReadDesc: prometheus.NewDesc(
			"node_process_io_read_bytes_per_second",  // 指标名称
			"进程每秒从磁盘读取的数据量(字节/秒)",         // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
		processIOWriteDesc: prometheus.NewDesc(
			"node_process_io_write_bytes_per_second", // 指标名称
			"进程每秒向磁盘写入的数据量(字节/秒)",         // 指标描述
			[]string{"process_name", "exe_path"}, nil,
		),
	}
}

// Describe 方法：实现 Prometheus Collector 接口，描述所有指标
func (c *SimplePortProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.portTCPAliveDesc
	ch <- c.processAliveDesc
	ch <- c.processCPUPercentDesc
	ch <- c.processMemPercentDesc
	ch <- c.processVMRSSDesc
	ch <- c.processVMSizeDesc
	ch <- c.processThreadsDesc
	ch <- c.processIOReadDesc
	ch <- c.processIOWriteDesc
}

// TCP检测异步化，避免阻塞指标暴露
var tcpDetectionQueue = struct {
	sync.Mutex
	ports map[int]bool
	done  chan struct{}
}{ports: make(map[int]bool), done: make(chan struct{})}

// 进程检测异步化，避免阻塞指标暴露
var processDetectionQueue = struct {
	sync.Mutex
	pids map[int]bool
	done chan struct{}
}{pids: make(map[int]bool), done: make(chan struct{})}

// TCP检测异步处理器
func startTCPDetectionWorker() {
	go func() {
		ticker := time.NewTicker(portStatusInterval)
		defer ticker.Stop()
		for {
			select {
			case <-tcpDetectionQueue.done:
				return
			case <-ticker.C:
				tcpDetectionQueue.Lock()
				ports := make([]int, 0, len(tcpDetectionQueue.ports))
				for port := range tcpDetectionQueue.ports {
					ports = append(ports, port)
				}
				// 清空队列
				tcpDetectionQueue.ports = make(map[int]bool)
				tcpDetectionQueue.Unlock()

				// 异步检测所有排队的端口
				sem := make(chan struct{}, maxParallelIPChecks)
				var wg sync.WaitGroup
				for _, port := range ports {
					wg.Add(1)
					go func(p int) {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[port_process_collector] TCP检测panic恢复: port=%d, error=%v", p, r)
							}
						}()

						sem <- struct{}{}
						defer func() { <-sem }()

						// 快速模式下使用更短的超时时间
						var alive int
						if fastMode {
							alive, _ = checkPortTCPWithTimeout(p, 500*time.Millisecond)
						} else {
							alive, _ = checkPortTCP(p)
						}

						portStatusCache.RWMutex.Lock()
						portStatusCache.Status[p] = alive
						portStatusCache.LastCheck[p] = time.Now()
						portStatusCache.RWMutex.Unlock()

					}(port)
				}
				wg.Wait()
			}
		}
	}()
}

// 进程检测异步处理器
func startProcessDetectionWorker() {
	go func() {
		ticker := time.NewTicker(processAliveStatusInterval)
		defer ticker.Stop()
		for {
			select {
			case <-processDetectionQueue.done:
				return
			case <-ticker.C:
				processDetectionQueue.Lock()
				pids := make([]int, 0, len(processDetectionQueue.pids))
				for pid := range processDetectionQueue.pids {
					pids = append(pids, pid)
				}
				// 清空队列
				processDetectionQueue.pids = make(map[int]bool)
				processDetectionQueue.Unlock()

				// 异步检测所有排队的进程
				var wg sync.WaitGroup
				for _, pid := range pids {
					wg.Add(1)
					go func(p int) {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[simple_port_process_collector] 进程检测panic恢复: pid=%d, error=%v", p, r)
							}
						}()

						status := checkProcess(p)
						key := getPidKey(p)

						processAliveCache.RWMutex.Lock()
						processAliveCache.Status[key] = status
						processAliveCache.LastCheck[key] = time.Now()
						processAliveCache.RWMutex.Unlock()

					}(pid)
				}
				wg.Wait()
			}
		}
	}()
}

// 初始化异步检测工作器
func init() {
	startTCPDetectionWorker()
	startProcessDetectionWorker()
	startProcessStatusDetectionWorker()
}

// 优雅关闭所有异步工作器
var shutdownOnce sync.Once

func ShutdownWorkers() {
	shutdownOnce.Do(func() {
		close(tcpDetectionQueue.done)
		close(processDetectionQueue.done)
		close(processStatusDetectionQueue.done)
	})
}

var (
	portStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 30 * time.Second
	}()
	processAliveStatusInterval = func() time.Duration {
		if v := os.Getenv("PROCESS_ALIVE_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return time.Minute
	}()
	portCheckTimeout = func() time.Duration {
		if v := os.Getenv("PORT_CHECK_TIMEOUT"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 3 * time.Second
	}()
	maxParallelIPChecks = func() int {
		if v := os.Getenv("MAX_PARALLEL_IP_CHECKS"); v != "" {
			n, err := strconv.Atoi(v)
			if err == nil && n > 0 {
				return n
			}
		}
		return 8
	}()
	fastMode = func() bool {
		if v := os.Getenv("FAST_MODE"); v != "" {
			enabled, err := strconv.ParseBool(v)
			if err == nil {
				return enabled
			}
		}
		return true
	}()
)

type portStatusCacheStruct struct {
	LastCheck map[int]time.Time
	Status    map[int]int
	RWMutex   sync.RWMutex
}

var portStatusCache = &portStatusCacheStruct{
	LastCheck: make(map[int]time.Time),
	Status:    make(map[int]int),
}

type processAliveCacheStruct struct {
	LastCheck map[string]time.Time
	Status    map[string]int
	RWMutex   sync.RWMutex
}

var processAliveCache = &processAliveCacheStruct{
	LastCheck: make(map[string]time.Time),
	Status:    make(map[string]int),
}

// 进程启动时间缓存，避免重复计算
var pidStartTimeCache = struct {
	sync.RWMutex
	cache map[int]string
}{cache: make(map[int]string)}

// 进程状态缓存，避免重复读取stat文件
var processStatusCache = struct {
	sync.RWMutex
	cache map[int]ProcessStatus
	lastCheck map[int]time.Time
}{cache: make(map[int]ProcessStatus), lastCheck: make(map[int]time.Time)}

// 进程详细状态缓存（CPU、内存、IO等）
type ProcessDetailedStatus struct {
	CPUPercent     float64 `json:"cpu_percent"`
	MinFaultsPerS  float64 `json:"minflt_per_s"`
	MajFaultsPerS  float64 `json:"majflt_per_s"`
	VMRSS          float64 `json:"vmrss"`
	VMSize         float64 `json:"vmsize"`
	MemPercent     float64 `json:"mem_percent"`
	KBReadPerS     float64 `json:"kb_rd_per_s"`
	KBWritePerS    float64 `json:"kb_wr_per_s"`
	Threads        float64 `json:"threads"`
	Voluntary      float64 `json:"voluntary"`
	NonVoluntary   float64 `json:"nonvoluntary"`
	LastUpdate     time.Time `json:"last_update"`
	// 添加CPU累计时间字段用于正确计算CPU使用率
	LastUtime      float64 `json:"last_utime"`
	LastStime      float64 `json:"last_stime"`
	LastMinflt     float64 `json:"last_minflt"`
	LastMajflt     float64 `json:"last_majflt"`
	LastReadBytes  float64 `json:"last_read_bytes"`
	LastWriteBytes float64 `json:"last_write_bytes"`
}

// 进程详细状态缓存
var processDetailedStatusCache = struct {
	sync.RWMutex
	cache map[int]*ProcessDetailedStatus
	lastCheck map[int]time.Time
}{cache: make(map[int]*ProcessDetailedStatus), lastCheck: make(map[int]time.Time)}

// 进程状态采集队列
var processStatusDetectionQueue = struct {
	sync.Mutex
	pids map[int]bool
	done chan struct{}
}{pids: make(map[int]bool), done: make(chan struct{})}

// 进程状态采集间隔
var processStatusInterval = func() time.Duration {
	if v := os.Getenv("PROCESS_STATUS_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return 30 * time.Second
}()

// Collect 方法：实现 Prometheus Collector 接口，采集所有指标
func (c *SimplePortProcessCollector) Collect(ch chan<- prometheus.Metric) {
	infos := getPortProcessInfo()
	reportedProcessKeys := make(map[string]bool)
	tcpPortDone := make(map[int]bool)

	for _, info := range infos {
		// 只处理TCP协议
		if info.Protocol == "tcp" {
			labels := []string{info.ProcessName, info.ExePath, strconv.Itoa(info.Port)}

			if !tcpPortDone[info.Port] {
				// TCP端口存活检测
				alive := getPortStatus(info.Port)
				if alive >= 0 {
					ch <- prometheus.MustNewConstMetric(
						c.portTCPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
					)
				}
				tcpPortDone[info.Port] = true
			}
		}

		// 进程存活指标去重：每个唯一进程（进程名+路径）只采集一次
		processKey := info.ProcessName + "|" + info.ExePath
		if !reportedProcessKeys[processKey] {
			// 获取进程详细状态（包含存活状态）
			procStatus := getDetailedProcessStatus(info.Pid)

			// 使用详细状态中的存活信息，避免重复检测
			if procStatus.Alive >= 0 {
				ch <- prometheus.MustNewConstMetric(
					c.processAliveDesc, prometheus.GaugeValue, float64(procStatus.Alive),
					info.ProcessName, info.ExePath, procStatus.State,
				)

				// 获取进程详细状态数据（CPU、内存、IO等）
				detailedStatus := getProcessDetailedStatusCached(info.Pid)
				if detailedStatus != nil {
					// CPU使用率
					ch <- prometheus.MustNewConstMetric(
						c.processCPUPercentDesc, prometheus.GaugeValue, detailedStatus.CPUPercent,
						info.ProcessName, info.ExePath,
					)

					// 内存使用率
					ch <- prometheus.MustNewConstMetric(
						c.processMemPercentDesc, prometheus.GaugeValue, detailedStatus.MemPercent,
						info.ProcessName, info.ExePath,
					)

					// 物理内存（RSS）- 从KB转换为字节
					ch <- prometheus.MustNewConstMetric(
						c.processVMRSSDesc, prometheus.GaugeValue, detailedStatus.VMRSS*1024,
						info.ProcessName, info.ExePath,
					)

					// 虚拟内存（VMSize）- 从KB转换为字节
					ch <- prometheus.MustNewConstMetric(
						c.processVMSizeDesc, prometheus.GaugeValue, detailedStatus.VMSize*1024,
						info.ProcessName, info.ExePath,
					)

					// 线程数
					ch <- prometheus.MustNewConstMetric(
						c.processThreadsDesc, prometheus.GaugeValue, detailedStatus.Threads,
						info.ProcessName, info.ExePath,
					)

					// IO读取速率 - 从KB/秒转换为字节/秒
					ch <- prometheus.MustNewConstMetric(
						c.processIOReadDesc, prometheus.GaugeValue, detailedStatus.KBReadPerS*1024,
						info.ProcessName, info.ExePath,
					)

					// IO写入速率 - 从KB/秒转换为字节/秒
					ch <- prometheus.MustNewConstMetric(
						c.processIOWriteDesc, prometheus.GaugeValue, detailedStatus.KBWritePerS*1024,
						info.ProcessName, info.ExePath,
					)
				}
			}
			reportedProcessKeys[processKey] = true
		}
	}
}

// getPortProcessInfo 函数：获取端口与进程信息，带缓存机制
func getPortProcessInfo() []PortProcessInfo {
	portProcessCache.RWMutex.RLock()
	expired := time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0
	portProcessCache.RWMutex.RUnlock()
	if expired {
		var needClean bool
		var dataCopy []PortProcessInfo
		portProcessCache.RWMutex.Lock()
		// 再次检查，防止并发下重复扫描
		if time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0 {
			portProcessCache.Data = discoverPortProcess()
			portProcessCache.LastScan = time.Now()
			// 复制一份用于锁外清理，避免长时间持有写锁
			dataCopy = append([]PortProcessInfo(nil), portProcessCache.Data...)
			needClean = true
		}
		portProcessCache.RWMutex.Unlock()
		if needClean {
			// 自动清理所有端口相关缓存（锁外执行，避免长时间持有写锁）
			cleanStalePortCaches(dataCopy)
		}
	}
	portProcessCache.RWMutex.RLock()
	defer portProcessCache.RWMutex.RUnlock()
	return portProcessCache.Data
}

// discoverPortProcess 函数：优化端口发现效率，先建立 inode->port 映射，再遍历进程 fd 查找 socket inode
func discoverPortProcess() []PortProcessInfo {
	var results []PortProcessInfo
	tcpInodePort := parseInodePortMap([]string{"/proc/net/tcp", "/proc/net/tcp6"}, "tcp")
	seenTCP := make(map[int]bool)

	procDir, err := os.Open(procPath("/proc"))
	if err != nil {
		log.Printf("[simple_port_process_collector] failed to open /proc: %v\n", err)
		return results
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		log.Printf("[simple_port_process_collector] failed to read /proc: %v\n", err)
		return results
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdPath := procPath(fmt.Sprintf("/proc/%d/fd", pid))
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			log.Printf("[simple_port_process_collector] failed to read %s: %v\n", fdPath, err)
			continue
		}

		for _, fdEntry := range fds {
			fdLink := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			link, err := os.Readlink(fdLink)
			if err != nil {
				log.Printf("[simple_port_process_collector] failed to readlink %s: %v\n", fdLink, err)
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := link[8 : len(link)-1]

			// TCP
			if port, ok := tcpInodePort[inode]; ok {
				if seenTCP[port] {
					continue
				}
				seenTCP[port] = true
				exePath := getProcessExe(pid)
				exeName := filepath.Base(exePath)
				if isExcludedProcess(exeName) {
					continue
				}
				results = append(results, PortProcessInfo{
					ProcessName: safeLabel(exeName),
					ExePath:     safeLabel(exePath),
					Port:        port,
					Pid:         pid,
					WorkDir:     safeLabel(getProcessCwd(pid)),
					Username:    safeLabel(getProcessUser(pid)),
					Protocol:    "tcp",
				})
			}


		}
	}
	return results
}

// parseInodePortMap 解析 /proc/net/tcp 或 udp，返回 inode->port 映射
func parseInodePortMap(files []string, proto string) map[string]int {
	result := make(map[string]int)
	for _, file := range files {
		content, err := os.ReadFile(procPath(file))
		if err != nil {
			log.Printf("[simple_port_process_collector] failed to read %s: %v\n", file, err)
			continue
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if proto == "tcp" && fields[3] != "0A" {
				continue // 只查TCP LISTEN
			}
			inode := fields[9]
			addrParts := strings.Split(fields[1], ":")
			if len(addrParts) < 2 {
				continue
			}
			portHex := addrParts[len(addrParts)-1]
			port, err := strconv.ParseInt(portHex, 16, 32)
			if err != nil {
				continue
			}
			result[inode] = int(port)
		}
	}
	return result
}

// checkPortTCP 并发检测所有本地IP
func checkPortTCP(port int) (alive int, respTime float64) {
	return checkPortTCPWithTimeout(port, portCheckTimeout)
}

func checkPortTCPWithTimeout(port int, timeout time.Duration) (alive int, respTime float64) {
	commonAddrs := []string{"127.0.0.1", "0.0.0.0", "::1", "::"}
	minResp := -1.0
	found := false

	// 先检测常用地址
	for _, ip := range commonAddrs {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		cost := time.Since(start).Seconds()
		if err == nil {
			conn.Close()
			if minResp < 0 || cost < minResp {
				minResp = cost
			}
			found = true
		}
	}
	if found {
		return 1, minResp
	}

	// 常用地址都不通，再检测所有本地IP（并发）
	addrs := []string{}
	ifaces, _ := net.InterfaceAddrs()
	for _, addr := range ifaces {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		// 过滤掉无效地址：只检测GlobalUnicast
		if !ip.IsGlobalUnicast() {
			continue
		}
		addrs = append(addrs, ip.String())
	}
	if len(addrs) == 0 {
		return 0, 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resultOnce := make(chan float64, 1)
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup

	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return
			default:
			}
			start := time.Now()
			d := &net.Dialer{Timeout: timeout}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err == nil {
				// 连接成功立即关闭
				conn.Close()
				cost := time.Since(start).Seconds()
				select {
				case resultOnce <- cost:
					// 首个成功，取消其他拨号
					cancel()
				default:
				}
			}
		}(ip)
	}

	select {
	case resp := <-resultOnce:
		wg.Wait()
		return 1, resp
	case <-ctx.Done():
		wg.Wait()
		return 0, 0
	}
}

// checkProcess 函数：检测进程是否存活（检查实际进程状态）
func checkProcess(pid int) int {
	statPath := procPath(fmt.Sprintf("/proc/%d/stat", pid))
	content, err := os.ReadFile(statPath)
	if err != nil {
		return 0 // 进程不存在
	}

	fields := strings.Fields(string(content))
	if len(fields) < 3 {
		return 0
	}

	// 检查进程状态：Z表示僵尸进程，视为死亡
	state := fields[2]
	if state == "Z" {
		return 0 // 僵尸进程视为死亡
	}

	return 1 // 进程存活
}

// getProcessExe 函数：获取进程的可执行文件路径
func getProcessExe(pid int) string {
	path, err := os.Readlink(procPath(fmt.Sprintf("/proc/%d/exe", pid)))
	if err != nil || path == "" {
		return "/"
	}
	return path
}

// getProcessCwd 函数：获取进程的工作目录
func getProcessCwd(pid int) string {
	path, err := os.Readlink(procPath(fmt.Sprintf("/proc/%d/cwd", pid)))
	if err != nil || path == "" {
		return "/"
	}
	return path
}

// getProcessUser 函数：获取进程的运行用户（UID）
func getProcessUser(pid int) string {
	content, err := os.ReadFile(procPath(fmt.Sprintf("/proc/%d/status", pid)))
	if err != nil {
		return "/"
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "" {
				return fields[1]
			}
		}
	}
	return "/"
}

// safeLabel 保证 Prometheus 标签不为空，若为空则返回 "/"
func safeLabel(val string) string {
	if strings.TrimSpace(val) == "" {
		return "/"
	}
	return val
}

var excludedProcessNames = func() []string {
	env := os.Getenv("EXCLUDED_PROCESS_NAMES")
	if env == "" {
		return nil
	}
	var result []string
	for _, name := range strings.Split(env, ",") {
		n := strings.TrimSpace(name)
		if n != "" {
			result = append(result, n)
		}
	}
	return result
}()

func isExcludedProcess(exeName string) bool {
	defaultExcluded := []string{
		"systemd", "init", "kthreadd", "ksoftirqd", "rcu_sched", "rcu_bh", "bo-agent",
		"migration", "watchdog", "cpuhp", "netns", "khungtaskd", "oom_reaper", "chronyd",
		"kswapd", "fsnotify_mark", "ecryptfs-kthrea", "kauditd", "khubd", "ssh", "snmpd",
		"zabbix", "prometheus", "rpcbind", "smartdns", "cupsd", "dhclient", "master",
		"rpc.statd", "titanagent", "node_exporter", "monitor_manage", "dnsmasq",
	}
	all := append(defaultExcluded, excludedProcessNames...)
	for _, name := range all {
		if strings.Contains(exeName, name) {
			return true
		}
	}
	return false
}

// Update 实现 node_exporter 本地 Collector 接口，适配 Prometheus 的 Collect 方法
func (c *SimplePortProcessCollector) Update(ch chan<- prometheus.Metric) error {
	c.Collect(ch)
	return nil
}

// 带缓存的TCP端口存活检测（完全异步化，避免阻塞指标暴露）
func getPortStatus(port int) int {
	portStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := portStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > portStatusInterval {
		// 先获取历史状态，避免死锁
		var lastAlive int
		var hasHistory bool
		if lastAlive, hasHistory = portStatusCache.Status[port]; hasHistory {
			portStatusCache.RWMutex.RUnlock()

			// 缓存过期，加入TCP异步检测队列
			tcpDetectionQueue.Lock()
			tcpDetectionQueue.ports[port] = true
			tcpDetectionQueue.Unlock()

			// 使用上次检测结果作为临时值
			return lastAlive
		}
		portStatusCache.RWMutex.RUnlock()

		// 没有历史记录，加入TCP异步检测队列
		tcpDetectionQueue.Lock()
		tcpDetectionQueue.ports[port] = true
		tcpDetectionQueue.Unlock()

		// 不暴露指标，等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	alive := portStatusCache.Status[port]
	portStatusCache.RWMutex.RUnlock()
	return alive
}

// 自动清理所有端口相关缓存（只保留当前活跃端口）
func cleanStalePortCaches(infos []PortProcessInfo) {
	activePorts := make(map[int]bool)
	activePidKeys := make(map[string]bool)

	// 预先计算所有活跃的PidKey，避免在持有锁时调用文件系统操作
	for _, info := range infos {
		activePorts[info.Port] = true
		activePidKeys[getPidKey(info.Pid)] = true
	}

	// 原子性清理：先清理队列，再清理缓存
	cleanDetectionQueues(activePorts, activePidKeys)
	cleanStatusCaches(activePorts, activePidKeys)
}

// 清理检测队列中的过期项目
func cleanDetectionQueues(activePorts map[int]bool, activePidKeys map[string]bool) {
	// 清理TCP检测队列
	tcpDetectionQueue.Lock()
	for port := range tcpDetectionQueue.ports {
		if !activePorts[port] {
			delete(tcpDetectionQueue.ports, port)
		}
	}
	tcpDetectionQueue.Unlock()

	// 清理进程检测队列
	processDetectionQueue.Lock()
	for pid := range processDetectionQueue.pids {
		key := getPidKey(pid)
		if !activePidKeys[key] {
			delete(processDetectionQueue.pids, pid)
		}
	}
	processDetectionQueue.Unlock()

	// 清理进程状态检测队列
	processStatusDetectionQueue.Lock()
	for pid := range processStatusDetectionQueue.pids {
		key := getPidKey(pid)
		if !activePidKeys[key] {
			delete(processStatusDetectionQueue.pids, pid)
		}
	}
	processStatusDetectionQueue.Unlock()
}

// 清理状态缓存中的过期项目
func cleanStatusCaches(activePorts map[int]bool, activePidKeys map[string]bool) {
	// 清理端口状态缓存
	portStatusCache.RWMutex.Lock()
	for port := range portStatusCache.Status {
		if !activePorts[port] {
			delete(portStatusCache.Status, port)
			delete(portStatusCache.LastCheck, port)
		}
	}
	portStatusCache.RWMutex.Unlock()

	// 清理进程存活缓存
	processAliveCache.RWMutex.Lock()
	for key := range processAliveCache.Status {
		if !activePidKeys[key] {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
		}
	}
	processAliveCache.RWMutex.Unlock()

	// 清理进程启动时间缓存
	pidStartTimeCache.Lock()
	for pid := range pidStartTimeCache.cache {
		key := fmt.Sprintf("%d_%s", pid, pidStartTimeCache.cache[pid])
		if !activePidKeys[key] {
			delete(pidStartTimeCache.cache, pid)
		}
	}
	pidStartTimeCache.Unlock()

	// 清理进程状态缓存
	processStatusCache.Lock()
	// 先获取pidStartTimeCache的锁，避免并发访问
	pidStartTimeCache.RLock()
	for pid := range processStatusCache.cache {
		startTime := pidStartTimeCache.cache[pid]
		key := fmt.Sprintf("%d_%s", pid, startTime)
		if !activePidKeys[key] {
			delete(processStatusCache.cache, pid)
			delete(processStatusCache.lastCheck, pid)
		}
	}
	pidStartTimeCache.RUnlock()
	processStatusCache.Unlock()

	// 清理进程详细状态缓存
	processDetailedStatusCache.Lock()
	// 先获取pidStartTimeCache的锁，避免并发访问
	pidStartTimeCache.RLock()
	for pid := range processDetailedStatusCache.cache {
		startTime := pidStartTimeCache.cache[pid]
		key := fmt.Sprintf("%d_%s", pid, startTime)
		if !activePidKeys[key] {
			delete(processDetailedStatusCache.cache, pid)
			delete(processDetailedStatusCache.lastCheck, pid)
		}
	}
	pidStartTimeCache.RUnlock()
	processDetailedStatusCache.Unlock()
}

// 带缓存的进程存活检测（完全异步化，避免阻塞指标暴露）
func getProcessAliveStatus(pid int) int {
	key := getPidKey(pid)
	processAliveCache.RWMutex.RLock()
	now := time.Now()
	t, ok := processAliveCache.LastCheck[key]
	if !ok || now.Sub(t) > processAliveStatusInterval {
		// 先获取历史状态，避免死锁
		var lastStatus int
		var hasHistory bool
		if lastStatus, hasHistory = processAliveCache.Status[key]; hasHistory {
			processAliveCache.RWMutex.RUnlock()

			// 缓存过期，加入进程异步检测队列
			processDetectionQueue.Lock()
			processDetectionQueue.pids[pid] = true
			processDetectionQueue.Unlock()

			// 使用上次检测结果作为临时值
			return lastStatus
		}
		processAliveCache.RWMutex.RUnlock()

		// 没有历史记录，加入进程异步检测队列
		processDetectionQueue.Lock()
		processDetectionQueue.pids[pid] = true
		processDetectionQueue.Unlock()

		// 不暴露指标，等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	status := processAliveCache.Status[key]
	processAliveCache.RWMutex.RUnlock()
	return status
}

// getPidKey 生成进程缓存唯一key（pid+starttime），使用缓存避免重复计算
func getPidKey(pid int) string {
	pidStartTimeCache.RLock()
	if startTime, exists := pidStartTimeCache.cache[pid]; exists {
		pidStartTimeCache.RUnlock()
		return fmt.Sprintf("%d_%s", pid, startTime)
	}
	pidStartTimeCache.RUnlock()

	startTime := getProcessStartTime(pid)
	pidStartTimeCache.Lock()
	pidStartTimeCache.cache[pid] = startTime
	pidStartTimeCache.Unlock()

	return fmt.Sprintf("%d_%s", pid, startTime)
}

// getProcessStartTime 获取进程启动时间（/proc/<pid>/stat 第22字段）
func getProcessStartTime(pid int) string {
	statPath := procPath(fmt.Sprintf("/proc/%d/stat", pid))
	content, err := os.ReadFile(statPath)
	if err != nil {
		return "0"
	}
	fields := strings.Fields(string(content))
	if len(fields) >= 22 {
		return fields[21]
	}
	return "0"
}

// ProcessStatus 进程状态信息
type ProcessStatus struct {
	Alive     int    `json:"alive"`
	State     string `json:"state"`     // R/S/D/Z/T/t/W/X/x/K
	StartTime string `json:"starttime"`
	Pid       int    `json:"pid"`
}

// getDetailedProcessStatus 获取进程详细状态信息（带缓存）
func getDetailedProcessStatus(pid int) ProcessStatus {
	processStatusCache.RLock()
	now := time.Now()
	if status, exists := processStatusCache.cache[pid]; exists {
		if lastCheck, hasCheck := processStatusCache.lastCheck[pid]; hasCheck {
			// 如果缓存未过期（5秒内），直接返回缓存结果
			if now.Sub(lastCheck) < 5*time.Second {
				processStatusCache.RUnlock()
				return status
			}
		}
	}
	processStatusCache.RUnlock()

	// 缓存过期或不存在，重新读取
	statPath := procPath(fmt.Sprintf("/proc/%d/stat", pid))
	content, err := os.ReadFile(statPath)
	if err != nil {
		status := ProcessStatus{Pid: pid, Alive: 0, State: "X"}
		// 缓存失败结果，避免频繁重试
		processStatusCache.Lock()
		processStatusCache.cache[pid] = status
		processStatusCache.lastCheck[pid] = now
		processStatusCache.Unlock()
		return status
	}

	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		status := ProcessStatus{Pid: pid, Alive: 0, State: "X"}
		processStatusCache.Lock()
		processStatusCache.cache[pid] = status
		processStatusCache.lastCheck[pid] = now
		processStatusCache.Unlock()
		return status
	}

	state := fields[2]
	startTime := fields[21]

	alive := 1
	if state == "Z" {
		alive = 0
	}

	status := ProcessStatus{
		Pid:       pid,
		Alive:     alive,
		State:     state,
		StartTime: startTime,
	}

	// 更新缓存
	processStatusCache.Lock()
	processStatusCache.cache[pid] = status
	processStatusCache.lastCheck[pid] = now
	processStatusCache.Unlock()

	return status
}

// 进程状态检测异步处理器
func startProcessStatusDetectionWorker() {
	go func() {
		ticker := time.NewTicker(processStatusInterval)
		defer ticker.Stop()
		for {
			select {
			case <-processStatusDetectionQueue.done:
				return
			case <-ticker.C:
				processStatusDetectionQueue.Lock()
				pids := make([]int, 0, len(processStatusDetectionQueue.pids))
				for pid := range processStatusDetectionQueue.pids {
					pids = append(pids, pid)
				}
				// 清空队列
				processStatusDetectionQueue.pids = make(map[int]bool)
				processStatusDetectionQueue.Unlock()

				// 异步检测所有排队的进程状态
				var wg sync.WaitGroup
				for _, pid := range pids {
					wg.Add(1)
					go func(p int) {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[simple_port_process_collector] 进程状态检测panic恢复: pid=%d, error=%v", p, r)
							}
						}()

						status := getProcessDetailedStatusData(p)
						if status != nil {
							processDetailedStatusCache.Lock()
							processDetailedStatusCache.cache[p] = status
							processDetailedStatusCache.lastCheck[p] = time.Now()
							processDetailedStatusCache.Unlock()
						}

					}(pid)
				}
				wg.Wait()
			}
		}
	}()
}

// 获取进程详细状态数据（CPU、内存、IO等）
func getProcessDetailedStatusData(pid int) *ProcessDetailedStatus {
	now := time.Now()

	// 获取基础状态信息
	statusData, err := getProcessStatusData(pid)
	if err != nil {
		log.Printf("[simple_port_process_collector] 获取进程状态失败: pid=%d, error=%v", pid, err)
		return nil
	}

	// 获取CPU和缺页信息
	utime, stime, minflt, majflt, err := getProcessCPUAndFaults(pid)
	if err != nil {
		log.Printf("[simple_port_process_collector] 获取进程CPU信息失败: pid=%d, error=%v", pid, err)
		return nil
	}

	// 获取IO数据
	readBytes, writeBytes, err := getProcessIOStats(pid)
	if err != nil {
		log.Printf("[simple_port_process_collector] 获取进程IO信息失败: pid=%d, error=%v", pid, err)
		return nil
	}

	// 获取内存总量
	memTotal, _ := getSystemMemTotal()
	if memTotal == 0 {
		memTotal = 1 // 防止除零
	}

	// 计算增量值
	processDetailedStatusCache.RLock()
	cache, exists := processDetailedStatusCache.cache[pid]
	processDetailedStatusCache.RUnlock()

	var cpuPercent, minFaultsPerS, majFaultsPerS, kbReadPerS, kbWritePerS float64

	if exists && cache != nil {
		timeDiff := now.Sub(cache.LastUpdate).Seconds()
		if timeDiff > 0 {
			// CPU使用率计算：基于累计CPU时间差值（utime/stime单位是jiffies，需要转换为秒）
			totalCPUDiff := (utime - cache.LastUtime) + (stime - cache.LastStime)
			cpuPercent = (totalCPUDiff / 100) / timeDiff // 转换为秒，然后计算百分比

			// 缺页错误速率计算
			minFaultsPerS = (minflt - cache.LastMinflt) / timeDiff
			majFaultsPerS = (majflt - cache.LastMajflt) / timeDiff

			// IO速率计算
			kbReadPerS = (readBytes - cache.LastReadBytes) / 1024 / timeDiff
			kbWritePerS = (writeBytes - cache.LastWriteBytes) / 1024 / timeDiff
		}
	}

	// 静态指标
	vmrss := parseProcessStatusValue(statusData["vmrss"])
	vmsize := parseProcessStatusValue(statusData["vmsize"])
	threads := parseProcessStatusValue(statusData["threads"])
	voluntary := parseProcessStatusValue(statusData["voluntary_ctxt_switches"])
	nonvoluntary := parseProcessStatusValue(statusData["nonvoluntary_ctxt_switches"])
	memPercent := vmrss / memTotal * 100

	return &ProcessDetailedStatus{
		CPUPercent:     cpuPercent,
		MinFaultsPerS:  minFaultsPerS,
		MajFaultsPerS:  majFaultsPerS,
		VMRSS:          vmrss,
		VMSize:         vmsize,
		MemPercent:     memPercent,
		KBReadPerS:     kbReadPerS,
		KBWritePerS:    kbWritePerS,
		Threads:        threads,
		Voluntary:      voluntary,
		NonVoluntary:   nonvoluntary,
		LastUpdate:     now,
		// 保存累计时间用于下次计算
		LastUtime:      utime,
		LastStime:      stime,
		LastMinflt:     minflt,
		LastMajflt:     majflt,
		LastReadBytes:  readBytes,
		LastWriteBytes: writeBytes,
	}
}

// 从/proc/[pid]/status获取状态信息
func getProcessStatusData(pid int) (map[string]string, error) {
	statusFile := procPath(fmt.Sprintf("/proc/%d/status", pid))
	file, err := os.Open(statusFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		data[key] = value
	}
	return data, scanner.Err()
}

// 从/proc/[pid]/stat获取CPU和缺页信息
func getProcessCPUAndFaults(pid int) (float64, float64, float64, float64, error) {
	content, err := os.ReadFile(procPath(fmt.Sprintf("/proc/%d/stat", pid)))
	if err != nil {
		return 0, 0, 0, 0, err
	}

	fields := strings.Fields(string(content))
	if len(fields) < 24 {
		return 0, 0, 0, 0, fmt.Errorf("invalid stat format")
	}

	utime, _ := strconv.ParseFloat(fields[13], 64)
	stime, _ := strconv.ParseFloat(fields[14], 64)
	minflt, _ := strconv.ParseFloat(fields[9], 64)
	majflt, _ := strconv.ParseFloat(fields[11], 64)

	// 返回原始值，不除以100，在CPU计算时再处理
	return utime, stime, minflt, majflt, nil
}

// 从/proc/[pid]/io获取IO数据
func getProcessIOStats(pid int) (float64, float64, error) {
	content, err := os.ReadFile(procPath(fmt.Sprintf("/proc/%d/io", pid)))
	if err != nil {
		return 0, 0, err
	}

	var readBytes, writeBytes float64
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "read_bytes:") {
			fmt.Sscanf(line, "read_bytes: %f", &readBytes)
		}
		if strings.HasPrefix(line, "write_bytes:") {
			fmt.Sscanf(line, "write_bytes: %f", &writeBytes)
		}
	}
	return readBytes, writeBytes, nil
}

// 获取系统内存总量
func getSystemMemTotal() (float64, error) {
	content, err := os.ReadFile(procPath("/proc/meminfo"))
	if err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "MemTotal:") {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				return strconv.ParseFloat(fields[1], 64)
			}
		}
	}
	return 0, fmt.Errorf("MemTotal not found")
}

// 辅助函数：转换状态值，支持带单位（如 '25592 kB'）
func parseProcessStatusValue(value string) float64 {
	if value == "" {
		return 0
	}
	// 只取第一个数字部分
	fields := strings.Fields(value)
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return f
}

// 带缓存的进程详细状态检测（完全异步化，避免阻塞指标暴露）
func getProcessDetailedStatusCached(pid int) *ProcessDetailedStatus {
	processDetailedStatusCache.RLock()
	now := time.Now()
	t, ok := processDetailedStatusCache.lastCheck[pid]
	if !ok || now.Sub(t) > processStatusInterval {
		// 先获取历史状态，避免死锁
		var lastStatus *ProcessDetailedStatus
		var hasHistory bool
		if lastStatus, hasHistory = processDetailedStatusCache.cache[pid]; hasHistory {
			processDetailedStatusCache.RUnlock()

			// 缓存过期，加入进程状态异步检测队列
			processStatusDetectionQueue.Lock()
			processStatusDetectionQueue.pids[pid] = true
			processStatusDetectionQueue.Unlock()

			// 使用上次检测结果作为临时值
			return lastStatus
		}
		processDetailedStatusCache.RUnlock()

		// 没有历史记录，加入进程状态异步检测队列
		processStatusDetectionQueue.Lock()
		processStatusDetectionQueue.pids[pid] = true
		processStatusDetectionQueue.Unlock()

		// 不暴露指标，等待异步检测完成
		return nil
	}
	status := processDetailedStatusCache.cache[pid]
	processDetailedStatusCache.RUnlock()
	return status
}
