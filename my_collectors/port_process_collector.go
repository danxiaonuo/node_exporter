package my_collectors

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PortProcessInfo 结构体：用于存储端口与进程的关联信息
// 包含进程名、可执行文件路径、端口号、进程号、工作目录、用户名、协议类型
// 主要用于 Prometheus 指标的标签信息
type PortProcessInfo struct {
	ProcessName string // 进程名
	ExePath     string // 可执行文件路径
	Port        int    // 端口号
	Pid         int    // 进程号
	WorkDir     string // 工作目录
	Username    string // 运行用户
	Protocol    string // 协议类型：tcp/udp
}

// portProcessCacheStruct 结构体：用于缓存端口与进程的发现结果，减少频繁扫描带来的系统负载
// LastScan 记录上次扫描时间，Data 存储扫描结果，RWMutex 用于并发保护
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

// PortProcessCollector 结构体：实现 Prometheus Collector 接口
// 用于采集端口存活、进程存活、端口响应时间等指标
// 新增HTTP存活指标描述符
type PortProcessCollector struct {
	portTCPAliveDesc *prometheus.Desc // TCP端口存活指标描述符
	portTCPRespDesc  *prometheus.Desc // TCP端口响应时间指标描述符
	portUDPAliveDesc *prometheus.Desc // UDP端口存活指标描述符
	httpAliveDesc    *prometheus.Desc // HTTP端口存活指标描述符
	processAliveDesc *prometheus.Desc // 进程存活指标描述符
}

// NewPortProcessCollector 构造函数：创建并返回一个新的端口进程采集器
func NewPortProcessCollector() *PortProcessCollector {
	labels := []string{"process_name", "exe_path", "port"}
	return &PortProcessCollector{
		portTCPAliveDesc: prometheus.NewDesc(
			"node_tcp_port_alive",
			"TCP Port alive status (1=alive, 0=dead)",
			labels, nil,
		),
		portTCPRespDesc: prometheus.NewDesc(
			"node_tcp_port_response_seconds",
			"TCP Port response time in seconds",
			labels, nil,
		),
		portUDPAliveDesc: prometheus.NewDesc(
			"node_udp_port_alive",
			"UDP Port alive status (1=exist, 0=not exist)",
			labels, nil,
		),
		httpAliveDesc: prometheus.NewDesc(
			"node_http_port_alive",
			"HTTP Port alive status (1=alive, 0=dead)",
			labels, nil,
		),
		processAliveDesc: prometheus.NewDesc(
			"node_process_alive",
			"Process alive status (1=alive, 0=dead)",
			[]string{"process_name", "exe_path"}, nil,
		),
	}
}

// Describe 方法：实现 Prometheus Collector 接口，描述所有指标
func (c *PortProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.portTCPAliveDesc
	ch <- c.portTCPRespDesc
	ch <- c.portUDPAliveDesc
	ch <- c.httpAliveDesc
	ch <- c.processAliveDesc
}

// 记录哪些端口曾经 HTTP 检测通过
var httpAliveHistory = struct {
	sync.RWMutex
	Ports map[int]bool
}{Ports: make(map[int]bool)}

// 新增：HTTP检测异步化，避免阻塞指标暴露
var httpDetectionQueue = struct {
	sync.Mutex
	ports map[int]bool
	done  chan struct{}
}{ports: make(map[int]bool), done: make(chan struct{})}

// 新增：TCP检测异步化，避免阻塞指标暴露
var tcpDetectionQueue = struct {
	sync.Mutex
	ports map[int]bool
	done  chan struct{}
}{ports: make(map[int]bool), done: make(chan struct{})}

// 新增：进程检测异步化，避免阻塞指标暴露
var processDetectionQueue = struct {
	sync.Mutex
	pids map[int]bool
	done chan struct{}
}{pids: make(map[int]bool), done: make(chan struct{})}

// 新增：UDP检测异步化，避免阻塞指标暴露
var udpDetectionQueue = struct {
	sync.Mutex
	ports map[int]bool
	done  chan struct{}
}{ports: make(map[int]bool), done: make(chan struct{})}

// 新增：HTTP检测异步处理器
func startHTTPDetectionWorker() {
	go func() {
		ticker := time.NewTicker(httpDetectionInterval) // 每30秒处理一次队列
		defer ticker.Stop()
		for {
			select {
			case <-httpDetectionQueue.done:
				return
			case <-ticker.C:
				httpDetectionQueue.Lock()
				ports := make([]int, 0, len(httpDetectionQueue.ports))
				for port := range httpDetectionQueue.ports {
					ports = append(ports, port)
				}
				// 清空队列
				httpDetectionQueue.ports = make(map[int]bool)
				httpDetectionQueue.Unlock()

				// 异步检测所有排队的端口，使用信号量控制并发数
				sem := make(chan struct{}, httpDetectionConcurrency) // 使用配置的并发数
				var wg sync.WaitGroup
				for _, port := range ports {
					wg.Add(1)
					// 修复：正确捕获循环变量
					port := port
					go func() {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[port_process_collector] HTTP检测panic恢复: port=%d, error=%v", port, r)
							}
						}()

						// 修复：正确的信号量使用
						sem <- struct{}{}
						defer func() { <-sem }()

						status := checkPortHTTP(port)

						httpStatusCache.RWMutex.Lock()
						httpStatusCache.Status[port] = status
						httpStatusCache.LastCheck[port] = time.Now()
						if status == 1 {
							httpAliveHistory.Lock()
							httpAliveHistory.Ports[port] = true
							httpAliveHistory.Unlock()
						}
						httpStatusCache.RWMutex.Unlock()

					}()
				}
				wg.Wait()
			}
		}
	}()
}

// 新增：TCP检测异步处理器
func startTCPDetectionWorker() {
	go func() {
		ticker := time.NewTicker(portStatusInterval) // 使用TCP检测间隔
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
					// 修复：正确捕获循环变量
					port := port
					go func() {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[port_process_collector] TCP检测panic恢复: port=%d, error=%v", port, r)
							}
						}()

						sem <- struct{}{}
						defer func() { <-sem }()

						// 快速模式下使用更短的超时时间
						var alive int
						var respTime float64
						if fastMode {
							alive, respTime = checkPortTCPWithTimeout(port, 500*time.Millisecond)
						} else {
							alive, respTime = checkPortTCP(port)
						}

						portStatusCache.RWMutex.Lock()
						portStatusCache.Status[port] = alive
						portStatusCache.RespTime[port] = respTime
						portStatusCache.LastCheck[port] = time.Now()
						portStatusCache.RWMutex.Unlock()

					}()
				}
				wg.Wait()
			}
		}
	}()
}

// 新增：进程检测异步处理器
func startProcessDetectionWorker() {
	go func() {
		ticker := time.NewTicker(processAliveStatusInterval) // 使用进程检测间隔
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
					// 修复：正确捕获循环变量
					pid := pid
					go func() {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[port_process_collector] 进程检测panic恢复: pid=%d, error=%v", pid, r)
							}
						}()

						status := checkProcess(pid)
						key := getPidKey(pid)

						processAliveCache.RWMutex.Lock()
						processAliveCache.Status[key] = status
						processAliveCache.LastCheck[key] = time.Now()
						processAliveCache.RWMutex.Unlock()

					}()
				}
				wg.Wait()
			}
		}
	}()
}

// 新增：UDP检测异步处理器
func startUDPDetectionWorker() {
	go func() {
		ticker := time.NewTicker(udpStatusInterval) // 使用UDP检测间隔
		defer ticker.Stop()
		for {
			select {
			case <-udpDetectionQueue.done:
				return
			case <-ticker.C:
				udpDetectionQueue.Lock()
				ports := make([]int, 0, len(udpDetectionQueue.ports))
				for port := range udpDetectionQueue.ports {
					ports = append(ports, port)
				}
				// 清空队列
				udpDetectionQueue.ports = make(map[int]bool)
				udpDetectionQueue.Unlock()

				// 异步检测所有排队的UDP端口
				var wg sync.WaitGroup
				for _, port := range ports {
					wg.Add(1)
					// 修复：正确捕获循环变量
					port := port
					go func() {
						defer wg.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Printf("[port_process_collector] UDP检测panic恢复: port=%d, error=%v", port, r)
							}
						}()

						// UDP检测：检查端口是否在监听（基于/proc/net/udp）
						status := checkUDPPort(port)

						udpStatusCache.RWMutex.Lock()
						udpStatusCache.Status[port] = status
						udpStatusCache.LastCheck[port] = time.Now()
						udpStatusCache.RWMutex.Unlock()

					}()
				}
				wg.Wait()
			}
		}
	}()
}

// 新增：初始化所有异步检测工作器
func init() {
	startHTTPDetectionWorker()
	startTCPDetectionWorker()
	startProcessDetectionWorker()
	startUDPDetectionWorker()
}

var (
	portStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 30 * time.Second // 减少到30秒，提高缓存命中率
	}()
	// 新增 HTTP 检测缓存周期
	httpStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_HTTP_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 5 * time.Minute // 完全异步检测下，保持较长的缓存时间
	}()
	// 新增 UDP 检测缓存周期
	udpStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_UDP_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return portStatusInterval // 默认与 TCP 检测一致
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
		return 3 * time.Second // 默认3秒，适应更多网络环境
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
	// 新增：是否启用HTTP检测的环境变量
	enableHTTPDetection = func() bool {
		if v := os.Getenv("ENABLE_HTTP_DETECTION"); v != "" {
			enabled, err := strconv.ParseBool(v)
			if err == nil {
				return enabled
			}
		}
		return true // 默认启用
	}()
	// 新增：HTTP检测并发数配置
	httpDetectionConcurrency = func() int {
		if v := os.Getenv("HTTP_DETECTION_CONCURRENCY"); v != "" {
			n, err := strconv.Atoi(v)
			if err == nil && n > 0 {
				return n
			}
		}
		return 10 // 默认10个并发
	}()
	// 新增：HTTP检测工作器处理间隔配置
	httpDetectionInterval = func() time.Duration {
		if v := os.Getenv("HTTP_DETECTION_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 30 * time.Second // 完全异步检测下，30秒处理一次即可
	}()
	// 新增：快速模式配置，减少指标暴露时间
	fastMode = func() bool {
		if v := os.Getenv("FAST_MODE"); v != "" {
			enabled, err := strconv.ParseBool(v)
			if err == nil {
				return enabled
			}
		}
		return true // 默认启用快速模式，提高性能稳定性
	}()
)

type portStatusCacheStruct struct {
	LastCheck map[int]time.Time
	Status    map[int]int
	RespTime  map[int]float64
	RWMutex   sync.RWMutex
}

var portStatusCache = &portStatusCacheStruct{
	LastCheck: make(map[int]time.Time),
	Status:    make(map[int]int),
	RespTime:  make(map[int]float64),
}

// 新增 HTTP 检测缓存结构

type httpStatusCacheStruct struct {
	LastCheck map[int]time.Time
	Status    map[int]int
	RWMutex   sync.RWMutex
}

var httpStatusCache = &httpStatusCacheStruct{
	LastCheck: make(map[int]time.Time),
	Status:    make(map[int]int),
}

// 新增 UDP 检测缓存结构

type udpStatusCacheStruct struct {
	LastCheck map[int]time.Time
	Status    map[int]int
	RWMutex   sync.RWMutex
}

var udpStatusCache = &udpStatusCacheStruct{
	LastCheck: make(map[int]time.Time),
	Status:    make(map[int]int),
}

// 进程存活检测缓存结构

type processAliveCacheStruct struct {
	LastCheck map[string]time.Time
	Status    map[string]int
	RWMutex   sync.RWMutex
}

var processAliveCache = &processAliveCacheStruct{
	LastCheck: make(map[string]time.Time),
	Status:    make(map[string]int),
}

// Collect 方法：实现 Prometheus Collector 接口，采集所有指标
// TCP/UDP端口分别采集，指标名区分，HTTP端口单独采集
func (c *PortProcessCollector) Collect(ch chan<- prometheus.Metric) {

	infos := getPortProcessInfo()                // 获取端口与进程列表（8小时刷新一次）
	reportedProcessKeys := make(map[string]bool) // 记录已上报的进程，避免重复（基于进程名+路径）
	tcpPortDone := make(map[int]bool)
	udpPortDone := make(map[int]bool)

	// 优化：批量处理，减少锁竞争和HTTP检测逻辑复杂度
	for _, info := range infos {
		labels := []string{info.ProcessName, info.ExePath, strconv.Itoa(info.Port)}
		if info.Protocol == "tcp" {
			if !tcpPortDone[info.Port] {
				// TCP端口存活和响应时间（快速检测，不阻塞）
				alive, respTime := getPortStatus(info.Port)
				if alive >= 0 { // 只暴露有效的TCP状态（>=0）
					ch <- prometheus.MustNewConstMetric(
						c.portTCPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
					)
					ch <- prometheus.MustNewConstMetric(
						c.portTCPRespDesc, prometheus.GaugeValue, respTime, labels...,
					)
				}
				// alive == -1 表示暂时不暴露指标，等待异步检测完成
				// HTTP检测优化：简化逻辑，减少锁竞争
				if enableHTTPDetection {
					httpStatus := getPortHTTPStatus(info.Port)
					if httpStatus >= 0 { // 只暴露有效的HTTP状态（>=0）
						// 只暴露曾经HTTP成功的端口
						httpAliveHistory.RLock()
						everAlive := httpAliveHistory.Ports[info.Port]
						httpAliveHistory.RUnlock()

						if everAlive {
							ch <- prometheus.MustNewConstMetric(
								c.httpAliveDesc, prometheus.GaugeValue, float64(httpStatus), labels...,
							)
						}
					}
					// httpStatus == -1 表示暂时不暴露指标，等待异步检测完成
				}
				tcpPortDone[info.Port] = true
			}
		} else if info.Protocol == "udp" {
			if !udpPortDone[info.Port] {
				alive := getPortUDPStatus(info.Port, 1)
				if alive >= 0 { // 只暴露有效的UDP状态（>=0）
					ch <- prometheus.MustNewConstMetric(
						c.portUDPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
					)
				}
				// alive == -1 表示暂时不暴露指标，等待异步检测完成
				udpPortDone[info.Port] = true
			}
		}
		// 进程存活指标去重：每个唯一进程（进程名+路径）只采集一次
		processKey := info.ProcessName + "|" + info.ExePath
		if !reportedProcessKeys[processKey] {
			procAlive := getProcessAliveStatus(info.Pid)
			if procAlive >= 0 { // 只暴露有效的进程状态（>=0）
				ch <- prometheus.MustNewConstMetric(
					c.processAliveDesc, prometheus.GaugeValue, float64(procAlive),
					info.ProcessName, info.ExePath,
				)
			}
			// procAlive == -1 表示暂时不暴露指标，等待异步检测完成
			reportedProcessKeys[processKey] = true
		}
	}
}

// getPortProcessInfo 函数：获取端口与进程信息，带缓存机制
// 仅在缓存过期（8小时）或首次运行时重新扫描，其他时间直接返回缓存结果
func getPortProcessInfo() []PortProcessInfo {
	portProcessCache.RWMutex.RLock()
	expired := time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0
	portProcessCache.RWMutex.RUnlock()
	if expired {
		portProcessCache.RWMutex.Lock()
		// 再次检查，防止并发下重复扫描
		if time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0 {
			portProcessCache.Data = discoverPortProcess()
			portProcessCache.LastScan = time.Now()
			// 新增：自动清理所有端口相关缓存
			cleanStalePortCaches(portProcessCache.Data)
		}
		portProcessCache.RWMutex.Unlock()
	}
	portProcessCache.RWMutex.RLock()
	defer portProcessCache.RWMutex.RUnlock()
	return portProcessCache.Data
}

// discoverPortProcess 函数：优化端口发现效率，先建立 inode->port 映射，再遍历进程 fd 查找 socket inode
func discoverPortProcess() []PortProcessInfo {
	var results []PortProcessInfo
	tcpInodePort := parseInodePortMap([]string{"/proc/net/tcp", "/proc/net/tcp6"}, "tcp")
	udpInodePort := parseInodePortMap([]string{"/proc/net/udp", "/proc/net/udp6"}, "udp")
	seenTCP := make(map[int]bool) // 端口唯一
	seenUDP := make(map[int]bool)
	// 优化：缓存进程信息，避免重复获取
	processInfoCache := make(map[int]struct {
		exePath  string
		exeName  string
		workDir  string
		username string
	})

	procDir, err := os.Open(procPath("/proc"))
	if err != nil {
		log.Printf("[port_process_collector] failed to open /proc: %v\n", err)
		return results
	}
	defer procDir.Close()
	entries, err := procDir.Readdir(-1)
	if err != nil {
		log.Printf("[port_process_collector] failed to read /proc: %v\n", err)
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
			log.Printf("[port_process_collector] failed to read %s: %v\n", fdPath, err)
			continue
		}

		// 优化：获取进程信息（只获取一次）
		var processInfo struct {
			exePath  string
			exeName  string
			workDir  string
			username string
		}
		if cached, exists := processInfoCache[pid]; exists {
			processInfo = cached
		} else {
			exePath := getProcessExe(pid)
			exeName := filepath.Base(exePath)
			if isExcludedProcess(exeName) {
				continue // 排除的进程直接跳过
			}
			processInfo = struct {
				exePath  string
				exeName  string
				workDir  string
				username string
			}{
				exePath:  exePath,
				exeName:  exeName,
				workDir:  getProcessCwd(pid),
				username: getProcessUser(pid),
			}
			processInfoCache[pid] = processInfo
		}

		for _, fdEntry := range fds {
			fdLink := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			link, err := os.Readlink(fdLink)
			if err != nil {
				log.Printf("[port_process_collector] failed to readlink %s: %v\n", fdLink, err)
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
				results = append(results, PortProcessInfo{
					ProcessName: safeLabel(processInfo.exeName),
					ExePath:     safeLabel(processInfo.exePath),
					Port:        port,
					Pid:         pid,
					WorkDir:     safeLabel(processInfo.workDir),
					Username:    safeLabel(processInfo.username),
					Protocol:    "tcp",
				})
			}
			// UDP
			if port, ok := udpInodePort[inode]; ok {
				if seenUDP[port] {
					continue
				}
				seenUDP[port] = true
				results = append(results, PortProcessInfo{
					ProcessName: safeLabel(processInfo.exeName),
					ExePath:     safeLabel(processInfo.exePath),
					Port:        port,
					Pid:         pid,
					WorkDir:     safeLabel(processInfo.workDir),
					Username:    safeLabel(processInfo.username),
					Protocol:    "udp",
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
			log.Printf("[port_process_collector] failed to read %s: %v\n", file, err)
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

// checkPortTCP 并发检测所有本地IP，常用地址串行，其他并发，取最快成功
// 1. 先串行检测常用地址（127.0.0.1、0.0.0.0、::1、::），极快返回常见监听场景
// 2. 若全部不通，再对所有本地IP（IPv4/IPv6）做有限并发检测（最大maxParallelIPChecks），一旦有一个成功立即返回
// 3. 并发控制用信号量，防止极端大规模主机拖垮性能
// 4. 检测超时时间可通过PORT_CHECK_TIMEOUT配置，默认1分钟
// 返回值：alive（1=存活，0=不可用），respTime（TCP连接耗时，秒）
func checkPortTCP(port int) (alive int, respTime float64) {
	return checkPortTCPWithTimeout(port, portCheckTimeout)
}

func checkPortTCPWithTimeout(port int, timeout time.Duration) (alive int, respTime float64) {
	commonAddrs := []string{"127.0.0.1", "0.0.0.0", "::1", "::"}
	minResp := -1.0 // 检测失败时返回-1
	found := false
	// 先检测常用地址
	for _, ip := range commonAddrs {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		cost := time.Since(start).Seconds()
		if err == nil {
			// 修复：立即关闭连接，避免资源泄漏
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
	resultCh := make(chan float64, len(addrs))
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup
	for _, ip := range addrs {
		wg.Add(1)
		// 修复：正确捕获循环变量
		ip := ip
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			select {
			case <-ctx.Done():
				<-sem
				return
			default:
			}
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
			cost := time.Since(start).Seconds()
			if err == nil {
				// 修复：立即关闭连接，避免资源泄漏
				conn.Close()
				select {
				case resultCh <- cost:
					cancel() // 有一个成功就取消其他
				default:
				}
			}
			<-sem
		}()
	}
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	for resp := range resultCh {
		return 1, resp
	}
	return 0, 0 // 检测失败时respTime返回0
}

// checkPortHTTP 并发检测所有本地IP，常用地址串行，其他并发，取最快成功
// 1. 先串行检测常用地址（127.0.0.1、0.0.0.0、::1、::），极快返回常见监听场景
// 2. 若全部不通，再对所有本地IP（IPv4/IPv6）做有限并发检测（最大maxParallelIPChecks），一旦有一个成功立即返回
// 3. 并发控制用信号量，防止极端大规模主机拖垮性能
// 4. 检测超时时间可通过PORT_CHECK_TIMEOUT配置，默认1分钟
// 返回值：1=HTTP服务可访问，0=不可访问
func checkPortHTTP(port int) int {
	return checkPortHTTPWithTimeout(port, portCheckTimeout)
}

func checkPortHTTPWithTimeout(port int, timeout time.Duration) int {
	// 获取所有本地IP地址
	addrs := []string{}

	// 添加常用地址
	commonAddrs := []string{"127.0.0.1", "0.0.0.0", "::1", "::"}
	addrs = append(addrs, commonAddrs...)

	// 添加其他本地IP地址
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
		// 避免重复添加常用地址
		ipStr := ip.String()
		duplicate := false
		for _, commonAddr := range commonAddrs {
			if ipStr == commonAddr {
				duplicate = true
				break
			}
		}
		if !duplicate {
			addrs = append(addrs, ipStr)
		}
	}

	if len(addrs) == 0 {
		return 0
	}

	// 对所有地址进行并发检测
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resultCh := make(chan struct{}, len(addrs))
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup

	for _, ip := range addrs {
		wg.Add(1)
		// 修复：正确捕获循环变量
		ip := ip
		go func() {
			defer wg.Done()

			// 获取信号量
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			// 构建URL
			url := "http://[" + ip + "]:" + strconv.Itoa(port)
			if strings.Count(ip, ":") == 0 {
				url = "http://" + ip + ":" + strconv.Itoa(port)
			}

			// 创建HTTP客户端
			client := &http.Client{Timeout: timeout}
			resp, err := client.Get(url)
			if err == nil && resp != nil {
				// 修复：确保响应体被正确关闭
				defer resp.Body.Close()
				// 更严格的HTTP检测：检查状态码和Content-Type
				if resp.StatusCode >= 200 && resp.StatusCode < 600 {
					contentType := resp.Header.Get("Content-Type")
					// 检查是否为有效的HTTP响应
					if contentType != "" || resp.Header.Get("Server") != "" ||
						strings.HasPrefix(contentType, "text/") ||
						strings.HasPrefix(contentType, "application/") ||
						strings.HasPrefix(contentType, "image/") {
						select {
						case resultCh <- struct{}{}:
							cancel() // 有一个成功就取消其他
						default:
						}
						return
					}
				}
			}
		}()
	}

	// 等待所有goroutine完成或超时
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 等待结果
	for range resultCh {
		return 1
	}
	return 0
}

// checkUDPPort 函数：检测UDP端口是否在监听
// 通过检查 /proc/net/udp 和 /proc/net/udp6 来判断端口是否在监听
func checkUDPPort(port int) int {
	// 检查IPv4 UDP端口
	tcpInodePort := parseInodePortMap([]string{"/proc/net/udp"}, "udp")
	for _, p := range tcpInodePort {
		if p == port {
			return 1
		}
	}

	// 检查IPv6 UDP端口
	udpInodePort := parseInodePortMap([]string{"/proc/net/udp6"}, "udp")
	for _, p := range udpInodePort {
		if p == port {
			return 1
		}
	}

	return 0
}

// checkProcess 函数：检测进程是否存活
// 只要 /proc/<pid> 目录存在即认为进程存活
func checkProcess(pid int) int {
	if _, err := os.Stat(procPath(fmt.Sprintf("/proc/%d", pid))); err == nil {
		return 1
	}
	return 0
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
func (c *PortProcessCollector) Update(ch chan<- prometheus.Metric) error {
	c.Collect(ch)
	return nil
}

// 带缓存的TCP端口存活检测（完全异步化，避免阻塞指标暴露）
func getPortStatus(port int) (alive int, respTime float64) {
	portStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := portStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > portStatusInterval {
		portStatusCache.RWMutex.RUnlock()

		// 缓存过期，加入TCP异步检测队列
		tcpDetectionQueue.Lock()
		tcpDetectionQueue.ports[port] = true
		tcpDetectionQueue.Unlock()

		// 修复：避免重复获取锁，直接返回-1等待异步检测完成
		return -1, -1 // 使用-1表示暂时不暴露指标
	}
	alive = portStatusCache.Status[port]
	respTime = portStatusCache.RespTime[port]
	portStatusCache.RWMutex.RUnlock()
	return
}

// 带缓存的HTTP端口存活检测（完全异步化，避免阻塞指标暴露）
func getPortHTTPStatus(port int) int {
	httpStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := httpStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > httpStatusInterval {
		httpStatusCache.RWMutex.RUnlock()
		// 缓存过期，加入异步检测队列
		httpDetectionQueue.Lock()
		httpDetectionQueue.ports[port] = true
		httpDetectionQueue.Unlock()

		// 使用历史状态作为临时值，避免阻塞
		httpAliveHistory.RLock()
		everAlive := httpAliveHistory.Ports[port]
		httpAliveHistory.RUnlock()

		if everAlive {
			// 曾经HTTP成功过，使用历史状态
			// 修复：避免重复获取锁，直接使用历史状态
			return 1 // 有历史记录但无缓存，假设为存活
		}
		// 无历史记录，不暴露HTTP指标，等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	status := httpStatusCache.Status[port]
	httpStatusCache.RWMutex.RUnlock()
	return status
}

// 带缓存的UDP端口存活检测（完全异步化，避免阻塞指标暴露）
func getPortUDPStatus(port int, exist int) int {
	udpStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := udpStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > udpStatusInterval {
		udpStatusCache.RWMutex.RUnlock()

		// 缓存过期，加入UDP异步检测队列
		udpDetectionQueue.Lock()
		udpDetectionQueue.ports[port] = true
		udpDetectionQueue.Unlock()

		// 修复：避免重复获取锁，直接返回-1等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	status := udpStatusCache.Status[port]
	udpStatusCache.RWMutex.RUnlock()
	return status
}

// 自动清理所有端口相关缓存（只保留当前活跃端口）
func cleanStalePortCaches(infos []PortProcessInfo) {
	activePorts := make(map[int]bool)
	activePidKeys := make(map[string]bool)
	for _, info := range infos {
		activePorts[info.Port] = true
		activePidKeys[getPidKey(info.Pid)] = true
	}

	// 修复：按照固定顺序获取锁，避免死锁
	// 顺序：httpDetectionQueue -> tcpDetectionQueue -> processDetectionQueue -> udpDetectionQueue -> httpAliveHistory -> portStatusCache -> udpStatusCache -> httpStatusCache -> processAliveCache

	// 清理异步检测队列中的过期端口和进程
	httpDetectionQueue.Lock()
	for port := range httpDetectionQueue.ports {
		if !activePorts[port] {
			delete(httpDetectionQueue.ports, port)
		}
	}
	// 防止内存泄漏：限制队列大小
	if len(httpDetectionQueue.ports) > 1000 {
		// 如果队列过大，清理最旧的条目
		ports := make([]int, 0, len(httpDetectionQueue.ports))
		for port := range httpDetectionQueue.ports {
			ports = append(ports, port)
		}
		// 保留最新的1000个
		if len(ports) > 1000 {
			httpDetectionQueue.ports = make(map[int]bool)
			for i := len(ports) - 1000; i < len(ports); i++ {
				httpDetectionQueue.ports[ports[i]] = true
			}
		}
	}
	httpDetectionQueue.Unlock()

	tcpDetectionQueue.Lock()
	for port := range tcpDetectionQueue.ports {
		if !activePorts[port] {
			delete(tcpDetectionQueue.ports, port)
		}
	}
	// 防止内存泄漏：限制队列大小
	if len(tcpDetectionQueue.ports) > 1000 {
		ports := make([]int, 0, len(tcpDetectionQueue.ports))
		for port := range tcpDetectionQueue.ports {
			ports = append(ports, port)
		}
		if len(ports) > 1000 {
			tcpDetectionQueue.ports = make(map[int]bool)
			for i := len(ports) - 1000; i < len(ports); i++ {
				tcpDetectionQueue.ports[ports[i]] = true
			}
		}
	}
	tcpDetectionQueue.Unlock()

	processDetectionQueue.Lock()
	for pid := range processDetectionQueue.pids {
		key := getPidKey(pid)
		if !activePidKeys[key] {
			delete(processDetectionQueue.pids, pid)
		}
	}
	// 防止内存泄漏：限制队列大小
	if len(processDetectionQueue.pids) > 1000 {
		pids := make([]int, 0, len(processDetectionQueue.pids))
		for pid := range processDetectionQueue.pids {
			pids = append(pids, pid)
		}
		if len(pids) > 1000 {
			processDetectionQueue.pids = make(map[int]bool)
			for i := len(pids) - 1000; i < len(pids); i++ {
				processDetectionQueue.pids[pids[i]] = true
			}
		}
	}
	processDetectionQueue.Unlock()

	udpDetectionQueue.Lock()
	for port := range udpDetectionQueue.ports {
		if !activePorts[port] {
			delete(udpDetectionQueue.ports, port)
		}
	}
	// 防止内存泄漏：限制队列大小
	if len(udpDetectionQueue.ports) > 1000 {
		ports := make([]int, 0, len(udpDetectionQueue.ports))
		for port := range udpDetectionQueue.ports {
			ports = append(ports, port)
		}
		if len(ports) > 1000 {
			udpDetectionQueue.ports = make(map[int]bool)
			for i := len(ports) - 1000; i < len(ports); i++ {
				udpDetectionQueue.ports[ports[i]] = true
			}
		}
	}
	udpDetectionQueue.Unlock()

	// 清理 httpAliveHistory
	httpAliveHistory.Lock()
	for port := range httpAliveHistory.Ports {
		if !activePorts[port] {
			delete(httpAliveHistory.Ports, port)
		}
	}
	// 防止内存泄漏：限制历史记录大小
	if len(httpAliveHistory.Ports) > 2000 {
		ports := make([]int, 0, len(httpAliveHistory.Ports))
		for port := range httpAliveHistory.Ports {
			ports = append(ports, port)
		}
		if len(ports) > 2000 {
			httpAliveHistory.Ports = make(map[int]bool)
			for i := len(ports) - 2000; i < len(ports); i++ {
				httpAliveHistory.Ports[ports[i]] = true
			}
		}
	}
	httpAliveHistory.Unlock()

	// 清理 portStatusCache
	portStatusCache.RWMutex.Lock()
	for port := range portStatusCache.Status {
		if !activePorts[port] {
			delete(portStatusCache.Status, port)
			delete(portStatusCache.RespTime, port)
			delete(portStatusCache.LastCheck, port)
		}
	}
	// 防止内存泄漏：限制缓存大小
	if len(portStatusCache.Status) > 2000 {
		ports := make([]int, 0, len(portStatusCache.Status))
		for port := range portStatusCache.Status {
			ports = append(ports, port)
		}
		if len(ports) > 2000 {
			// 清理最旧的缓存
			for i := 0; i < len(ports)-2000; i++ {
				delete(portStatusCache.Status, ports[i])
				delete(portStatusCache.RespTime, ports[i])
				delete(portStatusCache.LastCheck, ports[i])
			}
		}
	}
	portStatusCache.RWMutex.Unlock()

	// 清理 udpStatusCache
	udpStatusCache.RWMutex.Lock()
	for port := range udpStatusCache.Status {
		if !activePorts[port] {
			delete(udpStatusCache.Status, port)
			delete(udpStatusCache.LastCheck, port)
		}
	}
	// 防止内存泄漏：限制缓存大小
	if len(udpStatusCache.Status) > 2000 {
		ports := make([]int, 0, len(udpStatusCache.Status))
		for port := range udpStatusCache.Status {
			ports = append(ports, port)
		}
		if len(ports) > 2000 {
			for i := 0; i < len(ports)-2000; i++ {
				delete(udpStatusCache.Status, ports[i])
				delete(udpStatusCache.LastCheck, ports[i])
			}
		}
	}
	udpStatusCache.RWMutex.Unlock()

	// 清理 httpStatusCache
	httpStatusCache.RWMutex.Lock()
	for port := range httpStatusCache.Status {
		if !activePorts[port] {
			delete(httpStatusCache.Status, port)
			delete(httpStatusCache.LastCheck, port)
		}
	}
	// 防止内存泄漏：限制缓存大小
	if len(httpStatusCache.Status) > 2000 {
		ports := make([]int, 0, len(httpStatusCache.Status))
		for port := range httpStatusCache.Status {
			ports = append(ports, port)
		}
		if len(ports) > 2000 {
			for i := 0; i < len(ports)-2000; i++ {
				delete(httpStatusCache.Status, ports[i])
				delete(httpStatusCache.LastCheck, ports[i])
			}
		}
	}
	httpStatusCache.RWMutex.Unlock()

	// 清理进程存活缓存
	processAliveCache.RWMutex.Lock()
	for key := range processAliveCache.Status {
		if !activePidKeys[key] {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
		}
	}
	// 防止内存泄漏：限制缓存大小
	if len(processAliveCache.Status) > 2000 {
		keys := make([]string, 0, len(processAliveCache.Status))
		for key := range processAliveCache.Status {
			keys = append(keys, key)
		}
		if len(keys) > 2000 {
			for i := 0; i < len(keys)-2000; i++ {
				delete(processAliveCache.Status, keys[i])
				delete(processAliveCache.LastCheck, keys[i])
			}
		}
	}
	processAliveCache.RWMutex.Unlock()
}

// 带缓存的进程存活检测（完全异步化，避免阻塞指标暴露）
func getProcessAliveStatus(pid int) int {
	key := getPidKey(pid)
	processAliveCache.RWMutex.RLock()
	now := time.Now()
	t, ok := processAliveCache.LastCheck[key]
	if !ok || now.Sub(t) > processAliveStatusInterval {
		processAliveCache.RWMutex.RUnlock()

		// 缓存过期，加入进程异步检测队列
		processDetectionQueue.Lock()
		processDetectionQueue.pids[pid] = true
		processDetectionQueue.Unlock()

		// 修复：避免重复获取锁，直接返回-1等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	status := processAliveCache.Status[key]
	processAliveCache.RWMutex.RUnlock()
	return status
}

// getPidKey 生成进程缓存唯一key（pid+starttime）
func getPidKey(pid int) string {
	start := getProcessStartTime(pid)
	return fmt.Sprintf("%d_%s", pid, start)
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
