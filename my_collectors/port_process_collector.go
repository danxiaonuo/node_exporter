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

// 新增：HTTP检测异步处理器
func startHTTPDetectionWorker() {
	go func() {
		ticker := time.NewTicker(3 * time.Second) // 每3秒处理一次队列，提高响应速度
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
					go func(p int) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()

						status := checkPortHTTP(p)
						httpStatusCache.RWMutex.Lock()
						httpStatusCache.Status[p] = status
						httpStatusCache.LastCheck[p] = time.Now()
						if status == 1 {
							httpAliveHistory.Lock()
							httpAliveHistory.Ports[p] = true
							httpAliveHistory.Unlock()
						}
						httpStatusCache.RWMutex.Unlock()
					}(port)
				}
				wg.Wait()
			}
		}
	}()
}

// 新增：初始化HTTP检测工作器
func init() {
	startHTTPDetectionWorker()
}

var (
	portStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return time.Minute
	}()
	portLabelInterval = func() time.Duration {
		if v := os.Getenv("PORT_LABEL_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return 8 * time.Hour
	}()
	// 新增 HTTP 检测缓存周期
	httpStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_HTTP_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return portStatusInterval // 默认与 TCP 检测一致
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
		return 1 * time.Second // 减少到1秒，避免长时间阻塞
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

	for _, info := range infos {
		labels := []string{info.ProcessName, info.ExePath, strconv.Itoa(info.Port)}
		if info.Protocol == "tcp" {
			if !tcpPortDone[info.Port] {
				// TCP端口存活和响应时间（快速检测，不阻塞）
				alive, respTime := getPortStatus(info.Port)
				ch <- prometheus.MustNewConstMetric(
					c.portTCPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
				)
				ch <- prometheus.MustNewConstMetric(
					c.portTCPRespDesc, prometheus.GaugeValue, respTime, labels...,
				)

				// HTTP检测优化：异步处理，智能过滤
				if enableHTTPDetection {
					// 检查缓存中是否已有结果
					httpStatusCache.RWMutex.RLock()
					now := time.Now()
					t, ok := httpStatusCache.LastCheck[info.Port]
					hasCache := ok && now.Sub(t) <= httpStatusInterval
					httpStatusCache.RWMutex.RUnlock()

					if hasCache {
						// 有缓存结果，直接使用
						httpStatusCache.RWMutex.RLock()
						httpAlive := httpStatusCache.Status[info.Port]
						httpStatusCache.RWMutex.RUnlock()

						httpAliveHistory.RLock()
						everAlive := httpAliveHistory.Ports[info.Port]
						httpAliveHistory.RUnlock()

						if httpAlive == 1 {
							ch <- prometheus.MustNewConstMetric(
								c.httpAliveDesc, prometheus.GaugeValue, 1, labels...,
							)
						} else if everAlive {
							ch <- prometheus.MustNewConstMetric(
								c.httpAliveDesc, prometheus.GaugeValue, 0, labels...,
							)
						}
					} else {
						// 无缓存结果，加入异步检测队列
						httpDetectionQueue.Lock()
						httpDetectionQueue.ports[info.Port] = true
						httpDetectionQueue.Unlock()

						// 检查历史记录，如果有过HTTP存活记录，先暴露0
						httpAliveHistory.RLock()
						everAlive := httpAliveHistory.Ports[info.Port]
						httpAliveHistory.RUnlock()

						if everAlive {
							ch <- prometheus.MustNewConstMetric(
								c.httpAliveDesc, prometheus.GaugeValue, 0, labels...,
							)
						}
					}
				}
				tcpPortDone[info.Port] = true
			}
		} else if info.Protocol == "udp" {
			if !udpPortDone[info.Port] {
				alive := getPortUDPStatus(info.Port, 1)
				ch <- prometheus.MustNewConstMetric(
					c.portUDPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
				)
				udpPortDone[info.Port] = true
			}
		}
		// 进程存活指标去重：每个唯一进程（进程名+路径）只采集一次
		processKey := info.ProcessName + "|" + info.ExePath
		if !reportedProcessKeys[processKey] {
			procAlive := getProcessAliveStatus(info.Pid)
			ch <- prometheus.MustNewConstMetric(
				c.processAliveDesc, prometheus.GaugeValue, float64(procAlive),
				info.ProcessName, info.ExePath,
			)
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
			// UDP
			if port, ok := udpInodePort[inode]; ok {
				if seenUDP[port] {
					continue
				}
				seenUDP[port] = true
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
	commonAddrs := []string{"127.0.0.1", "0.0.0.0", "::1", "::"}
	minResp := -1.0 // 检测失败时返回-1
	found := false
	// 先检测常用地址
	for _, ip := range commonAddrs {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), portCheckTimeout)
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
	ctx, cancel := context.WithTimeout(context.Background(), portCheckTimeout)
	defer cancel()
	resultCh := make(chan float64, len(addrs))
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			select {
			case <-ctx.Done():
				<-sem
				return
			default:
			}
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), portCheckTimeout)
			cost := time.Since(start).Seconds()
			if err == nil {
				conn.Close()
				select {
				case resultCh <- cost:
					cancel() // 有一个成功就取消其他
				default:
				}
			}
			<-sem
		}(ip)
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
	commonAddrs := []string{"127.0.0.1", "0.0.0.0", "::1", "::"}
	client := &http.Client{Timeout: portCheckTimeout}
	// 先检测常用地址
	for _, ip := range commonAddrs {
		url := "http://[" + ip + "]:" + strconv.Itoa(port)
		if strings.Count(ip, ":") == 0 {
			url = "http://" + ip + ":" + strconv.Itoa(port)
		}
		resp, err := client.Get(url)
		if err == nil && resp != nil && len(resp.Header) > 0 {
			resp.Body.Close()
			return 1
		}
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
		addrs = append(addrs, ip.String())
	}
	if len(addrs) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), portCheckTimeout)
	defer cancel()
	resultCh := make(chan struct{}, len(addrs))
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			select {
			case <-ctx.Done():
				<-sem
				return
			default:
			}
			url := "http://[" + ip + "]:" + strconv.Itoa(port)
			if strings.Count(ip, ":") == 0 {
				url = "http://" + ip + ":" + strconv.Itoa(port)
			}
			resp, err := client.Get(url)
			if err == nil && resp != nil && len(resp.Header) > 0 {
				resp.Body.Close()
				select {
				case resultCh <- struct{}{}:
					cancel() // 有一个成功就取消其他
				default:
				}
			}
			<-sem
		}(ip)
	}
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	for range resultCh {
		return 1
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

func getPortStatus(port int) (alive int, respTime float64) {
	portStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := portStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > portStatusInterval {
		portStatusCache.RWMutex.RUnlock()
		portStatusCache.RWMutex.Lock()
		// 再次检查，防止并发下重复写
		t, ok = portStatusCache.LastCheck[port]
		if !ok || now.Sub(t) > portStatusInterval {
			alive, respTime = checkPortTCP(port)
			portStatusCache.Status[port] = alive
			portStatusCache.RespTime[port] = respTime
			portStatusCache.LastCheck[port] = now
		} else {
			alive = portStatusCache.Status[port]
			respTime = portStatusCache.RespTime[port]
		}
		portStatusCache.RWMutex.Unlock()
		return
	}
	alive = portStatusCache.Status[port]
	respTime = portStatusCache.RespTime[port]
	portStatusCache.RWMutex.RUnlock()
	return
}

// 新增：带缓存的 HTTP 检测
func getPortHTTPStatus(port int) int {
	httpStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := httpStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > httpStatusInterval {
		httpStatusCache.RWMutex.RUnlock()
		httpStatusCache.RWMutex.Lock()
		t, ok = httpStatusCache.LastCheck[port]
		if !ok || now.Sub(t) > httpStatusInterval {
			status := checkPortHTTP(port)
			httpStatusCache.Status[port] = status
			httpStatusCache.LastCheck[port] = now
			httpStatusCache.RWMutex.Unlock()
			return status
		} else {
			status := httpStatusCache.Status[port]
			httpStatusCache.RWMutex.Unlock()
			return status
		}
	}
	status := httpStatusCache.Status[port]
	httpStatusCache.RWMutex.RUnlock()
	return status
}

// 带缓存的UDP端口存活检测（仍以fd存在为准）
func getPortUDPStatus(port int, exist int) int {
	udpStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := udpStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > udpStatusInterval {
		udpStatusCache.RWMutex.RUnlock()
		udpStatusCache.RWMutex.Lock()
		t, ok = udpStatusCache.LastCheck[port]
		if !ok || now.Sub(t) > udpStatusInterval {
			udpStatusCache.Status[port] = exist
			udpStatusCache.LastCheck[port] = now
			udpStatusCache.RWMutex.Unlock()
			return exist
		} else {
			status := udpStatusCache.Status[port]
			udpStatusCache.RWMutex.Unlock()
			return status
		}
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
	// 清理 httpAliveHistory
	httpAliveHistory.Lock()
	for port := range httpAliveHistory.Ports {
		if !activePorts[port] {
			delete(httpAliveHistory.Ports, port)
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
	portStatusCache.RWMutex.Unlock()
	// 清理 udpStatusCache
	udpStatusCache.RWMutex.Lock()
	for port := range udpStatusCache.Status {
		if !activePorts[port] {
			delete(udpStatusCache.Status, port)
			delete(udpStatusCache.LastCheck, port)
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
	httpStatusCache.RWMutex.Unlock()
	// 清理进程存活缓存
	processAliveCache.RWMutex.Lock()
	for key := range processAliveCache.Status {
		if !activePidKeys[key] {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
		}
	}
	processAliveCache.RWMutex.Unlock()
}

// 带缓存的进程存活检测
func getProcessAliveStatus(pid int) int {
	key := getPidKey(pid)
	processAliveCache.RWMutex.RLock()
	now := time.Now()
	t, ok := processAliveCache.LastCheck[key]
	if !ok || now.Sub(t) > processAliveStatusInterval {
		processAliveCache.RWMutex.RUnlock()
		processAliveCache.RWMutex.Lock()
		t, ok = processAliveCache.LastCheck[key]
		if !ok || now.Sub(t) > processAliveStatusInterval {
			status := checkProcess(pid)
			processAliveCache.Status[key] = status
			processAliveCache.LastCheck[key] = now
			processAliveCache.RWMutex.Unlock()
			return status
		} else {
			status := processAliveCache.Status[key]
			processAliveCache.RWMutex.Unlock()
			return status
		}
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
