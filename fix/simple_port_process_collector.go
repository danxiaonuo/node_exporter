package my_collectors

import (
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
	portTCPAliveDesc *prometheus.Desc // TCP端口存活指标描述符
	processAliveDesc *prometheus.Desc // 进程存活指标描述符
}

// NewSimplePortProcessCollector 构造函数：创建并返回一个新的简化端口进程采集器
func NewSimplePortProcessCollector() *SimplePortProcessCollector {
	return &SimplePortProcessCollector{
		portTCPAliveDesc: prometheus.NewDesc(
			"node_tcp_port_alive",
			"TCP Port alive status (1=alive, 0=dead)",
			[]string{"process_name", "exe_path", "port"}, nil,
		),
		processAliveDesc: prometheus.NewDesc(
			"node_process_alive",
			"Process alive status (1=alive, 0=dead)",
			[]string{"process_name", "exe_path"}, nil,
		),
	}
}

// Describe 方法：实现 Prometheus Collector 接口，描述所有指标
func (c *SimplePortProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.portTCPAliveDesc
	ch <- c.processAliveDesc
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
								log.Printf("[simple_port_process_collector] TCP检测panic恢复: port=%d, error=%v", p, r)
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
}

// 优雅关闭所有异步工作器
var shutdownOnce sync.Once

func ShutdownWorkers() {
	shutdownOnce.Do(func() {
		close(tcpDetectionQueue.done)
		close(processDetectionQueue.done)
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
			procAlive := getProcessAliveStatus(info.Pid)
			if procAlive >= 0 {
				ch <- prometheus.MustNewConstMetric(
					c.processAliveDesc, prometheus.GaugeValue, float64(procAlive),
					info.ProcessName, info.ExePath,
				)
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

// checkProcess 函数：检测进程是否存活
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

	// 清理异步检测队列中的过期端口和进程
	// 使用固定的锁顺序避免死锁：队列锁 -> 缓存锁
	tcpDetectionQueue.Lock()
	for port := range tcpDetectionQueue.ports {
		if !activePorts[port] {
			delete(tcpDetectionQueue.ports, port)
		}
	}
	tcpDetectionQueue.Unlock()

	// 复制当前队列中的 PID，锁外计算 key，避免持锁执行 I/O
	processDetectionQueue.Lock()
	queuedPids := make([]int, 0, len(processDetectionQueue.pids))
	for pid := range processDetectionQueue.pids {
		queuedPids = append(queuedPids, pid)
	}
	processDetectionQueue.Unlock()

	// 锁外计算需要删除的 PID
	pidsToRemove := make([]int, 0)
	for _, pid := range queuedPids {
		key := fmt.Sprintf("%d_%s", pid, getProcessStartTime(pid))
		if !activePidKeys[key] {
			pidsToRemove = append(pidsToRemove, pid)
		}
	}

	// 重新加锁，快速删除
	processDetectionQueue.Lock();
	for _, pid := range pidsToRemove {
		delete(processDetectionQueue.pids, pid)
	}
	processDetectionQueue.Unlock()

	// 清理缓存 - 使用写锁，按固定顺序获取
	portStatusCache.RWMutex.Lock()
	for port := range portStatusCache.Status {
		if !activePorts[port] {
			delete(portStatusCache.Status, port)
			delete(portStatusCache.LastCheck, port)
		}
	}
	portStatusCache.RWMutex.Unlock()

	processAliveCache.RWMutex.Lock()
	for key := range processAliveCache.Status {
		if !activePidKeys[key] {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
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
