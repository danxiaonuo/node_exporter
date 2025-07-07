package my_collectors

import (
	"fmt"
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

// Collect 方法：实现 Prometheus Collector 接口，采集所有指标
// TCP/UDP端口分别采集，指标名区分，HTTP端口单独采集
func (c *PortProcessCollector) Collect(ch chan<- prometheus.Metric) {
	infos := getPortProcessInfo()      // 获取端口与进程列表（8小时刷新一次）
	reportedPids := make(map[int]bool) // 记录已上报的进程，避免重复
	tcpPortDone := make(map[int]bool)
	udpPortDone := make(map[int]bool)
	for _, info := range infos {
		labels := []string{info.ProcessName, info.ExePath, strconv.Itoa(info.Port)}
		if info.Protocol == "tcp" {
			if !tcpPortDone[info.Port] {
				alive, respTime := getPortStatus(info.Port)
				ch <- prometheus.MustNewConstMetric(
					c.portTCPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
				)
				ch <- prometheus.MustNewConstMetric(
					c.portTCPRespDesc, prometheus.GaugeValue, respTime, labels...,
				)
				httpAlive := checkPortHTTP(info.Port)
				ch <- prometheus.MustNewConstMetric(
					c.httpAliveDesc, prometheus.GaugeValue, float64(httpAlive), labels...,
				)
				tcpPortDone[info.Port] = true
			}
		} else if info.Protocol == "udp" {
			if !udpPortDone[info.Port] {
				ch <- prometheus.MustNewConstMetric(
					c.portUDPAliveDesc, prometheus.GaugeValue, 1, labels...,
				)
				udpPortDone[info.Port] = true
			}
		}
		// 进程存活指标去重：每个唯一pid只采集一次
		if !reportedPids[info.Pid] {
			procAlive := checkProcess(info.Pid)
			ch <- prometheus.MustNewConstMetric(
				c.processAliveDesc, prometheus.GaugeValue, float64(procAlive),
				info.ProcessName, info.ExePath,
			)
			reportedPids[info.Pid] = true
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
		fmt.Fprintf(os.Stderr, "[port_process_collector] failed to open /proc: %v\n", err)
		return results
	}
	defer procDir.Close()
	entries, err := procDir.Readdir(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[port_process_collector] failed to read /proc: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "[port_process_collector] failed to read %s: %v\n", fdPath, err)
			continue
		}
		for _, fdEntry := range fds {
			fdLink := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			link, err := os.Readlink(fdLink)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[port_process_collector] failed to readlink %s: %v\n", fdLink, err)
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
			fmt.Fprintf(os.Stderr, "[port_process_collector] failed to read %s: %v\n", file, err)
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

// checkPortTCP 函数：仅检测TCP端口存活状态和连接耗时（不做HTTP请求）
// 返回值：alive（1=存活，0=不可用），respTime（TCP连接耗时，秒）
func checkPortTCP(port int) (alive int, respTime float64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	respTime = time.Since(start).Seconds()
	if err == nil {
		conn.Close()
		return 1, respTime
	}
	return 0, 0
}

// checkPortHTTP 函数：检测端口是否为可访问的HTTP服务（用于假死检测）
// 返回值：1=HTTP服务可访问，0=不可访问
func checkPortHTTP(port int) int {
	// 这里直接实现简单HTTP GET检测，或调用 handlers_http_status.go 的 CheckHttpStatus
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err == nil && resp != nil && len(resp.Header) > 0 {
		resp.Body.Close()
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

// isExcludedProcess 函数：判断进程名是否在排除列表中
// 用于过滤掉系统进程、监控进程等不需要采集的进程
func isExcludedProcess(exeName string) bool {
	excluded := []string{
		"systemd", "init", "kthreadd", "ksoftirqd", "rcu_sched", "rcu_bh", "bo-agent",
		"migration", "watchdog", "cpuhp", "netns", "khungtaskd", "oom_reaper", "chronyd",
		"kswapd", "fsnotify_mark", "ecryptfs-kthrea", "kauditd", "khubd", "ssh", "snmpd",
		"zabbix", "prometheus", "rpcbind", "smartdns", "cupsd", "dhclient", "master",
		"rpc.statd", "titanagent", "node_exporter", "monitor_manage", "dnsmasq",
	}
	for _, name := range excluded {
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
)

type portStatusCacheStruct struct {
	LastCheck map[int]time.Time
	Status    map[int]int
	RespTime  map[int]float64
	Mutex     sync.Mutex
}

var portStatusCache = &portStatusCacheStruct{
	LastCheck: make(map[int]time.Time),
	Status:    make(map[int]int),
	RespTime:  make(map[int]float64),
}

func getPortStatus(port int) (alive int, respTime float64) {
	portStatusCache.Mutex.Lock()
	defer portStatusCache.Mutex.Unlock()
	now := time.Now()
	if t, ok := portStatusCache.LastCheck[port]; !ok || now.Sub(t) > portStatusInterval {
		alive, respTime = checkPortTCP(port)
		portStatusCache.Status[port] = alive
		portStatusCache.RespTime[port] = respTime
		portStatusCache.LastCheck[port] = now
	} else {
		alive = portStatusCache.Status[port]
		respTime = portStatusCache.RespTime[port]
	}
	return
}
