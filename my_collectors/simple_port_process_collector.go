// Package my_collectors 提供 Prometheus 指标收集器
// 本包实现了端口进程监控收集器，用于监控系统中端口与进程的关联关系
// 以及进程的详细状态信息（CPU、内存、IO等）
package my_collectors

import (
	"bufio"    // 提供缓冲读取功能，用于逐行读取文件
	"context"  // 提供上下文管理，用于超时控制和取消操作
	"fmt"      // 提供格式化输出功能
	"log"      // 提供日志记录功能
	"net"      // 提供网络相关功能，用于端口检测
	"os"       // 提供操作系统接口，用于文件操作
	"path/filepath" // 提供路径操作功能
	"runtime"  // 提供运行时信息，用于内存统计
	"sort"     // 提供排序功能，用于优化缓存清理算法
	"strconv"  // 提供字符串与数字转换功能
	"strings"  // 提供字符串操作功能
	"sync"     // 提供同步原语，用于并发控制
	"time"     // 提供时间相关功能

	"github.com/prometheus/client_golang/prometheus" // Prometheus 客户端库
)

// PortProcessInfo 结构体：用于存储端口与进程的关联信息
// 该结构体包含了端口监听进程的完整信息，用于建立端口与进程的映射关系
type PortProcessInfo struct {
	ProcessName string // 进程名称，从可执行文件路径中提取
	ExePath     string // 可执行文件的完整路径
	Port        int    // 端口号，进程正在监听的端口
	Pid         int    // 进程ID，系统中进程的唯一标识符
	WorkDir     string // 工作目录，进程运行时的工作目录路径
	Username    string // 运行用户，进程所属的用户ID
	Protocol    string // 协议类型，目前支持 tcp/udp
}

// portProcessCacheStruct 结构体：用于缓存端口与进程的发现结果
// 该结构体提供了线程安全的缓存机制，避免频繁扫描系统信息
type portProcessCacheStruct struct {
	LastScan time.Time        // 最后一次扫描的时间戳
	Data     []PortProcessInfo // 缓存的端口进程信息列表
	RWMutex  sync.RWMutex     // 读写互斥锁，保证并发安全
}

// portProcessCache 全局变量：端口进程信息缓存实例
// 使用指针类型，避免结构体复制时的性能开销
var portProcessCache = &portProcessCacheStruct{}

// 全局goroutine管理器
var goroutineManager = NewSafeGoroutineManager()

// 常量定义区域
// 所有常量都使用有意义的名称，避免魔法数字，提高代码可读性和可维护性
const (
	// ========== 时间间隔常量 ==========
	// DefaultScanInterval 默认端口进程扫描间隔
	// 端口进程映射关系相对稳定，使用较长的扫描间隔减少系统开销
	DefaultScanInterval = 8 * time.Hour

	// DefaultPortStatusInterval 默认端口状态检测间隔
	// 端口状态变化较快，使用较短的检测间隔保证监控的实时性
	DefaultPortStatusInterval = 60 * time.Second

	// DefaultProcessAliveStatusInterval 默认进程存活状态检测间隔
	// 进程存活状态检测频率，平衡实时性和性能开销
	DefaultProcessAliveStatusInterval = 60 * time.Second

	// DefaultProcessStatusInterval 默认进程状态检测间隔
	// 进程详细状态（CPU、内存等）检测频率
	DefaultProcessStatusInterval = 60 * time.Second

	// DefaultProcessPidCacheCleanInterval 默认进程PID缓存清理间隔
	// 定期清理过期的进程PID缓存，防止内存泄漏
	DefaultProcessPidCacheCleanInterval = time.Minute

	// DefaultPortCheckTimeout 默认端口检测超时时间
	// 单个端口检测的超时时间，避免长时间阻塞
	DefaultPortCheckTimeout = 3 * time.Second

	// DefaultMemoryCleanupInterval 默认内存清理间隔
	// 定期清理过期缓存数据的间隔，防止内存无限增长
	DefaultMemoryCleanupInterval = 10 * time.Minute

	// ========== 强制重扫节流间隔 ==========
	// ForceRescanThrottleInterval 强制重扫节流间隔
	// 防止频繁的强制重扫导致系统开销过大
	ForceRescanThrottleInterval = 5 * time.Second

	// ========== 缓存过期时间 ==========
	// ProcessIdentityExpireTime 进程身份过期时间
	// 进程身份信息在缓存中的有效期
	ProcessIdentityExpireTime = 2 * time.Minute

	// ProcessIdentityCleanupTime 进程身份清理时间
	// 超过此时间未见的进程身份将被清理
	ProcessIdentityCleanupTime = 5 * time.Minute

	// PortStatusExpireTime 端口状态过期时间
	// 端口状态信息在缓存中的有效期
	PortStatusExpireTime = time.Hour

	// ProcessAliveExpireTime 进程存活状态过期时间
	// 进程存活状态信息在缓存中的有效期
	ProcessAliveExpireTime = time.Hour

	// ========== 缓存大小限制 ==========
	// MaxStringCacheSize 字符串缓存最大大小
	// 限制字符串缓存的最大条目数，防止内存无限增长
	MaxStringCacheSize = 10000

	// StringCacheCleanupSize 字符串缓存清理大小
	// 当缓存超过最大大小时，清理的条目数量
	StringCacheCleanupSize = 5000

	// ========== 端口范围 ==========
	// MinPortNumber 最小端口号
	// TCP/UDP端口号的有效范围最小值
	MinPortNumber = 1

	// MaxPortNumber 最大端口号
	// TCP/UDP端口号的有效范围最大值
	MaxPortNumber = 65535

	// ========== 默认并发数 ==========
	// DefaultMaxParallelIPChecks 默认最大并行IP检测数
	// 同时进行端口检测的最大并发数，避免过多并发导致系统负载过高
	DefaultMaxParallelIPChecks = 8

	// DefaultTicksPerSecond 默认每秒时钟滴答数
	// 系统时钟频率，用于CPU使用率计算
	DefaultTicksPerSecond = 100

	// ========== 性能优化常量 ==========
	// DefaultProcessFieldsCapacity 默认进程字段容量
	// 用于预分配切片容量，减少内存重新分配
	DefaultProcessFieldsCapacity = 52

	// DefaultStringBuilderCapacity 默认字符串构建器容量
	// 用于预分配字符串构建器容量，提高字符串拼接效率
	DefaultStringBuilderCapacity = 64

	// ========== 错误处理常量 ==========
	// DefaultMemTotalKB 默认内存总量（KB），防止除零错误
	DefaultMemTotalKB = 1024 * 1024

	// MaxRetryAttempts 最大重试次数
	MaxRetryAttempts = 3

	// RetryDelay 重试延迟时间
	RetryDelay = 100 * time.Millisecond

	// ========== 超时和限制常量 ==========
	// MaxGoroutineTimeout 最大goroutine超时时间
	MaxGoroutineTimeout = 30 * time.Second

	// GoroutineCleanupTimeout goroutine清理超时时间
	GoroutineCleanupTimeout = 5 * time.Second

	// MaxFileDescriptorLimit 最大文件描述符限制
	MaxFileDescriptorLimit = 1000

	// ========== 缓存清理阈值 ==========
	// CacheCleanupThreshold 缓存清理阈值（百分比）
	CacheCleanupThreshold = 80

	// MinCacheSize 最小缓存大小
	MinCacheSize = 100

	// ========== 字符串常量 ==========
	// 文件系统路径常量
	ProcPathPrefix     = "/proc"
	ProcNetTCPPath     = "/proc/net/tcp"
	ProcNetTCP6Path    = "/proc/net/tcp6"
	ProcMemInfoPath    = "/proc/meminfo"
	ProcFdSuffix       = "/fd"
	ProcExeSuffix      = "/exe"
	ProcCwdSuffix      = "/cwd"
	ProcStatusSuffix   = "/status"
	ProcStatSuffix     = "/stat"
	ProcIOSuffix       = "/io"
	ProcCgroupPath     = "/proc/1/cgroup"

	// 网络相关常量
	SocketPrefix       = "socket:["
	SocketSuffix       = "]"
	TCPListenState     = "0A"
	TCPProtocol        = "tcp"
	UDPProtocol        = "udp"

	// 进程状态常量
	ProcessStateRunning    = "R"
	ProcessStateSleeping   = "S"
	ProcessStateDiskWait   = "D"
	ProcessStateZombie     = "Z"
	ProcessStateTraced     = "T"
	ProcessStatePaging     = "t"
	ProcessStateWakeKill   = "W"
	ProcessStateDead       = "X"
	ProcessStateWakeDead   = "x"
	ProcessStateKillable   = "K"

	// 文件系统标识符
	HostProcPrefix     = "/host/proc"
	DockerIdentifier   = "docker"
	KubepodsIdentifier = "kubepods"

	// 网络接口前缀（虚拟网卡）
	DockerInterfacePrefix  = "docker"
	VethInterfacePrefix   = "veth"
	BridgeInterfacePrefix  = "br-"
	VirbrInterfacePrefix  = "virbr"
	LoopbackInterface     = "lo"
	VMNetInterfacePrefix  = "vmnet"
	TapInterfacePrefix    = "tap"
	TunInterfacePrefix     = "tun"
	WlxInterfacePrefix    = "wlx"
	EnxInterfacePrefix    = "enx"

	// 常用IP地址
	LocalhostIPv4     = "127.0.0.1"
	AnyIPv4           = "0.0.0.0"
	LocalhostIPv6     = "::1"
	AnyIPv6           = "::"

	// 字符串分隔符
	ProcessKeySeparator   = "|"
	PidKeySeparator       = "_"
	PathSeparator         = "/"
	ColonSeparator        = ":"
	CommaSeparator        = ","
	SpaceSeparator        = " "

	// 默认标签值
	DefaultLabelValue     = "/"
	EmptyString           = ""

	// 日志标识符
	LogPrefix             = "[simple_port_process_collector]"
	PortProcessLogPrefix  = "[port_process_collector]"

	// 环境变量名称
	EnvDebugPortCheck              = "DEBUG_PORT_CHECK"
	EnvEnableHostIPDetection       = "ENABLE_HOST_IP_DETECTION"
	EnvPortLabelInterval           = "PORT_LABEL_INTERVAL"
	EnvProcPrefix                  = "PROC_PREFIX"
	EnvPortStatusInterval          = "PORT_STATUS_INTERVAL"
	EnvProcessAliveStatusInterval  = "PROCESS_ALIVE_STATUS_INTERVAL"
	EnvPortCheckTimeout            = "PORT_CHECK_TIMEOUT"
	EnvMaxParallelIPChecks         = "MAX_PARALLEL_IP_CHECKS"
	EnvFastMode                    = "FAST_MODE"
	EnvProcessHz                   = "PROCESS_HZ"
	EnvProcessStatusInterval       = "PROCESS_STATUS_INTERVAL"
	EnvProcessPidCacheCleanInterval = "PROCESS_PID_CACHE_CLEAN_INTERVAL"
	EnvEnableProcessAggregation    = "ENABLE_PROCESS_AGGREGATION"
	EnvExcludedProcessNames        = "EXCLUDED_PROCESS_NAMES"
	EnvHostIPCacheInterval         = "HOST_IP_CACHE_INTERVAL"

	// 性能统计操作名称
	OpPortScan         = "port_scan"
	OpProcessScan      = "process_scan"
	OpCacheHit         = "cache_hit"
	OpCacheMiss        = "cache_miss"
	OpPanicRecovery    = "panic_recovery"

	// Goroutine名称
	GoroutineTCPDetectionWorker     = "tcp-detection-worker"
	GoroutineProcessDetectionWorker = "process-detection-worker"
	GoroutineProcessStatusWorker    = "process-status-worker"
	GoroutinePidCacheCleanWorker    = "pid-cache-clean-worker"
	GoroutineMemoryCleanupWorker    = "memory-cleanup-worker"

	// 错误消息模板
	ErrMsgFailedToOpenProc          = "failed to open /proc: %v"
	ErrMsgFailedToCloseProc         = "failed to close /proc: %v"
	ErrMsgFailedToReadProc          = "failed to read /proc: %v"
	ErrMsgFailedToReadFile          = "failed to read %s: %v"
	ErrMsgFailedToReadlink          = "failed to readlink %s: %v"
	ErrMsgInvalidPortNumber         = "invalid port number: %d"
	ErrMsgPortDetectionTimeout      = "TCP检测超时，部分goroutine可能仍在运行"
	ErrMsgGoroutineTimeout          = "超时后仍有goroutine未退出"
	ErrMsgGoroutinePanic            = "goroutine %s panic recovered: %v"
	ErrMsgGoroutineTimeoutShutdown = "goroutine %s did not finish within timeout"

	// 状态文件字段名
	StatusFieldUid                    = "Uid:"
	StatusFieldVmrss                  = "vmrss"
	StatusFieldVmsize                 = "vmsize"
	StatusFieldThreads                = "threads"
	StatusFieldVoluntaryCtxtSwitches  = "voluntary_ctxt_switches"
	StatusFieldNonvoluntaryCtxtSwitches = "nonvoluntary_ctxt_switches"

	// IO文件字段名
	IOFieldReadBytes  = "read_bytes:"
	IOFieldWriteBytes = "write_bytes:"

	// 内存信息字段名
	MemInfoFieldMemTotal = "MemTotal:"

	// 单位标识符
	UnitKB = "kB"
	UnitMB = "MB"
	UnitGB = "GB"

)

// ========== 安全资源管理结构体 ==========

// SafeFileHandle 安全的文件句柄管理
// 提供自动关闭和错误处理的文件操作封装
type SafeFileHandle struct {
	file *os.File
	path string
}

// NewSafeFileHandle 创建安全的文件句柄
func NewSafeFileHandle(path string) (*SafeFileHandle, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	return &SafeFileHandle{file: file, path: path}, nil
}

// Close 安全关闭文件句柄
func (sfh *SafeFileHandle) Close() error {
	if sfh.file == nil {
		return nil
	}
	err := sfh.file.Close()
	sfh.file = nil
	if err != nil {
		log.Printf("[simple_port_process_collector] failed to close file %s: %v", sfh.path, err)
	}
	return err
}

// Read 读取文件内容
func (sfh *SafeFileHandle) Read() ([]byte, error) {
	if sfh.file == nil {
		return nil, fmt.Errorf("file handle is closed")
	}
	return os.ReadFile(sfh.path)
}

// ReadDir 读取目录内容
func (sfh *SafeFileHandle) ReadDir() ([]os.DirEntry, error) {
	if sfh.file == nil {
		return nil, fmt.Errorf("file handle is closed")
	}
	return sfh.file.ReadDir(-1)
}

// SafeGoroutineManager 安全的goroutine管理器
// 提供goroutine生命周期管理和泄漏防护
type SafeGoroutineManager struct {
	activeGoroutines sync.Map // map[string]*GoroutineInfo
	shutdown         chan struct{}
	once             sync.Once
}

// GoroutineInfo goroutine信息
type GoroutineInfo struct {
	Name      string
	StartTime time.Time
	Done      chan struct{}
}

// NewSafeGoroutineManager 创建安全的goroutine管理器
func NewSafeGoroutineManager() *SafeGoroutineManager {
	return &SafeGoroutineManager{
		shutdown: make(chan struct{}),
	}
}

// StartGoroutine 启动受管理的goroutine
func (sgm *SafeGoroutineManager) StartGoroutine(name string, fn func()) {
	info := &GoroutineInfo{
		Name:      name,
		StartTime: time.Now(),
		Done:      make(chan struct{}),
	}

	sgm.activeGoroutines.Store(name, info)

	go func() {
		defer func() {
			close(info.Done)
			sgm.activeGoroutines.Delete(name)
			if r := recover(); r != nil {
				log.Printf("[simple_port_process_collector] goroutine %s panic recovered: %v", name, r)
			}
		}()

		fn()
	}()
}

// Shutdown 优雅关闭所有goroutine
func (sgm *SafeGoroutineManager) Shutdown() {
	sgm.once.Do(func() {
		close(sgm.shutdown)

		// 等待所有goroutine完成
		sgm.activeGoroutines.Range(func(key, value interface{}) bool {
			if info, ok := value.(*GoroutineInfo); ok {
				select {
				case <-info.Done:
					// goroutine已完成
				case <-time.After(MaxGoroutineTimeout):
					log.Printf("[simple_port_process_collector] goroutine %s did not finish within timeout", info.Name)
				}
			}
			return true
		})
	})
}

// GetActiveCount 获取活跃goroutine数量
func (sgm *SafeGoroutineManager) GetActiveCount() int {
	count := 0
	sgm.activeGoroutines.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// SafeStringBuilder 安全的字符串构建器
// 提供预分配容量和错误处理的字符串拼接
type SafeStringBuilder struct {
	builder strings.Builder
	capacity int
}

// NewSafeStringBuilder 创建安全的字符串构建器
func NewSafeStringBuilder(capacity int) *SafeStringBuilder {
	sb := &SafeStringBuilder{capacity: capacity}
	sb.builder.Grow(capacity)
	return sb
}

// WriteString 写入字符串
func (ssb *SafeStringBuilder) WriteString(s string) {
	ssb.builder.WriteString(s)
}

// WriteByte 写入字节
func (ssb *SafeStringBuilder) WriteByte(c byte) {
	ssb.builder.WriteByte(c)
}

// String 获取字符串结果
func (ssb *SafeStringBuilder) String() string {
	return ssb.builder.String()
}

// Reset 重置构建器
func (ssb *SafeStringBuilder) Reset() {
	ssb.builder.Reset()
	ssb.builder.Grow(ssb.capacity)
}

// StringPool 字符串池，用于复用常用字符串
type StringPool struct {
	pool sync.Pool
}

// NewStringPool 创建字符串池
func NewStringPool() *StringPool {
	return &StringPool{
		pool: sync.Pool{
			New: func() interface{} {
				return NewSafeStringBuilder(DefaultStringBuilderCapacity)
			},
		},
	}
}

// Get 从池中获取字符串构建器
func (sp *StringPool) Get() *SafeStringBuilder {
	return sp.pool.Get().(*SafeStringBuilder)
}

// Put 将字符串构建器放回池中
func (sp *StringPool) Put(sb *SafeStringBuilder) {
	sb.Reset()
	sp.pool.Put(sb)
}

// 全局字符串池
var globalStringPool = NewStringPool()

// StringUtils 字符串工具类
type StringUtils struct{}

// BuildPath 构建文件路径
func (su *StringUtils) BuildPath(parts ...string) string {
	sb := globalStringPool.Get()
	defer globalStringPool.Put(sb)

	for i, part := range parts {
		if i > 0 && !strings.HasSuffix(sb.String(), PathSeparator) {
			sb.WriteString(PathSeparator)
		}
		sb.WriteString(part)
	}
	return sb.String()
}

// BuildProcessKey 构建进程键
func (su *StringUtils) BuildProcessKey(processName, exePath string) string {
	sb := globalStringPool.Get()
	defer globalStringPool.Put(sb)

	sb.WriteString(processName)
	sb.WriteString(ProcessKeySeparator)
	sb.WriteString(exePath)
	return sb.String()
}

// BuildPidKey 构建PID键
func (su *StringUtils) BuildPidKey(pid int, startTime string) string {
	sb := globalStringPool.Get()
	defer globalStringPool.Put(sb)

	sb.WriteString(strconv.Itoa(pid))
	sb.WriteString(PidKeySeparator)
	sb.WriteString(startTime)
	return sb.String()
}

// BuildSocketPath 构建socket路径
func (su *StringUtils) BuildSocketPath(fdPath, fdName string) string {
	sb := globalStringPool.Get()
	defer globalStringPool.Put(sb)

	sb.WriteString(fdPath)
	sb.WriteString(PathSeparator)
	sb.WriteString(fdName)
	return sb.String()
}

// 全局字符串工具实例
var stringUtils = &StringUtils{}

// ========== 可配置变量区域 ==========
// 这些变量支持通过环境变量进行配置，提供运行时灵活性

// EnablePortCheckDebugLog 是否启用端口检测调试日志
// 通过环境变量 DEBUG_PORT_CHECK 控制，默认为 false
var EnablePortCheckDebugLog = func() bool {
	if v := os.Getenv(EnvDebugPortCheck); v != EmptyString {
		enabled, err := strconv.ParseBool(v)
		if err == nil {
			return enabled
		}
	}
	return true // 默认禁用调试日志
}()

// EnableHostIPDetection 是否启用宿主机IP检测
// 通过环境变量 ENABLE_HOST_IP_DETECTION 控制，默认为 true
var EnableHostIPDetection = func() bool {
	if v := os.Getenv(EnvEnableHostIPDetection); v != EmptyString {
		enabled, err := strconv.ParseBool(v)
		if err == nil {
			return enabled
		}
	}
	return true // 默认启用宿主机IP检测
}()

// scanInterval 端口进程扫描间隔配置
// 支持通过环境变量 PORT_LABEL_INTERVAL 进行配置
// 如果环境变量解析失败，则使用默认值 DefaultScanInterval
var scanInterval = func() time.Duration {
	// 尝试从环境变量读取配置
	if v := os.Getenv(EnvPortLabelInterval); v != EmptyString {
		// 解析环境变量中的时间间隔
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	// 使用默认值
	return DefaultScanInterval
}()

// procPrefix 进程文件系统路径前缀配置
// 支持容器环境下的进程文件系统访问
var procPrefix = func() string {
	// 尝试从环境变量读取配置
	if p := os.Getenv(EnvProcPrefix); p != EmptyString {
		return p
	}
	// 自动判断容器环境
	cgroupFile := ProcCgroupPath
	content, err := os.ReadFile(cgroupFile)
	if err == nil {
		s := string(content)
		// 检查是否为容器环境
		if strings.Contains(s, DockerIdentifier) || strings.Contains(s, KubepodsIdentifier) {
			return HostProcPrefix // 容器环境下使用主机进程文件系统
		}
	}
	return EmptyString // 非容器环境使用默认路径
}()

// procPath 辅助函数：构建完整的进程文件系统路径
// 根据配置的前缀和相对路径，构建完整的文件系统路径
func procPath(path string) string {
	if procPrefix == EmptyString {
		return path
	}
	return stringUtils.BuildPath(procPrefix, path)
}

// ========== 主要收集器结构体 ==========

// SimplePortProcessCollector 结构体：实现 Prometheus Collector 接口
// 该结构体包含了所有需要暴露的 Prometheus 指标描述符
// 每个描述符定义了指标的名称、描述和标签
type SimplePortProcessCollector struct {
	portTCPAliveDesc        *prometheus.Desc // TCP端口存活指标描述符，监控端口是否可访问
	portTCPResponseTimeDesc *prometheus.Desc // TCP端口响应时间指标描述符，监控端口响应时间
	processAliveDesc        *prometheus.Desc // 进程存活指标描述符，监控进程是否运行（包含进程状态）
	processCPUPercentDesc   *prometheus.Desc // 进程CPU使用率指标描述符，监控进程CPU占用百分比
	processMemPercentDesc   *prometheus.Desc // 进程内存使用率指标描述符，监控进程内存占用百分比
	processVMRSSDesc        *prometheus.Desc // 进程物理内存指标描述符，监控进程实际使用的物理内存
	processVMSizeDesc       *prometheus.Desc // 进程虚拟内存指标描述符，监控进程使用的虚拟内存
	processThreadsDesc      *prometheus.Desc // 进程线程数指标描述符，监控进程中的线程数量
	processIOReadDesc       *prometheus.Desc // 进程IO读取指标描述符，监控进程每秒读取的数据量
	processIOWriteDesc      *prometheus.Desc // 进程IO写入指标描述符，监控进程每秒写入的数据量
}

// NewSimplePortProcessCollector 构造函数：创建并返回一个新的简化端口进程采集器
// 该函数初始化所有 Prometheus 指标描述符，定义指标的元数据信息
func NewSimplePortProcessCollector() *SimplePortProcessCollector {
	return &SimplePortProcessCollector{
		// TCP端口存活指标描述符
		// 监控端口是否可访问，值为1表示端口存活，0表示端口死亡
		portTCPAliveDesc: prometheus.NewDesc(
			"node_tcp_port_alive",                    // 指标名称：节点TCP端口存活状态
			"TCP端口存活状态 (1=存活, 0=死亡)",           // 指标描述：TCP端口的存活状态
			[]string{"process_name", "exe_path", "port"}, nil, // 标签：进程名、可执行文件路径、端口号
		),
		// TCP端口响应时间指标描述符
		// 监控端口响应时间，单位为秒
		portTCPResponseTimeDesc: prometheus.NewDesc(
			"node_tcp_port_response_time_seconds",     // 指标名称：节点TCP端口响应时间
			"TCP端口响应时间(秒)",                       // 指标描述：TCP端口的响应时间
			[]string{"process_name", "exe_path", "port"}, nil, // 标签：进程名、可执行文件路径、端口号
		),
		// 进程存活指标描述符
		// 监控进程是否运行，包含进程状态信息
		processAliveDesc: prometheus.NewDesc(
			"node_process_alive",                     // 指标名称：节点进程存活状态
			"进程存活状态 (1=存活, 0=死亡) 包含进程状态",  // 指标描述：进程的存活状态和状态信息
			[]string{"process_name", "exe_path", "state"}, nil, // 标签：进程名、可执行文件路径、进程状态
		),
		// 进程CPU使用率指标描述符
		// 监控进程的CPU使用率百分比
		processCPUPercentDesc: prometheus.NewDesc(
			"node_process_cpu_percent",               // 指标名称：节点进程CPU使用率
			"进程CPU使用率百分比",                      // 指标描述：进程CPU使用率百分比
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程内存使用率指标描述符
		// 监控进程的物理内存使用率百分比
		processMemPercentDesc: prometheus.NewDesc(
			"node_process_memory_percent",            // 指标名称：节点进程内存使用率
			"进程物理内存使用率百分比",                  // 指标描述：进程物理内存使用率百分比
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程物理内存指标描述符
		// 监控进程实际使用的物理内存大小（字节）
		processVMRSSDesc: prometheus.NewDesc(
			"node_process_memory_rss_bytes",          // 指标名称：节点进程物理内存使用量
			"进程使用的物理内存大小(字节)",              // 指标描述：进程实际使用的物理内存大小
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程虚拟内存指标描述符
		// 监控进程使用的虚拟内存大小（字节）
		processVMSizeDesc: prometheus.NewDesc(
			"node_process_memory_vms_bytes",          // 指标名称：节点进程虚拟内存使用量
			"进程使用的虚拟内存大小(字节)",              // 指标描述：进程使用的虚拟内存大小
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程线程数指标描述符
		// 监控进程中的线程总数
		processThreadsDesc: prometheus.NewDesc(
			"node_process_threads",                   // 指标名称：节点进程线程数
			"进程中的线程总数",                         // 指标描述：进程中的线程总数
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程IO读取指标描述符
		// 监控进程每秒从磁盘读取的数据量（字节/秒）
		processIOReadDesc: prometheus.NewDesc(
			"node_process_io_read_bytes_per_second",  // 指标名称：节点进程IO读取速率
			"进程每秒从磁盘读取的数据量(字节/秒)",         // 指标描述：进程每秒从磁盘读取的数据量
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
		// 进程IO写入指标描述符
		// 监控进程每秒向磁盘写入的数据量（字节/秒）
		processIOWriteDesc: prometheus.NewDesc(
			"node_process_io_write_bytes_per_second", // 指标名称：节点进程IO写入速率
			"进程每秒向磁盘写入的数据量(字节/秒)",         // 指标描述：进程每秒向磁盘写入的数据量
			[]string{"process_name", "exe_path"}, nil, // 标签：进程名、可执行文件路径
		),
	}
}

// Describe 方法：实现 Prometheus Collector 接口，描述所有指标
// 该方法向 Prometheus 注册所有指标描述符，定义指标的元数据
func (c *SimplePortProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	// 向 Prometheus 注册所有指标描述符
	ch <- c.portTCPAliveDesc        // TCP端口存活指标
	ch <- c.portTCPResponseTimeDesc // TCP端口响应时间指标
	ch <- c.processAliveDesc        // 进程存活指标
	ch <- c.processCPUPercentDesc // 进程CPU使用率指标
	ch <- c.processMemPercentDesc // 进程内存使用率指标
	ch <- c.processVMRSSDesc      // 进程物理内存指标
	ch <- c.processVMSizeDesc     // 进程虚拟内存指标
	ch <- c.processThreadsDesc    // 进程线程数指标
	ch <- c.processIOReadDesc     // 进程IO读取指标
	ch <- c.processIOWriteDesc    // 进程IO写入指标
}

// ========== 异步检测队列结构体 ==========
// 这些队列用于异步处理端口和进程检测，避免阻塞 Prometheus 指标暴露

// tcpDetectionQueue TCP端口检测队列
// 用于异步处理TCP端口存活检测，避免阻塞指标收集
var tcpDetectionQueue = struct {
	sync.Mutex           // 互斥锁，保护队列的并发访问
	ports map[int]bool   // 待检测的端口映射，key为端口号，value为是否待检测
	done  chan struct{}  // 关闭信号通道，用于优雅关闭检测工作器
}{ports: make(map[int]bool), done: make(chan struct{})}

// processDetectionQueue 进程检测队列
// 用于异步处理进程存活检测，避免阻塞指标收集
var processDetectionQueue = struct {
	sync.Mutex           // 互斥锁，保护队列的并发访问
	pids map[int]bool    // 待检测的进程ID映射，key为PID，value为是否待检测
	done chan struct{}   // 关闭信号通道，用于优雅关闭检测工作器
}{pids: make(map[int]bool), done: make(chan struct{})}

// startTCPDetectionWorker TCP检测异步处理器
// 该函数启动一个后台goroutine，定期处理TCP端口检测队列
// 使用异步处理避免阻塞Prometheus指标暴露
func startTCPDetectionWorker() {
	goroutineManager.StartGoroutine(GoroutineTCPDetectionWorker, func() {
		// 创建定时器，按照配置的间隔定期处理检测队列
		ticker := time.NewTicker(portStatusInterval)
		defer ticker.Stop() // 确保定时器被正确关闭

		// 无限循环处理检测任务
		for {
			select {
			case <-tcpDetectionQueue.done:
				// 收到关闭信号，退出工作器
				return
			case <-ticker.C:
				// 定时器触发，处理队列中的端口检测任务
				processTCPDetectionQueue()
			}
		}
	})
}

// processTCPDetectionQueue 处理TCP检测队列
// 分离出独立的函数，便于测试和错误处理
func processTCPDetectionQueue() {
	// 获取待检测的端口列表（加锁保护）
	tcpDetectionQueue.Lock()
	ports := makeSliceWithCapacity[int](len(tcpDetectionQueue.ports))
	for port := range tcpDetectionQueue.ports {
		ports = append(ports, port)
	}
	// 清空队列，避免重复检测
	tcpDetectionQueue.ports = make(map[int]bool)
	tcpDetectionQueue.Unlock()

	if len(ports) == 0 {
		return // 没有待检测的端口
	}

	// 异步检测所有排队的端口
	// 使用信号量控制并发数，避免过多并发导致系统负载过高
	sem := make(chan struct{}, maxParallelIPChecks)
	var wg sync.WaitGroup // 等待组，用于等待所有检测任务完成

	for _, port := range ports {
		wg.Add(1) // 增加等待计数
		go func(p int) {
			defer wg.Done() // 任务完成时减少等待计数

			// panic恢复机制，确保单个端口检测失败不影响其他端口
			defer recoverFromPanic("TCP检测", p)

			// 获取信号量，控制并发数
			sem <- struct{}{}
			defer func() { <-sem }() // 释放信号量

			// 根据配置选择检测模式
			var alive int
			var respTime float64
			if fastMode {
				// 快速模式下使用更短的超时时间，提高检测速度
				alive, respTime = checkPortTCPWithTimeout(p, 500*time.Millisecond)
			} else {
				// 标准模式使用默认超时时间
				alive, respTime = checkPortTCP(p)
			}

			// 原子更新端口状态缓存
			updatePortStatusCache(p, alive, respTime)

		}(port)
	}

	// 使用带超时的等待，避免goroutine泄漏的同时防止阻塞
	done := make(chan struct{})
	go func() {
		wg.Wait() // 等待所有检测任务完成
		close(done) // 关闭完成信号通道
	}()

	select {
	case <-done:
		// 所有goroutine正常完成
		case <-time.After(MaxGoroutineTimeout):
			// 超时，记录警告但不阻塞
			log.Printf("%s %s", PortProcessLogPrefix, ErrMsgPortDetectionTimeout)
			// 等待一小段时间让goroutine有机会退出
			select {
			case <-done:
				// goroutine已经完成
			case <-time.After(GoroutineCleanupTimeout):
				log.Printf("%s %s", PortProcessLogPrefix, ErrMsgGoroutineTimeout)
			}
	}
}

// updatePortStatusCache 原子更新端口状态缓存
// 提供线程安全的端口状态更新
func updatePortStatusCache(port int, alive int, respTime float64) {
	portStatusCache.RWMutex.Lock()
	defer portStatusCache.RWMutex.Unlock()

	portStatusCache.Status[port] = alive
	// 如果端口挂了，响应时间设为0
	if alive == 0 {
		portStatusCache.ResponseTime[port] = 0
	} else {
		portStatusCache.ResponseTime[port] = respTime
	}
	portStatusCache.LastCheck[port] = time.Now()
}

// startProcessDetectionWorker 进程检测异步处理器
// 该函数启动一个后台goroutine，定期处理进程存活检测队列
// 使用异步处理避免阻塞Prometheus指标暴露
func startProcessDetectionWorker() {
	goroutineManager.StartGoroutine(GoroutineProcessDetectionWorker, func() {
		// 创建定时器，按照配置的间隔定期处理检测队列
		ticker := time.NewTicker(processAliveStatusInterval)
		defer ticker.Stop() // 确保定时器被正确关闭

		// 无限循环处理检测任务
		for {
			select {
			case <-processDetectionQueue.done:
				// 收到关闭信号，退出工作器
				return
			case <-ticker.C:
				// 定时器触发，处理队列中的进程检测任务
				processProcessDetectionQueue()
			}
		}
	})
}

// processProcessDetectionQueue 处理进程检测队列
// 分离出独立的函数，便于测试和错误处理
func processProcessDetectionQueue() {
	// 获取待检测的进程ID列表（加锁保护）
	processDetectionQueue.Lock()
	pids := makeSliceWithCapacity[int](len(processDetectionQueue.pids))
	for pid := range processDetectionQueue.pids {
		pids = append(pids, pid)
	}
	// 清空队列，避免重复检测
	processDetectionQueue.pids = make(map[int]bool)
	processDetectionQueue.Unlock()

	if len(pids) == 0 {
		return // 没有待检测的进程
	}

	// 异步检测所有排队的进程
	var wg sync.WaitGroup // 等待组，用于等待所有检测任务完成
	for _, pid := range pids {
		wg.Add(1) // 增加等待计数
		go func(p int) {
			defer wg.Done() // 任务完成时减少等待计数

			// panic恢复机制，确保单个进程检测失败不影响其他进程
			defer recoverFromPanic("进程检测", p)

			// 检测进程是否存活
			status := checkProcess(p)
			key := getPidKey(p) // 获取进程的唯一标识键

			// 原子更新进程存活状态缓存
			updateProcessAliveCache(key, status)

		}(pid)
	}
	wg.Wait() // 等待所有检测任务完成
}

// updateProcessAliveCache 原子更新进程存活状态缓存
// 提供线程安全的进程状态更新
func updateProcessAliveCache(key string, status int) {
	processAliveCache.RWMutex.Lock()
	defer processAliveCache.RWMutex.Unlock()

	processAliveCache.Status[key] = status
	processAliveCache.LastCheck[key] = time.Now()
}

// startProcessPidCacheCleanWorker 进程PID缓存清理工作器
// 该函数启动一个后台goroutine，定期清理过期的进程PID缓存
// 专门用于清理进程重启后的旧PID缓存，防止内存泄漏
func startProcessPidCacheCleanWorker() {
	go func() {
		// 创建定时器，按照配置的间隔定期清理进程缓存
		ticker := time.NewTicker(processPidCacheCleanInterval)
		defer ticker.Stop() // 确保定时器被正确关闭

		// 无限循环处理清理任务
		for {
			select {
			case <-processPidCacheCleanQueue.done:
				// 收到关闭信号，退出工作器
				return
			case <-ticker.C:
				// 定时器触发，执行缓存清理
				// 获取当前活跃的进程信息，只清理非活跃的缓存
				activePidKeys := getCurrentActivePidKeys()
				cleanProcessCaches(activePidKeys)
			}
		}
	}()
}

// getCurrentActivePidKeys 获取当前活跃进程的PID键
// 该函数扫描当前系统中的活跃进程，返回它们的唯一标识键
// 用于缓存清理时保留活跃进程的缓存，只清理已死亡进程的缓存
func getCurrentActivePidKeys() map[string]bool {
	activePidKeys := make(map[string]bool)

	// 获取当前端口进程信息
	infos := getPortProcessInfo()

	// 遍历所有端口进程信息，收集活跃的PID键
	for _, info := range infos {
		// 检查进程是否仍然有效
		if isProcessValid(info.Pid) {
			// 获取进程的唯一标识键
			key := getPidKey(info.Pid)
			activePidKeys[key] = true
		}
	}

	return activePidKeys
}

// ========== 初始化和关闭管理 ==========

// init 包初始化函数
// 在包被导入时自动执行，启动所有必要的异步工作器
func init() {
	startTCPDetectionWorker()           // 启动TCP端口检测工作器
	startProcessDetectionWorker()       // 启动进程存活检测工作器
	startProcessStatusDetectionWorker() // 启动进程状态检测工作器
	startProcessPidCacheCleanWorker()   // 启动进程PID缓存清理工作器
	startMemoryCleanupWorker()          // 启动内存清理工作器
}

// shutdownOnce 确保关闭操作只执行一次的同步原语
var shutdownOnce sync.Once

// ShutdownWorkers 优雅关闭所有异步工作器
// 该函数确保所有后台工作器能够优雅地停止，避免资源泄漏
func ShutdownWorkers() {
	shutdownOnce.Do(func() {
		// 关闭所有检测队列的done通道，通知工作器停止
		close(tcpDetectionQueue.done)           // 关闭TCP检测队列
		close(processDetectionQueue.done)        // 关闭进程检测队列
		close(processStatusDetectionQueue.done)  // 关闭进程状态检测队列
		close(processPidCacheCleanQueue.done)    // 关闭进程PID缓存清理队列
		close(memoryCleanupQueue.done)           // 关闭内存清理队列

		// 使用goroutine管理器优雅关闭所有goroutine
		goroutineManager.Shutdown()
	})
}

// ========== 运行时配置变量 ==========
// 这些变量支持通过环境变量进行运行时配置，提供灵活的部署选项

var (
	// portStatusInterval 端口状态检测间隔配置
	// 支持通过环境变量 PORT_STATUS_INTERVAL 进行配置
	portStatusInterval = func() time.Duration {
		if v := os.Getenv("PORT_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return DefaultPortStatusInterval
	}()

	// processAliveStatusInterval 进程存活状态检测间隔配置
	// 支持通过环境变量 PROCESS_ALIVE_STATUS_INTERVAL 进行配置
	processAliveStatusInterval = func() time.Duration {
		if v := os.Getenv("PROCESS_ALIVE_STATUS_INTERVAL"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return DefaultProcessAliveStatusInterval
	}()

	// portCheckTimeout 端口检测超时时间配置
	// 支持通过环境变量 PORT_CHECK_TIMEOUT 进行配置
	portCheckTimeout = func() time.Duration {
		if v := os.Getenv("PORT_CHECK_TIMEOUT"); v != "" {
			d, err := time.ParseDuration(v)
			if err == nil {
				return d
			}
		}
		return DefaultPortCheckTimeout
	}()

	// maxParallelIPChecks 最大并行IP检测数配置
	// 支持通过环境变量 MAX_PARALLEL_IP_CHECKS 进行配置
	maxParallelIPChecks = func() int {
		if v := os.Getenv("MAX_PARALLEL_IP_CHECKS"); v != "" {
			n, err := strconv.Atoi(v)
			if err == nil && n > 0 {
				return n
			}
		}
		return DefaultMaxParallelIPChecks
	}()

	// fastMode 快速模式配置
	// 支持通过环境变量 FAST_MODE 进行配置，启用后使用更短的超时时间
	fastMode = func() bool {
		if v := os.Getenv("FAST_MODE"); v != "" {
			enabled, err := strconv.ParseBool(v)
			if err == nil {
				return enabled
			}
		}
		return true // 默认启用快速模式
	}()
)

// ticksPerSecond 进程CPU时钟频率配置
// 支持通过环境变量 PROCESS_HZ 进行配置，用于CPU使用率计算
// 默认值为100，表示每秒100个时钟滴答
var ticksPerSecond = func() float64 {
    if v := os.Getenv("PROCESS_HZ"); v != "" {
        if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
            return f
        }
    }
    return DefaultTicksPerSecond
}()

// ========== 缓存结构体定义 ==========

// portStatusCacheStruct 端口状态缓存结构体
// 用于缓存TCP端口的存活状态和响应时间，避免频繁的网络检测
type portStatusCacheStruct struct {
	LastCheck     map[int]time.Time // 端口最后检测时间映射，key为端口号
	Status        map[int]int       // 端口状态映射，key为端口号，value为状态（1=存活，0=死亡，-1=未知）
	ResponseTime  map[int]float64   // 端口响应时间映射，key为端口号，value为响应时间（秒）
	RWMutex       sync.RWMutex      // 读写互斥锁，保证并发安全
}

// portStatusCache 端口状态缓存实例
// 全局变量，使用指针类型避免结构体复制时的性能开销
var portStatusCache = &portStatusCacheStruct{
	LastCheck:    make(map[int]time.Time),
	Status:       make(map[int]int),
	ResponseTime: make(map[int]float64),
}

// processAliveCacheStruct 进程存活状态缓存结构体
// 用于缓存进程的存活状态，避免频繁的进程检测
type processAliveCacheStruct struct {
	LastCheck map[string]time.Time // 进程最后检测时间映射，key为进程唯一标识
	Status    map[string]int       // 进程状态映射，key为进程唯一标识，value为状态（1=存活，0=死亡）
	RWMutex   sync.RWMutex         // 读写互斥锁，保证并发安全
}

// processAliveCache 进程存活状态缓存实例
// 全局变量，使用指针类型避免结构体复制时的性能开销
var processAliveCache = &processAliveCacheStruct{
	LastCheck: make(map[string]time.Time),
	Status:    make(map[string]int),
}

// pidStartTimeCache 进程启动时间缓存
// 用于缓存进程的启动时间，避免重复读取/proc/[pid]/stat文件
// 使用匿名结构体，包含读写锁和缓存映射
var pidStartTimeCache = struct {
	sync.RWMutex           // 读写互斥锁，保证并发安全
	cache map[int]string   // 进程启动时间映射，key为PID，value为启动时间字符串
}{cache: make(map[int]string)}

// processIdentityCache 进程身份缓存
// 基于进程名+路径的进程身份管理，解决服务重启后PID变化的问题
// 使用匿名结构体，包含读写锁和缓存映射
var processIdentityCache = struct {
	sync.RWMutex                    // 读写互斥锁，保证并发安全
	cache map[string]ProcessIdentity // 进程身份映射，key为"processName|exePath"，value为进程身份信息
}{cache: make(map[string]ProcessIdentity)}

// ProcessIdentity 进程身份信息结构体
// 用于跟踪进程的身份信息，解决服务重启后PID变化的问题
type ProcessIdentity struct {
	ProcessName string    `json:"process_name"` // 进程名称
	ExePath     string    `json:"exe_path"`     // 可执行文件路径
	CurrentPid  int       `json:"current_pid"`  // 当前进程ID
	LastSeen    time.Time `json:"last_seen"`    // 最后见到的时间
	IsAlive     bool      `json:"is_alive"`     // 是否存活
}

// forceRescanGuard 强制重扫节流器
// 防止频繁的强制重扫导致系统开销过大
// 使用匿名结构体，包含互斥锁和最后重扫时间
var forceRescanGuard = struct {
    sync.Mutex  // 互斥锁，保证并发安全
    last time.Time // 最后一次重扫的时间戳
}{}

// forceRescanPortProcess 立即强制刷新端口-进程映射与相关缓存（带最小间隔节流）
// 该函数用于在检测到进程重启时强制重新扫描端口-进程映射关系
// 使用节流机制防止频繁重扫导致系统开销过大
func forceRescanPortProcess() {
    // 节流检查：确保最小间隔时间
    forceRescanGuard.Lock()
    if time.Since(forceRescanGuard.last) < ForceRescanThrottleInterval {
        forceRescanGuard.Unlock()
        return // 距离上次重扫时间太短，跳过本次重扫
    }
    forceRescanGuard.last = time.Now() // 更新最后重扫时间
    forceRescanGuard.Unlock()

    // 执行端口-进程映射扫描
    scanned := discoverPortProcess()
    now := time.Now()

    // 原子更新缓存数据（加写锁保护）
    portProcessCache.RWMutex.Lock()
    portProcessCache.Data = scanned      // 更新扫描结果
    portProcessCache.LastScan = now      // 更新扫描时间
    portProcessCache.RWMutex.Unlock()

    // 锁外清理依赖缓存，避免长时间持有锁
    if len(scanned) > 0 {
        // 创建数据副本，避免在清理过程中修改原始数据
        dataCopy := append([]PortProcessInfo(nil), scanned...)
        cleanStalePortCaches(dataCopy) // 清理过期的缓存项
    }
}

// processStatusCache 进程状态缓存
// 用于缓存进程的基础状态信息，避免重复读取/proc/[pid]/stat文件
// 使用匿名结构体，包含读写锁、缓存映射和最后检查时间映射
var processStatusCache = struct {
	sync.RWMutex                    // 读写互斥锁，保证并发安全
	cache map[int]ProcessStatus     // 进程状态映射，key为PID，value为进程状态信息
	lastCheck map[int]time.Time     // 最后检查时间映射，key为PID，value为最后检查时间
}{cache: make(map[int]ProcessStatus), lastCheck: make(map[int]time.Time)}

// ProcessDetailedStatus 进程详细状态结构体
// 包含进程的详细性能指标，如CPU使用率、内存使用量、IO统计等
type ProcessDetailedStatus struct {
	CPUPercent     float64 `json:"cpu_percent"`      // CPU使用率百分比
	MinFaultsPerS  float64 `json:"minflt_per_s"`     // 每秒次要缺页错误数
	MajFaultsPerS  float64 `json:"majflt_per_s"`     // 每秒主要缺页错误数
	VMRSS          float64 `json:"vmrss"`            // 物理内存使用量（KB）
	VMSize         float64 `json:"vmsize"`           // 虚拟内存使用量（KB）
	MemPercent     float64 `json:"mem_percent"`      // 内存使用率百分比
	KBReadPerS     float64 `json:"kb_rd_per_s"`      // 每秒读取数据量（KB）
	KBWritePerS    float64 `json:"kb_wr_per_s"`      // 每秒写入数据量（KB）
	Threads        float64 `json:"threads"`          // 线程数量
	Voluntary      float64 `json:"voluntary"`        // 自愿上下文切换次数
	NonVoluntary   float64 `json:"nonvoluntary"`     // 非自愿上下文切换次数
	LastUpdate     time.Time `json:"last_update"`    // 最后更新时间
	// 以下字段用于增量计算，存储上次的值
	LastUtime      float64 `json:"last_utime"`       // 上次用户态CPU时间（ticks）
	LastStime      float64 `json:"last_stime"`       // 上次内核态CPU时间（ticks）
	LastMinflt     float64 `json:"last_minflt"`     // 上次次要缺页错误数
	LastMajflt     float64 `json:"last_majflt"`     // 上次主要缺页错误数
	LastReadBytes  float64 `json:"last_read_bytes"`  // 上次读取字节数
	LastWriteBytes float64 `json:"last_write_bytes"` // 上次写入字节数
}

// processDetailedStatusCache 进程详细状态缓存
// 用于缓存进程的详细性能指标，避免频繁读取系统文件
// 使用匿名结构体，包含读写锁、缓存映射和最后检查时间映射
var processDetailedStatusCache = struct {
	sync.RWMutex                              // 读写互斥锁，保证并发安全
	cache map[int]*ProcessDetailedStatus      // 进程详细状态映射，key为PID，value为详细状态指针
	lastCheck map[int]time.Time               // 最后检查时间映射，key为PID，value为最后检查时间
}{cache: make(map[int]*ProcessDetailedStatus), lastCheck: make(map[int]time.Time)}

// ProcessGroupAggregatedStatus 进程分组累计状态结构体
// 用于存储同类型进程的累计性能指标，支持进程分组监控
type ProcessGroupAggregatedStatus struct {
	ProcessName    string  `json:"process_name"`     // 进程名称
	ProcessCount   int     `json:"process_count"`    // 进程数量
	TotalCPUPercent float64 `json:"total_cpu_percent"` // 总CPU使用率百分比
	TotalMemPercent float64 `json:"total_mem_percent"` // 总内存使用率百分比
	TotalVMRSS     float64 `json:"total_vmrss"`     // 总物理内存使用量（KB）
	TotalVMSize    float64 `json:"total_vmsize"`    // 总虚拟内存使用量（KB）
	TotalThreads   float64 `json:"total_threads"`   // 总线程数量
	TotalIORead    float64 `json:"total_io_read"`   // 总IO读取量（KB/s）
	TotalIOWrite   float64 `json:"total_io_write"`  // 总IO写入量（KB/s）
	LastUpdate     time.Time `json:"last_update"`   // 最后更新时间
}

// processGroupAggregatedCache 进程分组累计缓存
// 用于缓存进程分组的累计状态，避免重复计算
// 使用匿名结构体，包含读写锁、缓存映射和最后检查时间映射
var processGroupAggregatedCache = struct {
	sync.RWMutex                                    // 读写互斥锁，保证并发安全
	cache map[string]*ProcessGroupAggregatedStatus  // 分组状态映射，key为进程名，value为累计状态指针
	lastCheck map[string]time.Time                 // 最后检查时间映射，key为进程名，value为最后检查时间
}{cache: make(map[string]*ProcessGroupAggregatedStatus), lastCheck: make(map[string]time.Time)}

// processStatusDetectionQueue 进程状态检测队列
// 用于异步处理进程详细状态检测，避免阻塞指标收集
var processStatusDetectionQueue = struct {
	sync.Mutex           // 互斥锁，保护队列的并发访问
	pids map[int]bool    // 待检测的进程ID映射，key为PID，value为是否待检测
	done chan struct{}   // 关闭信号通道，用于优雅关闭检测工作器
}{pids: make(map[int]bool), done: make(chan struct{})}

// processPidCacheCleanQueue 进程PID缓存清理队列
// 用于异步清理过期的进程PID缓存
var processPidCacheCleanQueue = struct {
	done chan struct{}   // 关闭信号通道，用于优雅关闭清理工作器
}{done: make(chan struct{})}

// memoryCleanupQueue 内存清理队列
// 用于异步清理过期的缓存数据
var memoryCleanupQueue = struct {
	done chan struct{}   // 关闭信号通道，用于优雅关闭清理工作器
}{done: make(chan struct{})}

// processStatusInterval 进程状态检测间隔配置
// 支持通过环境变量 PROCESS_STATUS_INTERVAL 进行配置
// 控制进程详细状态检测的频率
var processStatusInterval = func() time.Duration {
	if v := os.Getenv("PROCESS_STATUS_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return DefaultProcessStatusInterval
}()

// processPidCacheCleanInterval 进程PID缓存清理间隔配置
// 支持通过环境变量 PROCESS_PID_CACHE_CLEAN_INTERVAL 进行配置
// 专门用于清理进程重启后的旧PID缓存
var processPidCacheCleanInterval = func() time.Duration {
	if v := os.Getenv("PROCESS_PID_CACHE_CLEAN_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return DefaultProcessPidCacheCleanInterval
}()

// enableProcessAggregation 进程分组累计功能开关配置
// 支持通过环境变量 ENABLE_PROCESS_AGGREGATION 进行配置
// 控制是否启用进程分组累计计算（默认启用）
var enableProcessAggregation = func() bool {
	if v := os.Getenv("ENABLE_PROCESS_AGGREGATION"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err == nil {
			return enabled
		}
	}
	return true // 默认启用分组累计功能
}()

// shouldAggregateProcess 判断进程是否需要分组累计
// 该函数决定是否对指定进程进行分组累计计算
// 当前实现中，所有进程都按名称进行分组累计
func shouldAggregateProcess(processName string) bool {
	// 所有进程都按名称进行分组累计
	// 这样可以监控同类型进程的整体资源使用情况
	return true
}

// calculateProcessGroupAggregation 计算进程分组累计状态
// 该函数计算指定进程组的所有进程的累计性能指标
// 用于提供进程组的整体监控视图
func calculateProcessGroupAggregation(processName string, infos []PortProcessInfo) *ProcessGroupAggregatedStatus {
	var totalCPU, totalMem, totalVMRSS, totalVMSize, totalThreads, totalIORead, totalIOWrite float64
	processCount := len(infos) // 直接使用传入的进程数量

	// 遍历所有进程，累计各项指标
	for _, info := range infos {
		// 由于infos已经是预分组的，不需要再次检查进程名
		detailedStatus := getProcessDetailedStatusCached(info.Pid)
		if detailedStatus != nil {
			totalCPU += detailedStatus.CPUPercent      // 累计CPU使用率
			totalMem += detailedStatus.MemPercent      // 累计内存使用率
			totalVMRSS += detailedStatus.VMRSS         // 累计物理内存使用量
			totalVMSize += detailedStatus.VMSize       // 累计虚拟内存使用量
			totalThreads += detailedStatus.Threads     // 累计线程数量
			totalIORead += detailedStatus.KBReadPerS   // 累计IO读取量
			totalIOWrite += detailedStatus.KBWritePerS // 累计IO写入量
		}
	}

	// 返回累计状态对象
	return &ProcessGroupAggregatedStatus{
		ProcessName:     processName,
		ProcessCount:    processCount,
		TotalCPUPercent: totalCPU,
		TotalMemPercent: totalMem,
		TotalVMRSS:      totalVMRSS,
		TotalVMSize:     totalVMSize,
		TotalThreads:    totalThreads,
		TotalIORead:     totalIORead,
		TotalIOWrite:    totalIOWrite,
		LastUpdate:      time.Now(),
	}
}

// Collect 方法：实现 Prometheus Collector 接口，采集所有指标
// 该方法是Prometheus指标收集的核心函数，负责收集并暴露所有监控指标
func (c *SimplePortProcessCollector) Collect(ch chan<- prometheus.Metric) {
	// 获取端口进程信息，带缓存机制
	infos := getPortProcessInfo()

	// 用于跟踪已报告的进程组，避免重复报告
	reportedGroupKeys := make(map[string]bool) // 分组累计的进程名
	tcpPortDone := make(map[int]bool)          // 已处理的TCP端口，避免重复检测

	// 预处理：按进程名+exe_path分组，避免重复计算
	// 将相同进程名的进程分组，用于后续的累计计算
	processGroups := make(map[string][]PortProcessInfo)
	for _, info := range infos {
		groupKey := info.ProcessName + "|" + info.ExePath
		processGroups[groupKey] = append(processGroups[groupKey], info)
	}

	// 遍历所有端口进程信息，生成相应的Prometheus指标
	for _, info := range infos {
		// 只处理TCP协议的端口
		if info.Protocol == "tcp" {
			// 构建指标标签
			labels := []string{info.ProcessName, info.ExePath, strconv.Itoa(info.Port)}

			// 避免对同一端口重复检测
			if !tcpPortDone[info.Port] {
				// TCP端口存活检测
				alive := getPortStatus(info.Port)
				if alive >= 0 {
					// 生成TCP端口存活指标
					ch <- prometheus.MustNewConstMetric(
						c.portTCPAliveDesc, prometheus.GaugeValue, float64(alive), labels...,
					)

					// 生成TCP端口响应时间指标（端口挂了时响应时间为0）
					respTime := getPortResponseTime(info.Port)
					// 总是暴露响应时间指标，端口挂了时为0
					ch <- prometheus.MustNewConstMetric(
						c.portTCPResponseTimeDesc, prometheus.GaugeValue, respTime, labels...,
					)
				}
				tcpPortDone[info.Port] = true
			}
		}

		// 只对有端口监听的进程进行分组累计
		if enableProcessAggregation && shouldAggregateProcess(info.ProcessName) {
			groupKey := info.ProcessName + "|" + info.ExePath
			if !reportedGroupKeys[groupKey] {
				// 使用预分组的进程列表，避免重复计算
				groupInfos := processGroups[groupKey]
				aggregatedStatus := calculateProcessGroupAggregation(info.ProcessName, groupInfos)

				// 更新进程身份信息（解决服务重启问题）- 智能选择PID
				if len(groupInfos) > 0 {
					// 智能选择PID：优先选择存活的进程，确保身份信息准确
					selectedPid := selectBestPidForIdentity(groupInfos)
					updateProcessIdentity(info.ProcessName, info.ExePath, selectedPid)
				}

				// 使用智能进程身份状态检查（解决服务重启问题）
				overallAlive, firstAliveState := getProcessIdentityStatus(info.ProcessName, info.ExePath)

				if overallAlive >= 0 {
					// 进程存活状态（累计）- 使用智能身份管理
					// 生成进程存活状态指标（累计）- 使用智能身份管理
					ch <- prometheus.MustNewConstMetric(
						c.processAliveDesc, prometheus.GaugeValue, float64(overallAlive),
						info.ProcessName, info.ExePath, firstAliveState,
					)

					// 生成累计的性能指标（进程挂了时设为0）
					var cpuPercent, memPercent, vmRSS, vmSize, threads, ioRead, ioWrite float64
					if overallAlive == 1 {
						// 进程存活时使用实际值
						cpuPercent = aggregatedStatus.TotalCPUPercent
						memPercent = aggregatedStatus.TotalMemPercent
						vmRSS = aggregatedStatus.TotalVMRSS * 1024
						vmSize = aggregatedStatus.TotalVMSize * 1024
						threads = aggregatedStatus.TotalThreads
						ioRead = aggregatedStatus.TotalIORead * 1024
						ioWrite = aggregatedStatus.TotalIOWrite * 1024
					} else {
						// 进程挂了时设为0
						cpuPercent = 0
						memPercent = 0
						vmRSS = 0
						vmSize = 0
						threads = 0
						ioRead = 0
						ioWrite = 0
					}

					// CPU使用率指标
					ch <- prometheus.MustNewConstMetric(
						c.processCPUPercentDesc, prometheus.GaugeValue, cpuPercent,
						info.ProcessName, info.ExePath,
					)

					// 内存使用率指标
					ch <- prometheus.MustNewConstMetric(
						c.processMemPercentDesc, prometheus.GaugeValue, memPercent,
						info.ProcessName, info.ExePath,
					)

					// 物理内存使用量指标（转换为字节）
					ch <- prometheus.MustNewConstMetric(
						c.processVMRSSDesc, prometheus.GaugeValue, vmRSS,
						info.ProcessName, info.ExePath,
					)

					// 虚拟内存使用量指标（转换为字节）
					ch <- prometheus.MustNewConstMetric(
						c.processVMSizeDesc, prometheus.GaugeValue, vmSize,
						info.ProcessName, info.ExePath,
					)

					// 线程数量指标
					ch <- prometheus.MustNewConstMetric(
						c.processThreadsDesc, prometheus.GaugeValue, threads,
						info.ProcessName, info.ExePath,
					)

					// IO读取速率指标（转换为字节/秒）
					ch <- prometheus.MustNewConstMetric(
						c.processIOReadDesc, prometheus.GaugeValue, ioRead,
						info.ProcessName, info.ExePath,
					)

					// IO写入速率指标（转换为字节/秒）
					ch <- prometheus.MustNewConstMetric(
						c.processIOWriteDesc, prometheus.GaugeValue, ioWrite,
						info.ProcessName, info.ExePath,
					)
				}

				// 标记该进程组已报告，避免重复处理
				reportedGroupKeys[groupKey] = true
			}
		}
	}
}


// getPortProcessInfo 函数：获取端口与进程信息，带缓存机制
// 该函数是端口进程信息获取的核心函数，使用双重检查锁定模式优化性能
// 避免频繁的系统扫描，同时保证数据的实时性
func getPortProcessInfo() []PortProcessInfo {
	// 第一次判断是否过期（使用读锁，允许并发读取）
	portProcessCache.RWMutex.RLock()
	expired := time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0
	portProcessCache.RWMutex.RUnlock()

	if expired {
		// 缓存过期，需要重新扫描
		// 锁外执行重扫描，避免在写锁内做重IO操作
		scanned := discoverPortProcess()
		now := time.Now()
		var needClean bool
		var dataCopy []PortProcessInfo

		// 二次检查并提交（使用写锁，确保原子性）
		portProcessCache.RWMutex.Lock()
		// 双重检查：防止多个goroutine同时执行扫描
		if time.Since(portProcessCache.LastScan) > scanInterval || len(portProcessCache.Data) == 0 {
			portProcessCache.Data = scanned      // 更新扫描结果
			portProcessCache.LastScan = now      // 更新扫描时间
			dataCopy = append([]PortProcessInfo(nil), scanned...) // 创建数据副本
			needClean = true                     // 标记需要清理缓存
		}
		portProcessCache.RWMutex.Unlock()

		if needClean {
			// 锁外清理过期缓存，缩短锁持有时间
			cleanStalePortCaches(dataCopy)
		}
	}

	// 返回缓存的数据（使用读锁保护）
	portProcessCache.RWMutex.RLock()
	defer portProcessCache.RWMutex.RUnlock()
	return portProcessCache.Data
}

// discoverPortProcess 函数：优化端口发现效率，先建立 inode->port 映射，再遍历进程 fd 查找 socket inode
// 该函数是端口进程发现的核心算法，使用高效的映射方式减少系统调用
// 算法思路：先解析网络连接表建立inode到端口的映射，再遍历进程文件描述符查找socket inode
func discoverPortProcess() []PortProcessInfo {
	start := time.Now()
	defer func() {
		updatePerformanceStats("port_scan", time.Since(start))
	}()

	var results []PortProcessInfo

	// 第一步：解析网络连接表，建立inode到端口的映射
	// 同时解析IPv4和IPv6的TCP连接表
	tcpInodePort := parseInodePortMap([]string{ProcNetTCPPath, ProcNetTCP6Path}, TCPProtocol)
	seenTCP := make(map[int]bool) // 用于去重，避免重复处理同一端口

	// 第二步：打开/proc目录，遍历所有进程
	procHandle, err := NewSafeFileHandle(procPath(ProcPathPrefix))
	if err != nil {
		log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToOpenProc, err))
		return results
	}
	defer func() {
		if closeErr := procHandle.Close(); closeErr != nil {
			log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToCloseProc, closeErr))
		}
	}()

	// 读取/proc目录中的所有条目
	entries, err := procHandle.ReadDir()
	if err != nil {
		log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToReadProc, err))
		return results
	}

	// 第三步：遍历所有进程目录
	for _, entry := range entries {
		// 跳过非目录条目
		if !entry.IsDir() {
			continue
		}

		// 尝试解析PID
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 跳过非数字目录名
		}

		// 第四步：读取进程的文件描述符目录
		// 使用字符串工具构建路径
		fdPath := stringUtils.BuildPath(ProcPathPrefix, entry.Name(), ProcFdSuffix)

		fdHandle, err := NewSafeFileHandle(procPath(fdPath))
		if err != nil {
			log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToReadFile, fdPath, err))
			continue
		}

		fds, err := fdHandle.ReadDir()
		fdHandle.Close() // 立即关闭文件句柄
		if err != nil {
			log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToReadFile, fdPath, err))
			continue
		}

		// 第五步：遍历进程的所有文件描述符
		for _, fdEntry := range fds {
			// 使用字符串工具构建socket路径
			fdLink := stringUtils.BuildSocketPath(fdPath, fdEntry.Name())

			link, err := os.Readlink(fdLink)
			if err != nil {
				log.Printf("%s %s\n", LogPrefix, fmt.Sprintf(ErrMsgFailedToReadlink, fdLink, err))
				continue
			}

			// 只处理socket类型的文件描述符
			if !strings.HasPrefix(link, SocketPrefix) {
				continue
			}

			// 提取socket的inode号
			if len(link) < len(SocketPrefix)+len(SocketSuffix) {
				continue // 防止越界访问
			}
			inode := link[len(SocketPrefix) : len(link)-len(SocketSuffix)]

			// 第六步：检查TCP端口映射
			if port, ok := tcpInodePort[inode]; ok {
				// 避免重复处理同一端口
				if seenTCP[port] {
					continue
				}
				seenTCP[port] = true

				// 获取进程信息
				exePath := getProcessExe(pid)        // 获取可执行文件路径
				exeName := filepath.Base(exePath)    // 提取进程名

				// 检查是否为排除的进程
				if isExcludedProcess(exeName) {
					continue
				}

				// 构建端口进程信息并添加到结果中
				results = append(results, PortProcessInfo{
					ProcessName: safeLabel(exeName),                    // 进程名（安全标签）
					ExePath:     safeLabel(exePath),                    // 可执行文件路径（安全标签）
					Port:        port,                                  // 端口号
					Pid:         pid,                                   // 进程ID
					WorkDir:     safeLabel(getProcessCwd(pid)),         // 工作目录（安全标签）
					Username:    safeLabel(getProcessUser(pid)),       // 用户名（安全标签）
					Protocol:    TCPProtocol,                          // 协议类型
				})
			}
		}
	}
	return results
}

// parseInodePortMap 解析 /proc/net/tcp 或 udp，返回 inode->port 映射
// 该函数解析Linux网络连接表，建立socket inode到端口号的映射关系
// 这是端口发现算法的关键步骤，用于后续的进程端口关联
func parseInodePortMap(files []string, proto string) map[string]int {
	result := make(map[string]int)

	// 遍历所有网络连接表文件
	for _, file := range files {
		// 读取网络连接表文件内容
		content, err := os.ReadFile(procPath(file))
		if err != nil {
			log.Printf("[simple_port_process_collector] failed to read %s: %v\n", file, err)
			continue
		}

		// 按行分割文件内容
		lines := strings.Split(string(content), "\n")

		// 检查是否有数据行
		if len(lines) <= 1 {
			continue // 跳过没有数据行的文件
		}

		// 跳过第一行（标题行），处理数据行
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue // 跳过格式不正确的行
			}

			// 对于TCP协议，只处理LISTEN状态的连接
			if proto == TCPProtocol && fields[3] != TCPListenState {
				continue // TCPListenState表示TCP LISTEN状态
			}

			// 提取socket inode号（第10个字段）
			inode := fields[9]

			// 解析地址和端口（第2个字段格式：IP:PORT）
			addrParts := strings.Split(fields[1], ColonSeparator)
			if len(addrParts) < 2 {
				continue // 跳过格式不正确的地址
			}

			// 提取端口号（十六进制格式）
			portHex := addrParts[len(addrParts)-1]
			port, err := strconv.ParseInt(portHex, 16, 32)
			if err != nil {
				continue // 跳过无法解析的端口
			}

			// 建立inode到端口的映射
			result[inode] = int(port)
		}
	}
	return result
}

// checkPortTCP 并发检测所有本地IP的TCP端口
// 该函数使用默认超时时间检测指定端口是否可访问
// 返回端口存活状态和响应时间
func checkPortTCP(port int) (alive int, respTime float64) {
	return checkPortTCPWithTimeout(port, portCheckTimeout)
}

// ========== 宿主机IP检测相关代码 ==========
// 这些代码专门用于容器环境中的宿主机IP检测，比环境变量检测更准确

// hostIPCache 宿主机IP缓存结构体
var hostIPCache = struct {
	LastScan time.Time
	Data     []HostIPInfo
	Mutex    sync.RWMutex
}{Data: nil}

// hostIPCacheInterval 宿主机IP缓存刷新周期，默认8小时
var hostIPCacheInterval = func() time.Duration {
	if v := os.Getenv("HOST_IP_CACHE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return 8 * time.Hour
}()

// HostIPInfo 宿主机IP信息结构体
type HostIPInfo struct {
	InterfaceName string
	IPAddresses   []string
}

// getHostIPInfo 获取宿主机IP信息，带缓存，每8小时刷新一次
func getHostIPInfo() []HostIPInfo {
	hostIPCache.Mutex.RLock()
	expired := time.Since(hostIPCache.LastScan) > hostIPCacheInterval || hostIPCache.Data == nil
	hostIPCache.Mutex.RUnlock()
	if expired {
		hostIPCache.Mutex.Lock()
		if time.Since(hostIPCache.LastScan) > hostIPCacheInterval || hostIPCache.Data == nil {
			hostIPCache.Data = collectHostIPInfo()
			hostIPCache.LastScan = time.Now()
		}
		hostIPCache.Mutex.Unlock()
	}
	hostIPCache.Mutex.RLock()
	defer hostIPCache.Mutex.RUnlock()
	return hostIPCache.Data
}

// isVirtualHostInterface 判断是否为虚拟网卡（如 docker、veth、br-、virbr、lo 等）
func isVirtualHostInterface(name string) bool {
	virtualPrefixes := []string{
		DockerInterfacePrefix, VethInterfacePrefix, BridgeInterfacePrefix, VirbrInterfacePrefix,
		LoopbackInterface, VMNetInterfacePrefix, TapInterfacePrefix, TunInterfacePrefix,
		WlxInterfacePrefix, EnxInterfacePrefix,
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// collectHostIPInfo 采集物理网卡及其 IPv4 地址
func collectHostIPInfo() []HostIPInfo {
	var result []HostIPInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if isVirtualHostInterface(iface.Name) || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		// 使用 map 来去重 IP 地址
		ipSet := make(map[string]bool)
		var ipAddresses []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ipStr := ipnet.IP.String()
				if !ipSet[ipStr] {
					ipSet[ipStr] = true
					ipAddresses = append(ipAddresses, ipStr)
				}
			}
		}
		if len(ipAddresses) > 0 {
			result = append(result, HostIPInfo{
				InterfaceName: iface.Name,
				IPAddresses:   ipAddresses,
			})
		}
	}
	return result
}

// getHostIPs 获取宿主机IP地址列表
// 只通过物理网卡检测获取宿主机IP，这是最准确的方式
func getHostIPs() []string {
	var hostIPs []string

	// 通过物理网卡获取宿主机IP（最准确的方式）
	hostIPInfos := getHostIPInfo()
	for _, info := range hostIPInfos {
		hostIPs = append(hostIPs, info.IPAddresses...)
		if EnablePortCheckDebugLog {
			log.Printf("%s 从物理网卡 %s 获取宿主机IP: %v", LogPrefix, info.InterfaceName, info.IPAddresses)
		}
	}

	// 去重
	uniqueIPs := make(map[string]bool)
	var result []string
	for _, ip := range hostIPs {
		if !uniqueIPs[ip] {
			uniqueIPs[ip] = true
			result = append(result, ip)
		}
	}

	return result
}

// checkPortTCPWithTimeout 带超时的TCP端口检测函数
// 该函数检测指定端口是否可访问，支持自定义超时时间
// 使用并发检测多个IP地址，提高检测效率
func checkPortTCPWithTimeout(port int, timeout time.Duration) (alive int, respTime float64) {
	// 输入验证：检查端口号是否在有效范围内
	if port < MinPortNumber || port > MaxPortNumber {
		log.Printf("[simple_port_process_collector] 无效端口号: %d", port)
		return 0, 0
	}

	// 输入验证：检查超时时间是否有效
	if timeout <= 0 {
		timeout = portCheckTimeout
	}

	// 定义常用IP地址列表，优先检测这些地址
	commonAddrs := []string{LocalhostIPv4, AnyIPv4, LocalhostIPv6, AnyIPv6}
	minResp := -1.0
	found := false
	var failedAddrs []string // 记录失败的地址

	// 第一步：检测常用地址，这些地址通常响应最快
	var bestIP string
	for _, ip := range commonAddrs {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		cost := time.Since(start).Seconds()
		if err == nil {
			conn.Close()
			if minResp < 0 || cost < minResp {
				minResp = cost
				bestIP = ip
			}
			found = true
			// 可选：记录成功的连接（仅在调试模式下）
			if EnablePortCheckDebugLog {
				log.Printf("%s 端口 %d 在地址 %s 检测成功，响应时间: %.9f秒", LogPrefix, port, ip, cost)
			}
		} else {
			// 记录失败的地址
			failedAddrs = append(failedAddrs, ip)
			// 可选：记录详细的错误信息（仅在调试模式下）
			if EnablePortCheckDebugLog {
				log.Printf("%s 端口 %d 在地址 %s 检测失败: %v", LogPrefix, port, ip, err)
			}
		}
	}

	// 如果是第一个成功的地址，记录最终使用的响应时间
	if found && bestIP != "" && EnablePortCheckDebugLog {
		log.Printf("%s 端口 %d 最终使用地址 %s 的响应时间: %.9f秒 (指标值)", LogPrefix, port, bestIP, minResp)
	}

	// 如果常用地址检测成功，直接返回结果
	if found {
		return 1, minResp
	}

	// 常用地址都不通，再检测所有本地IP和宿主机IP（并发）
	addrs := []string{}

	// 获取宿主机IP（如果启用）
	if EnableHostIPDetection {
		hostIPs := getHostIPs()
		addrs = append(addrs, hostIPs...)
		if EnablePortCheckDebugLog && len(hostIPs) > 0 {
			log.Printf("%s 检测到宿主机IP: %v", LogPrefix, hostIPs)
		}
	}

	// 获取本地网络接口IP
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

	// 去重
	uniqueAddrs := make(map[string]bool)
	var finalAddrs []string
	for _, addr := range addrs {
		if !uniqueAddrs[addr] {
			uniqueAddrs[addr] = true
			finalAddrs = append(finalAddrs, addr)
		}
	}
	addrs = finalAddrs

	if len(addrs) == 0 {
		// 记录所有常用地址都失败的情况
		log.Printf("%s 端口 %d 检测失败: 常用地址 %v 均不可达", LogPrefix, port, failedAddrs)
		return 0, 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resultOnce := make(chan float64, 1)
	failedOnce := make(chan string, len(addrs)) // 用于收集失败的地址
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
				// 可选：记录成功的连接（仅在调试模式下）
				if EnablePortCheckDebugLog {
					log.Printf("%s 端口 %d 在地址 %s 检测成功，响应时间: %.9f秒", LogPrefix, port, ip, cost)
				}
				select {
				case resultOnce <- cost:
					// 首个成功，取消其他拨号
					cancel()
				default:
				}
			} else {
				// 记录失败的地址
				select {
				case failedOnce <- ip:
				default:
				}
				// 可选：记录详细的错误信息（仅在调试模式下）
				if EnablePortCheckDebugLog {
					log.Printf("%s 端口 %d 在地址 %s 检测失败: %v", LogPrefix, port, ip, err)
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
		// 收集所有失败的地址
		var allFailedAddrs []string
		// 不关闭channel，而是通过非阻塞方式收集失败的地址
		for {
			select {
			case failedIP := <-failedOnce:
				allFailedAddrs = append(allFailedAddrs, failedIP)
			default:
				// 没有更多失败的地址，退出循环
				goto logFailure
			}
		}
	logFailure:
		// 记录所有地址都失败的情况
		log.Printf("%s 端口 %d 检测失败: 常用地址 %v 和本地IP %v 均不可达", LogPrefix, port, failedAddrs, addrs)
		return 0, 0
	}
}

// isProcessValid 检查进程是否仍然有效（快速检查）
func isProcessValid(pid int) bool {
	statPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcStatSuffix)
	_, err := os.Stat(procPath(statPath))
	return err == nil
}

// getProcStatFields 安全解析 /proc/[pid]/stat，兼容 comm 字段含空格/括号
func getProcStatFields(pid int) ([]string, error) {
	statPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcStatSuffix)
    content, err := os.ReadFile(procPath(statPath))
    if err != nil {
        return nil, err
    }
    s := strings.TrimSpace(string(content))
    if s == EmptyString {
        return nil, fmt.Errorf("empty stat file for pid %d", pid)
    }

    // 形如: pid (comm with spaces) state ...
    l := strings.IndexByte(s, '(')
    r := strings.LastIndexByte(s, ')')
    if l == -1 || r == -1 || r < l {
        // 回退：尽力拆分
        fields := strings.Fields(s)
        if len(fields) < 3 {
            return nil, fmt.Errorf("invalid stat format for pid %d", pid)
        }
        return fields, nil
    }

    pre := strings.TrimSpace(s[:l])
    comm := s[l+1 : r]
    post := strings.TrimSpace(s[r+1:])

    fields := make([]string, 0, DefaultProcessFieldsCapacity)
    if pre != "" {
        fields = append(fields, strings.Fields(pre)...)
    }
    fields = append(fields, comm)
    if post != "" {
        fields = append(fields, strings.Fields(post)...)
    }

    if len(fields) < 3 {
        return nil, fmt.Errorf("insufficient fields in stat file for pid %d", pid)
    }

    return fields, nil
}

// checkProcess 函数：检测进程是否存活（检查实际进程状态）
func checkProcess(pid int) int {
    fields, err := getProcStatFields(pid)
    if err != nil || len(fields) < 3 {
        return 0
    }
    // 检查进程状态：Z表示僵尸进程，视为死亡
    state := fields[2]
	if state == ProcessStateZombie {
		return 0 // 僵尸进程视为死亡
	}

	return 1 // 进程存活
}

// getProcessExe 函数：获取进程的可执行文件路径
func getProcessExe(pid int) string {
	exePath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcExeSuffix)
	path, err := os.Readlink(procPath(exePath))
	if err != nil || path == EmptyString {
		return PathSeparator
	}
	return path
}

// getProcessCwd 函数：获取进程的工作目录
func getProcessCwd(pid int) string {
	cwdPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcCwdSuffix)
	path, err := os.Readlink(procPath(cwdPath))
	if err != nil || path == EmptyString {
		return PathSeparator
	}
	return path
}

// getProcessUser 函数：获取进程的运行用户（UID）
func getProcessUser(pid int) string {
	statusPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcStatusSuffix)
	content, err := os.ReadFile(procPath(statusPath))
	if err != nil {
		return PathSeparator
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, StatusFieldUid) {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != EmptyString {
				return fields[1]
			}
		}
	}
	return PathSeparator
}

// safeLabel 保证 Prometheus 标签不为空，若为空则返回 "/"
func safeLabel(val string) string {
	if strings.TrimSpace(val) == EmptyString {
		return DefaultLabelValue
	}
	return val
}

// DefaultExcludedProcesses 默认排除的进程列表
var DefaultExcludedProcesses = []string{
	"systemd",
	"init",
	"kthreadd",
	"ksoftirqd",
	"rcu_sched",
	"rcu_bh",
	"bo-agent",
	"migration",
	"watchdog",
	"cpuhp",
	"netns",
	"khungtaskd",
	"oom_reaper",
	"chronyd",
	"kswapd",
	"fsnotify_mark",
	"ecryptfs-kthrea",
	"kauditd",
	"khubd",
	"ssh",
	"snmpd",
	"zabbix",
	"prometheus",
	"rpcbind",
	"smartdns",
	"cupsd",
	"dhclient",
	"master",
	"rpc.statd",
	"titanagent",
	"node_exporter",
	"monitor_manage",
	"dnsmasq",
}

var excludedProcessNames = func() []string {
	env := os.Getenv(EnvExcludedProcessNames)
	if env == EmptyString {
		return nil
	}
	var result []string
	for _, name := range strings.Split(env, CommaSeparator) {
		n := strings.TrimSpace(name)
		if n != EmptyString {
			result = append(result, n)
		}
	}
	return result
}()

func isExcludedProcess(exeName string) bool {
	all := append(DefaultExcludedProcesses, excludedProcessNames...)
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

// 性能优化辅助函数
// makeSliceWithCapacity 创建带预分配容量的切片，减少内存重新分配
func makeSliceWithCapacity[T any](capacity int) []T {
	return make([]T, 0, capacity)
}

// 性能统计结构体
type PerformanceStats struct {
	PortScans        int64     `json:"port_scans"`         // 端口扫描次数
	ProcessScans     int64     `json:"process_scans"`      // 进程扫描次数
	CacheHits        int64     `json:"cache_hits"`         // 缓存命中次数
	CacheMisses      int64     `json:"cache_misses"`       // 缓存未命中次数
	PanicRecoveries  int64     `json:"panic_recoveries"`   // panic恢复次数
	LastScanTime     time.Time `json:"last_scan_time"`     // 最后扫描时间
	AverageScanTime  float64   `json:"average_scan_time"`  // 平均扫描时间(秒)
	CacheSize        int       `json:"cache_size"`         // 当前缓存大小
	MemoryUsage      int64     `json:"memory_usage"`       // 内存使用量(字节)
}

// 全局性能统计
var performanceStats = struct {
	sync.RWMutex
	stats PerformanceStats
}{
	stats: PerformanceStats{},
}

// 更新性能统计
func updatePerformanceStats(operation string, duration time.Duration) {
	performanceStats.Lock()
	defer performanceStats.Unlock()

	switch operation {
	case OpPortScan:
		performanceStats.stats.PortScans++
	case OpProcessScan:
		performanceStats.stats.ProcessScans++
	case OpCacheHit:
		performanceStats.stats.CacheHits++
	case OpCacheMiss:
		performanceStats.stats.CacheMisses++
	case OpPanicRecovery:
		performanceStats.stats.PanicRecoveries++
	}

	performanceStats.stats.LastScanTime = time.Now()
	if duration > 0 {
		// 简单的移动平均计算
		if performanceStats.stats.AverageScanTime == 0 {
			performanceStats.stats.AverageScanTime = duration.Seconds()
		} else {
			performanceStats.stats.AverageScanTime = (performanceStats.stats.AverageScanTime*0.9 + duration.Seconds()*0.1)
		}
	}
}

// 获取性能统计
func GetPerformanceStats() PerformanceStats {
	// 获取内存使用量（简化计算）
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// 获取性能统计
	performanceStats.RLock()
	defer performanceStats.RUnlock()

	stats := performanceStats.stats
	stats.MemoryUsage = int64(memStats.Alloc)

	// 注意：缓存大小计算可能不准确，因为访问多个缓存时没有加锁
	// 但这避免了锁嵌套问题，对于监控目的来说是可接受的
	stats.CacheSize = 0 // 暂时设为0，避免数据不一致

	return stats
}

// 错误恢复辅助函数
// recoverFromPanic 从panic中恢复并记录错误信息
func recoverFromPanic(operation string, pid int) {
	if r := recover(); r != nil {
		log.Printf("%s %s panic恢复: pid=%d, error=%v", LogPrefix, operation, pid, r)

		// 更新性能统计（在锁外执行，避免锁嵌套）
		go func() {
			updatePerformanceStats(OpPanicRecovery, 0)
		}()

		// 根据操作类型设置相应的错误状态
		switch operation {
		case "TCP检测":
			// 设置端口状态为未知，响应时间为0
			portStatusCache.RWMutex.Lock()
			portStatusCache.Status[pid] = -1
			portStatusCache.ResponseTime[pid] = 0
			portStatusCache.LastCheck[pid] = time.Now()
			portStatusCache.RWMutex.Unlock()
		case "进程检测":
			// 设置进程状态为死亡
			key := getPidKey(pid)
			processAliveCache.RWMutex.Lock()
			processAliveCache.Status[key] = 0
			processAliveCache.LastCheck[key] = time.Now()
			processAliveCache.RWMutex.Unlock()
		case "进程状态检测":
			// 设置进程详细状态为0（进程挂了）
			processDetailedStatusCache.Lock()
			// 创建一个全0的默认状态，表示进程挂了
			defaultStatus := &ProcessDetailedStatus{
				CPUPercent:     0,
				MinFaultsPerS:  0,
				MajFaultsPerS:  0,
				VMRSS:          0,
				VMSize:         0,
				MemPercent:     0,
				KBReadPerS:     0,
				KBWritePerS:    0,
				Threads:        0,
				Voluntary:      0,
				NonVoluntary:   0,
				LastUpdate:     time.Now(),
				LastUtime:      0,
				LastStime:      0,
				LastMinflt:     0,
				LastMajflt:     0,
				LastReadBytes:  0,
				LastWriteBytes: 0,
			}
			processDetailedStatusCache.cache[pid] = defaultStatus
			processDetailedStatusCache.lastCheck[pid] = time.Now()
			processDetailedStatusCache.Unlock()
		}
	}
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
		// 没有历史记录，释放读锁
		portStatusCache.RWMutex.RUnlock()

		// 加入TCP异步检测队列
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

// 带缓存的TCP端口响应时间检测（完全异步化，避免阻塞指标暴露）
func getPortResponseTime(port int) float64 {
	portStatusCache.RWMutex.RLock()
	now := time.Now()
	t, ok := portStatusCache.LastCheck[port]
	if !ok || now.Sub(t) > portStatusInterval {
		// 先获取历史响应时间，避免死锁
		var lastRespTime float64
		var hasHistory bool
		if lastRespTime, hasHistory = portStatusCache.ResponseTime[port]; hasHistory {
			portStatusCache.RWMutex.RUnlock()

			// 缓存过期，加入TCP异步检测队列
			tcpDetectionQueue.Lock()
			tcpDetectionQueue.ports[port] = true
			tcpDetectionQueue.Unlock()

			// 使用上次检测结果作为临时值
			return lastRespTime
		}
		// 没有历史记录，释放读锁
		portStatusCache.RWMutex.RUnlock()

		// 加入TCP异步检测队列
		tcpDetectionQueue.Lock()
		tcpDetectionQueue.ports[port] = true
		tcpDetectionQueue.Unlock()

		// 不暴露指标，等待异步检测完成
		return -1 // 使用-1表示暂时不暴露指标
	}
	respTime := portStatusCache.ResponseTime[port]
	status := portStatusCache.Status[port]
	portStatusCache.RWMutex.RUnlock()

	// 如果端口状态为死亡(0)或未知(-1)，响应时间设为0
	if status <= 0 {
		return 0
	}

	return respTime
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
	// 清理TCP检测队列（锁内仅做内存操作）
	tcpDetectionQueue.Lock()
	for port := range tcpDetectionQueue.ports {
		if !activePorts[port] {
			delete(tcpDetectionQueue.ports, port)
		}
	}
	tcpDetectionQueue.Unlock()

	// 进程检测队列：先快照后计算，再回写删除，避免锁内IO
	processDetectionQueue.Lock()
	pidSnapshot := make([]int, 0, len(processDetectionQueue.pids))
	for pid := range processDetectionQueue.pids {
		pidSnapshot = append(pidSnapshot, pid)
	}
	processDetectionQueue.Unlock()

	// 计算需要删除的PID（锁外，允许触发 getPidKey 的磁盘读取）
	pidsToDelete := makeSliceWithCapacity[int](len(pidSnapshot))
	for _, pid := range pidSnapshot {
		key := getPidKey(pid)
		if !activePidKeys[key] {
			pidsToDelete = append(pidsToDelete, pid)
		}
	}
	// 回写删除
	if len(pidsToDelete) > 0 {
		processDetectionQueue.Lock()
		for _, pid := range pidsToDelete {
			delete(processDetectionQueue.pids, pid)
		}
		processDetectionQueue.Unlock()
	}

	// 进程状态检测队列：同样采用快照+锁外判断（包含 isProcessValid）
	processStatusDetectionQueue.Lock()
	statusPidSnapshot := make([]int, 0, len(processStatusDetectionQueue.pids))
	for pid := range processStatusDetectionQueue.pids {
		statusPidSnapshot = append(statusPidSnapshot, pid)
	}
	processStatusDetectionQueue.Unlock()

	statusPidsToDelete := makeSliceWithCapacity[int](len(statusPidSnapshot))
	for _, pid := range statusPidSnapshot {
		key := getPidKey(pid)
		if !activePidKeys[key] || !isProcessValid(pid) {
			statusPidsToDelete = append(statusPidsToDelete, pid)
		}
	}
	if len(statusPidsToDelete) > 0 {
		processStatusDetectionQueue.Lock()
		for _, pid := range statusPidsToDelete {
			delete(processStatusDetectionQueue.pids, pid)
		}
		processStatusDetectionQueue.Unlock()
	}
}

// 清理进程相关缓存（专门用于进程PID缓存清理）
func cleanProcessCaches(activePidKeys map[string]bool) {
	// 清理进程存活缓存
	processAliveCache.RWMutex.Lock()
	for key := range processAliveCache.Status {
		if !activePidKeys[key] {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
		}
	}
	processAliveCache.RWMutex.Unlock()

	// 获取进程启动时间缓存的快照，避免锁嵌套
	pidStartTimeCache.RLock()
	pidSnapshot := make(map[int]string)
	for pid, startTime := range pidStartTimeCache.cache {
		pidSnapshot[pid] = startTime
	}
	pidStartTimeCache.RUnlock()

	// 计算需要删除的PID（锁外操作）
	pidsToDelete := makeSliceWithCapacity[int](len(pidSnapshot))
	for pid, startTime := range pidSnapshot {
		// 使用字符串工具构建PID键
		key := stringUtils.BuildPidKey(pid, startTime)

		// 双重检查：既检查活跃PID键，也检查进程是否仍然有效
		if !activePidKeys[key] || !isProcessValid(pid) {
			pidsToDelete = append(pidsToDelete, pid)
		}
	}

	// 批量删除进程启动时间缓存
	if len(pidsToDelete) > 0 {
		pidStartTimeCache.Lock()
		for _, pid := range pidsToDelete {
			delete(pidStartTimeCache.cache, pid)
		}
		pidStartTimeCache.Unlock()
	}

	// 清理进程状态缓存
	processStatusCache.Lock()
	for _, pid := range pidsToDelete {
		delete(processStatusCache.cache, pid)
		delete(processStatusCache.lastCheck, pid)
	}
	processStatusCache.Unlock()

	// 清理进程详细状态缓存
	processDetailedStatusCache.Lock()
	for _, pid := range pidsToDelete {
		delete(processDetailedStatusCache.cache, pid)
		delete(processDetailedStatusCache.lastCheck, pid)
	}
	processDetailedStatusCache.Unlock()

	// 清理进程身份缓存（基于进程名+路径，解决服务重启问题）
	processIdentityCache.Lock()
	now := time.Now()
	for key, identity := range processIdentityCache.cache {
		// 清理超过指定时间未见的进程身份
		if now.Sub(identity.LastSeen) > ProcessIdentityExpireTime {
			delete(processIdentityCache.cache, key)
		}
	}
	processIdentityCache.Unlock()
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

	// 获取进程启动时间缓存的快照，避免锁嵌套
	pidStartTimeCache.RLock()
	pidSnapshot := make(map[int]string)
	for pid, startTime := range pidStartTimeCache.cache {
		pidSnapshot[pid] = startTime
	}
	pidStartTimeCache.RUnlock()

	// 计算需要删除的PID（锁外操作）
	pidsToDelete := makeSliceWithCapacity[int](len(pidSnapshot))
	for pid, startTime := range pidSnapshot {
		// 使用字符串工具构建PID键
		key := stringUtils.BuildPidKey(pid, startTime)

		if !activePidKeys[key] {
			pidsToDelete = append(pidsToDelete, pid)
		}
	}

	// 批量删除进程启动时间缓存
	if len(pidsToDelete) > 0 {
		pidStartTimeCache.Lock()
		for _, pid := range pidsToDelete {
			delete(pidStartTimeCache.cache, pid)
		}
		pidStartTimeCache.Unlock()
	}

	// 清理进程状态缓存
	processStatusCache.Lock()
	for _, pid := range pidsToDelete {
		delete(processStatusCache.cache, pid)
		delete(processStatusCache.lastCheck, pid)
	}
	processStatusCache.Unlock()

	// 清理进程详细状态缓存
	processDetailedStatusCache.Lock()
	for _, pid := range pidsToDelete {
		delete(processDetailedStatusCache.cache, pid)
		delete(processDetailedStatusCache.lastCheck, pid)
	}
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
		// 没有历史记录，释放读锁
		processAliveCache.RWMutex.RUnlock()

		// 加入进程异步检测队列
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
		// 使用字符串工具构建PID键
		return stringUtils.BuildPidKey(pid, startTime)
	}
	pidStartTimeCache.RUnlock()

	startTime := getProcessStartTime(pid)
	pidStartTimeCache.Lock()
	pidStartTimeCache.cache[pid] = startTime
	pidStartTimeCache.Unlock()

	// 使用字符串工具构建PID键
	return stringUtils.BuildPidKey(pid, startTime)
}

// 字符串缓存结构体，包含缓存映射和访问时间戳
// 用于实现基于时间戳的缓存清理策略，避免清理最近使用的缓存项
var stringCache = struct {
	sync.RWMutex
	cache map[string]string        // 字符串缓存映射，key为原始字符串，value为缓存值
	accessTime map[string]time.Time // 访问时间映射，key为原始字符串，value为最后访问时间
}{
	cache: make(map[string]string),
	accessTime: make(map[string]time.Time),
}

// getProcessIdentityKey 生成进程身份key（基于进程名+路径）- 使用缓存
// 该函数使用带时间戳的缓存机制，记录每次访问时间
// 用于后续的基于时间戳的缓存清理策略
func getProcessIdentityKey(processName, exePath string) string {
	// 使用字符串工具构建进程键
	key := stringUtils.BuildProcessKey(processName, exePath)

	stringCache.Lock()
	defer stringCache.Unlock()

	if cached, exists := stringCache.cache[key]; exists {
		// 更新访问时间戳
		stringCache.accessTime[key] = time.Now()
		updatePerformanceStats(OpCacheHit, 0)
		return cached
	}

	// 缓存未命中，创建新字符串并缓存
	stringCache.cache[key] = key
	stringCache.accessTime[key] = time.Now()
	updatePerformanceStats(OpCacheMiss, 0)
	return key
}

// selectBestPidForIdentity 智能选择最佳PID用于身份管理
func selectBestPidForIdentity(groupInfos []PortProcessInfo) int {
	if len(groupInfos) == 0 {
		return 0
	}

	// 策略1：优先选择存活的进程（使用更快的checkProcess而不是getDetailedProcessStatus）
	for _, info := range groupInfos {
		if checkProcess(info.Pid) == 1 {
			return info.Pid // 找到第一个存活的进程
		}
	}

	// 策略2：如果没有存活进程，选择第一个进程（可能是刚重启的）
	return groupInfos[0].Pid
}

// updateProcessIdentity 更新进程身份信息（解决服务重启问题）
func updateProcessIdentity(processName, exePath string, pid int) ProcessIdentity {
	key := getProcessIdentityKey(processName, exePath)
	now := time.Now()

	processIdentityCache.RLock()
	identity, exists := processIdentityCache.cache[key]
	processIdentityCache.RUnlock()

	if !exists {
		// 新进程，创建身份信息
		identity = ProcessIdentity{
			ProcessName: processName,
			ExePath:     exePath,
			CurrentPid:  pid,
			LastSeen:    now,
			IsAlive:     true,
		}
	} else {
		// 更新现有进程信息
		identity.CurrentPid = pid
		identity.LastSeen = now
		identity.IsAlive = true
	}

	processIdentityCache.Lock()
	processIdentityCache.cache[key] = identity
	processIdentityCache.Unlock()

	return identity
}

// getProcessIdentityStatus 获取进程身份状态（解决服务重启问题）
func getProcessIdentityStatus(processName, exePath string) (int, string) {
	key := getProcessIdentityKey(processName, exePath)

	processIdentityCache.RLock()
	identity, exists := processIdentityCache.cache[key]
	processIdentityCache.RUnlock()

	if !exists {
		// 未找到进程身份，尝试直接查找当前进程
		alivePid := findAliveProcessInGroup(processName, exePath)
		if alivePid > 0 {
			// 找到存活进程，创建新的身份信息
			processIdentityCache.Lock()
			processIdentityCache.cache[key] = ProcessIdentity{
				ProcessName: processName,
				ExePath:     exePath,
				CurrentPid:  alivePid,
				LastSeen:    time.Now(),
				IsAlive:     true,
			}
			processIdentityCache.Unlock()
			// 触发端口-进程映射的强制重扫，尽快更新分组里的PID
			forceRescanPortProcess()
			return 1, "R" // 进程存活（新发现）
		}
		return -1, "X" // 未找到进程
	}

	// 检查进程是否仍然存活
	if identity.IsAlive {
		// 检查当前PID是否仍然有效
		status := getDetailedProcessStatus(identity.CurrentPid)
		if status.Alive == 1 {
			return 1, status.State // 进程存活
		} else {
			// 当前PID已死，尝试查找同组其他存活进程
			alivePid := findAliveProcessInGroup(processName, exePath)
			if alivePid > 0 {
				// 找到其他存活进程，更新身份信息
				processIdentityCache.Lock()
				if updatedIdentity, stillExists := processIdentityCache.cache[key]; stillExists {
					updatedIdentity.CurrentPid = alivePid
					updatedIdentity.IsAlive = true
					updatedIdentity.LastSeen = time.Now()
					processIdentityCache.cache[key] = updatedIdentity
				}
				processIdentityCache.Unlock()
				// 强制重扫端口-进程映射，避免累计仍使用旧PID
				forceRescanPortProcess()
				return 1, "R" // 进程存活（使用其他PID）
			} else {
				// 所有进程都已死，标记为非存活
				processIdentityCache.Lock()
				if updatedIdentity, stillExists := processIdentityCache.cache[key]; stillExists {
					updatedIdentity.IsAlive = false
					processIdentityCache.cache[key] = updatedIdentity
				}
				processIdentityCache.Unlock()
				return 0, status.State // 进程死亡
			}
		}
	}

	// 进程已标记为死亡，但需要重新检查是否真的死亡
	alivePid := findAliveProcessInGroup(processName, exePath)
	if alivePid > 0 {
		// 发现进程重新启动，更新身份信息
		processIdentityCache.Lock()
		if updatedIdentity, stillExists := processIdentityCache.cache[key]; stillExists {
			updatedIdentity.CurrentPid = alivePid
			updatedIdentity.IsAlive = true
			updatedIdentity.LastSeen = time.Now()
			processIdentityCache.cache[key] = updatedIdentity
		}
		processIdentityCache.Unlock()
		// 触发强制重扫，以便聚合指标立刻使用新PID
		forceRescanPortProcess()
		return 1, "R" // 进程存活（重新启动）
	}

	return 0, "X" // 进程已标记为死亡
}

// findAliveProcessInGroup 在进程组中查找存活的进程
// 优化版本：使用缓存减少文件系统访问
func findAliveProcessInGroup(processName, exePath string) int {
	// 首先尝试从当前端口进程信息中查找，避免全量扫描
	infos := getPortProcessInfo()
	for _, info := range infos {
		if info.ProcessName == processName && info.ExePath == exePath {
			// 检查进程是否仍然存活
			if checkProcess(info.Pid) == 1 {
				return info.Pid
			}
		}
	}

	// 如果端口信息中没有找到，再进行全量扫描
	procDir, err := os.Open(procPath("/proc"))
	if err != nil {
		log.Printf("[simple_port_process_collector] 无法打开/proc目录: %v", err)
		return 0
	}
	defer func() {
		if closeErr := procDir.Close(); closeErr != nil {
			log.Printf("[simple_port_process_collector] 无法关闭/proc目录: %v", closeErr)
		}
	}()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		log.Printf("[simple_port_process_collector] 无法读取/proc目录: %v", err)
		return 0
	}

	// 查找同组中的存活进程
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// 检查进程是否存活
		status := checkProcess(pid)
		if status != 1 {
			continue // 进程不存活，跳过
		}

		// 检查进程名和路径是否匹配
		currentExePath := getProcessExe(pid)
		if currentExePath == exePath {
			return pid
		}
	}

	return 0 // 没有找到存活的进程
}

// getProcessStartTime 获取进程启动时间（/proc/<pid>/stat 第22字段）
func getProcessStartTime(pid int) string {
    fields, err := getProcStatFields(pid)
    if err == nil && len(fields) >= 22 {
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
    fields, err := getProcStatFields(pid)
    if err != nil {
		status := ProcessStatus{Pid: pid, Alive: 0, State: "X"}
		// 缓存失败结果，避免频繁重试
		processStatusCache.Lock()
		processStatusCache.cache[pid] = status
		processStatusCache.lastCheck[pid] = now
		processStatusCache.Unlock()
		return status
	}
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
	if state == ProcessStateZombie {
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
				pids := makeSliceWithCapacity[int](len(processStatusDetectionQueue.pids))
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
						defer recoverFromPanic("进程状态检测", p)

						// 在检测前先验证PID是否仍然有效，避免处理已死亡的进程
						if !isProcessValid(p) {
							// 进程已死亡，从缓存中清理
							processDetailedStatusCache.Lock()
							delete(processDetailedStatusCache.cache, p)
							delete(processDetailedStatusCache.lastCheck, p)
							processDetailedStatusCache.Unlock()
							return
						}

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

// startMemoryCleanupWorker 内存清理工作器
// 该函数启动一个后台goroutine，定期清理过期的缓存数据
// 防止内存无限增长，提高系统稳定性
func startMemoryCleanupWorker() {
	go func() {
		// 创建定时器，按照配置的间隔定期清理缓存
		ticker := time.NewTicker(DefaultMemoryCleanupInterval)
		defer ticker.Stop() // 确保定时器被正确关闭

		// 无限循环处理清理任务
		for {
			select {
			case <-memoryCleanupQueue.done:
				// 收到关闭信号，退出工作器
				return
			case <-ticker.C:
				// 定时器触发，执行缓存清理
				cleanupExpiredCaches()
			}
		}
	}()
}

// cleanupExpiredCaches 清理过期的缓存数据
// 该函数定期清理各种缓存中的过期项，防止内存无限增长
// 包括字符串缓存、进程身份缓存、端口状态缓存和进程存活缓存
func cleanupExpiredCaches() {
	now := time.Now()

	// 清理字符串缓存（基于时间戳的清理策略）
	// 当缓存大小超过限制时，清理最久未访问的缓存项
	stringCache.Lock()
	if len(stringCache.cache) > MaxStringCacheSize {
		// 基于时间戳清理最久未访问的缓存项
		// 收集所有缓存项及其访问时间
		type cacheItem struct {
			key        string        // 缓存键
			accessTime time.Time     // 最后访问时间
		}

		items := make([]cacheItem, 0, len(stringCache.accessTime))
		for key, accessTime := range stringCache.accessTime {
			items = append(items, cacheItem{key: key, accessTime: accessTime})
		}

		// 按访问时间排序（最久未访问的在前）
		// 使用Go标准库的sort包，时间复杂度O(n log n)
		sort.Slice(items, func(i, j int) bool {
			return items[i].accessTime.Before(items[j].accessTime)
		})

		// 清理最久未访问的缓存项
		cleanupCount := StringCacheCleanupSize
		if cleanupCount > len(items) {
			cleanupCount = len(items)
		}

		for i := 0; i < cleanupCount; i++ {
			key := items[i].key
			delete(stringCache.cache, key)
			delete(stringCache.accessTime, key)
		}
	}
	stringCache.Unlock()

	// 清理进程身份缓存中的过期项
	// 清理超过指定时间未见的进程身份，防止缓存无限增长
	processIdentityCache.Lock()
	for key, identity := range processIdentityCache.cache {
		// 清理超过指定时间未见的进程身份
		if now.Sub(identity.LastSeen) > ProcessIdentityCleanupTime {
			delete(processIdentityCache.cache, key)
		}
	}
	processIdentityCache.Unlock()

	// 清理端口状态缓存中的过期项
	// 清理超过指定时间未检查的端口状态，释放内存空间
	portStatusCache.RWMutex.Lock()
	for port, lastCheck := range portStatusCache.LastCheck {
		// 清理超过指定时间未检查的端口状态
		if now.Sub(lastCheck) > PortStatusExpireTime {
			delete(portStatusCache.Status, port)
			delete(portStatusCache.LastCheck, port)
		}
	}
	portStatusCache.RWMutex.Unlock()

	// 清理进程存活缓存中的过期项
	// 清理超过指定时间未检查的进程状态，防止缓存泄漏
	processAliveCache.RWMutex.Lock()
	for key, lastCheck := range processAliveCache.LastCheck {
		// 清理超过指定时间未检查的进程状态
		if now.Sub(lastCheck) > ProcessAliveExpireTime {
			delete(processAliveCache.Status, key)
			delete(processAliveCache.LastCheck, key)
		}
	}
	processAliveCache.RWMutex.Unlock()
}

// 获取进程详细状态数据（CPU、内存、IO等）
func getProcessDetailedStatusData(pid int) *ProcessDetailedStatus {
	now := time.Now()

	// 获取基础状态信息
	statusData, err := getProcessStatusData(pid)
	if err != nil {
		log.Printf("%s 获取进程状态失败: pid=%d, error=%v", LogPrefix, pid, err)
		// 返回默认状态而不是静默忽略错误
		return &ProcessDetailedStatus{
			CPUPercent:     0,
			MinFaultsPerS:  0,
			MajFaultsPerS:  0,
			VMRSS:          0,
			VMSize:         0,
			MemPercent:     0,
			KBReadPerS:     0,
			KBWritePerS:    0,
			Threads:        0,
			Voluntary:      0,
			NonVoluntary:   0,
			LastUpdate:     now,
			LastUtime:      0,
			LastStime:      0,
			LastMinflt:     0,
			LastMajflt:     0,
			LastReadBytes:  0,
			LastWriteBytes: 0,
		}
	}

	// 获取CPU和缺页信息
	utime, stime, minflt, majflt, err := getProcessCPUAndFaults(pid)
	if err != nil {
		log.Printf("%s 获取进程CPU信息失败: pid=%d, error=%v", LogPrefix, pid, err)
		// 容错：CPU读取失败则按0处理，避免中断其余指标
		utime, stime, minflt, majflt = 0, 0, 0, 0
	}

	// 获取IO数据
	readBytes, writeBytes, err := getProcessIOStats(pid)
	if err != nil {
		log.Printf("%s 获取进程IO信息失败: pid=%d, error=%v", LogPrefix, pid, err)
		// 容错：很多系统对 /proc/<pid>/io 有权限限制，读不到时置0但不影响其他指标
		readBytes, writeBytes = 0, 0
	}

	// 获取内存总量
	memTotal, err := getSystemMemTotal()
	if err != nil {
		log.Printf("%s 获取系统内存总量失败: %v", LogPrefix, err)
		memTotal = DefaultMemTotalKB // 使用默认值，防止除零
	}

	// 计算增量值
	processDetailedStatusCache.RLock()
	cache, exists := processDetailedStatusCache.cache[pid]
	processDetailedStatusCache.RUnlock()

	var cpuPercent, minFaultsPerS, majFaultsPerS, kbReadPerS, kbWritePerS float64

	if exists && cache != nil {
		timeDiff := now.Sub(cache.LastUpdate).Seconds()
		if timeDiff > 0 && ticksPerSecond > 0 {
			// CPU使用率计算：基于累计CPU时间差值（utime/stime为ticks），换算为秒再转百分比
			totalCPUDiff := (utime - cache.LastUtime) + (stime - cache.LastStime)
			// 单核百分比： (ticksDiff / ticksPerSecond) / interval * 100
			cpuPercent = (totalCPUDiff / ticksPerSecond) / timeDiff * 100

			// 缺页错误速率计算
			minFaultsPerS = (minflt - cache.LastMinflt) / timeDiff
			majFaultsPerS = (majflt - cache.LastMajflt) / timeDiff

			// IO速率计算
			kbReadPerS = (readBytes - cache.LastReadBytes) / 1024 / timeDiff
			kbWritePerS = (writeBytes - cache.LastWriteBytes) / 1024 / timeDiff
		}
	}

	// 静态指标（优先从 /proc/[pid]/status 读取）
	vmrss := parseProcessStatusValue(statusData[StatusFieldVmrss])
	vmsize := parseProcessStatusValue(statusData[StatusFieldVmsize])
	threads := parseProcessStatusValue(statusData[StatusFieldThreads])

	// 兜底：若从 status 读取失败或值为 0，尝试从 /proc/[pid]/stat 计算
	if vmrss == 0 || vmsize == 0 || threads == 0 {
		th, rssKB, vsizeKB, err := getProcessStatFallback(pid)
		if err == nil {
			if threads == 0 {
				threads = th
			}
			if vmrss == 0 {
				vmrss = rssKB
			}
			if vmsize == 0 {
				vmsize = vsizeKB
			}
		}
	}
	voluntary := parseProcessStatusValue(statusData[StatusFieldVoluntaryCtxtSwitches])
	nonvoluntary := parseProcessStatusValue(statusData[StatusFieldNonvoluntaryCtxtSwitches])

	// 安全计算内存百分比，防止除零错误
	var memPercent float64
	if memTotal > 0 {
		memPercent = vmrss / memTotal * 100
	} else {
		// 如果内存总量为0或无效，使用默认值计算
		memPercent = vmrss / DefaultMemTotalKB * 100
	}

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

// 从 /proc/[pid]/stat 兜底获取线程数与RSS/VSize（以KB为单位）
func getProcessStatFallback(pid int) (float64, float64, float64, error) {
    fields, err := getProcStatFields(pid)
    if err != nil {
        return 0, 0, 0, err
    }
    // 需要至少到 rss 字段（1-based 24 => 0-based 23）
    if len(fields) < 24 {
        return 0, 0, 0, fmt.Errorf("invalid stat format: insufficient fields")
    }

    var (
        threadsVal float64
        rssPages   float64
        vsizeBytes float64
    )

    // 安全解析字段，处理解析错误
    if len(fields) > 19 {
        if v, err := strconv.ParseFloat(fields[19], 64); err == nil { // 1-based 20 num_threads
            threadsVal = v
        }
    }
    if len(fields) > 23 {
        if v, err := strconv.ParseFloat(fields[23], 64); err == nil { // 1-based 24 rss (pages)
            rssPages = v
        }
    }
    if len(fields) > 22 {
        if v, err := strconv.ParseFloat(fields[22], 64); err == nil { // 1-based 23 vsize (bytes)
            vsizeBytes = v
        }
    }

    pageSizeKB := float64(os.Getpagesize()) / 1024.0
    rssKB := rssPages * pageSizeKB
    vsizeKB := vsizeBytes / 1024.0

    return threadsVal, rssKB, vsizeKB, nil
}

// 从/proc/[pid]/status获取状态信息
func getProcessStatusData(pid int) (map[string]string, error) {
	statusPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcStatusSuffix)
	file, err := os.Open(procPath(statusPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open status file for pid %d: %w", pid, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			log.Printf("%s failed to close status file for pid %d: %v", LogPrefix, pid, closeErr)
		}
	}()

	data := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ColonSeparator, 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		data[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan status file for pid %d: %w", pid, err)
	}

	return data, nil
}

// 从/proc/[pid]/stat获取CPU和缺页信息
func getProcessCPUAndFaults(pid int) (float64, float64, float64, float64, error) {
    fields, err := getProcStatFields(pid)
    if err != nil {
        return 0, 0, 0, 0, err
    }
    if len(fields) < 24 {
		return 0, 0, 0, 0, fmt.Errorf("invalid stat format: insufficient fields")
	}

	// 安全解析字段，处理解析错误
	var utime, stime, minflt, majflt float64
	if len(fields) > 13 {
		if v, err := strconv.ParseFloat(fields[13], 64); err == nil {
			utime = v
		}
	}
	if len(fields) > 14 {
		if v, err := strconv.ParseFloat(fields[14], 64); err == nil {
			stime = v
		}
	}
	if len(fields) > 9 {
		if v, err := strconv.ParseFloat(fields[9], 64); err == nil {
			minflt = v
		}
	}
	if len(fields) > 11 {
		if v, err := strconv.ParseFloat(fields[11], 64); err == nil {
			majflt = v
		}
	}

	// 返回原始值，不除以100，在CPU计算时再处理
	return utime, stime, minflt, majflt, nil
}

// 从/proc/[pid]/io获取IO数据
func getProcessIOStats(pid int) (float64, float64, error) {
	ioPath := stringUtils.BuildPath(ProcPathPrefix, strconv.Itoa(pid), ProcIOSuffix)
	content, err := os.ReadFile(procPath(ioPath))
	if err != nil {
		return 0, 0, err
	}

	var readBytes, writeBytes float64
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, IOFieldReadBytes) {
			fmt.Sscanf(line, "%s %f", &readBytes)
		}
		if strings.HasPrefix(line, IOFieldWriteBytes) {
			fmt.Sscanf(line, "%s %f", &writeBytes)
		}
	}
	return readBytes, writeBytes, nil
}

// 获取系统内存总量
func getSystemMemTotal() (float64, error) {
	content, err := os.ReadFile(procPath(ProcMemInfoPath))
	if err != nil {
		return DefaultMemTotalKB, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), MemInfoFieldMemTotal) {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				memTotal, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					return DefaultMemTotalKB, fmt.Errorf("failed to parse MemTotal: %w", err)
				}
				// 防止除零错误，确保内存总量至少为默认值
				if memTotal <= 0 {
					return DefaultMemTotalKB, fmt.Errorf("invalid MemTotal value: %f", memTotal)
				}
				return memTotal, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return DefaultMemTotalKB, fmt.Errorf("failed to scan /proc/meminfo: %w", err)
	}

	return DefaultMemTotalKB, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// 辅助函数：转换状态值，支持带单位（如 '25592 kB'）
func parseProcessStatusValue(value string) float64 {
	if value == EmptyString {
		return 0
	}
	// 只取第一个数字部分
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
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
		// 没有历史记录，释放读锁
		processDetailedStatusCache.RUnlock()

		// 没有历史记录，使用原子操作避免竞态条件
		processDetailedStatusCache.Lock()
		// 双重检查，避免重复初始化
		if _, exists := processDetailedStatusCache.cache[pid]; !exists {
			processDetailedStatusCache.Unlock()

			// 锁外执行重IO
			status := getProcessDetailedStatusData(pid)

			// 重新加锁并检查是否已被其他goroutine初始化
			processDetailedStatusCache.Lock()
			if _, exists := processDetailedStatusCache.cache[pid]; !exists {
				if status != nil {
					processDetailedStatusCache.cache[pid] = status
					processDetailedStatusCache.lastCheck[pid] = now
				} else {
					// 如果获取失败，创建一个默认的状态对象，避免返回nil
					defaultStatus := &ProcessDetailedStatus{
						CPUPercent:     0,
						MinFaultsPerS:  0,
						MajFaultsPerS:  0,
						VMRSS:          0,
						VMSize:         0,
						MemPercent:     0,
						KBReadPerS:     0,
						KBWritePerS:    0,
						Threads:        0,
						Voluntary:      0,
						NonVoluntary:   0,
						LastUpdate:     now,
						LastUtime:      0,
						LastStime:      0,
						LastMinflt:     0,
						LastMajflt:     0,
						LastReadBytes:  0,
						LastWriteBytes: 0,
					}
					processDetailedStatusCache.cache[pid] = defaultStatus
					processDetailedStatusCache.lastCheck[pid] = now
				}
			}
			processDetailedStatusCache.Unlock()
		} else {
			// 如果缓存已存在，释放锁
			processDetailedStatusCache.Unlock()
		}

		// 返回刚获取的数据
		processDetailedStatusCache.RLock()
		status := processDetailedStatusCache.cache[pid]
		processDetailedStatusCache.RUnlock()
		return status
	}
	status := processDetailedStatusCache.cache[pid]
	processDetailedStatusCache.RUnlock()
	return status
}
