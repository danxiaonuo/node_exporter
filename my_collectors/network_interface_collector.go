package my_collectors

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// 网卡信息缓存结构体
var networkInterfaceCache = struct {
	LastScan time.Time
	Data     []NetworkInterfaceInfo
	Mutex    sync.RWMutex
}{Data: nil}

// 缓存刷新周期，默认8小时，可通过环境变量 NETWORK_INTERFACE_INTERVAL 配置
var networkInterfaceInterval = func() time.Duration {
	if v := os.Getenv("NETWORK_INTERFACE_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return 8 * time.Hour
}()

// 物理网卡信息结构体
// InterfaceName: 网卡名称
// IPAddresses: IPv4 地址列表
type NetworkInterfaceInfo struct {
	InterfaceName string
	IPAddresses   []string
}

// 获取物理网卡信息，带缓存，每8小时刷新一次
func getNetworkInterfaceInfo() []NetworkInterfaceInfo {
	networkInterfaceCache.Mutex.RLock()
	expired := time.Since(networkInterfaceCache.LastScan) > networkInterfaceInterval || networkInterfaceCache.Data == nil
	networkInterfaceCache.Mutex.RUnlock()
	if expired {
		networkInterfaceCache.Mutex.Lock()
		if time.Since(networkInterfaceCache.LastScan) > networkInterfaceInterval || networkInterfaceCache.Data == nil {
			networkInterfaceCache.Data = collectNetworkInterfaceInfo()
			networkInterfaceCache.LastScan = time.Now()
		}
		networkInterfaceCache.Mutex.Unlock()
	}
	networkInterfaceCache.Mutex.RLock()
	defer networkInterfaceCache.Mutex.RUnlock()
	return networkInterfaceCache.Data
}

// 判断是否为虚拟网卡（如 docker、veth、br-、virbr、lo 等）
func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{"docker", "veth", "br-", "virbr", "lo", "vmnet", "tap", "tun", "wlx", "enx"}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// 采集物理网卡及其 IPv4 地址
func collectNetworkInterfaceInfo() []NetworkInterfaceInfo {
	var result []NetworkInterfaceInfo
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if isVirtualInterface(iface.Name) || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ipAddresses []string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ipAddresses = append(ipAddresses, ipnet.IP.String())
			}
		}
		if len(ipAddresses) > 0 {
			result = append(result, NetworkInterfaceInfo{
				InterfaceName: iface.Name,
				IPAddresses:   ipAddresses,
			})
		}
	}
	return result
}

// 网卡信息采集器
// 每个物理网卡及其 IPv4 地址暴露为一个指标，help 用中文

type NetworkInterfaceCollector struct {
	desc *prometheus.Desc
}

func NewNetworkInterfaceCollector() *NetworkInterfaceCollector {
	return &NetworkInterfaceCollector{
		desc: prometheus.NewDesc(
			"node_network_interface_info",
			"物理网卡及其IPv4地址信息（每8小时刷新一次）",
			[]string{"interface", "ip"}, nil,
		),
	}
}

func (c *NetworkInterfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *NetworkInterfaceCollector) Collect(ch chan<- prometheus.Metric) {
	infos := getNetworkInterfaceInfo()
	for _, info := range infos {
		for _, ip := range info.IPAddresses {
			ch <- prometheus.MustNewConstMetric(
				c.desc, prometheus.GaugeValue, 1,
				info.InterfaceName, ip,
			)
		}
	}
}

// 实现 node_exporter Collector 接口的 Update 方法
func (c *NetworkInterfaceCollector) Update(ch chan<- prometheus.Metric) error {
	c.Collect(ch)
	return nil
}
