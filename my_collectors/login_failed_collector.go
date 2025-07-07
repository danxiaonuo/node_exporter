package my_collectors

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// 登录失败次数缓存结构体
var loginFailedCache = struct {
	LastScan time.Time
	Count    int
	Mutex    sync.RWMutex
}{Count: 0}

// 缓存刷新周期，默认1分钟，可通过环境变量 LOGIN_FAILED_INTERVAL 配置
var loginFailedInterval = func() time.Duration {
	if v := os.Getenv("LOGIN_FAILED_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return time.Minute
}()

// 获取登录失败次数，带缓存，每1分钟刷新一次
func getLoginFailedCount() int {
	loginFailedCache.Mutex.RLock()
	expired := time.Since(loginFailedCache.LastScan) > loginFailedInterval
	loginFailedCache.Mutex.RUnlock()
	if expired {
		loginFailedCache.Mutex.Lock()
		if time.Since(loginFailedCache.LastScan) > loginFailedInterval {
			loginFailedCache.Count = collectLoginFailedCount()
			loginFailedCache.LastScan = time.Now()
		}
		loginFailedCache.Mutex.Unlock()
	}
	loginFailedCache.Mutex.RLock()
	defer loginFailedCache.Mutex.RUnlock()
	return loginFailedCache.Count
}

// 采集登录失败次数，优先用 lastb，否则查日志
func collectLoginFailedCount() int {
	// 取最近1小时内的失败次数，防止计数过大
	now := time.Now()
	day := fmt.Sprintf("%02d", now.Day())
	hour := now.Format("15")
	// 优先尝试 lastb
	count, err := getLastbFailedAttempts(day, hour)
	if err == nil {
		return count
	}
	// 失败则查日志
	count, err = getLogFileFailedAttempts(day, hour)
	if err == nil {
		return count
	}
	return 0
}

// 使用 lastb 命令获取登录失败次数
func getLastbFailedAttempts(day, hour string) (int, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("lastb | grep '%s %s' | wc -l", day, hour))
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	countStr := strings.TrimSpace(string(output))
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// 从日志文件中获取登录失败次数
func getLogFileFailedAttempts(day, hour string) (int, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(
		"find /var/log/ -iname 'secure' -or -iname 'auth.log' -or -iname 'messages' | xargs grep '%s %s' | egrep 'Failed password' | wc -l", day, hour))
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	countStr := strings.TrimSpace(string(output))
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// 登录失败次数采集器
// help 用中文

type LoginFailedCollector struct {
	desc *prometheus.Desc
}

func NewLoginFailedCollector() *LoginFailedCollector {
	return &LoginFailedCollector{
		desc: prometheus.NewDesc(
			"node_login_failed_count",
			"主机登录失败次数（每分钟刷新一次）",
			nil, nil,
		),
	}
}

func (c *LoginFailedCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *LoginFailedCollector) Collect(ch chan<- prometheus.Metric) {
	count := getLoginFailedCount()
	ch <- prometheus.MustNewConstMetric(
		c.desc, prometheus.GaugeValue, float64(count),
	)
}

// 实现 node_exporter Collector 接口的 Update 方法
func (c *LoginFailedCollector) Update(ch chan<- prometheus.Metric) error {
	c.Collect(ch)
	return nil
}
