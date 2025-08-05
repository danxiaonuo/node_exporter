#!/bin/bash

echo "=== HTTP检测调试脚本 ==="
echo "时间: $(date)"
echo

echo "1. 检查node_exporter是否运行:"
if pgrep -f node_exporter > /dev/null; then
    echo "✓ node_exporter 正在运行"
    ps aux | grep node_exporter | grep -v grep
else
    echo "✗ node_exporter 未运行"
    exit 1
fi
echo

echo "2. 检查端口发现情况:"
echo "TCP端口列表:"
ss -tlnp | grep LISTEN | head -10
echo

echo "3. 检查node_exporter日志中的HTTP相关信息:"
echo "最近的日志:"
journalctl -u node_exporter --since "5 minutes ago" | grep -i "http\|port_process" | tail -20
echo

echo "4. 检查metrics中的端口指标:"
echo "TCP端口指标数量:"
curl -s localhost:9100/metrics | grep node_tcp_port_alive | wc -l
echo "HTTP端口指标数量:"
curl -s localhost:9100/metrics | grep node_http_port_alive | wc -l
echo

echo "5. 手动测试常见HTTP端口:"
for port in 80 443 8080 8000 3000 5000 8008 8888 9000 9090; do
    if ss -tlnp | grep ":$port " > /dev/null; then
        echo "端口 $port 正在监听，测试HTTP连接:"
        timeout 2 curl -I http://localhost:$port 2>/dev/null | head -1 || echo "  HTTP连接失败"
    fi
done
echo

echo "6. 检查环境变量:"
echo "ENABLE_HTTP_DETECTION: ${ENABLE_HTTP_DETECTION:-未设置}"
echo "HTTP_DETECTION_CONCURRENCY: ${HTTP_DETECTION_CONCURRENCY:-未设置}"
echo "PORT_CHECK_TIMEOUT: ${PORT_CHECK_TIMEOUT:-未设置}"
echo

echo "7. 建议的排查步骤:"
echo "a) 重启node_exporter并观察日志:"
echo "   sudo systemctl restart node_exporter"
echo "   sudo journalctl -u node_exporter -f"
echo
echo "b) 检查是否有HTTP服务在运行:"
echo "   ss -tlnp | grep LISTEN"
echo
echo "c) 手动测试HTTP端口:"
echo "   curl -I http://localhost:80"
echo
echo "d) 如果仍然没有HTTP指标，请检查:"
echo "   - 是否有真正的HTTP服务在运行"
echo "   - 防火墙是否阻止了HTTP检测"
echo "   - 网络连接是否正常" 