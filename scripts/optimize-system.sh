#!/bin/bash

echo "=== PGW System Optimization Script ==="
echo "Optimizing system for better performance with many proxy connections..."

# Tạo thư mục cần thiết
mkdir -p /etc/security
mkdir -p /etc/systemd/system.conf.d

# Cấu hình File Descriptor Limits
echo "Configuring file descriptor limits..."
cat >> /etc/security/limits.conf << 'LIMITS'
# PGW File Descriptor Limits
pgw soft nofile 65536
pgw hard nofile 65536
root soft nofile 65536
root hard nofile 65536
* soft nofile 65536
* hard nofile 65536
LIMITS

# Cấu hình systemd global limits
cat > /etc/systemd/system.conf.d/limits.conf << 'SYSTEMD_LIMITS'
[Manager]
DefaultLimitNOFILE=65536
DefaultTasksMax=8192
SYSTEMD_LIMITS

echo "File descriptor limits configured."

# Tối ưu kernel network parameters
echo "Optimizing kernel network parameters..."
cat >> /etc/sysctl.conf << 'SYSCTL'

# PGW Network Optimizations
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.netfilter.nf_conntrack_max = 131072
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
SYSCTL

echo "Network parameters configured."

# Apply sysctl changes
echo "Applying sysctl changes..."
sysctl -p

echo "=== Optimization completed! ==="
echo "Please restart the services for changes to take effect:"
echo "systemctl daemon-reload"
echo "systemctl restart pgw-*"
