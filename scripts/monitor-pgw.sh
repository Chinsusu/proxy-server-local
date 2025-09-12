#!/bin/bash

echo "=== PGW System Monitor ==="
echo "Monitoring PGW system resources and performance"
echo "Date: $(date)"
echo "==============================================="

# System overview
echo
echo "=== SYSTEM OVERVIEW ==="
echo "Uptime: $(uptime | awk '{print $3,$4}' | sed 's/,//')"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2 " (" $3/$2*100 "% used)"}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $3"/"$2 " (" $5 " used)"}')"

# PGW Services Status
echo
echo "=== PGW SERVICES ==="
for service in pgw-api pgw-agent pgw-ui pgw-health; do
    status=$(systemctl is-active $service)
    uptime_info=$(systemctl show $service --property=ActiveEnterTimestamp --value)
    echo "$service: $status ($uptime_info)"
done

echo
echo "=== PGW FORWARDERS ==="
fwd_count=$(systemctl list-units --state=running 'pgw-fwd@*' --no-legend | wc -l)
echo "Active forwarders: $fwd_count"

# Resource usage per service
echo
echo "=== RESOURCE USAGE ==="
ps aux | grep pgw | grep -v grep | while read line; do
    echo "$line"
done | awk '{print $11 ": CPU " $3 "%, MEM " $4 "%, RSS " $6 "KB"}'

# Network connections
echo
echo "=== NETWORK CONNECTIONS ==="
pgw_connections=$(lsof -i -P | grep pgw | wc -l)
echo "Total PGW connections: $pgw_connections"

tcp_count=$(ss -tuln | grep :150 | wc -l)
echo "PGW forwarder ports listening: $tcp_count"

# File descriptors
echo
echo "=== FILE DESCRIPTOR USAGE ==="
for pid in $(pgrep pgw); do
    process_name=$(ps -p $pid -o comm= 2>/dev/null)
    fd_count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
    echo "$process_name (PID $pid): $fd_count FDs"
done

# System limits
echo
echo "=== SYSTEM LIMITS ==="
echo "File descriptor limit (soft): $(ulimit -Sn)"
echo "File descriptor limit (hard): $(ulimit -Hn)"
echo "Process limit: $(ulimit -u)"

# nftables rules count
echo
echo "=== NFTABLES STATUS ==="
nat_rules=$(nft list table ip pgw 2>/dev/null | grep "redirect to" | wc -l)
filter_rules=$(nft list table inet pgw_filter 2>/dev/null | grep "ip saddr" | wc -l)
echo "NAT rules: $nat_rules"
echo "Filter rules: $filter_rules"

echo
echo "=== END REPORT ==="
