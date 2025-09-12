# PGW Performance Optimization Guide

## Overview
This document describes performance optimizations applied to PGW to handle more concurrent proxy connections reliably.

## Problem Analysis
When running more than 10 proxies, the system experienced instability:
- File descriptor exhaustion (ulimit 1024 too low)
- SO_ORIGINAL_DST errors in forwarders
- Connection timeouts to upstream proxies
- Resource contention between multiple pgw-fwd processes

## Optimizations Implemented

### 1. File Descriptor Limits
**Issue**: Default limit of 1024 FDs insufficient for many concurrent connections
**Solution**: Increased to 65536 FDs per process

Files modified:
- `/etc/security/limits.conf` - User-level limits
- `/etc/systemd/system.conf.d/limits.conf` - Systemd defaults
- All service files - Per-service limits

### 2. Network Kernel Parameters
**Issue**: Default TCP/network settings not optimized for high connection load
**Solution**: Tuned kernel parameters for better network performance

Key settings:
```
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.netfilter.nf_conntrack_max = 131072
net.ipv4.tcp_fin_timeout = 15
```

### 3. Memory Limits per Service
**Issue**: Services could consume excessive memory causing OOM
**Solution**: Set appropriate memory limits

Limits applied:
- pgw-api: 512M
- pgw-agent: 256M  
- pgw-fwd@: 128M each
- pgw-ui: 128M
- pgw-health: 64M

### 4. Process/Task Limits
Set reasonable task limits to prevent fork bombs:
- pgw-api: 4096 tasks
- pgw-agent: 2048 tasks
- pgw-fwd@: 1024 tasks each

## Deployment Scripts

### Quick Deployment
```bash
sudo ./scripts/deploy-optimizations.sh
```

### Manual Steps
1. Apply file descriptor limits:
```bash
sudo cat deploy/limits-pgw.conf >> /etc/security/limits.conf
```

2. Apply network optimizations:
```bash
sudo cp deploy/sysctl-pgw.conf /etc/sysctl.d/99-pgw.conf
sudo sysctl -p /etc/sysctl.d/99-pgw.conf
```

3. Update service files:
```bash
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

4. Restart services:
```bash
sudo systemctl restart pgw-*
```

## Monitoring

### System Monitor
```bash
./scripts/monitor-pgw.sh
```

### Key Metrics to Watch
- File descriptor usage per process
- Memory consumption per service
- Number of active network connections
- TCP connection states
- nftables rule count

## Expected Results

After optimization:
- Support for 50+ concurrent proxies
- Stable connections under high load
- Reduced SO_ORIGINAL_DST errors
- Better resource utilization
- Improved system responsiveness

## Troubleshooting

### Common Issues
1. **Service fails to start**: Check file descriptor limits
2. **High memory usage**: Verify memory limits are appropriate
3. **Connection timeouts**: Check network parameter tuning
4. **SO_ORIGINAL_DST errors**: Verify nftables rules and connection tracking

### Debug Commands
```bash
# Check current limits
ulimit -a

# Monitor connections
ss -tuln | grep :150

# Check service resource usage
systemctl status pgw-api
```

## Server Requirements

### Minimum for 25+ proxies:
- CPU: 2+ cores
- RAM: 2GB+ (with optimization)
- Network: Stable connection
- OS: Ubuntu 20.04+ with nftables support

### Recommended for 50+ proxies:
- CPU: 4+ cores
- RAM: 4GB+
- Network: High bandwidth connection
- SSD storage for better I/O performance
