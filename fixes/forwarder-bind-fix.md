# Fix: Forwarder Binding Issue

## Problem
Forwarders were binding to `:::port` (IPv6 all interfaces) causing routing loops when clients tried to connect to localhost addresses.

## Root Cause
- NAT rules redirect client traffic to forwarder ports
- Forwarders bind to all interfaces including localhost
- When forwarder processes outgoing connections, they get redirected back to themselves
- This creates infinite loops and connection failures

## Solution
Change forwarder binding from `:port` to `192.168.2.1:port` (LAN interface only).

## Implementation
Updated `/etc/systemd/system/pgw-fwd@.service`:

```diff
- Environment=PGW_FWD_ADDR=:%i  
+ Environment=PGW_FWD_ADDR=192.168.2.1:%i
```

## Result
- All forwarders now bind to LAN IP only: `192.168.2.1:15001-15017`
- No more routing loops
- Client connections successful: `192.168.2.101 -> proxy -> internet`
- Fixed "CONNECT 127.0.0.1:15001 failed" errors

## Verification
```bash
netstat -tlnp | grep "192.168.2.1:"
systemctl status pgw-fwd@15001.service
```
