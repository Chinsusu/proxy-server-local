# Kiến trúc hệ thống

## Thành phần

- **pgw-api (:8080)**: CRUD proxies/clients/mappings; health-check; telemetry.
- **pgw-agent (:9090/agent)**: gọi API `/v1/mappings/active` → render script `nft` → `nft -f -`.
- **pgw-fwd (:15001)**: TCP listener; transparent CONNECT (+SNI log ẩn PII); nối upstream proxy.
- **pgw-ui (:8081)**: giao diện web; reverse proxy `/api/*`→API, `/agent/*`→Agent.

## nftables sinh ra

```nft
table ip pgw {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # cho từng client /32 (hoặc tập hợp nếu về sau mở rộng):
    iifname "ens19" ip saddr 192.168.2.3/32 tcp dport {80,443} redirect to :15001
    # ...
  }
}

table inet pgw_filter {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state established,related accept

    # chặn leak ra WAN & chặn UDP từ client
    ip saddr 192.168.2.3/32 oifname "eth0" drop
    ip saddr 192.168.2.3/32 meta l4proto udp drop
    # ...
  }

  chain input {
    type filter hook input priority filter; policy accept;

    # mở DNS (53) từ LAN vào gateway
    iifname "ens19" ip saddr 192.168.2.3/32 udp dport 53 accept
    iifname "ens19" ip saddr 192.168.2.3/32 tcp dport 53 accept

    # mở cổng forwarder
    iifname "ens19" ip saddr 192.168.2.3/32 tcp dport 15001 accept
  }
}
```

> Tên interface: `ens19` (LAN), `eth0` (WAN) có thể chỉnh bằng env Agent.

## Ràng buộc /32

* API chỉ chấp nhận `ip_cidr` với prefix **= 32**. Nếu người dùng nhập IP không có `/`, API tự chuyển thành `/32`. Nếu prefix `< 32` trả 400.
