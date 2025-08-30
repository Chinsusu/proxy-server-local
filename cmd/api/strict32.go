package main

import (
	"fmt"
	"net"
	"strings"
)

// normalizeIPv4HostCIDR accepts "a.b.c.d" or "a.b.c.d/32" and returns "a.b.c.d/32".
// Rejects any prefix other than /32 and any non-IPv4 address.
func normalizeIPv4HostCIDR(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", fmt.Errorf("empty ip_cidr")
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("invalid IPv4")
		}
		return ip.String() + "/32", nil
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil || ip == nil || ip.To4() == nil || ipnet == nil {
		return "", fmt.Errorf("invalid IPv4 CIDR")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones != 32 {
		return "", fmt.Errorf("only /32 allowed")
	}
	return ip.String() + "/32", nil
}
