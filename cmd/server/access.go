package main

import (
	"net"
	"strings"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
)

func mappingAllows(item controller.Mapping, address net.Addr) bool {
	if item.AccessMode == "" || item.AccessMode == "public" {
		return true
	}
	if item.AccessMode != "allowlist" || address == nil {
		return false
	}
	var source net.IP
	switch value := address.(type) {
	case *net.TCPAddr:
		source = value.IP
	case *net.UDPAddr:
		source = value.IP
	default:
		host, _, err := net.SplitHostPort(address.String())
		if err == nil {
			source = net.ParseIP(strings.Trim(host, "[]"))
		}
	}
	return mappingAllowsIP(item, source)
}

func mappingAllowsIP(item controller.Mapping, source net.IP) bool {
	if item.AccessMode == "" || item.AccessMode == "public" {
		return true
	}
	if item.AccessMode != "allowlist" || source == nil {
		return false
	}
	for _, raw := range strings.Split(item.AllowedIPs, ",") {
		value := strings.TrimSpace(raw)
		if allowed := net.ParseIP(value); allowed != nil && allowed.Equal(source) {
			return true
		}
		if _, network, err := net.ParseCIDR(value); err == nil && network.Contains(source) {
			return true
		}
	}
	return false
}
