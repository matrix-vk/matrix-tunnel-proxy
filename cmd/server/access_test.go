package main

import (
	"net"
	"testing"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
)

func TestMappingAllowsIP(t *testing.T) {
	public := controller.Mapping{AccessMode: "public"}
	if !mappingAllowsIP(public, net.ParseIP("203.0.113.8")) {
		t.Fatal("public mapping denied")
	}
	limited := controller.Mapping{AccessMode: "allowlist", AllowedIPs: "192.0.2.5,2001:db8::/32,198.51.100.0/24"}
	for _, value := range []string{"192.0.2.5", "198.51.100.42", "2001:db8::10"} {
		if !mappingAllowsIP(limited, net.ParseIP(value)) {
			t.Fatalf("allowed address %s denied", value)
		}
	}
	if mappingAllowsIP(limited, net.ParseIP("203.0.113.8")) {
		t.Fatal("unlisted address allowed")
	}
}
