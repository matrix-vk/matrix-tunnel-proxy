package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/identity"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/pki"
)

type countingCloser struct{ calls int }

func (closer *countingCloser) Close() error {
	closer.calls++
	return nil
}

func TestMappingManagerCloseAllIsFinalAndIdempotent(t *testing.T) {
	manager := newMappingManager(newHub(), "203.0.113.10:7000")
	closer := &countingCloser{}
	manager.listeners["full"] = activeMapping{closer: closer, signature: "full"}

	manager.closeAll()
	manager.closeAll()
	manager.apply(controller.ServerConfig{Mappings: []controller.Mapping{{ID: "full", MappingType: "full", Status: "effective"}}})

	if closer.calls != 1 {
		t.Fatalf("mapping closer called %d times; want exactly once", closer.calls)
	}
	if len(manager.listeners) != 0 {
		t.Fatal("closed mapping manager accepted a new mapping")
	}
}

func TestTunnelListenAddressUsesAllInterfaces(t *testing.T) {
	tests := []string{
		"203.0.113.10:7000",
		"edge.example.com:7000",
		"[2001:db8::10]:7000",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			address, err := tunnelListenAddress(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			if host != "" || port != "7000" {
				t.Fatalf("tunnelListenAddress(%q) = %q; want all interfaces on port 7000", endpoint, address)
			}
		})
	}
}

func TestTunnelListenAddressRejectsMissingPort(t *testing.T) {
	if _, err := tunnelListenAddress("203.0.113.10"); err == nil {
		t.Fatal("tunnelListenAddress accepted an endpoint without a port")
	}
}

func TestServerCertificateStateHotSwap(t *testing.T) {
	authority, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstPEM, err := authority.IssueDevice("srv_test", "server", "127.0.0.1:7000", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	secondPEM, err := authority.IssueDevice("srv_test", "server", "127.0.0.1:7000", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := identity.Config{PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey), CertificatePEM: string(firstPEM)}
	first, err := config.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	state := &serverCertificateState{}
	state.certificate.Store(&first)
	if err := state.update(config, string(secondPEM)); err != nil {
		t.Fatal(err)
	}
	current, err := state.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current.Certificate[0], first.Certificate[0]) {
		t.Fatal("certificate state did not change")
	}
}
