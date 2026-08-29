package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestListServersReturnsEmptySliceForNewDatabase(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	servers, err := store.ListServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	if servers == nil {
		t.Fatal("list servers returned nil; JSON must encode an empty list as []")
	}
	if len(servers) != 0 {
		t.Fatalf("unexpected server count: %d", len(servers))
	}
}

func TestMappingPriorityAndWildcardConflict(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverToken := sha256.Sum256([]byte("server-token"))
	if _, err := store.CreateServer(context.Background(), "srv_test", "server", "127.0.0.1:7000", publicKey, []byte("certificate"), serverToken[:]); err != nil {
		t.Fatal(err)
	}
	clientToken := sha256.Sum256([]byte("client-token"))
	if _, err := store.CreateClient(context.Background(), "cli_test", "srv_test", "client", "linux-amd64", clientToken[:]); err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateMapping(context.Background(), Mapping{ID: "map_specific", ServerID: "srv_test", ClientID: "cli_test", PublicIP: "127.0.0.1", Protocol: "tcp", MappingType: "port", PublicPort: 8080, TargetHost: "127.0.0.1", TargetPort: 80, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "effective" {
		t.Fatalf("first status = %s", first.Status)
	}
	second, err := store.CreateMapping(context.Background(), Mapping{ID: "map_wildcard", ServerID: "srv_test", ClientID: "cli_test", PublicIP: "0.0.0.0", Protocol: "tcp", MappingType: "port", PublicPort: 8080, TargetHost: "127.0.0.1", TargetPort: 81, Priority: 20})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "effective" {
		t.Fatalf("higher wildcard status = %s", second.Status)
	}
	udp, err := store.CreateMapping(context.Background(), Mapping{ID: "map_udp", ServerID: "srv_test", ClientID: "cli_test", PublicIP: "0.0.0.0", Protocol: "udp", MappingType: "port", PublicPort: 8080, TargetHost: "127.0.0.1", TargetPort: 81, Priority: 1})
	if err != nil {
		t.Fatal(err)
	}
	if udp.Status != "effective" {
		t.Fatalf("UDP should not conflict with TCP: %s", udp.Status)
	}
	items, err := store.ListMappings(context.Background(), "srv_test")
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, item := range items {
		statuses[item.ID] = item.Status
	}
	if statuses["map_specific"] != "occupied" {
		t.Fatalf("specific status = %s", statuses["map_specific"])
	}
	if err := store.UpdateMappingPriority(context.Background(), "srv_test", "map_specific", 30); err != nil {
		t.Fatal(err)
	}
	items, err = store.ListMappings(context.Background(), "srv_test")
	if err != nil {
		t.Fatal(err)
	}
	statuses = map[string]string{}
	for _, item := range items {
		statuses[item.ID] = item.Status
	}
	if statuses["map_specific"] != "effective" || statuses["map_wildcard"] != "occupied" {
		t.Fatalf("statuses after priority update: %#v", statuses)
	}
	if err := store.UpdateMappingAccess(context.Background(), "srv_test", "map_specific", "allowlist", "203.0.113.8; 198.51.100.0/24\n203.0.113.8"); err != nil {
		t.Fatal(err)
	}
	items, err = store.ListMappings(context.Background(), "srv_test")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == "map_specific" && (item.AccessMode != "allowlist" || item.AllowedIPs != "198.51.100.0/24,203.0.113.8") {
			t.Fatalf("unexpected mapping access: %#v", item)
		}
	}
}

func TestNormalizeAllowedIPsRejectsInvalidInput(t *testing.T) {
	if _, err := NormalizeAllowedIPs("not-an-ip"); err == nil {
		t.Fatal("invalid allow-list was accepted")
	}
	if _, err := NormalizeAllowedIPs("  "); err == nil {
		t.Fatal("empty allow-list was accepted")
	}
}

func TestFullMappingPriorityAndReservedPorts(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	serverToken := sha256.Sum256([]byte("server-token"))
	if _, err := store.CreateServer(context.Background(), "srv_full", "server", "127.0.0.1:7000", publicKey, []byte("certificate"), serverToken[:]); err != nil {
		t.Fatal(err)
	}
	clientToken := sha256.Sum256([]byte("client-token"))
	if _, err := store.CreateClient(context.Background(), "cli_full", "srv_full", "client", "windows-amd64", clientToken[:]); err != nil {
		t.Fatal(err)
	}
	full, err := store.CreateMapping(context.Background(), Mapping{ID: "map_full", ServerID: "srv_full", ClientID: "cli_full", PublicIP: "203.0.113.10", Protocol: "both", MappingType: "full", TargetHost: "192.168.1.20", ExcludedPorts: "3389,22,8000-8010,8005", Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if full.Status != "effective" || full.ExcludedPorts != "22,3389,8000-8010" {
		t.Fatalf("unexpected full mapping: %#v", full)
	}
	higherPort, err := store.CreateMapping(context.Background(), Mapping{ID: "map_tcp_high", ServerID: "srv_full", ClientID: "cli_full", PublicIP: "203.0.113.10", Protocol: "tcp", MappingType: "port", PublicPort: 443, TargetHost: "192.168.1.30", TargetPort: 8443, Priority: 20})
	if err != nil || higherPort.Status != "effective" {
		t.Fatalf("higher port override: %#v err=%v", higherPort, err)
	}
	lowerPort, err := store.CreateMapping(context.Background(), Mapping{ID: "map_udp_low", ServerID: "srv_full", ClientID: "cli_full", PublicIP: "203.0.113.10", Protocol: "udp", MappingType: "port", PublicPort: 53, TargetHost: "192.168.1.30", TargetPort: 53, Priority: 5})
	if err != nil || lowerPort.Status != "occupied" || lowerPort.OccupiedBy != "map_full" {
		t.Fatalf("lower port should be occupied by full mapping: %#v err=%v", lowerPort, err)
	}
	newFull, err := store.CreateMapping(context.Background(), Mapping{ID: "map_full_high", ServerID: "srv_full", ClientID: "cli_full", PublicIP: "203.0.113.10", Protocol: "both", MappingType: "full", TargetHost: "192.168.1.40", Priority: 30})
	if err != nil || newFull.Status != "effective" {
		t.Fatalf("new full winner: %#v err=%v", newFull, err)
	}
	items, err := store.ListMappings(context.Background(), "srv_full")
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(map[string]Mapping)
	for _, item := range items {
		statuses[item.ID] = item
	}
	if statuses["map_full"].OccupiedBy != "map_full_high" || statuses["map_tcp_high"].OccupiedBy != "map_full_high" {
		t.Fatalf("full mapping priority was not applied: %#v", statuses)
	}
}
