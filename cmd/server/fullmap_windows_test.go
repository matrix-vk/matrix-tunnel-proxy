//go:build windows

package main

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestWinDivertAddressABIAndPacketParser(t *testing.T) {
	if size := unsafe.Sizeof(windivertAddress{}); size != 80 {
		t.Fatalf("WINDIVERT_ADDRESS size = %d", size)
	}
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[22:24], 8443)
	protocol, port, ok := ipv4DestinationPort(packet)
	if !ok || protocol != 6 || port != 8443 {
		t.Fatalf("parsed protocol=%d port=%d ok=%v", protocol, port, ok)
	}
}
