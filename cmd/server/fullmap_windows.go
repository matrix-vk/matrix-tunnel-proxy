//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func fullMappingSupported() bool { return true }

func cleanupStaleFullMappings() {}

// windivertAddress mirrors WINDIVERT_ADDRESS from WinDivert 2.x. Network-layer
// handles use only the first 8 bytes of Data, but the complete union is kept so
// the ABI size remains 80 bytes on 64-bit Windows.
type windivertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved  uint32
	Data      [64]byte
}

type windowsFullMapper struct {
	spec        fullMappingSpec
	manager     *mappingManager
	dll         *syscall.LazyDLL
	handle      uintptr
	recv        *syscall.LazyProc
	send        *syscall.LazyProc
	shutdown    *syscall.LazyProc
	closeHandle *syscall.LazyProc

	mutex     sync.Mutex
	ports     map[windowsPortKey]*windowsPortListener
	done      chan struct{}
	closeOnce sync.Once
}

type windowsPortKey struct {
	protocol byte
	port     uint16
}

type windowsPortListener struct {
	closer   io.Closer
	lastSeen time.Time
}

func startFullMapping(spec fullMappingSpec, manager *mappingManager) (fullMapper, error) {
	if net.ParseIP(spec.Mapping.PublicIP).To4() == nil {
		return nil, errors.New("Windows full mapping currently requires an IPv4 public address")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(executable)
	dllPath := filepath.Join(directory, "WinDivert.dll")
	driverPath := filepath.Join(directory, "WinDivert64.sys")
	if _, err := os.Stat(dllPath); err != nil {
		return nil, errors.New("WinDivert.dll is missing beside server.exe")
	}
	if _, err := os.Stat(driverPath); err != nil {
		return nil, errors.New("WinDivert64.sys is missing beside server.exe")
	}
	dll := syscall.NewLazyDLL(dllPath)
	open := dll.NewProc("WinDivertOpen")
	filter, _ := syscall.BytePtrFromString("inbound and ip and ip.DstAddr == " + spec.Mapping.PublicIP + " and (tcp or udp)")
	priority := int16(-1000)
	handle, _, callErr := open.Call(uintptr(unsafe.Pointer(filter)), 0, uintptr(uint16(priority)), 0)
	if handle == ^uintptr(0) {
		return nil, fmt.Errorf("open WinDivert (run server.exe as Administrator): %w", callErr)
	}
	mapper := &windowsFullMapper{
		spec: spec, manager: manager, dll: dll, handle: handle,
		recv: dll.NewProc("WinDivertRecv"), send: dll.NewProc("WinDivertSend"),
		shutdown: dll.NewProc("WinDivertShutdown"), closeHandle: dll.NewProc("WinDivertClose"),
		ports: make(map[windowsPortKey]*windowsPortListener), done: make(chan struct{}),
	}
	go mapper.run()
	go mapper.expireIdlePorts()
	return mapper, nil
}

func (mapper *windowsFullMapper) run() {
	packet := make([]byte, 65575)
	for {
		var address windivertAddress
		var received uint32
		ok, _, callErr := mapper.recv.Call(mapper.handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&received)), uintptr(unsafe.Pointer(&address)))
		if ok == 0 {
			select {
			case <-mapper.done:
				return
			default:
				log.Printf("Windows full mapping %s receive error: %v", mapper.spec.Mapping.ID, callErr)
				return
			}
		}
		contents := packet[:received]
		protocol, port, valid := ipv4DestinationPort(contents)
		if valid && !mapper.excluded(protocol, int(port)) {
			if err := mapper.ensurePort(protocol, port); err != nil {
				log.Printf("Windows full mapping %s cannot activate %s/%d: %v", mapper.spec.Mapping.ID, protocolName(protocol), port, err)
			}
		}
		var sent uint32
		ok, _, callErr = mapper.send.Call(mapper.handle, uintptr(unsafe.Pointer(&contents[0])), uintptr(len(contents)), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&address)))
		if ok == 0 {
			log.Printf("Windows full mapping %s reinject error: %v", mapper.spec.Mapping.ID, callErr)
		}
	}
}

func ipv4DestinationPort(packet []byte) (byte, uint16, bool) {
	if len(packet) < 24 || packet[0]>>4 != 4 {
		return 0, 0, false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || len(packet) < headerLength+4 {
		return 0, 0, false
	}
	protocol := packet[9]
	if protocol != 6 && protocol != 17 {
		return 0, 0, false
	}
	// Non-initial IPv4 fragments do not contain a TCP/UDP header. The first
	// fragment creates the listener before later fragments are reinjected.
	fragmentOffset := binary.BigEndian.Uint16(packet[6:8]) & 0x1fff
	if fragmentOffset != 0 {
		return 0, 0, false
	}
	return protocol, binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]), true
}

func (mapper *windowsFullMapper) excluded(protocol byte, port int) bool {
	if protocol == 6 {
		return portIsExcluded(port, mapper.spec.ExcludedTCP)
	}
	return portIsExcluded(port, mapper.spec.ExcludedUDP)
}

func protocolName(protocol byte) string {
	if protocol == 6 {
		return "TCP"
	}
	return "UDP"
}

func (mapper *windowsFullMapper) ensurePort(protocol byte, port uint16) error {
	key := windowsPortKey{protocol: protocol, port: port}
	mapper.mutex.Lock()
	defer mapper.mutex.Unlock()
	if active := mapper.ports[key]; active != nil {
		active.lastSeen = time.Now()
		return nil
	}
	if len(mapper.ports) >= 4096 {
		mapper.evictOldestLocked()
	}
	address := net.JoinHostPort(mapper.spec.Mapping.PublicIP, strconv.Itoa(int(port)))
	item := mapper.spec.Mapping
	item.TargetPort = int(port)
	if protocol == 6 {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			return err
		}
		mapper.ports[key] = &windowsPortListener{closer: listener, lastSeen: time.Now()}
		go mapper.manager.acceptMapping(listener, item)
		return nil
	}
	connection, err := net.ListenPacket("udp4", address)
	if err != nil {
		return err
	}
	mapping := newUDPMapping(connection, item, mapper.manager.hub)
	mapper.ports[key] = &windowsPortListener{closer: mapping, lastSeen: time.Now()}
	go mapping.run()
	return nil
}

func (mapper *windowsFullMapper) evictOldestLocked() {
	var oldestKey windowsPortKey
	var oldest *windowsPortListener
	for key, active := range mapper.ports {
		if oldest == nil || active.lastSeen.Before(oldest.lastSeen) {
			oldestKey, oldest = key, active
		}
	}
	if oldest != nil {
		oldest.closer.Close()
		delete(mapper.ports, oldestKey)
	}
}

func (mapper *windowsFullMapper) expireIdlePorts() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-mapper.done:
			return
		case now := <-ticker.C:
			mapper.mutex.Lock()
			for key, active := range mapper.ports {
				if now.Sub(active.lastSeen) > 10*time.Minute {
					active.closer.Close()
					delete(mapper.ports, key)
				}
			}
			mapper.mutex.Unlock()
		}
	}
}

func (mapper *windowsFullMapper) Close() error {
	mapper.closeOnce.Do(func() {
		close(mapper.done)
		mapper.shutdown.Call(mapper.handle, 3)
		mapper.closeHandle.Call(mapper.handle)
		mapper.mutex.Lock()
		for key, active := range mapper.ports {
			active.closer.Close()
			delete(mapper.ports, key)
		}
		mapper.mutex.Unlock()
	})
	return nil
}
