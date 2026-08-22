package main

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

type recordingConnection struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
	closed bool
}

func (connection *recordingConnection) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (connection *recordingConnection) Write(payload []byte) (int, error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.closed {
		return 0, net.ErrClosed
	}
	return connection.buffer.Write(payload)
}
func (connection *recordingConnection) Close() error {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.closed = true
	return nil
}
func (connection *recordingConnection) LocalAddr() net.Addr              { return testAddress("local") }
func (connection *recordingConnection) RemoteAddr() net.Addr             { return testAddress("remote") }
func (connection *recordingConnection) SetDeadline(time.Time) error      { return nil }
func (connection *recordingConnection) SetReadDeadline(time.Time) error  { return nil }
func (connection *recordingConnection) SetWriteDeadline(time.Time) error { return nil }
func (connection *recordingConnection) contents() string {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return connection.buffer.String()
}

type testAddress string

func (address testAddress) Network() string { return string(address) }
func (address testAddress) String() string  { return string(address) }

func TestClientStreamPreservesDataReceivedBeforeTargetConnects(t *testing.T) {
	stream := &clientStream{}
	if err := stream.write([]byte("first")); err != nil {
		t.Fatalf("queue first payload: %v", err)
	}
	connection := &recordingConnection{}
	if err := stream.activate(connection); err != nil {
		t.Fatalf("activate stream: %v", err)
	}
	if err := stream.write([]byte("second")); err != nil {
		t.Fatalf("write second payload: %v", err)
	}
	if got := connection.contents(); got != "firstsecond" {
		t.Fatalf("payload order = %q, want firstsecond", got)
	}
}
