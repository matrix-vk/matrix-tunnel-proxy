package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/identity"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/protocol"
)

func main() {
	configPath := flag.String("config", "", "bound client configuration file (defaults to client.json beside the executable)")
	flag.Parse()
	config, err := identity.Load(identity.ResolveConfigPath(*configPath, "client.json"), "client")
	if err != nil {
		log.Fatalf("load bound client package: %v", err)
	}
	tlsConfig, err := config.ClientTLSConfig()
	if err != nil {
		log.Fatalf("load client certificate: %v", err)
	}
	log.Printf("client %s connecting to %s with TLS", config.ClientID, config.Server)
	for {
		if err := connect(config.ClientID, config.Token, config.Server, tlsConfig); err != nil {
			log.Printf("connection lost: %v; retrying in 5s", err)
		}
		time.Sleep(5 * time.Second)
	}
}

type tunnelClient struct {
	connection net.Conn
	write      sync.Mutex
	streams    sync.Map
	pongs      chan struct{}
}

type clientStream struct {
	mutex        sync.Mutex
	connection   net.Conn
	pending      [][]byte
	pendingBytes int
	closed       bool
}

const maxPendingStreamBytes = 4 << 20

const (
	tunnelWriteTimeout = 15 * time.Second
	heartbeatInterval  = 15 * time.Second
	heartbeatTimeout   = 15 * time.Second
)

func (stream *clientStream) write(payload []byte) error {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	if stream.closed {
		return net.ErrClosed
	}
	if stream.connection == nil {
		if stream.pendingBytes+len(payload) > maxPendingStreamBytes {
			return errors.New("pending stream data limit exceeded")
		}
		stream.pending = append(stream.pending, append([]byte(nil), payload...))
		stream.pendingBytes += len(payload)
		return nil
	}
	_, err := stream.connection.Write(payload)
	return err
}

func (stream *clientStream) activate(connection net.Conn) error {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	if stream.closed {
		_ = connection.Close()
		return net.ErrClosed
	}
	for _, payload := range stream.pending {
		if _, err := connection.Write(payload); err != nil {
			_ = connection.Close()
			return err
		}
	}
	stream.pending = nil
	stream.pendingBytes = 0
	stream.connection = connection
	return nil
}

func (stream *clientStream) close() {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	stream.closed = true
	stream.pending = nil
	stream.pendingBytes = 0
	if stream.connection != nil {
		_ = stream.connection.Close()
	}
}

func (client *tunnelClient) send(frame protocol.Frame) error {
	client.write.Lock()
	defer client.write.Unlock()
	err := protocol.WriteFrameWithDeadline(client.connection, frame, tunnelWriteTimeout)
	if err != nil {
		_ = client.connection.Close()
	}
	return err
}
func (client *tunnelClient) closeStreams() {
	client.streams.Range(func(key, value any) bool { client.streams.Delete(key); value.(*clientStream).close(); return true })
}

func connect(clientID, token, endpoint string, tlsConfig *tls.Config) error {
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     30 * time.Second,
			Interval: 10 * time.Second,
			Count:    3,
		},
	}
	connection, err := tls.DialWithDialer(dialer, "tcp", endpoint, tlsConfig)
	if err != nil {
		return err
	}
	defer connection.Close()
	client := &tunnelClient{connection: connection, pongs: make(chan struct{}, 1)}
	defer client.closeStreams()
	hello, _ := json.Marshal(map[string]string{"clientId": clientID, "token": token})
	if err := client.send(protocol.Frame{Type: protocol.Hello, Payload: hello}); err != nil {
		return err
	}
	_ = connection.SetReadDeadline(time.Now().Add(15 * time.Second))
	acknowledgement, err := protocol.ReadFrame(connection)
	if err != nil {
		return err
	}
	if acknowledgement.Type != protocol.HelloAck {
		return errors.New("server did not acknowledge client authentication")
	}
	_ = connection.SetReadDeadline(time.Time{})
	log.Printf("connected: client %s authenticated to %s", clientID, endpoint)
	errors := make(chan error, 1)
	go client.readFrames(errors)
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case err := <-errors:
			return err
		case <-ticker.C:
			if err := client.send(protocol.Frame{Type: protocol.Ping}); err != nil {
				return fmt.Errorf("send heartbeat ping: %w", err)
			}
			select {
			case <-client.pongs:
			case <-time.After(heartbeatTimeout):
				return fmt.Errorf("heartbeat pong timeout after %s", heartbeatTimeout)
			}
		}
	}
}

func (client *tunnelClient) readFrames(errors chan<- error) {
	for {
		frame, err := protocol.ReadFrame(client.connection)
		if err != nil {
			errors <- err
			return
		}
		switch frame.Type {
		case protocol.Pong:
			select {
			case client.pongs <- struct{}{}:
			default:
			}
		case protocol.OpenStream:
			stream := &clientStream{}
			client.streams.Store(frame.StreamID, stream)
			go client.openStream(frame, stream, "tcp")
		case protocol.OpenDatagram:
			stream := &clientStream{}
			client.streams.Store(frame.StreamID, stream)
			go client.openStream(frame, stream, "udp")
		case protocol.Data:
			if value, ok := client.streams.Load(frame.StreamID); ok {
				stream := value.(*clientStream)
				if err := stream.write(frame.Payload); err != nil {
					client.streams.Delete(frame.StreamID)
					stream.close()
					_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
				}
			}
		case protocol.CloseStream:
			if value, ok := client.streams.LoadAndDelete(frame.StreamID); ok {
				value.(*clientStream).close()
			}
		}
	}
}

func (client *tunnelClient) openStream(frame protocol.Frame, stream *clientStream, network string) {
	defer client.streams.CompareAndDelete(frame.StreamID, stream)
	var target struct {
		Host string `json:"host"`
		Port string `json:"port"`
	}
	if err := json.Unmarshal(frame.Payload, &target); err != nil || target.Host == "" {
		stream.close()
		_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
		return
	}
	if _, err := strconv.Atoi(target.Port); err != nil {
		stream.close()
		_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
		return
	}
	log.Printf("mapping request: protocol=%s stream=%d target=%s", strings.ToUpper(network), frame.StreamID, net.JoinHostPort(target.Host, target.Port))
	local, err := net.DialTimeout(network, net.JoinHostPort(target.Host, target.Port), 10*time.Second)
	if err != nil {
		log.Printf("mapping failed: protocol=%s stream=%d target=%s error=%v", strings.ToUpper(network), frame.StreamID, net.JoinHostPort(target.Host, target.Port), err)
		stream.close()
		_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
		return
	}
	if err := stream.activate(local); err != nil {
		_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
		return
	}
	log.Printf("mapping connected: protocol=%s stream=%d target=%s", strings.ToUpper(network), frame.StreamID, net.JoinHostPort(target.Host, target.Port))
	defer func() {
		stream.close()
		_ = client.send(protocol.Frame{Type: protocol.CloseStream, StreamID: frame.StreamID})
	}()
	buffer := make([]byte, 64*1024)
	for {
		count, err := local.Read(buffer)
		if (count > 0 || network == "udp") && client.send(protocol.Frame{Type: protocol.Data, StreamID: frame.StreamID, Payload: append([]byte(nil), buffer[:count]...)}) != nil {
			return
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("local target read: %v", err)
			}
			return
		}
	}
}
