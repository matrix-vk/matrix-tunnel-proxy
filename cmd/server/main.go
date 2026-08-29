package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/identity"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/protocol"
)

func main() {
	configPath := flag.String("config", "", "bound server configuration file (defaults to server.json beside the executable)")
	flag.Parse()
	config, err := identity.Load(identity.ResolveConfigPath(*configPath, "server.json"), "server")
	if err != nil {
		log.Fatalf("load bound server package: %v", err)
	}
	certificate, err := config.Certificate()
	if err != nil {
		log.Fatalf("load server certificate: %v", err)
	}
	certificateState := &serverCertificateState{}
	certificateState.certificate.Store(&certificate)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certificateState.get}
	cleanupStaleFullMappings()
	hub := newHub()
	mapper := newMappingManager(hub, config.Endpoint)
	if config.Controller != "" {
		go pollController(config, mapper, certificateState)
	}
	listenAddress, err := tunnelListenAddress(config.Endpoint)
	if err != nil {
		log.Fatalf("invalid public endpoint %s: %v", config.Endpoint, err)
	}
	listener, err := tls.Listen("tcp", listenAddress, tlsConfig)
	if err != nil {
		log.Fatalf("listen on %s: %v", listenAddress, err)
	}
	log.Printf("server %s listening with TLS on %s (public endpoint %s)", config.ServerID, listenAddress, config.Endpoint)
	signals := make(chan os.Signal, 1)
	shutdown := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		close(shutdown)
		log.Printf("server shutdown requested; closing mappings")
		mapper.closeAll()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-shutdown:
				return
			default:
			}
			log.Printf("accept client: %v", err)
			continue
		}
		tlsConnection := connection.(*tls.Conn)
		enableTCPKeepAlive(tlsConnection)
		go serveClient(tlsConnection, hub, mapper.allowed)
	}
}

// tunnelListenAddress keeps the configured endpoint as the address advertised
// to clients, but binds the local listener on every interface. Public or NAT
// addresses are commonly not assigned to a local network interface.
func tunnelListenAddress(publicEndpoint string) (string, error) {
	_, port, err := net.SplitHostPort(publicEndpoint)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort("", port), nil
}

func enableTCPKeepAlive(connection *tls.Conn) {
	tcpConnection, ok := connection.NetConn().(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConnection.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}); err != nil {
		log.Printf("configure client TCP keepalive: %v", err)
	}
}

type serverCertificateState struct {
	certificate atomic.Pointer[tls.Certificate]
}

func (state *serverCertificateState) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := state.certificate.Load()
	if certificate == nil {
		return nil, errors.New("server TLS certificate is unavailable")
	}
	return certificate, nil
}

func (state *serverCertificateState) update(config identity.Config, certificatePEM string) error {
	config.CertificatePEM = certificatePEM
	certificate, err := config.Certificate()
	if err != nil {
		return err
	}
	state.certificate.Store(&certificate)
	return nil
}

type clientSession struct {
	connection net.Conn
	write      sync.Mutex
	streams    sync.Map
}

const tunnelWriteTimeout = 15 * time.Second

type streamDestination interface {
	Write([]byte) (int, error)
	Close() error
}

func (session *clientSession) send(frame protocol.Frame) error {
	session.write.Lock()
	defer session.write.Unlock()
	err := protocol.WriteFrameWithDeadline(session.connection, frame, tunnelWriteTimeout)
	if err != nil {
		_ = session.connection.Close()
	}
	return err
}
func (session *clientSession) closeStreams() {
	session.streams.Range(func(key, value any) bool {
		session.streams.Delete(key)
		_ = value.(streamDestination).Close()
		return true
	})
}

type hub struct {
	mutex    sync.RWMutex
	clients  map[string]*clientSession
	streamID atomic.Uint32
}

func newHub() *hub { return &hub{clients: make(map[string]*clientSession)} }
func (hub *hub) put(clientID string, session *clientSession) {
	hub.mutex.Lock()
	previous := hub.clients[clientID]
	hub.clients[clientID] = session
	hub.mutex.Unlock()
	if previous != nil && previous != session {
		_ = previous.connection.Close()
		previous.closeStreams()
	}
}
func (hub *hub) remove(clientID string, session *clientSession) {
	hub.mutex.Lock()
	if hub.clients[clientID] == session {
		delete(hub.clients, clientID)
	}
	hub.mutex.Unlock()
}
func (hub *hub) get(clientID string) *clientSession {
	hub.mutex.RLock()
	defer hub.mutex.RUnlock()
	return hub.clients[clientID]
}
func (hub *hub) disconnectUnauthorized(previous, allowed map[string]string) {
	hub.mutex.RLock()
	sessions := make(map[string]*clientSession, len(hub.clients))
	for id, session := range hub.clients {
		sessions[id] = session
	}
	hub.mutex.RUnlock()
	for id, session := range sessions {
		if nextHash, ok := allowed[id]; !ok || previous[id] != nextHash {
			_ = session.connection.Close()
		}
	}
}
func (hub *hub) connectedIDs() []string {
	hub.mutex.RLock()
	defer hub.mutex.RUnlock()
	ids := make([]string, 0, len(hub.clients))
	for id := range hub.clients {
		ids = append(ids, id)
	}
	return ids
}
func (hub *hub) nextStreamID() uint32 { return hub.streamID.Add(1) }

func serveClient(connection *tls.Conn, hub *hub, isAllowed func(string, string) bool) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	if err := connection.Handshake(); err != nil {
		log.Printf("TLS handshake rejected: %v", err)
		return
	}
	frame, err := protocol.ReadFrame(connection)
	if err != nil || frame.Type != protocol.Hello {
		log.Printf("client hello rejected: %v", err)
		return
	}
	var hello struct {
		ClientID string `json:"clientId"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(frame.Payload, &hello); err != nil || !isAllowed(hello.ClientID, hello.Token) {
		log.Printf("client token mismatch or revoked")
		return
	}
	_ = connection.SetDeadline(time.Time{})
	session := &clientSession{connection: connection}
	hub.put(hello.ClientID, session)
	defer hub.remove(hello.ClientID, session)
	defer session.closeStreams()
	if err := session.send(protocol.Frame{Type: protocol.HelloAck}); err != nil {
		log.Printf("client %s authentication acknowledgement failed: %v", hello.ClientID, err)
		return
	}
	log.Printf("client %s connected", hello.ClientID)
	for {
		_ = connection.SetReadDeadline(time.Now().Add(45 * time.Second))
		frame, err = protocol.ReadFrame(connection)
		if err != nil {
			log.Printf("client %s disconnected: %v", hello.ClientID, err)
			return
		}
		switch frame.Type {
		case protocol.Ping:
			if err := session.send(protocol.Frame{Type: protocol.Pong}); err != nil {
				log.Printf("client %s heartbeat pong failed: %v", hello.ClientID, err)
				return
			}
		case protocol.Data:
			if value, ok := session.streams.Load(frame.StreamID); ok {
				_, _ = value.(streamDestination).Write(frame.Payload)
			}
		case protocol.CloseStream:
			if value, ok := session.streams.LoadAndDelete(frame.StreamID); ok {
				_ = value.(streamDestination).Close()
			}
		}
	}
}

type mappingManager struct {
	hub            *hub
	mutex          sync.RWMutex
	allowedClients map[string]string
	listeners      map[string]activeMapping
	tunnelPort     int
	closed         bool
}

type activeMapping struct {
	closer    io.Closer
	signature string
}

func newMappingManager(hub *hub, endpoint string) *mappingManager {
	_, portText, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portText)
	return &mappingManager{hub: hub, allowedClients: make(map[string]string), listeners: make(map[string]activeMapping), tunnelPort: port}
}
func (manager *mappingManager) allowed(clientID, token string) bool {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()
	hash := sha256.Sum256([]byte(token))
	return manager.allowedClients[clientID] == base64.RawStdEncoding.EncodeToString(hash[:])
}
func (manager *mappingManager) apply(config controller.ServerConfig) {
	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return
	}
	nextClients := make(map[string]string, len(config.Clients))
	for _, credential := range config.Clients {
		nextClients[credential.ID] = credential.TokenHash
	}
	manager.hub.disconnectUnauthorized(manager.allowedClients, nextClients)
	manager.allowedClients = nextClients
	wanted := make(map[string]controller.Mapping)
	for _, item := range config.Mappings {
		if item.Status == "effective" && (item.MappingType == "port" || item.MappingType == "full") {
			wanted[item.ID] = item
		}
	}
	specs := make(map[string]fullMappingSpec)
	for _, item := range wanted {
		if item.MappingType == "full" {
			specs[item.ID] = buildFullMappingSpec(item, config.Mappings, manager.tunnelPort)
		}
	}
	for id, active := range manager.listeners {
		item, exists := wanted[id]
		signature := mappingSignature(item, specs[id])
		if !exists || signature != active.signature {
			if err := active.closer.Close(); err != nil {
				log.Printf("mapping %s cleanup failed: %v", id, err)
			} else {
				log.Printf("mapping %s stopped", id)
			}
			delete(manager.listeners, id)
		}
	}
	for id, item := range wanted {
		if _, exists := manager.listeners[id]; exists {
			continue
		}
		if item.MappingType == "full" {
			spec := specs[id]
			mapper, err := startFullMapping(spec, manager)
			if err != nil {
				log.Printf("full mapping %s cannot start: %v", id, err)
				continue
			}
			manager.listeners[id] = activeMapping{closer: mapper, signature: mappingSignature(item, spec)}
			log.Printf("FULL TCP+UDP mapping %s effective on %s", id, item.PublicIP)
			continue
		}
		address := net.JoinHostPort(item.PublicIP, strconv.Itoa(item.PublicPort))
		if item.Protocol == "tcp" {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				log.Printf("TCP mapping %s cannot listen on %s: %v", id, address, err)
				continue
			}
			manager.listeners[id] = activeMapping{closer: listener, signature: mappingSignature(item, fullMappingSpec{})}
			go manager.acceptMapping(listener, item)
		} else {
			packetConnection, err := net.ListenPacket("udp", address)
			if err != nil {
				log.Printf("UDP mapping %s cannot listen on %s: %v", id, address, err)
				continue
			}
			mapping := newUDPMapping(packetConnection, item, manager.hub)
			manager.listeners[id] = activeMapping{closer: mapping, signature: mappingSignature(item, fullMappingSpec{})}
			go mapping.run()
		}
		log.Printf("%s mapping %s effective on %s", strings.ToUpper(item.Protocol), id, address)
	}
	manager.mutex.Unlock()
}

func (manager *mappingManager) closeAll() {
	manager.mutex.Lock()
	if manager.closed {
		manager.mutex.Unlock()
		return
	}
	manager.closed = true
	active := manager.listeners
	manager.listeners = make(map[string]activeMapping)
	manager.mutex.Unlock()
	for id, mapping := range active {
		if err := mapping.closer.Close(); err != nil {
			log.Printf("mapping %s shutdown cleanup failed: %v", id, err)
		}
	}
}

type udpReply struct {
	connection net.PacketConn
	remote     net.Addr
	closed     atomic.Bool
}

func (reply *udpReply) Write(payload []byte) (int, error) {
	if reply.closed.Load() {
		return 0, net.ErrClosed
	}
	return reply.connection.WriteTo(payload, reply.remote)
}

func (reply *udpReply) Close() error {
	reply.closed.Store(true)
	return nil
}

type udpFlow struct {
	streamID uint32
	session  *clientSession
	reply    *udpReply
	lastSeen atomic.Int64
}

type udpMapping struct {
	connection net.PacketConn
	item       controller.Mapping
	hub        *hub
	mutex      sync.Mutex
	flows      map[string]*udpFlow
	done       chan struct{}
	closeOnce  sync.Once
}

func newUDPMapping(connection net.PacketConn, item controller.Mapping, hub *hub) *udpMapping {
	return &udpMapping{connection: connection, item: item, hub: hub, flows: make(map[string]*udpFlow), done: make(chan struct{})}
}

func (mapping *udpMapping) run() {
	go mapping.expireFlows()
	buffer := make([]byte, 64*1024)
	for {
		count, remote, err := mapping.connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		mapping.forward(remote, append([]byte(nil), buffer[:count]...))
	}
}

func (mapping *udpMapping) forward(remote net.Addr, payload []byte) {
	if !mappingAllows(mapping.item, remote) {
		return
	}
	session := mapping.hub.get(mapping.item.ClientID)
	if session == nil {
		return
	}
	key := remote.Network() + ":" + remote.String()
	mapping.mutex.Lock()
	defer mapping.mutex.Unlock()
	flow := mapping.flows[key]
	if flow != nil && (flow.session != session || flow.reply.closed.Load()) {
		flow.session.streams.Delete(flow.streamID)
		delete(mapping.flows, key)
		flow = nil
	}
	if flow == nil {
		flow = &udpFlow{streamID: mapping.hub.nextStreamID(), session: session, reply: &udpReply{connection: mapping.connection, remote: remote}}
		flow.lastSeen.Store(time.Now().UnixNano())
		mapping.flows[key] = flow
		session.streams.Store(flow.streamID, flow.reply)
		target, _ := json.Marshal(map[string]string{"host": mapping.item.TargetHost, "port": strconv.Itoa(mapping.item.TargetPort)})
		if err := session.send(protocol.Frame{Type: protocol.OpenDatagram, StreamID: flow.streamID, Payload: target}); err != nil {
			session.streams.Delete(flow.streamID)
			flow.reply.Close()
			delete(mapping.flows, key)
			return
		}
	}
	flow.lastSeen.Store(time.Now().UnixNano())
	if err := session.send(protocol.Frame{Type: protocol.Data, StreamID: flow.streamID, Payload: payload}); err != nil {
		session.streams.Delete(flow.streamID)
		flow.reply.Close()
		delete(mapping.flows, key)
	}
}

func (mapping *udpMapping) expireFlows() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-mapping.done:
			return
		case now := <-ticker.C:
			mapping.mutex.Lock()
			for key, flow := range mapping.flows {
				if flow.reply.closed.Load() || now.Sub(time.Unix(0, flow.lastSeen.Load())) > 60*time.Second {
					flow.session.streams.Delete(flow.streamID)
					flow.reply.Close()
					_ = flow.session.send(protocol.Frame{Type: protocol.CloseStream, StreamID: flow.streamID})
					delete(mapping.flows, key)
				}
			}
			mapping.mutex.Unlock()
		}
	}
}

func (mapping *udpMapping) Close() error {
	var closeErr error
	mapping.closeOnce.Do(func() {
		close(mapping.done)
		closeErr = mapping.connection.Close()
		mapping.mutex.Lock()
		for key, flow := range mapping.flows {
			flow.session.streams.Delete(flow.streamID)
			flow.reply.Close()
			_ = flow.session.send(protocol.Frame{Type: protocol.CloseStream, StreamID: flow.streamID})
			delete(mapping.flows, key)
		}
		mapping.mutex.Unlock()
	})
	return closeErr
}
func (manager *mappingManager) acceptMapping(listener net.Listener, item controller.Mapping) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go manager.forward(item, connection)
	}
}
func (manager *mappingManager) forward(item controller.Mapping, publicConnection net.Conn) {
	defer publicConnection.Close()
	if !mappingAllows(item, publicConnection.RemoteAddr()) {
		return
	}
	session := manager.hub.get(item.ClientID)
	if session == nil {
		return
	}
	streamID := manager.hub.nextStreamID()
	session.streams.Store(streamID, publicConnection)
	defer session.streams.Delete(streamID)
	payload, _ := json.Marshal(map[string]string{"host": item.TargetHost, "port": strconv.Itoa(item.TargetPort)})
	if err := session.send(protocol.Frame{Type: protocol.OpenStream, StreamID: streamID, Payload: payload}); err != nil {
		return
	}
	buffer := make([]byte, 32*1024)
	for {
		count, err := publicConnection.Read(buffer)
		if count > 0 && session.send(protocol.Frame{Type: protocol.Data, StreamID: streamID, Payload: append([]byte(nil), buffer[:count]...)}) != nil {
			return
		}
		if err != nil {
			_ = session.send(protocol.Frame{Type: protocol.CloseStream, StreamID: streamID})
			if err != io.EOF {
				log.Printf("public mapping read: %v", err)
			}
			return
		}
	}
}

func pollController(config identity.Config, manager *mappingManager, certificateState *serverCertificateState) {
	tlsConfig, err := config.OutboundTLSConfig(config.Controller)
	if err != nil {
		log.Printf("controller TLS configuration: %v", err)
		return
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 10 * time.Second}
	base := strings.TrimRight(config.Controller, "/") + "/agent/v1/servers/" + config.ServerID
	activeCertificatePEM := config.CertificatePEM
	poll := func() {
		reportBody, _ := json.Marshal(map[string]any{"onlineClients": manager.hub.connectedIDs(), "publicIps": localInterfaceIPs(), "platform": runtime.GOOS, "architecture": runtime.GOARCH, "fullMapping": fullMappingSupported()})
		request, _ := http.NewRequest(http.MethodPost, base+"/report", bytes.NewReader(reportBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+config.Token)
		response, err := client.Do(request)
		if err != nil {
			log.Printf("controller report: %v", err)
			return
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			log.Printf("controller report returned %s", response.Status)
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusNotFound {
				manager.apply(controller.ServerConfig{})
			}
			return
		}
		request, _ = http.NewRequest(http.MethodGet, base+"/config", nil)
		request.Header.Set("Authorization", "Bearer "+config.Token)
		response, err = client.Do(request)
		if err != nil {
			log.Printf("controller config pull: %v", err)
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			log.Printf("controller config pull returned %s", response.Status)
			return
		}
		var remoteConfig controller.ServerConfig
		if err := json.NewDecoder(response.Body).Decode(&remoteConfig); err != nil {
			log.Printf("decode controller config: %v", err)
			return
		}
		if remoteConfig.CertificatePEM != "" && remoteConfig.CertificatePEM != activeCertificatePEM {
			if err := certificateState.update(config, remoteConfig.CertificatePEM); err != nil {
				log.Printf("update server certificate: %v", err)
				return
			}
			activeCertificatePEM = remoteConfig.CertificatePEM
			log.Printf("server TLS certificate rotated")
		}
		manager.apply(remoteConfig)
	}
	poll()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		poll()
	}
}

func localInterfaceIPs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return []string{}
	}
	result := make([]string, 0)
	for _, current := range interfaces {
		if current.Flags&net.FlagUp == 0 || current.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := current.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip != nil {
				result = append(result, ip.String())
			}
		}
	}
	return result
}
