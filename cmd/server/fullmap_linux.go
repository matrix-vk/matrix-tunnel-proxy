//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/protocol"
	"golang.org/x/sys/unix"
)

func fullMappingSupported() bool { return true }

func cleanupStaleFullMappings() {
	removed := 0
	if output, err := exec.Command("nft", "list", "tables").Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "table" && fields[1] == "inet" && projectRuleName(fields[2], "mxp_") {
				if err := exec.Command("nft", "delete", "table", "inet", fields[2]).Run(); err != nil {
					log.Printf("stale nftables table %s cleanup failed: %v", fields[2], err)
				} else {
					removed++
				}
			}
		}
	}

	if output, err := exec.Command("iptables", "-t", "mangle", "-S").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		chains := make([]string, 0)
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "-N" && projectRuleName(fields[1], "MXP_") {
				chains = append(chains, fields[1])
			}
			if len(fields) < 4 || fields[0] != "-A" || fields[1] != "PREROUTING" {
				continue
			}
			for index := 2; index+1 < len(fields); index++ {
				if fields[index] == "-j" && projectRuleName(fields[index+1], "MXP_") {
					fields[0] = "-D"
					if err := exec.Command("iptables", append([]string{"-t", "mangle"}, fields...)...).Run(); err != nil {
						log.Printf("stale iptables jump cleanup failed: %v", err)
					} else {
						removed++
					}
					break
				}
			}
		}
		for _, chain := range chains {
			_ = exec.Command("iptables", "-t", "mangle", "-F", chain).Run()
			if err := exec.Command("iptables", "-t", "mangle", "-X", chain).Run(); err != nil {
				log.Printf("stale iptables chain %s cleanup failed: %v", chain, err)
			} else {
				removed++
			}
		}
	}

	if output, err := exec.Command("ip", "-o", "rule", "show").Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			mark, table, ok := matrixPolicyRule(strings.Fields(line))
			if !ok {
				continue
			}
			for exec.Command("ip", "rule", "del", "fwmark", mark, "table", table).Run() == nil {
				removed++
			}
			_ = exec.Command("ip", "route", "flush", "table", table).Run()
		}
	}
	if removed > 0 {
		log.Printf("removed %d stale full-mapping system rules", removed)
	}
}

type linuxFullMapper struct {
	spec        fullMappingSpec
	manager     *mappingManager
	tcp         net.Listener
	udp         *net.UDPConn
	tableName   string
	tcpChain    string
	udpChain    string
	ruleBackend string
	mark        int
	routeID     int
	done        chan struct{}
	closeOnce   sync.Once
	flowsMu     sync.Mutex
	flows       map[string]*linuxUDPFlow
}

type linuxUDPFlow struct {
	streamID uint32
	session  *clientSession
	reply    *linuxUDPReply
	lastSeen atomic.Int64
}

type linuxUDPReply struct {
	connection *net.UDPConn
	closed     atomic.Bool
}

func (reply *linuxUDPReply) Write(payload []byte) (int, error) {
	if reply.closed.Load() {
		return 0, net.ErrClosed
	}
	return reply.connection.Write(payload)
}

func (reply *linuxUDPReply) Close() error {
	if reply.closed.Swap(true) {
		return nil
	}
	return reply.connection.Close()
}

func startFullMapping(spec fullMappingSpec, manager *mappingManager) (fullMapper, error) {
	if net.ParseIP(spec.Mapping.PublicIP).To4() == nil {
		return nil, errors.New("Linux full mapping currently requires an IPv4 public address")
	}
	_, nftErr := exec.LookPath("nft")
	_, iptablesErr := exec.LookPath("iptables")
	if nftErr != nil && iptablesErr != nil {
		return nil, errors.New("Linux full mapping requires nftables or iptables")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return nil, errors.New("Linux full mapping requires iproute2 (ip command not found)")
	}
	tcp, err := listenTransparentTCP()
	if err != nil {
		return nil, fmt.Errorf("open transparent TCP listener: %w", err)
	}
	udp, err := listenTransparentUDP()
	if err != nil {
		tcp.Close()
		return nil, fmt.Errorf("open transparent UDP listener: %w", err)
	}
	hash := stableMappingNumber(spec.Mapping.ID)
	mapper := &linuxFullMapper{
		spec: spec, manager: manager, tcp: tcp, udp: udp,
		tableName: fmt.Sprintf("mxp_%x", hash),
		tcpChain:  fmt.Sprintf("MXP_%X_T", hash),
		udpChain:  fmt.Sprintf("MXP_%X_U", hash),
		mark:      0x4d0000 | hash&0xffff,
		routeID:   10000 + hash%20000,
		done:      make(chan struct{}), flows: make(map[string]*linuxUDPFlow),
	}
	if err := mapper.installRules(tcp.Addr().(*net.TCPAddr).Port, udp.LocalAddr().(*net.UDPAddr).Port); err != nil {
		tcp.Close()
		udp.Close()
		return nil, err
	}
	go mapper.acceptTCP()
	go mapper.readUDP()
	go mapper.expireUDP()
	return mapper, nil
}

func stableMappingNumber(value string) int {
	result := 0
	for _, current := range []byte(value) {
		result = (result*33 + int(current)) & 0x7fffffff
	}
	return result
}

func transparentControl(_ string, _ string, raw syscall.RawConn) error {
	var controlErr error
	err := raw.Control(func(fd uintptr) {
		if controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); controlErr == nil {
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}
	})
	if err != nil {
		return err
	}
	return controlErr
}

func listenTransparentTCP() (net.Listener, error) {
	config := net.ListenConfig{Control: transparentControl}
	return config.Listen(context.Background(), "tcp4", "0.0.0.0:0")
}

func listenTransparentUDP() (*net.UDPConn, error) {
	config := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		if err := transparentControl(network, address, raw); err != nil {
			return err
		}
		var controlErr error
		err := raw.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		})
		if err != nil {
			return err
		}
		return controlErr
	}}
	connection, err := config.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return connection.(*net.UDPConn), nil
}

func (mapper *linuxFullMapper) installRules(tcpPort, udpPort int) error {
	var nftErr error
	if _, err := exec.LookPath("nft"); err == nil {
		mapper.removeNFTRules()
		nftErr = mapper.installNFTRules(tcpPort, udpPort)
		if nftErr == nil {
			mapper.ruleBackend = "nft"
			return nil
		}
		mapper.removeNFTRules()
	} else {
		nftErr = err
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("install nftables rules: %w; iptables fallback is unavailable", nftErr)
	}
	mapper.removeIPTablesRules()
	if err := mapper.installIPTablesRules(tcpPort, udpPort); err != nil {
		mapper.removeIPTablesRules()
		return fmt.Errorf("install nftables rules: %v; install iptables fallback: %w", nftErr, err)
	}
	mapper.ruleBackend = "iptables"
	log.Printf("full mapping %s is using iptables TPROXY because native nftables TPROXY is unavailable: %v", mapper.spec.Mapping.ID, nftErr)
	return nil
}

func (mapper *linuxFullMapper) installNFTRules(tcpPort, udpPort int) error {
	commands := [][]string{
		{"nft", "add", "table", "inet", mapper.tableName},
		// Use the numeric NF_IP_PRI_MANGLE value for compatibility with the
		// older nftables releases shipped by CentOS. Newer releases also accept
		// the symbolic name "mangle", but older parsers require a number.
		{"nft", "add", "chain", "inet", mapper.tableName, "prerouting", "{", "type", "filter", "hook", "prerouting", "priority", "-150", ";", "policy", "accept", ";", "}"},
		// Do not capture reply traffic for connections initiated by this Server.
		// Public inbound connections stay in conntrack's original direction.
		{"nft", "add", "rule", "inet", mapper.tableName, "prerouting", "ip", "daddr", mapper.spec.Mapping.PublicIP, "ct", "direction", "reply", "return"},
	}
	commands = append(commands, mapper.nftRule("tcp", tcpPort, mapper.spec.ExcludedTCP))
	commands = append(commands, mapper.nftRule("udp", udpPort, mapper.spec.ExcludedUDP))
	commands = append(commands, mapper.policyRoutingCommands()...)
	return runLinuxCommands(commands)
}

func runLinuxCommands(commands [][]string) error {
	for _, command := range commands {
		arguments := command[1:]
		if command[0] == "nft" {
			// nft parses a complete command-language statement. Passing every
			// token as a separate argv entry lets older getopt implementations
			// mistake a negative chain priority such as -150 for an nft option.
			arguments = []string{strings.Join(arguments, " ")}
		}
		if output, err := exec.Command(command[0], arguments...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %w (%s)", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func (mapper *linuxFullMapper) policyRoutingCommands() [][]string {
	return [][]string{
		{"ip", "rule", "add", "fwmark", strconv.Itoa(mapper.mark), "table", strconv.Itoa(mapper.routeID)},
		{"ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(mapper.routeID)},
	}
}

func (mapper *linuxFullMapper) nftRule(network string, proxyPort int, excluded []portRange) []string {
	args := []string{"nft", "add", "rule", "inet", mapper.tableName, "prerouting", "ip", "daddr", mapper.spec.Mapping.PublicIP, network}
	if len(excluded) > 0 {
		args = append(args, "dport", "!=", "{", formatPortRanges(excluded), "}")
	}
	args = append(args, "meta", "mark", "set", strconv.Itoa(mapper.mark), "tproxy", "to", ":"+strconv.Itoa(proxyPort), "accept")
	return args
}

func (mapper *linuxFullMapper) installIPTablesRules(tcpPort, udpPort int) error {
	commands := [][]string{
		{"iptables", "-t", "mangle", "-N", mapper.tcpChain},
		{"iptables", "-t", "mangle", "-N", mapper.udpChain},
		iptablesReplyBypassCommand(mapper.tcpChain, "tcp"),
		iptablesReplyBypassCommand(mapper.udpChain, "udp"),
	}
	commands = append(commands, iptablesExclusionCommands(mapper.tcpChain, "tcp", mapper.spec.ExcludedTCP)...)
	commands = append(commands, iptablesExclusionCommands(mapper.udpChain, "udp", mapper.spec.ExcludedUDP)...)
	mark := strconv.Itoa(mapper.mark) + "/0xffffffff"
	commands = append(commands,
		[]string{"iptables", "-t", "mangle", "-A", mapper.tcpChain, "-p", "tcp", "-j", "TPROXY", "--on-ip", "0.0.0.0", "--on-port", strconv.Itoa(tcpPort), "--tproxy-mark", mark},
		[]string{"iptables", "-t", "mangle", "-A", mapper.udpChain, "-p", "udp", "-j", "TPROXY", "--on-ip", "0.0.0.0", "--on-port", strconv.Itoa(udpPort), "--tproxy-mark", mark},
	)
	commands = append(commands, mapper.policyRoutingCommands()...)
	commands = append(commands,
		[]string{"iptables", "-t", "mangle", "-A", "PREROUTING", "-d", mapper.spec.Mapping.PublicIP + "/32", "-p", "tcp", "-j", mapper.tcpChain},
		[]string{"iptables", "-t", "mangle", "-A", "PREROUTING", "-d", mapper.spec.Mapping.PublicIP + "/32", "-p", "udp", "-j", mapper.udpChain},
	)
	return runLinuxCommands(commands)
}

func (mapper *linuxFullMapper) removeNFTRules() {
	_ = exec.Command("nft", "delete", "table", "inet", mapper.tableName).Run()
	mapper.removePolicyRouting()
}

func (mapper *linuxFullMapper) removeIPTablesRules() {
	address := mapper.spec.Mapping.PublicIP + "/32"
	for exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING", "-d", address, "-p", "tcp", "-j", mapper.tcpChain).Run() == nil {
	}
	for exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING", "-d", address, "-p", "udp", "-j", mapper.udpChain).Run() == nil {
	}
	for _, chain := range []string{mapper.tcpChain, mapper.udpChain} {
		_ = exec.Command("iptables", "-t", "mangle", "-F", chain).Run()
		_ = exec.Command("iptables", "-t", "mangle", "-X", chain).Run()
	}
	mapper.removePolicyRouting()
}

func (mapper *linuxFullMapper) removePolicyRouting() {
	for exec.Command("ip", "rule", "del", "fwmark", strconv.Itoa(mapper.mark), "table", strconv.Itoa(mapper.routeID)).Run() == nil {
	}
	_ = exec.Command("ip", "route", "flush", "table", strconv.Itoa(mapper.routeID)).Run()
}

func (mapper *linuxFullMapper) removeRules() error {
	if mapper.ruleBackend == "nft" {
		mapper.removeNFTRules()
		if exec.Command("nft", "list", "table", "inet", mapper.tableName).Run() == nil {
			return fmt.Errorf("nftables table %s still exists after cleanup", mapper.tableName)
		}
	} else if mapper.ruleBackend == "iptables" {
		mapper.removeIPTablesRules()
		if exec.Command("iptables", "-t", "mangle", "-S", mapper.tcpChain).Run() == nil || exec.Command("iptables", "-t", "mangle", "-S", mapper.udpChain).Run() == nil {
			return fmt.Errorf("iptables chains %s/%s still exist after cleanup", mapper.tcpChain, mapper.udpChain)
		}
	}
	return nil
}

func (mapper *linuxFullMapper) acceptTCP() {
	for {
		connection, err := mapper.tcp.Accept()
		if err != nil {
			return
		}
		local, ok := connection.LocalAddr().(*net.TCPAddr)
		if !ok || local.Port < 1 {
			connection.Close()
			continue
		}
		item := mapper.spec.Mapping
		item.TargetPort = local.Port
		go mapper.manager.forward(item, connection)
	}
}

func (mapper *linuxFullMapper) readUDP() {
	payload := make([]byte, 64*1024)
	control := make([]byte, 256)
	for {
		count, controlCount, _, remote, err := mapper.udp.ReadMsgUDP(payload, control)
		if err != nil {
			return
		}
		original, err := originalUDPDestination(control[:controlCount])
		if err != nil || original.Port < 1 {
			log.Printf("full UDP mapping %s cannot read original destination: %v", mapper.spec.Mapping.ID, err)
			continue
		}
		mapper.forwardUDP(remote, original, append([]byte(nil), payload[:count]...))
	}
}

func originalUDPDestination(control []byte) (*net.UDPAddr, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR && len(message.Data) >= 8 {
			port := int(binary.BigEndian.Uint16(message.Data[2:4]))
			return &net.UDPAddr{IP: net.IPv4(message.Data[4], message.Data[5], message.Data[6], message.Data[7]), Port: port}, nil
		}
	}
	return nil, errors.New("IP_ORIGDSTADDR control message is missing")
}

func (mapper *linuxFullMapper) forwardUDP(remote, original *net.UDPAddr, payload []byte) {
	session := mapper.manager.hub.get(mapper.spec.Mapping.ClientID)
	if session == nil {
		return
	}
	key := remote.String() + "|" + original.String()
	mapper.flowsMu.Lock()
	defer mapper.flowsMu.Unlock()
	flow := mapper.flows[key]
	if flow != nil && (flow.session != session || flow.reply.closed.Load()) {
		flow.session.streams.Delete(flow.streamID)
		flow.reply.Close()
		delete(mapper.flows, key)
		flow = nil
	}
	if flow == nil {
		dialer := net.Dialer{LocalAddr: original, Control: transparentControl}
		connection, err := dialer.Dial("udp4", remote.String())
		if err != nil {
			log.Printf("full UDP mapping %s cannot create transparent reply socket: %v", mapper.spec.Mapping.ID, err)
			return
		}
		flow = &linuxUDPFlow{streamID: mapper.manager.hub.nextStreamID(), session: session, reply: &linuxUDPReply{connection: connection.(*net.UDPConn)}}
		flow.lastSeen.Store(time.Now().UnixNano())
		mapper.flows[key] = flow
		session.streams.Store(flow.streamID, flow.reply)
		target, _ := json.Marshal(map[string]string{"host": mapper.spec.Mapping.TargetHost, "port": strconv.Itoa(original.Port)})
		if err := session.send(protocol.Frame{Type: protocol.OpenDatagram, StreamID: flow.streamID, Payload: target}); err != nil {
			mapper.closeUDPFlow(key, flow)
			return
		}
	}
	flow.lastSeen.Store(time.Now().UnixNano())
	if err := session.send(protocol.Frame{Type: protocol.Data, StreamID: flow.streamID, Payload: payload}); err != nil {
		mapper.closeUDPFlow(key, flow)
	}
}

func (mapper *linuxFullMapper) closeUDPFlow(key string, flow *linuxUDPFlow) {
	flow.session.streams.Delete(flow.streamID)
	flow.reply.Close()
	_ = flow.session.send(protocol.Frame{Type: protocol.CloseStream, StreamID: flow.streamID})
	delete(mapper.flows, key)
}

func (mapper *linuxFullMapper) expireUDP() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-mapper.done:
			return
		case now := <-ticker.C:
			mapper.flowsMu.Lock()
			for key, flow := range mapper.flows {
				if now.Sub(time.Unix(0, flow.lastSeen.Load())) > 60*time.Second {
					mapper.closeUDPFlow(key, flow)
				}
			}
			mapper.flowsMu.Unlock()
		}
	}
}

func (mapper *linuxFullMapper) Close() error {
	var cleanupErr error
	mapper.closeOnce.Do(func() {
		// Detach the kernel interception rules first. This restores access to the
		// server immediately even if closing active tunnel flows takes time.
		cleanupErr = mapper.removeRules()
		close(mapper.done)
		mapper.tcp.Close()
		mapper.udp.Close()
		mapper.flowsMu.Lock()
		for key, flow := range mapper.flows {
			mapper.closeUDPFlow(key, flow)
		}
		mapper.flowsMu.Unlock()
	})
	return cleanupErr
}
