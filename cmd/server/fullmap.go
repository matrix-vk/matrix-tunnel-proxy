package main

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
)

type fullMappingSpec struct {
	Mapping     controller.Mapping
	ExcludedTCP []portRange
	ExcludedUDP []portRange
}

type portRange struct{ First, Last int }

func buildFullMappingSpec(full controller.Mapping, mappings []controller.Mapping, tunnelPort int) fullMappingSpec {
	// Keep the standard SSH and RDP management ports reachable by default so
	// enabling a full mapping cannot immediately lock an administrator out.
	// Either port can still be tunneled intentionally with an explicit port
	// mapping, which owns its listener separately from the full mapper.
	tcp := append(parsePortRanges(full.ExcludedPorts), portRange{First: 22, Last: 22}, portRange{First: 3389, Last: 3389})
	udp := parsePortRanges(full.ExcludedPorts)
	if tunnelPort > 0 {
		tcp = append(tcp, portRange{tunnelPort, tunnelPort})
	}
	for _, item := range mappings {
		if item.Status != "effective" || item.MappingType != "port" || !mappingIPOverlap(full.PublicIP, item.PublicIP) {
			continue
		}
		if item.Protocol == "tcp" {
			tcp = append(tcp, portRange{item.PublicPort, item.PublicPort})
		} else if item.Protocol == "udp" {
			udp = append(udp, portRange{item.PublicPort, item.PublicPort})
		}
	}
	return fullMappingSpec{Mapping: full, ExcludedTCP: mergePortRanges(tcp), ExcludedUDP: mergePortRanges(udp)}
}

func mappingIPOverlap(first, second string) bool {
	return first == second || net.ParseIP(first).IsUnspecified() || net.ParseIP(second).IsUnspecified()
}

func parsePortRanges(spec string) []portRange {
	var result []portRange
	for _, part := range strings.Split(spec, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		firstText, lastText, ranged := strings.Cut(part, "-")
		first, _ := strconv.Atoi(firstText)
		last := first
		if ranged {
			last, _ = strconv.Atoi(lastText)
		}
		if first > 0 && last >= first {
			result = append(result, portRange{first, last})
		}
	}
	return result
}

func mergePortRanges(ranges []portRange) []portRange {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].First < ranges[j].First })
	merged := make([]portRange, 0, len(ranges))
	for _, current := range ranges {
		if len(merged) == 0 || current.First > merged[len(merged)-1].Last+1 {
			merged = append(merged, current)
		} else if current.Last > merged[len(merged)-1].Last {
			merged[len(merged)-1].Last = current.Last
		}
	}
	return merged
}

func formatPortRanges(ranges []portRange) string {
	parts := make([]string, 0, len(ranges))
	for _, current := range ranges {
		if current.First == current.Last {
			parts = append(parts, strconv.Itoa(current.First))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", current.First, current.Last))
		}
	}
	return strings.Join(parts, ",")
}

func portIsExcluded(port int, ranges []portRange) bool {
	for _, current := range ranges {
		if port >= current.First && port <= current.Last {
			return true
		}
	}
	return false
}

func iptablesExclusionCommands(chain, network string, excluded []portRange) [][]string {
	commands := make([][]string, 0, len(excluded))
	for _, current := range excluded {
		port := strconv.Itoa(current.First)
		if current.First != current.Last {
			port += ":" + strconv.Itoa(current.Last)
		}
		commands = append(commands, []string{"iptables", "-t", "mangle", "-A", chain, "-p", network, "--dport", port, "-j", "RETURN"})
	}
	return commands
}

func iptablesReplyBypassCommand(chain, network string) []string {
	// A reply-direction packet belongs to a connection initiated by this Server
	// (Controller polling, DNS, package downloads, and so on). Incoming public
	// connections remain in conntrack's ORIGINAL direction and are intercepted.
	return []string{"iptables", "-t", "mangle", "-A", chain, "-p", network, "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"}
}

func projectRuleName(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return false
	}
	for _, current := range value[len(prefix):] {
		if !((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f') || (current >= 'A' && current <= 'F') || current == '_' || current == 'T' || current == 'U') {
			return false
		}
	}
	return true
}

func matrixPolicyRule(fields []string) (mark, table string, ok bool) {
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "fwmark" {
			mark = fields[index+1]
		}
		if fields[index] == "lookup" || fields[index] == "table" {
			table = fields[index+1]
		}
	}
	numericMark := strings.Split(mark, "/")[0]
	value, err := strconv.ParseUint(numericMark, 0, 32)
	return mark, table, err == nil && value&0xff0000 == 0x4d0000 && table != ""
}

func mappingSignature(item controller.Mapping, spec fullMappingSpec) string {
	if item.ID == "" {
		return ""
	}
	return strings.Join([]string{item.MappingType, item.Protocol, item.PublicIP, strconv.Itoa(item.PublicPort), item.ClientID, item.TargetHost, strconv.Itoa(item.TargetPort), item.AccessMode, item.AllowedIPs, formatPortRanges(spec.ExcludedTCP), formatPortRanges(spec.ExcludedUDP)}, "|")
}

type fullMapper interface{ io.Closer }
