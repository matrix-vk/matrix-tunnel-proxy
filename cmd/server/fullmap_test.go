package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
)

func TestIPTablesExclusionCommands(t *testing.T) {
	got := iptablesExclusionCommands("MXP_TEST_T", "tcp", []portRange{{First: 22, Last: 22}, {First: 8000, Last: 8010}})
	want := [][]string{
		{"iptables", "-t", "mangle", "-A", "MXP_TEST_T", "-p", "tcp", "--dport", "22", "-j", "RETURN"},
		{"iptables", "-t", "mangle", "-A", "MXP_TEST_T", "-p", "tcp", "--dport", "8000:8010", "-j", "RETURN"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("iptablesExclusionCommands() = %#v; want %#v", got, want)
	}
}

func TestIPTablesReplyBypassCommand(t *testing.T) {
	got := iptablesReplyBypassCommand("MXP_TEST_T", "tcp")
	want := []string{"iptables", "-t", "mangle", "-A", "MXP_TEST_T", "-p", "tcp", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("iptablesReplyBypassCommand() = %#v; want %#v", got, want)
	}
}

func TestMatrixPolicyRuleRecognition(t *testing.T) {
	mark, table, ok := matrixPolicyRule(strings.Fields("32765: from all fwmark 0x4dac03 lookup 26019"))
	if !ok || mark != "0x4dac03" || table != "26019" {
		t.Fatalf("matrixPolicyRule() = %q, %q, %v", mark, table, ok)
	}
	if _, _, ok := matrixPolicyRule(strings.Fields("32764: from all fwmark 0x123 lookup 100")); ok {
		t.Fatal("matrixPolicyRule accepted an unrelated policy rule")
	}
}

func TestProjectRuleNameRecognition(t *testing.T) {
	for _, name := range []string{"mxp_43ceac03", "MXP_43CEAC03_T", "MXP_43CEAC03_U"} {
		prefix := "mxp_"
		if strings.HasPrefix(name, "MXP_") {
			prefix = "MXP_"
		}
		if !projectRuleName(name, prefix) {
			t.Fatalf("projectRuleName rejected %q", name)
		}
	}
	if projectRuleName("MXP_unrelated", "MXP_") {
		t.Fatal("projectRuleName accepted an unrelated chain")
	}
}

func TestBuildFullMappingSpecReservesTunnelAndOverrides(t *testing.T) {
	full := controller.Mapping{ID: "full", MappingType: "full", PublicIP: "203.0.113.10", ExcludedPorts: "22,100-105"}
	mappings := []controller.Mapping{
		full,
		{ID: "tcp", MappingType: "port", Status: "effective", Protocol: "tcp", PublicIP: "203.0.113.10", PublicPort: 443},
		{ID: "udp", MappingType: "port", Status: "effective", Protocol: "udp", PublicIP: "0.0.0.0", PublicPort: 53},
		{ID: "occupied", MappingType: "port", Status: "occupied", Protocol: "tcp", PublicIP: "203.0.113.10", PublicPort: 80},
	}
	spec := buildFullMappingSpec(full, mappings, 7000)
	if got := formatPortRanges(spec.ExcludedTCP); got != "22,100-105,443,3389,7000" {
		t.Fatalf("TCP exclusions = %q", got)
	}
	if got := formatPortRanges(spec.ExcludedUDP); got != "22,53,100-105" {
		t.Fatalf("UDP exclusions = %q", got)
	}
}

func TestPortRangeMembership(t *testing.T) {
	ranges := mergePortRanges(append(parsePortRanges("10-20,22,21"), portRange{First: 80, Last: 80}))
	if got := formatPortRanges(ranges); got != "10-22,80" {
		t.Fatalf("merged ranges = %q", got)
	}
	if !portIsExcluded(18, ranges) || portIsExcluded(23, ranges) {
		t.Fatal("port membership is incorrect")
	}
}
