package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestDeviceCredentialsRemainStableAcrossReload(t *testing.T) {
	directory := t.TempDir()
	firstAuthority, err := LoadOrCreate(directory)
	if err != nil {
		t.Fatal(err)
	}
	firstPublic, firstPrivate, firstToken, err := firstAuthority.DeviceCredentials("client", "cli_test")
	if err != nil {
		t.Fatal(err)
	}
	secondAuthority, err := LoadOrCreate(directory)
	if err != nil {
		t.Fatal(err)
	}
	secondPublic, secondPrivate, secondToken, err := secondAuthority.DeviceCredentials("client", "cli_test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstPublic, secondPublic) || !bytes.Equal(firstPrivate, secondPrivate) || firstToken != secondToken {
		t.Fatal("bound credentials changed after Controller restart")
	}
}

func TestIssueServerCertificate(t *testing.T) {
	authority, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("load authority: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certificatePEM, err := authority.IssueDevice("srv_test", "server", "edge.example.com:7000", publicKey)
	if err != nil {
		t.Fatalf("issue device: %v", err)
	}
	block, _ := pem.Decode(certificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(authority.CertificatePEM())
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "edge.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify certificate: %v", err)
	}
}

func TestCertificateRenewalDetection(t *testing.T) {
	authority, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := authority.IssueDevice("srv_test", "server", "edge.example.com:7000", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if CertificateNeedsRenewal(certificatePEM, "edge.example.com:7000", 24*time.Hour) {
		t.Fatal("fresh certificate unexpectedly needs renewal")
	}
	if !CertificateNeedsRenewal(certificatePEM, "new.example.com:7000", 24*time.Hour) {
		t.Fatal("endpoint change did not require renewal")
	}
	if !CertificateNeedsRenewal(certificatePEM, "edge.example.com:7000", 2*365*24*time.Hour) {
		t.Fatal("renewal window did not require renewal")
	}
}

func TestControllerCertificateRotatesWhenEndpointChanges(t *testing.T) {
	directory := t.TempDir()
	authority, err := LoadOrCreate(directory)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.ControllerCertificate(directory, "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.ControllerCertificate(directory, "controller.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate[0]) == string(second.Certificate[0]) {
		t.Fatal("certificate was not rotated for a new endpoint")
	}
	leaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("controller.example.com"); err != nil {
		t.Fatalf("new certificate hostname: %v", err)
	}
}
