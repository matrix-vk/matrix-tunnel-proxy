// Package pki owns the private certificate authority used for TLS server certificates.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertificateFile = "matrix-ca.pem"
	caPrivateKeyFile  = "matrix-ca-key.pem"
)

type Authority struct {
	certificate    *x509.Certificate
	privateKey     crypto.Signer
	certificatePEM []byte
}

func LoadOrCreate(directory string) (*Authority, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	certificatePath := filepath.Join(directory, caCertificateFile)
	privateKeyPath := filepath.Join(directory, caPrivateKeyFile)
	certificatePEM, certificateErr := os.ReadFile(certificatePath)
	privateKeyPEM, privateKeyErr := os.ReadFile(privateKeyPath)
	if certificateErr == nil && privateKeyErr == nil {
		return parseAuthority(certificatePEM, privateKeyPEM)
	}
	if !errors.Is(certificateErr, os.ErrNotExist) || !errors.Is(privateKeyErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read certificate authority: cert=%v key=%v", certificateErr, privateKeyErr)
	}
	return createAuthority(certificatePath, privateKeyPath)
}

func (authority *Authority) CertificatePEM() []byte {
	return append([]byte(nil), authority.certificatePEM...)
}

// DeviceCredentials deterministically derives the permanent private key and
// Token for one bound record from the Controller CA key. Re-downloading the
// same record therefore produces the same identity without storing plaintext
// credentials in SQLite or invalidating an already-running package.
func (authority *Authority) DeviceCredentials(role, id string) (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	if role == "" || id == "" {
		return nil, nil, "", errors.New("device role and id are required")
	}
	rootKey, ok := authority.privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, "", errors.New("CA key cannot derive device credentials")
	}
	derive := func(purpose string) []byte {
		mac := hmac.New(sha256.New, rootKey)
		_, _ = mac.Write([]byte("matrix-proxy/v1/" + purpose + "/" + role + "/" + id))
		return mac.Sum(nil)
	}
	privateKey := ed25519.NewKeyFromSeed(derive("private-key"))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	token := base64.RawURLEncoding.EncodeToString(derive("token"))
	return publicKey, privateKey, token, nil
}

// CertificateNeedsRenewal reports whether a server certificate is invalid for
// its configured endpoint or is approaching expiry.
func CertificateNeedsRenewal(certificatePEM []byte, endpoint string, renewBefore time.Duration) bool {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return true
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return certificate.VerifyHostname(host) != nil || time.Until(certificate.NotAfter) <= renewBefore
}

// ControllerCertificate returns the persistent TLS identity used by the
// controller's agent endpoint.  Agents trust this certificate through the
// same private CA embedded in their bound package.
func (authority *Authority) ControllerCertificate(directory, endpoint string) (tls.Certificate, error) {
	certificatePath := filepath.Join(directory, "controller-cert.pem")
	keyPath := filepath.Join(directory, "controller-key.pem")
	if certificatePEM, certErr := os.ReadFile(certificatePath); certErr == nil {
		if keyPEM, keyErr := os.ReadFile(keyPath); keyErr == nil {
			if certificate, err := tls.X509KeyPair(certificatePEM, keyPEM); err == nil {
				host, _, splitErr := net.SplitHostPort(endpoint)
				if splitErr != nil {
					host = endpoint
				}
				host = strings.Trim(strings.TrimSpace(host), "[]")
				leaf, parseErr := x509.ParseCertificate(certificate.Certificate[0])
				if parseErr == nil && leaf.VerifyHostname(host) == nil {
					certificate.Leaf = leaf
					return certificate, nil
				}
			}
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificatePEM, err := authority.IssueDevice("controller", "server", endpoint, publicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certificatePEM, privatePEM)
}

func (authority *Authority) IssueDevice(id, role, endpoint string, publicKey ed25519.PublicKey) ([]byte, error) {
	if id == "" || role == "" || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid device certificate request")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         id,
			Organization:       []string{"Matrix Tunnel Proxy"},
			OrganizationalUnit: []string{role},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if role == "server" {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		addEndpointName(template, endpoint)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, publicKey, authority.privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), nil
}

func createAuthority(certificatePath, privateKeyPath string) (*Authority, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Matrix Tunnel Proxy Internal CA", Organization: []string{"Matrix Tunnel Proxy"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM}), 0o600); err != nil {
		return nil, err
	}
	return parseAuthority(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM}))
}

func parseAuthority(certificatePEM, privateKeyPEM []byte) (*Authority, error) {
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		return nil, errors.New("invalid CA certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, errors.New("invalid CA private key PEM")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA private key cannot sign certificates")
	}
	return &Authority{certificate: certificate, privateKey: signer, certificatePEM: certificatePEM}, nil
}

func addEndpointName(certificate *x509.Certificate, endpoint string) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if address := net.ParseIP(host); address != nil {
		certificate.IPAddresses = append(certificate.IPAddresses, address)
	} else if host != "" {
		certificate.DNSNames = append(certificate.DNSNames, host)
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
