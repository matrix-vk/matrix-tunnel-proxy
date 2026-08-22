package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/pki"
)

func TestDownloadedPackageFileModes(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	if err := addZipExecutable(writer, "client", []byte("binary")); err != nil {
		t.Fatal(err)
	}
	if err := addZipSecretFile(writer, "client.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := addZipFile(writer, "README.txt", []byte("read me")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint32{"client": 0o755, "client.json": 0o600, "README.txt": 0o644}
	for _, file := range reader.File {
		if got := uint32(file.Mode().Perm()); got != want[file.Name] {
			t.Fatalf("%s mode = %#o, want %#o", file.Name, got, want[file.Name])
		}
		delete(want, file.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing archive entries: %v", want)
	}
}

func TestWindowsServerDownloadIncludesFullMappingRuntime(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := OpenStore(filepath.Join(root, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := pki.LoadOrCreate(filepath.Join(root, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, token, err := authority.DeviceCredentials("server", "srv_windows")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := authority.IssueDevice("srv_windows", "server", "127.0.0.1:7000", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := store.CreateServer(ctx, "srv_windows", "windows", "127.0.0.1:7000", publicKey, certificate, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	superAdmin, err := store.CreateInitialSuperAdmin(ctx, "rootadmin", "correct-password")
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, _, err := store.CreateSession(ctx, superAdmin.ID)
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{"server.exe": []byte("exe"), "WinDivert.dll": []byte("dll"), "WinDivert64.sys": []byte("sys"), "WinDivert-LICENSE.txt": []byte("license")}
	for name, contents := range assets {
		if err := os.WriteFile(filepath.Join(binDir, name), contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(map[string]string{"platform": "windows-amd64"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/servers/srv_windows/download", strings.NewReader(string(body)))
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	recorder := httptest.NewRecorder()
	NewApp(store, "", binDir, "https://controller.example:8443", authority).Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("download status = %d: %s", recorder.Code, recorder.Body.String())
	}
	archive, err := zip.NewReader(bytes.NewReader(recorder.Body.Bytes()), int64(recorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"server.exe": true, "server.json": true, "README.txt": true, "WinDivert.dll": true, "WinDivert64.sys": true, "WinDivert-LICENSE.txt": true}
	for _, file := range archive.File {
		delete(want, file.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing Windows package entries: %v", want)
	}
	firstConfig := zipFileContents(t, archive, "server.json")
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/v1/servers/srv_windows/download", strings.NewReader(string(body)))
	secondRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	secondRecorder := httptest.NewRecorder()
	NewApp(store, "", binDir, "https://controller.example:8443", authority).Handler().ServeHTTP(secondRecorder, secondRequest)
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("second download status = %d: %s", secondRecorder.Code, secondRecorder.Body.String())
	}
	secondArchive, err := zip.NewReader(bytes.NewReader(secondRecorder.Body.Bytes()), int64(secondRecorder.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if secondConfig := zipFileContents(t, secondArchive, "server.json"); !bytes.Equal(firstConfig, secondConfig) {
		t.Fatal("re-downloading changed the bound server credentials")
	}
	servers, err := store.ListServers(ctx)
	if err != nil || len(servers) != 1 || servers[0].Platform != "windows" || !servers[0].FullMapping {
		t.Fatalf("server platform was not persisted: %+v, %v", servers, err)
	}
}

func zipFileContents(t *testing.T, archive *zip.Reader, name string) []byte {
	t.Helper()
	for _, file := range archive.File {
		if file.Name != name {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		contents, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	t.Fatalf("ZIP entry %s is missing", name)
	return nil
}

func TestCurrentServerCertificateRotatesForChangedEndpoint(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(t.TempDir() + "/controller.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authority, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldCertificate, err := authority.IssueDevice("srv_test", "server", "old.example.com:7000", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte("server-token"))
	if _, err := store.CreateServer(ctx, "srv_test", "server", "new.example.com:7000", publicKey, oldCertificate, tokenHash[:]); err != nil {
		t.Fatal(err)
	}
	app := NewApp(store, "", "", "", authority)
	rotated, err := app.currentServerCertificate(ctx, "srv_test")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(rotated)
	if block == nil {
		t.Fatal("rotated certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.VerifyHostname("new.example.com"); err != nil {
		t.Fatalf("rotated certificate hostname: %v", err)
	}
	stored, err := store.ServerCertificate(ctx, "srv_test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, rotated) {
		t.Fatal("rotated certificate was not persisted")
	}
}
