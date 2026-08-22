package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/controller"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/pki"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	agentListen := flag.String("agent-listen", ":8443", "TLS listener for server agents")
	agentURL := flag.String("agent-url", "https://127.0.0.1:8443", "public HTTPS URL of the agent listener")
	databasePath := flag.String("db", defaultDatabasePath(), "SQLite database path")
	webDirectory := flag.String("web-dir", defaultWebDirectory(), "external built web console directory")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*databasePath), 0o700); err != nil {
		log.Fatalf("create data directory: %v", err)
	}

	store, err := controller.OpenStore(*databasePath)
	if err != nil {
		log.Fatalf("open SQLite database: %v", err)
	}
	defer store.Close()
	authority, err := pki.LoadOrCreate(filepath.Join(filepath.Dir(*databasePath), "pki"))
	if err != nil {
		log.Fatalf("load internal certificate authority: %v", err)
	}

	listenerEndpoint, err := endpointFromURL(*agentURL)
	if err != nil {
		log.Fatalf("invalid agent URL: %v", err)
	}
	controllerCertificate, err := authority.ControllerCertificate(filepath.Join(filepath.Dir(*databasePath), "pki"), listenerEndpoint)
	if err != nil {
		log.Fatalf("create controller agent certificate: %v", err)
	}
	app := controller.NewApp(store, *webDirectory, agentBinaryDirectory(), *agentURL, authority)
	server := &http.Server{
		Addr:              *listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	agentServer := &http.Server{Addr: *agentListen, Handler: app.AgentHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{controllerCertificate}, MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		log.Printf("controller agent endpoint listening with TLS on %s", *agentListen)
		if err := agentServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("agent endpoint stopped: %v", err)
		}
	}()
	log.Printf("controller web console listening on %s", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("controller stopped: %v", err)
	}
}

func endpointFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", fmt.Errorf("must be an https URL")
	}
	return parsed.Host, nil
}

func defaultWebDirectory() string {
	executable, err := os.Executable()
	if err != nil {
		return "./web/dist"
	}
	executableDirectory := filepath.Dir(executable)
	candidates := []string{
		filepath.Join(executableDirectory, "web", "dist"),
		filepath.Join(executableDirectory, "..", "web", "dist"),
		filepath.Join(".", "web", "dist"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return filepath.Clean(candidate)
		}
	}
	return filepath.Clean(candidates[0])
}

func defaultDatabasePath() string {
	executable, err := os.Executable()
	if err != nil {
		return "./data/controller.db"
	}
	return filepath.Join(filepath.Dir(executable), "data", "controller.db")
}

func agentBinaryDirectory() string {
	executable, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(executable)
}
