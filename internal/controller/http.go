package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/matrix-vk/matrix-tunnel-proxy/internal/identity"
	"github.com/matrix-vk/matrix-tunnel-proxy/internal/pki"
)

type App struct {
	store       *Store
	webDir      string
	agentBinDir string
	agentURL    string
	authority   *pki.Authority
}

func NewApp(store *Store, webDir, agentBinDir, agentURL string, authority *pki.Authority) *App {
	return &App{store: store, webDir: webDir, agentBinDir: agentBinDir, agentURL: strings.TrimRight(agentURL, "/"), authority: authority}
}

func (a *App) Handler() http.Handler {
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/v1/auth/me", a.authMe)
	protected.HandleFunc("POST /api/v1/auth/logout", a.logout)
	protected.HandleFunc("PATCH /api/v1/auth/password", a.changeOwnPassword)
	protected.HandleFunc("GET /api/v1/users", a.listUsers)
	protected.HandleFunc("POST /api/v1/users", a.createUser)
	protected.HandleFunc("PATCH /api/v1/users/{userId}", a.updateUser)
	protected.HandleFunc("GET /api/v1/servers", a.listServers)
	protected.HandleFunc("POST /api/v1/servers", a.createServer)
	protected.HandleFunc("DELETE /api/v1/servers/{serverId}", a.deleteServer)
	protected.HandleFunc("POST /api/v1/servers/{serverId}/download", a.downloadServer)
	protected.HandleFunc("GET /api/v1/servers/{serverId}/clients", a.listClients)
	protected.HandleFunc("POST /api/v1/servers/{serverId}/clients", a.createClient)
	protected.HandleFunc("DELETE /api/v1/servers/{serverId}/clients/{clientId}", a.deleteClient)
	protected.HandleFunc("POST /api/v1/servers/{serverId}/clients/{clientId}/download", a.downloadClient)
	protected.HandleFunc("GET /api/v1/servers/{serverId}/mappings", a.listMappings)
	protected.HandleFunc("POST /api/v1/servers/{serverId}/mappings", a.createMapping)
	protected.HandleFunc("DELETE /api/v1/servers/{serverId}/mappings/{mappingId}", a.deleteMapping)
	protected.HandleFunc("PATCH /api/v1/servers/{serverId}/mappings/{mappingId}", a.updateMappingPriority)
	protected.HandleFunc("GET /api/v1/audit-logs", a.listAuditLogs)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("GET /api/v1/auth/status", a.authStatus)
	mux.HandleFunc("POST /api/v1/auth/database/setup", a.setupDatabase)
	mux.HandleFunc("POST /api/v1/auth/setup", a.setupSuperAdmin)
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.Handle("/api/v1/", a.requireAuth(protected))
	mux.Handle("/", a.webHandler())
	return withJSON(mux)
}

// AgentHandler is served only from Controller's separate TLS listener.
// Bound Server tokens authenticate status reports and configuration pulls.
func (a *App) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/servers/{serverId}/report", a.reportServer)
	mux.HandleFunc("GET /agent/v1/servers/{serverId}/config", a.serverConfig)
	return withJSON(mux)
}

func (a *App) authenticatedServer(r *http.Request) (string, error) {
	serverID := r.PathValue("serverId")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		return "", errors.New("server token is required")
	}
	storedHash, err := a.store.ServerTokenHash(r.Context(), serverID)
	if err != nil {
		return "", err
	}
	providedHash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(storedHash, providedHash[:]) != 1 {
		return "", errors.New("server token is invalid or revoked")
	}
	return serverID, nil
}

func (a *App) reportServer(w http.ResponseWriter, r *http.Request) {
	serverID, err := a.authenticatedServer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	var report struct {
		OnlineClients []string `json:"onlineClients"`
		PublicIPs     []string `json:"publicIps"`
		Platform      string   `json:"platform"`
		Architecture  string   `json:"architecture"`
		FullMapping   bool     `json:"fullMapping"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&report)
	}
	if err := a.store.ReportServer(r.Context(), serverID, report.OnlineClients, report.PublicIPs, report.Platform, report.Architecture, report.FullMapping); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) serverConfig(w http.ResponseWriter, r *http.Request) {
	serverID, err := a.authenticatedServer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	config, err := a.store.ServerConfig(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	certificatePEM, err := a.currentServerCertificate(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	config.CertificatePEM = string(certificatePEM)
	writeJSON(w, http.StatusOK, config)
}

func (a *App) currentServerCertificate(ctx context.Context, serverID string) ([]byte, error) {
	certificatePEM, err := a.store.ServerCertificate(ctx, serverID)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.store.ServerEndpoint(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if !pki.CertificateNeedsRenewal(certificatePEM, endpoint, 30*24*time.Hour) {
		return certificatePEM, nil
	}
	publicKey, err := a.store.ServerPublicKey(ctx, serverID)
	if err != nil {
		return nil, err
	}
	certificatePEM, err = a.authority.IssueDevice(serverID, "server", endpoint, publicKey)
	if err != nil {
		return nil, err
	}
	if err := a.store.UpdateServerCertificate(ctx, serverID, certificatePEM); err != nil {
		return nil, err
	}
	_ = a.store.RecordAudit(ctx, "rotate", "server-certificate", serverID, endpoint)
	return certificatePEM, nil
}

func (a *App) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) listServers(w http.ResponseWriter, r *http.Request) {
	user, _ := authenticatedUser(r.Context())
	servers, err := a.store.ListServersForUser(r.Context(), user.ID, user.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, servers)
}

func (a *App) createServer(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	if a.authority == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("certificate authority is unavailable"))
		return
	}
	serverID := NewID("srv")
	publicKey, _, authToken, err := a.authority.DeviceCredentials("server", serverID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	certificate, err := a.authority.IssueDevice(serverID, "server", strings.TrimSpace(request.Endpoint), publicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tokenHash := sha256.Sum256([]byte(authToken))
	user, _ := authenticatedUser(r.Context())
	server, err := a.store.CreateServerForOwner(r.Context(), serverID, strings.TrimSpace(request.Name), strings.TrimSpace(request.Endpoint), user.ID, publicKey, certificate, tokenHash[:])
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"server": server})
}

func (a *App) deleteServer(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	if err := a.store.DeleteServer(r.Context(), r.PathValue("serverId")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) downloadServer(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	var request struct {
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	endpoint, err := a.store.ServerEndpoint(r.Context(), r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("server not found"))
		return
	}

	binaryName, archiveName, err := agentBinaryName("server", request.Platform)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	binary, err := os.ReadFile(filepath.Join(a.agentBinDir, binaryName))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("server package binary is unavailable"))
		return
	}
	publicKey, privateKey, authToken, err := a.authority.DeviceCredentials("server", r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	storedPublicKey, err := a.store.ServerPublicKey(r.Context(), r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	storedTokenHash, err := a.store.ServerTokenHash(r.Context(), r.PathValue("serverId"))
	derivedTokenHash := sha256.Sum256([]byte(authToken))
	if err != nil || subtle.ConstantTimeCompare(storedPublicKey, publicKey) != 1 || subtle.ConstantTimeCompare(storedTokenHash, derivedTokenHash[:]) != 1 {
		writeError(w, http.StatusConflict, errors.New("这是升级前创建的服务器端记录，控制端未保存其原始明文密钥；请保留原程序包，或重新创建记录后使用重复下载"))
		return
	}
	certificate, err := a.store.ServerCertificate(r.Context(), r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	config, err := json.MarshalIndent(identity.Config{Role: "server", ServerID: r.PathValue("serverId"), Endpoint: endpoint, Controller: a.agentURL, PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey), Token: authToken, CertificatePEM: string(certificate), CAPEM: string(a.authority.CertificatePEM())}, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	if err := addZipExecutable(zipWriter, archiveName, binary); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := addZipSecretFile(zipWriter, "server.json", config); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	readme := "Keep server.json beside " + archiveName + " and run the program from this directory. This package is bound to one server record.\r\n"
	if request.Platform == "windows-amd64" {
		for _, asset := range []string{"WinDivert.dll", "WinDivert64.sys", "WinDivert-LICENSE.txt"} {
			contents, err := os.ReadFile(filepath.Join(a.agentBinDir, asset))
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("Windows full-mapping component is unavailable"))
				return
			}
			if err := addZipFile(zipWriter, asset, contents); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		readme += "Run server.exe as Administrator when TCP+UDP full mapping is enabled. WinDivert.dll and WinDivert64.sys must remain beside server.exe.\r\n"
	} else if strings.HasPrefix(request.Platform, "linux-") {
		readme += "TCP+UDP full mapping requires root, nftables, and iproute2. Port mappings can run without nftables.\r\n"
	} else {
		readme += "macOS supports TCP/UDP port mappings; full mapping is intentionally unavailable.\r\n"
	}
	if err := addZipFile(zipWriter, "README.txt", []byte(readme)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := zipWriter.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	platform, architecture, _ := strings.Cut(request.Platform, "-")
	if err := a.store.SetServerPlatform(r.Context(), r.PathValue("serverId"), platform, architecture, platform == "windows" || platform == "linux"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	_ = a.store.RecordAudit(r.Context(), "download", "server", r.PathValue("serverId"), request.Platform)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=matrix-tunnel-proxy-server-"+r.PathValue("serverId")+".zip")
	_, _ = w.Write(archive.Bytes())
}

func (a *App) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	user, _ := authenticatedUser(r.Context())
	items, err := a.store.ListAuditLogsForUser(r.Context(), limit, user.ID, user.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func addZipFile(writer *zip.Writer, name string, contents []byte) error {
	return addZipFileMode(writer, name, contents, 0o644)
}

func addZipSecretFile(writer *zip.Writer, name string, contents []byte) error {
	return addZipFileMode(writer, name, contents, 0o600)
}

func addZipFileMode(writer *zip.Writer, name string, contents []byte, mode fs.FileMode) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(mode)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(contents)
	return err
}

func addZipExecutable(writer *zip.Writer, name string, contents []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o755)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(contents)
	return err
}

func agentBinaryName(role, platform string) (sourceName, archiveName string, err error) {
	switch platform {
	case "windows-amd64":
		return role + ".exe", role + ".exe", nil
	case "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64":
		return role + "-" + platform, role, nil
	default:
		return "", "", errors.New("unsupported target platform")
	}
}

func (a *App) listClients(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	clients, err := a.store.ListClients(r.Context(), r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (a *App) createClient(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	var request struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	clientID := NewID("cli")
	_, _, authToken, err := a.authority.DeviceCredentials("client", clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	tokenHash := sha256.Sum256([]byte(authToken))
	client, err := a.store.CreateClient(r.Context(), clientID, r.PathValue("serverId"), strings.TrimSpace(request.Name), strings.TrimSpace(request.Platform), tokenHash[:])
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"client": client})
}

func (a *App) deleteClient(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	if err := a.store.DeleteClient(r.Context(), r.PathValue("serverId"), r.PathValue("clientId")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) listMappings(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	items, err := a.store.ListMappings(r.Context(), r.PathValue("serverId"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *App) createMapping(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	var request struct {
		ClientID      string `json:"clientId"`
		Protocol      string `json:"protocol"`
		MappingType   string `json:"mappingType"`
		PublicIP      string `json:"publicIp"`
		PublicPort    int    `json:"publicPort"`
		TargetHost    string `json:"targetHost"`
		TargetPort    int    `json:"targetPort"`
		ExcludedPorts string `json:"excludedPorts"`
		Priority      int    `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	protocolName := strings.ToLower(strings.TrimSpace(request.Protocol))
	if protocolName == "" {
		protocolName = "tcp"
	}
	mappingType := strings.ToLower(strings.TrimSpace(request.MappingType))
	if mappingType == "" {
		mappingType = "port"
	}
	if mappingType == "full" {
		platform, err := a.store.ServerPlatform(r.Context(), r.PathValue("serverId"))
		if err != nil {
			writeError(w, http.StatusNotFound, errors.New("server not found"))
			return
		}
		if platform == "darwin" {
			writeError(w, http.StatusBadRequest, errors.New("macOS server packages support TCP/UDP port mappings only"))
			return
		}
		protocolName = "both"
		request.PublicPort = 0
		request.TargetPort = 0
	}
	item, err := a.store.CreateMapping(r.Context(), Mapping{ID: NewID("map"), ServerID: r.PathValue("serverId"), ClientID: request.ClientID, PublicIP: strings.TrimSpace(request.PublicIP), Protocol: protocolName, MappingType: mappingType, PublicPort: request.PublicPort, TargetHost: strings.TrimSpace(request.TargetHost), TargetPort: request.TargetPort, ExcludedPorts: strings.TrimSpace(request.ExcludedPorts), Priority: request.Priority})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (a *App) deleteMapping(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	if err := a.store.DeleteMapping(r.Context(), r.PathValue("serverId"), r.PathValue("mappingId")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) updateMappingPriority(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	var request struct {
		Priority int `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	if err := a.store.UpdateMappingPriority(r.Context(), r.PathValue("serverId"), r.PathValue("mappingId"), request.Priority); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) downloadClient(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeServer(w, r) {
		return
	}
	var request struct {
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	serverID, clientID := r.PathValue("serverId"), r.PathValue("clientId")
	endpoint, err := a.store.ServerEndpoint(r.Context(), serverID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("server not found"))
		return
	}
	binaryName, archiveName, err := agentBinaryName("client", request.Platform)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	binary, err := os.ReadFile(filepath.Join(a.agentBinDir, binaryName))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("client package binary is unavailable"))
		return
	}
	_, _, authToken, err := a.authority.DeviceCredentials("client", clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	storedTokenHash, err := a.store.ClientTokenHash(r.Context(), serverID, clientID)
	derivedTokenHash := sha256.Sum256([]byte(authToken))
	if err != nil || subtle.ConstantTimeCompare(storedTokenHash, derivedTokenHash[:]) != 1 {
		writeError(w, http.StatusConflict, errors.New("这是升级前创建的客户端记录，控制端未保存其原始明文 Token；请保留原程序包，或重新创建记录后使用重复下载"))
		return
	}
	config, err := json.MarshalIndent(identity.Config{Role: "client", ClientID: clientID, Server: endpoint, Token: authToken, CAPEM: string(a.authority.CertificatePEM())}, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	if err := addZipExecutable(zipWriter, archiveName, binary); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := addZipSecretFile(zipWriter, "client.json", config); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := addZipFile(zipWriter, "README.txt", []byte("Keep client.json beside "+archiveName+" and run the program from this directory. This package is bound to one client record.\r\n")); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := zipWriter.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.store.SetClientPlatform(r.Context(), serverID, clientID, request.Platform); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	_ = a.store.RecordAudit(r.Context(), "download", "client", clientID, request.Platform)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=matrix-tunnel-proxy-client-"+clientID+".zip")
	_, _ = w.Write(archive.Bytes())
}

func (a *App) webHandler() http.Handler {
	if info, err := os.Stat(a.webDir); err == nil && info.IsDir() {
		return spaFileServer(os.DirFS(a.webDir))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Web console assets are unavailable. Build web/dist or pass -web-dir."))
	})
}

func spaFileServer(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if requestedPath == "." {
			requestedPath = "index.html"
		}
		if _, err := fs.Stat(files, requestedPath); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func withJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
