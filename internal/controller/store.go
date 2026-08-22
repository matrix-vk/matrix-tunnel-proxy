package controller

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Server struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Endpoint       string    `json:"endpoint"`
	Status         string    `json:"status"`
	ConfigRevision int64     `json:"configRevision"`
	PublicIPs      []string  `json:"publicIps"`
	Platform       string    `json:"platform"`
	Architecture   string    `json:"architecture"`
	FullMapping    bool      `json:"fullMapping"`
	OwnerUserID    string    `json:"ownerUserId,omitempty"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Client struct {
	ID        string    `json:"id"`
	ServerID  string    `json:"serverId"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

type ServerConfig struct {
	Revision       int64              `json:"revision"`
	CertificatePEM string             `json:"certificatePem"`
	Clients        []ClientCredential `json:"clients"`
	Mappings       []Mapping          `json:"mappings"`
}

type ClientCredential struct {
	ID        string `json:"id"`
	TokenHash string `json:"tokenHash"`
}

type AuditLog struct {
	ID           int64     `json:"id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	Detail       string    `json:"detail"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Mapping struct {
	ID            string    `json:"id"`
	ServerID      string    `json:"serverId"`
	ClientID      string    `json:"clientId"`
	PublicIP      string    `json:"publicIp"`
	Protocol      string    `json:"protocol"`
	MappingType   string    `json:"mappingType"`
	PublicPort    int       `json:"publicPort"`
	TargetHost    string    `json:"targetHost"`
	TargetPort    int       `json:"targetPort"`
	ExcludedPorts string    `json:"excludedPorts,omitempty"`
	Priority      int       `json:"priority"`
	Status        string    `json:"status"`
	OccupiedBy    string    `json:"occupiedByMappingId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	hadSettings, err := sqliteTableExists(ctx, s.db, "system_settings")
	if err != nil {
		return err
	}
	hadBusinessSchema, err := sqliteTableExists(ctx, s.db, "servers")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS system_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS servers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			endpoint TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			public_key BLOB,
			certificate_pem BLOB,
			auth_token_hash BLOB,
			config_revision INTEGER NOT NULL DEFAULT 1,
			last_seen_at TEXT,
			reported_ips TEXT NOT NULL DEFAULT '[]',
			platform TEXT NOT NULL DEFAULT '',
			architecture TEXT NOT NULL DEFAULT '',
			full_mapping INTEGER NOT NULL DEFAULT 0,
			owner_user_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL REFERENCES servers(id),
			name TEXT NOT NULL,
			platform TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			public_key BLOB,
			certificate_pem BLOB,
			auth_token_hash BLOB,
			created_at TEXT NOT NULL,
			UNIQUE(server_id, name)
		);
		CREATE TABLE IF NOT EXISTS mappings (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL REFERENCES servers(id),
			client_id TEXT NOT NULL REFERENCES clients(id),
			public_ip TEXT NOT NULL,
			protocol TEXT NOT NULL,
			mapping_type TEXT NOT NULL,
			public_port INTEGER,
			target_host TEXT NOT NULL,
			target_port INTEGER,
			priority INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'pending',
			occupied_by_mapping_id TEXT,
			excluded_ports TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			detail TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_salt BLOB NOT NULL,
			password_hash BLOB NOT NULL,
			password_iterations INTEGER NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			is_super_admin INTEGER NOT NULL DEFAULT 0,
			manual_locked INTEGER NOT NULL DEFAULT 0,
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS sessions (
			token_hash BLOB PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	`)
	if err != nil {
		return err
	}
	if !hadSettings {
		initialized := "0"
		if hadBusinessSchema {
			initialized = "1"
		}
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO system_settings (key, value) VALUES ('database_initialized', ?)`, initialized); err != nil {
			return err
		}
	}
	if err := ensureColumn(ctx, s.db, "servers", "public_key BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "certificate_pem BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "clients", "public_key BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "clients", "certificate_pem BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "auth_token_hash BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "clients", "auth_token_hash BLOB"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "reported_ips TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "platform TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "architecture TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "full_mapping INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "servers", "owner_user_id TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "audit_logs", "user_id TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "mappings", "excluded_ports TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return nil
}

func sqliteTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func (s *Store) DatabaseInitialized(ctx context.Context) (bool, error) {
	var value string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'database_initialized'`).Scan(&value); err != nil {
		return false, err
	}
	return value == "1", nil
}

func (s *Store) InitializeDatabase(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO system_settings (key, value) VALUES ('database_initialized', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	return err
}

func (s *Store) SiteName(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'site_name'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "Matrix Tunnel Proxy", nil
	}
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "Matrix Tunnel Proxy", nil
	}
	return value, nil
}

func ensureColumn(ctx context.Context, db *sql.DB, table, definition string) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+definition)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	return nil
}

func (s *Store) ListServers(ctx context.Context) ([]Server, error) {
	return s.ListServersForUser(ctx, "", true)
}

func (s *Store) ListServersForUser(ctx context.Context, userID string, all bool) ([]Server, error) {
	query := `SELECT id, name, endpoint, status, config_revision, COALESCE(last_seen_at, ''), COALESCE(reported_ips, '[]'), COALESCE(platform, ''), COALESCE(architecture, ''), COALESCE(full_mapping, 0), COALESCE(owner_user_id, ''), created_at FROM servers`
	args := make([]any, 0, 1)
	if !all {
		query += ` WHERE owner_user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := make([]Server, 0)
	for rows.Next() {
		var server Server
		var lastSeen, reportedIPs, created string
		if err := rows.Scan(&server.ID, &server.Name, &server.Endpoint, &server.Status, &server.ConfigRevision, &lastSeen, &reportedIPs, &server.Platform, &server.Architecture, &server.FullMapping, &server.OwnerUserID, &created); err != nil {
			return nil, err
		}
		server.LastSeenAt, _ = time.Parse(time.RFC3339, lastSeen)
		_ = json.Unmarshal([]byte(reportedIPs), &server.PublicIPs)
		if server.PublicIPs == nil {
			server.PublicIPs = make([]string, 0)
		}
		if server.Status == "online" && (server.LastSeenAt.IsZero() || time.Since(server.LastSeenAt) > 60*time.Second) {
			server.Status = "offline"
		}
		server.CreatedAt, _ = time.Parse(time.RFC3339, created)
		servers = append(servers, server)
	}
	return servers, rows.Err()
}

func (s *Store) CreateServer(ctx context.Context, id, name, endpoint string, publicKey, certificatePEM, tokenHash []byte) (Server, error) {
	return s.CreateServerForOwner(ctx, id, name, endpoint, "", publicKey, certificatePEM, tokenHash)
}

func (s *Store) CreateServerForOwner(ctx context.Context, id, name, endpoint, ownerUserID string, publicKey, certificatePEM, tokenHash []byte) (Server, error) {
	if id == "" || name == "" || endpoint == "" {
		return Server{}, errors.New("name and endpoint are required")
	}
	if len(publicKey) != ed25519.PublicKeySize || len(certificatePEM) == 0 || len(tokenHash) != 32 {
		return Server{}, errors.New("server identity is invalid")
	}
	server := Server{ID: id, Name: name, Endpoint: endpoint, Status: "pending", ConfigRevision: 1, OwnerUserID: ownerUserID, CreatedAt: time.Now().UTC()}
	_, err := s.db.ExecContext(ctx, `INSERT INTO servers (id, name, endpoint, status, public_key, certificate_pem, auth_token_hash, config_revision, owner_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, server.ID, server.Name, server.Endpoint, server.Status, publicKey, certificatePEM, tokenHash, server.ConfigRevision, ownerUserID, server.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return Server{}, fmt.Errorf("insert server: %w", err)
	}
	if err := s.audit(ctx, "create", "server", server.ID, server.Name); err != nil {
		return Server{}, err
	}
	return server, nil
}

func (s *Store) CanAccessServer(ctx context.Context, serverID, userID string, all bool) (bool, error) {
	var count int
	query := `SELECT COUNT(1) FROM servers WHERE id = ?`
	args := []any{serverID}
	if !all {
		query += ` AND owner_user_id = ?`
		args = append(args, userID)
	}
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func (s *Store) ServerPublicKey(ctx context.Context, serverID string) (ed25519.PublicKey, error) {
	var publicKey []byte
	if err := s.db.QueryRowContext(ctx, `SELECT public_key FROM servers WHERE id = ?`, serverID).Scan(&publicKey); err != nil {
		return nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("server has no valid provisioning key")
	}
	return ed25519.PublicKey(publicKey), nil
}

func (s *Store) ServerCertificate(ctx context.Context, serverID string) ([]byte, error) {
	var certificate []byte
	if err := s.db.QueryRowContext(ctx, `SELECT certificate_pem FROM servers WHERE id = ?`, serverID).Scan(&certificate); err != nil {
		return nil, err
	}
	if len(certificate) == 0 {
		return nil, errors.New("server has no certificate")
	}
	return certificate, nil
}

func (s *Store) UpdateServerCertificate(ctx context.Context, serverID string, certificatePEM []byte) error {
	if len(certificatePEM) == 0 {
		return errors.New("server certificate is empty")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE servers SET certificate_pem = ? WHERE id = ?`, certificatePEM, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("server not found")
	}
	return nil
}

func (s *Store) RotateServerIdentity(ctx context.Context, serverID, platform, architecture string, fullMapping bool, publicKey, certificatePEM, tokenHash []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || len(certificatePEM) == 0 || len(tokenHash) != 32 {
		return errors.New("server identity is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE servers SET public_key = ?, certificate_pem = ?, auth_token_hash = ?, platform = ?, architecture = ?, full_mapping = ?, status = 'pending', last_seen_at = NULL, config_revision = config_revision + 1 WHERE id = ?`, publicKey, certificatePEM, tokenHash, platform, architecture, fullMapping, serverID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("server not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE clients SET status = 'offline' WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ClientIdentity(ctx context.Context, serverID, clientID string) (ed25519.PublicKey, []byte, error) {
	var publicKey, certificate []byte
	if err := s.db.QueryRowContext(ctx, `SELECT public_key, certificate_pem FROM clients WHERE id = ? AND server_id = ?`, clientID, serverID).Scan(&publicKey, &certificate); err != nil {
		return nil, nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize || len(certificate) == 0 {
		return nil, nil, errors.New("client has no valid identity")
	}
	return ed25519.PublicKey(publicKey), certificate, nil
}

func (s *Store) ClientTokenHash(ctx context.Context, serverID, clientID string) ([]byte, error) {
	var tokenHash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT auth_token_hash FROM clients WHERE id = ? AND server_id = ?`, clientID, serverID).Scan(&tokenHash); err != nil {
		return nil, err
	}
	if len(tokenHash) != 32 {
		return nil, errors.New("client token is unavailable")
	}
	return tokenHash, nil
}

func (s *Store) RotateClientToken(ctx context.Context, serverID, clientID, platform string, tokenHash []byte) error {
	if platform == "" || len(tokenHash) != 32 {
		return errors.New("client identity is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE clients SET auth_token_hash = ?, platform = ?, status = 'pending' WHERE id = ? AND server_id = ?`, tokenHash, platform, clientID, serverID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("client not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, serverID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetClientPlatform(ctx context.Context, serverID, clientID, platform string) error {
	if platform == "" {
		return errors.New("client platform is required")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET platform = ? WHERE id = ? AND server_id = ?`, platform, clientID, serverID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("client not found")
	}
	return nil
}

func (s *Store) ServerEndpoint(ctx context.Context, serverID string) (string, error) {
	var endpoint string
	if err := s.db.QueryRowContext(ctx, `SELECT endpoint FROM servers WHERE id = ?`, serverID).Scan(&endpoint); err != nil {
		return "", err
	}
	return endpoint, nil
}

func (s *Store) SetServerPlatform(ctx context.Context, serverID, platform, architecture string, fullMapping bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE servers SET platform = ?, architecture = ?, full_mapping = ? WHERE id = ?`, platform, architecture, fullMapping, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("server not found")
	}
	return nil
}

func (s *Store) ServerPlatform(ctx context.Context, serverID string) (string, error) {
	var platform string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(platform, '') FROM servers WHERE id = ?`, serverID).Scan(&platform); err != nil {
		return "", err
	}
	return platform, nil
}

func (s *Store) ServerTokenHash(ctx context.Context, serverID string) ([]byte, error) {
	var tokenHash []byte
	if err := s.db.QueryRowContext(ctx, `SELECT auth_token_hash FROM servers WHERE id = ?`, serverID).Scan(&tokenHash); err != nil {
		return nil, err
	}
	if len(tokenHash) != 32 {
		return nil, errors.New("server token is unavailable")
	}
	return tokenHash, nil
}

func (s *Store) ReportServer(ctx context.Context, serverID string, onlineClients, publicIPs []string, platform, architecture string, fullMapping bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	reportedIPs, _ := json.Marshal(publicIPs)
	result, err := tx.ExecContext(ctx, `UPDATE servers SET status = 'online', last_seen_at = ?, reported_ips = ?, platform = ?, architecture = ?, full_mapping = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), string(reportedIPs), platform, architecture, fullMapping, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("server not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE clients SET status = 'offline' WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	for _, clientID := range onlineClients {
		if _, err := tx.ExecContext(ctx, `UPDATE clients SET status = 'online' WHERE id = ? AND server_id = ?`, clientID, serverID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ServerConfig(ctx context.Context, serverID string) (ServerConfig, error) {
	var result ServerConfig
	if err := s.db.QueryRowContext(ctx, `SELECT config_revision FROM servers WHERE id = ?`, serverID).Scan(&result.Revision); err != nil {
		return result, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, auth_token_hash FROM clients WHERE server_id = ? ORDER BY id`, serverID)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	result.Clients = make([]ClientCredential, 0)
	for rows.Next() {
		var credential ClientCredential
		var tokenHash []byte
		if err := rows.Scan(&credential.ID, &tokenHash); err != nil {
			return result, err
		}
		credential.TokenHash = base64.RawStdEncoding.EncodeToString(tokenHash)
		result.Clients = append(result.Clients, credential)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.Mappings, err = s.ListMappings(ctx, serverID)
	return result, err
}

func (s *Store) ListMappings(ctx context.Context, serverID string) ([]Mapping, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, server_id, client_id, public_ip, protocol, mapping_type, COALESCE(public_port, 0), target_host, COALESCE(target_port, 0), COALESCE(excluded_ports, ''), priority, status, COALESCE(occupied_by_mapping_id, ''), created_at FROM mappings WHERE server_id = ? ORDER BY priority DESC, created_at ASC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Mapping, 0)
	for rows.Next() {
		var item Mapping
		var created string
		if err := rows.Scan(&item.ID, &item.ServerID, &item.ClientID, &item.PublicIP, &item.Protocol, &item.MappingType, &item.PublicPort, &item.TargetHost, &item.TargetPort, &item.ExcludedPorts, &item.Priority, &item.Status, &item.OccupiedBy, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339, created)
		items = append(items, item)
	}
	return items, rows.Err()
}

func nullablePort(port int) any {
	if port == 0 {
		return nil
	}
	return port
}

type portInterval struct{ first, last int }

// NormalizePortSpec validates comma-separated ports and ranges such as
// "22,3389,8000-8010", then sorts and merges them into a stable form.
func NormalizePortSpec(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	intervals := make([]portInterval, 0)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", errors.New("reserved port list contains an empty item")
		}
		firstText, lastText, ranged := strings.Cut(part, "-")
		first, err := strconv.Atoi(strings.TrimSpace(firstText))
		if err != nil || first < 1 || first > 65535 {
			return "", fmt.Errorf("invalid reserved port %q", part)
		}
		last := first
		if ranged {
			last, err = strconv.Atoi(strings.TrimSpace(lastText))
			if err != nil || last < first || last > 65535 {
				return "", fmt.Errorf("invalid reserved port range %q", part)
			}
		}
		intervals = append(intervals, portInterval{first: first, last: last})
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].first < intervals[j].first })
	merged := make([]portInterval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 || interval.first > merged[len(merged)-1].last+1 {
			merged = append(merged, interval)
			continue
		}
		if interval.last > merged[len(merged)-1].last {
			merged[len(merged)-1].last = interval.last
		}
	}
	parts := make([]string, 0, len(merged))
	for _, interval := range merged {
		if interval.first == interval.last {
			parts = append(parts, strconv.Itoa(interval.first))
		} else {
			parts = append(parts, strconv.Itoa(interval.first)+"-"+strconv.Itoa(interval.last))
		}
	}
	return strings.Join(parts, ","), nil
}

func (s *Store) CreateMapping(ctx context.Context, item Mapping) (Mapping, error) {
	if item.ID == "" || item.ServerID == "" || item.ClientID == "" || item.TargetHost == "" {
		return Mapping{}, errors.New("invalid mapping")
	}
	if item.MappingType == "port" {
		if item.PublicIP == "" || (item.Protocol != "tcp" && item.Protocol != "udp") || item.PublicPort < 1 || item.PublicPort > 65535 || item.TargetPort < 1 || item.TargetPort > 65535 {
			return Mapping{}, errors.New("invalid TCP/UDP port mapping")
		}
		item.ExcludedPorts = ""
	} else if item.MappingType == "full" {
		publicIP := net.ParseIP(item.PublicIP)
		if publicIP == nil || publicIP.IsUnspecified() || item.Protocol != "both" || item.PublicPort != 0 || item.TargetPort != 0 {
			return Mapping{}, errors.New("full mapping requires one specific public IP")
		}
		normalized, err := NormalizePortSpec(item.ExcludedPorts)
		if err != nil {
			return Mapping{}, err
		}
		item.ExcludedPorts = normalized
	} else {
		return Mapping{}, errors.New("mapping type must be port or full")
	}
	item.CreatedAt = time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM clients WHERE id = ? AND server_id = ?`, item.ClientID, item.ServerID).Scan(&exists); err != nil || exists != 1 {
		return Mapping{}, errors.New("client is not bound to this server")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mappings (id, server_id, client_id, public_ip, protocol, mapping_type, public_port, target_host, target_port, excluded_ports, priority, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`, item.ID, item.ServerID, item.ClientID, item.PublicIP, item.Protocol, item.MappingType, nullablePort(item.PublicPort), item.TargetHost, nullablePort(item.TargetPort), item.ExcludedPorts, item.Priority, item.CreatedAt.Format(time.RFC3339)); err != nil {
		return Mapping{}, err
	}
	if err := s.resolveMappings(ctx, tx, item.ServerID); err != nil {
		return Mapping{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, item.ServerID); err != nil {
		return Mapping{}, err
	}
	detail := fmt.Sprintf("%s %s:%d -> %s:%d priority=%d", strings.ToUpper(item.Protocol), item.PublicIP, item.PublicPort, item.TargetHost, item.TargetPort, item.Priority)
	if item.MappingType == "full" {
		detail = fmt.Sprintf("FULL TCP+UDP %s -> %s excluded=%s priority=%d", item.PublicIP, item.TargetHost, item.ExcludedPorts, item.Priority)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES ('create', 'mapping', ?, ?, ?, ?)`, item.ID, detail, auditUserID(ctx), item.CreatedAt.Format(time.RFC3339)); err != nil {
		return Mapping{}, err
	}
	if err := tx.Commit(); err != nil {
		return Mapping{}, err
	}
	items, err := s.ListMappings(ctx, item.ServerID)
	if err != nil {
		return Mapping{}, err
	}
	for _, current := range items {
		if current.ID == item.ID {
			return current, nil
		}
	}
	return Mapping{}, errors.New("mapping was not created")
}

func (s *Store) DeleteMapping(ctx context.Context, serverID, mappingID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM mappings WHERE id = ? AND server_id = ?`, mappingID, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("mapping not found")
	}
	if err := s.resolveMappings(ctx, tx, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES ('delete', 'mapping', ?, '', ?, ?)`, mappingID, auditUserID(ctx), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateMappingPriority(ctx context.Context, serverID, mappingID string, priority int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE mappings SET priority = ? WHERE id = ? AND server_id = ?`, priority, mappingID, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("mapping not found")
	}
	if err := s.resolveMappings(ctx, tx, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES ('priority', 'mapping', ?, ?, ?, ?)`, mappingID, strconv.Itoa(priority), auditUserID(ctx), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) resolveMappings(ctx context.Context, tx *sql.Tx, serverID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, protocol, mapping_type, public_ip, COALESCE(public_port, 0), priority FROM mappings WHERE server_id = ? ORDER BY priority DESC, created_at ASC`, serverID)
	if err != nil {
		return err
	}
	type candidate struct {
		id, protocol, mappingType, ip string
		port, priority, rank          int
	}
	candidates := make([]candidate, 0)
	for rows.Next() {
		var item candidate
		item.rank = len(candidates)
		if err := rows.Scan(&item.id, &item.protocol, &item.mappingType, &item.ip, &item.port, &item.priority); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	statuses := make(map[string]string, len(candidates))
	occupiedBy := make(map[string]string, len(candidates))
	fullWinners := make([]candidate, 0)
	for _, item := range candidates {
		if item.mappingType != "full" {
			continue
		}
		for _, winner := range fullWinners {
			if mappingIPsConflict(winner.ip, item.ip) {
				occupiedBy[item.id] = winner.id
				break
			}
		}
		if occupiedBy[item.id] == "" {
			statuses[item.id] = "effective"
			fullWinners = append(fullWinners, item)
		} else {
			statuses[item.id] = "occupied"
		}
	}
	portWinners := make([]candidate, 0)
	for _, item := range candidates {
		if item.mappingType != "port" {
			continue
		}
		blocker := candidate{rank: len(candidates) + 1}
		for _, winner := range fullWinners {
			if winner.rank < item.rank && mappingIPsConflict(winner.ip, item.ip) && winner.rank < blocker.rank {
				blocker = winner
			}
		}
		for _, winner := range portWinners {
			if winner.protocol == item.protocol && winner.port == item.port && mappingIPsConflict(winner.ip, item.ip) && winner.rank < blocker.rank {
				blocker = winner
			}
		}
		if blocker.id == "" {
			statuses[item.id] = "effective"
			portWinners = append(portWinners, item)
		} else {
			statuses[item.id] = "occupied"
			occupiedBy[item.id] = blocker.id
		}
	}
	for _, item := range candidates {
		if statuses[item.id] == "effective" {
			if _, err := tx.ExecContext(ctx, `UPDATE mappings SET status = 'effective', occupied_by_mapping_id = NULL WHERE id = ?`, item.id); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE mappings SET status = 'occupied', occupied_by_mapping_id = ? WHERE id = ?`, occupiedBy[item.id], item.id); err != nil {
			return err
		}
	}
	return nil
}

func mappingIPsConflict(first, second string) bool {
	return first == second || first == "0.0.0.0" || first == "::" || second == "0.0.0.0" || second == "::"
}

func (s *Store) ListClients(ctx context.Context, serverID string) ([]Client, error) {
	cutoff := time.Now().UTC().Add(-60 * time.Second).Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.server_id, c.name, c.platform, CASE WHEN COALESCE(s.last_seen_at, '') >= ? THEN c.status ELSE 'offline' END, c.created_at FROM clients c JOIN servers s ON s.id = c.server_id WHERE c.server_id = ? ORDER BY c.created_at DESC`, cutoff, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make([]Client, 0)
	for rows.Next() {
		var client Client
		var created string
		if err := rows.Scan(&client.ID, &client.ServerID, &client.Name, &client.Platform, &client.Status, &created); err != nil {
			return nil, err
		}
		client.CreatedAt, _ = time.Parse(time.RFC3339, created)
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *Store) CreateClient(ctx context.Context, id, serverID, name, platform string, tokenHash []byte) (Client, error) {
	if id == "" || serverID == "" || name == "" || len(tokenHash) != 32 {
		return Client{}, errors.New("client provisioning request is invalid")
	}
	if platform == "" {
		platform = "pending"
	}
	client := Client{ID: id, ServerID: serverID, Name: name, Platform: platform, Status: "pending", CreatedAt: time.Now().UTC()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Client{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO clients (id, server_id, name, platform, status, auth_token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, client.ID, client.ServerID, client.Name, client.Platform, client.Status, tokenHash, client.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return Client{}, fmt.Errorf("insert client: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return Client{}, errors.New("server was not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, serverID); err != nil {
		return Client{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`, "create", "client", client.ID, client.Name, auditUserID(ctx), client.CreatedAt.Format(time.RFC3339)); err != nil {
		return Client{}, err
	}
	if err := tx.Commit(); err != nil {
		return Client{}, err
	}
	return client, nil
}

func (s *Store) DeleteClient(ctx context.Context, serverID, clientID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mappings WHERE server_id = ? AND client_id = ?`, serverID, clientID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM clients WHERE id = ? AND server_id = ?`, clientID, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("client not found")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET config_revision = config_revision + 1 WHERE id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES ('delete', 'client', ?, '', ?, ?)`, clientID, auditUserID(ctx), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteServer(ctx context.Context, serverID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mappings WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM clients WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, serverID)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return errors.New("server not found")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES ('delete', 'server', ?, '', ?, ?)`, serverID, auditUserID(ctx), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) audit(ctx context.Context, action, resourceType, resourceID, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (action, resource_type, resource_id, detail, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`, action, resourceType, resourceID, detail, auditUserID(ctx), time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) RecordAudit(ctx context.Context, action, resourceType, resourceID, detail string) error {
	return s.audit(ctx, action, resourceType, resourceID, detail)
}

func (s *Store) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	return s.ListAuditLogsForUser(ctx, limit, "", true)
}

func (s *Store) ListAuditLogsForUser(ctx context.Context, limit int, userID string, all bool) ([]AuditLog, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, action, resource_type, resource_id, detail, created_at FROM audit_logs`
	args := make([]any, 0, 2)
	if !all {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AuditLog, 0)
	for rows.Next() {
		var item AuditLog
		var created string
		if err := rows.Scan(&item.ID, &item.Action, &item.ResourceType, &item.ResourceID, &item.Detail, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339, created)
		items = append(items, item)
	}
	return items, rows.Err()
}
