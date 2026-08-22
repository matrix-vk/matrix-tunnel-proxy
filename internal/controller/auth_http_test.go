package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestPBKDF2SHA256Vector(t *testing.T) {
	want, _ := hex.DecodeString("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
	if got := pbkdf2SHA256([]byte("password"), []byte("salt"), 1); !bytes.Equal(got, want) {
		t.Fatalf("PBKDF2 result = %x, want %x", got, want)
	}
}

func TestFreshDatabaseMustBeInitializedBeforeSuperAdminSetup(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := NewApp(store, "", "", "", nil).Handler()

	status := performJSON(handler, http.MethodGet, "/api/v1/auth/status", nil, "")
	var initial AuthStatusForTest
	if err := json.Unmarshal(status.Body.Bytes(), &initial); err != nil || !initial.NeedsDatabaseSetup || !initial.NeedsSetup {
		t.Fatalf("initial status = %+v, error = %v", initial, err)
	}
	blocked := performJSON(handler, http.MethodPost, "/api/v1/auth/setup", map[string]any{"username": "rootadmin", "password": "root-password"}, "")
	if blocked.Code != http.StatusPreconditionRequired {
		t.Fatalf("setup before database initialization status = %d: %s", blocked.Code, blocked.Body.String())
	}
	initialized := performJSON(handler, http.MethodPost, "/api/v1/auth/database/setup", nil, "")
	if initialized.Code != http.StatusOK {
		t.Fatalf("database initialization status = %d: %s", initialized.Code, initialized.Body.String())
	}
	status = performJSON(handler, http.MethodGet, "/api/v1/auth/status", nil, "")
	if err := json.Unmarshal(status.Body.Bytes(), &initial); err != nil || initial.NeedsDatabaseSetup || !initial.NeedsSetup {
		t.Fatalf("initialized status = %+v, error = %v", initial, err)
	}
	created := performJSON(handler, http.MethodPost, "/api/v1/auth/setup", map[string]any{"siteName": "内网控制台", "username": "rootadmin", "password": "root-password"}, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("super admin setup status = %d: %s", created.Code, created.Body.String())
	}
	status = performJSON(handler, http.MethodGet, "/api/v1/auth/status", nil, "")
	if err := json.Unmarshal(status.Body.Bytes(), &initial); err != nil || initial.SiteName != "内网控制台" || initial.NeedsSetup {
		t.Fatalf("configured status = %+v, error = %v", initial, err)
	}
	secondSetup := performJSON(handler, http.MethodPost, "/api/v1/auth/setup", map[string]any{"siteName": "changed", "username": "another-admin", "password": "root-password"}, "")
	if secondSetup.Code == http.StatusCreated {
		t.Fatal("site name and super administrator could be initialized twice")
	}
}

type AuthStatusForTest struct {
	NeedsDatabaseSetup bool   `json:"needsDatabaseSetup"`
	NeedsSetup         bool   `json:"needsSetup"`
	SiteName           string `json:"siteName"`
}

func TestLoginLockoutAndSuperAdminUnlock(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	super, err := store.CreateInitialSuperAdmin(ctx, "rootadmin", "root-password")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := store.CreateUser(ctx, "alice", "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewApp(store, "", "", "", nil).Handler()

	for attempt := 1; attempt <= 5; attempt++ {
		response := performJSON(handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "alice", "password": "wrong-password"}, "")
		want := http.StatusUnauthorized
		if attempt == 5 {
			want = http.StatusLocked
		}
		if response.Code != want {
			t.Fatalf("attempt %d status = %d, want %d: %s", attempt, response.Code, want, response.Body.String())
		}
	}
	lockedLogin := performJSON(handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "alice", "password": "alice-password"}, "")
	if lockedLogin.Code != http.StatusLocked {
		t.Fatalf("locked login status = %d: %s", lockedLogin.Code, lockedLogin.Body.String())
	}

	superToken, _, err := store.CreateSession(ctx, super.ID)
	if err != nil {
		t.Fatal(err)
	}
	unlocked := performJSON(handler, http.MethodPatch, "/api/v1/users/"+alice.ID, map[string]any{"locked": false}, superToken)
	if unlocked.Code != http.StatusOK {
		t.Fatalf("unlock status = %d: %s", unlocked.Code, unlocked.Body.String())
	}
	success := performJSON(handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "alice", "password": "alice-password"}, "")
	if success.Code != http.StatusOK || success.Header().Get("Set-Cookie") == "" {
		t.Fatalf("login after unlock status = %d, cookie = %q: %s", success.Code, success.Header().Get("Set-Cookie"), success.Body.String())
	}
}

func TestUserModuleAndServerOwnershipPermissions(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	super, err := store.CreateInitialSuperAdmin(ctx, "rootadmin", "root-password")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := store.CreateUser(ctx, "alice", "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.CreateUser(ctx, "bob-user", "bob-password")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, certificate, tokenHash := make([]byte, 32), []byte("certificate"), make([]byte, 32)
	if _, err := store.CreateServerForOwner(ctx, "srv_alice", "alice server", "127.0.0.1:7001", alice.ID, publicKey, certificate, tokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateServerForOwner(ctx, "srv_bob", "bob server", "127.0.0.1:7002", bob.ID, publicKey, certificate, tokenHash); err != nil {
		t.Fatal(err)
	}
	handler := NewApp(store, "", "", "", nil).Handler()
	aliceToken, _, _ := store.CreateSession(ctx, alice.ID)
	forbidden := performJSON(handler, http.MethodGet, "/api/v1/users", nil, aliceToken)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("regular user users status = %d, want 403", forbidden.Code)
	}
	aliceServers := performJSON(handler, http.MethodGet, "/api/v1/servers", nil, aliceToken)
	if aliceServers.Code != http.StatusOK {
		t.Fatalf("alice servers status = %d: %s", aliceServers.Code, aliceServers.Body.String())
	}
	var servers []Server
	if err := json.Unmarshal(aliceServers.Body.Bytes(), &servers); err != nil || len(servers) != 1 || servers[0].ID != "srv_alice" {
		t.Fatalf("alice servers = %+v, error = %v", servers, err)
	}

	if err := store.UpdateUserAdmin(ctx, alice.ID, true); err != nil {
		t.Fatal(err)
	}
	adminToken, _, _ := store.CreateSession(ctx, alice.ID)
	adminServers := performJSON(handler, http.MethodGet, "/api/v1/servers", nil, adminToken)
	if err := json.Unmarshal(adminServers.Body.Bytes(), &servers); err != nil || len(servers) != 2 {
		t.Fatalf("admin servers = %+v, error = %v", servers, err)
	}
	stillForbidden := performJSON(handler, http.MethodGet, "/api/v1/users", nil, adminToken)
	if stillForbidden.Code != http.StatusForbidden {
		t.Fatalf("regular admin users status = %d, want 403", stillForbidden.Code)
	}
	superToken, _, _ := store.CreateSession(ctx, super.ID)
	allowed := performJSON(handler, http.MethodGet, "/api/v1/users", nil, superToken)
	if allowed.Code != http.StatusOK {
		t.Fatalf("super admin users status = %d: %s", allowed.Code, allowed.Body.String())
	}
}

func performJSON(handler http.Handler, method, path string, body any, sessionToken string) *httptest.ResponseRecorder {
	var encoded bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&encoded).Encode(body)
	}
	request := httptest.NewRequest(method, path, &encoded)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if sessionToken != "" {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
