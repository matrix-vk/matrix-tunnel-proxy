package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	passwordIterations = 600_000
	sessionLifetime    = 24 * time.Hour
	loginLockDuration  = 10 * time.Minute
	maxLoginFailures   = 5
	sessionCookieName  = "matrix_session"
)

type User struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	IsAdmin        bool       `json:"isAdmin"`
	IsSuperAdmin   bool       `json:"isSuperAdmin"`
	ManualLocked   bool       `json:"manualLocked"`
	FailedAttempts int        `json:"failedAttempts"`
	LockedUntil    *time.Time `json:"lockedUntil,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

type storedUser struct {
	User
	PasswordSalt       []byte
	PasswordHash       []byte
	PasswordIterations int
}

type authContextKey struct{}

func withAuthenticatedUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, authContextKey{}, user)
}

func authenticatedUser(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(authContextKey{}).(User)
	return user, ok
}

func auditUserID(ctx context.Context) string {
	user, ok := authenticatedUser(ctx)
	if !ok {
		return ""
	}
	return user.ID
}

func validateUsername(username string) error {
	username = strings.TrimSpace(username)
	count := utf8.RuneCountInString(username)
	if count < 3 || count > 64 {
		return errors.New("用户名长度必须为 3 到 64 个字符")
	}
	for _, current := range username {
		if unicode.IsControl(current) || unicode.IsSpace(current) {
			return errors.New("用户名不能包含空格或控制字符")
		}
	}
	return nil
}

func validatePassword(password string) error {
	length := len([]byte(password))
	if length < 8 {
		return errors.New("密码至少需要 8 个字符")
	}
	if length > 256 {
		return errors.New("密码不能超过 256 字节")
	}
	return nil
}

func newPasswordHash(password string) (salt, hash []byte, iterations int, err error) {
	if err = validatePassword(password); err != nil {
		return nil, nil, 0, err
	}
	salt = make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, 0, err
	}
	return salt, pbkdf2SHA256([]byte(password), salt, passwordIterations), passwordIterations, nil
}

func verifyPassword(user storedUser, password string) bool {
	if len(user.PasswordSalt) != 16 || len(user.PasswordHash) != 32 || user.PasswordIterations < 1 {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), user.PasswordSalt, user.PasswordIterations)
	return subtle.ConstantTimeCompare(actual, user.PasswordHash) == 1
}

// pbkdf2SHA256 derives one 32-byte block using PBKDF2-HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iterations int) []byte {
	block := make([]byte, len(salt)+4)
	copy(block, salt)
	block[len(salt)+3] = 1
	mac := hmac.New(sha256.New, password)
	_, _ = mac.Write(block)
	u := mac.Sum(nil)
	result := append([]byte(nil), u...)
	for iteration := 1; iteration < iterations; iteration++ {
		mac.Reset()
		_, _ = mac.Write(u)
		u = mac.Sum(u[:0])
		for index := range result {
			result[index] ^= u[index]
		}
	}
	return result
}

func (s *Store) SuperAdminExists(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE is_super_admin = 1`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) CreateInitialSuperAdmin(ctx context.Context, username, password string) (User, error) {
	return s.CreateInitialSuperAdminWithSiteName(ctx, username, password, "Matrix Tunnel Proxy")
}

func (s *Store) CreateInitialSuperAdminWithSiteName(ctx context.Context, username, password, siteName string) (User, error) {
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	siteName = strings.TrimSpace(siteName)
	if siteName == "" {
		siteName = "Matrix Tunnel Proxy"
	}
	if utf8.RuneCountInString(siteName) > 64 {
		return User{}, errors.New("网站名称不能超过 64 个字符")
	}
	for _, current := range siteName {
		if unicode.IsControl(current) {
			return User{}, errors.New("网站名称不能包含控制字符")
		}
	}
	salt, hash, iterations, err := newPasswordHash(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE is_super_admin = 1`).Scan(&count); err != nil {
		return User{}, err
	}
	if count != 0 {
		return User{}, errors.New("超级管理员已经存在")
	}
	user := User{ID: NewID("usr"), Username: strings.TrimSpace(username), IsAdmin: true, IsSuperAdmin: true, CreatedAt: time.Now().UTC()}
	now := user.CreatedAt.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO users (id, username, password_salt, password_hash, password_iterations, is_admin, is_super_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)`, user.ID, user.Username, salt, hash, iterations, now, now); err != nil {
		return User{}, fmt.Errorf("创建超级管理员: %w", err)
	}
	// Existing installations are adopted by the first super administrator.
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET owner_user_id = ? WHERE owner_user_id = ''`, user.ID); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_logs SET user_id = ? WHERE user_id = ''`, user.ID); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_settings (key, value) VALUES ('database_initialized', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_settings (key, value) VALUES ('site_name', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, siteName); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) CreateUser(ctx context.Context, username, password string) (User, error) {
	if err := validateUsername(username); err != nil {
		return User{}, err
	}
	salt, hash, iterations, err := newPasswordHash(password)
	if err != nil {
		return User{}, err
	}
	user := User{ID: NewID("usr"), Username: strings.TrimSpace(username), CreatedAt: time.Now().UTC()}
	now := user.CreatedAt.Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, password_salt, password_hash, password_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, user.ID, user.Username, salt, hash, iterations, now, now); err != nil {
		return User{}, fmt.Errorf("创建用户: %w", err)
	}
	return user, nil
}

func scanStoredUser(scanner interface{ Scan(...any) error }) (storedUser, error) {
	var result storedUser
	var lockedUntil, created string
	err := scanner.Scan(&result.ID, &result.Username, &result.PasswordSalt, &result.PasswordHash, &result.PasswordIterations, &result.IsAdmin, &result.IsSuperAdmin, &result.ManualLocked, &result.FailedAttempts, &lockedUntil, &created)
	if err != nil {
		return result, err
	}
	if parsed, err := time.Parse(time.RFC3339Nano, lockedUntil); err == nil {
		result.LockedUntil = &parsed
	}
	result.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return result, nil
}

const userSelect = `SELECT id, username, password_salt, password_hash, password_iterations, is_admin, is_super_admin, manual_locked, failed_attempts, COALESCE(locked_until, ''), created_at FROM users`

func (s *Store) UserByUsername(ctx context.Context, username string) (storedUser, error) {
	return scanStoredUser(s.db.QueryRowContext(ctx, userSelect+` WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)))
}

func (s *Store) UserByID(ctx context.Context, userID string) (storedUser, error) {
	return scanStoredUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id = ?`, userID))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` ORDER BY is_super_admin DESC, username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		user, err := scanStoredUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, user.User)
	}
	return result, rows.Err()
}

func (s *Store) RecordLoginFailure(ctx context.Context, user storedUser) (time.Time, error) {
	now := time.Now().UTC()
	failures := user.FailedAttempts
	if user.LockedUntil != nil && !now.Before(*user.LockedUntil) {
		failures = 0
	}
	failures++
	var lockedUntil any
	var lockTime time.Time
	if failures >= maxLoginFailures {
		lockTime = now.Add(loginLockDuration)
		lockedUntil = lockTime.Format(time.RFC3339Nano)
		failures = maxLoginFailures
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?`, failures, lockedUntil, now.Format(time.RFC3339Nano), user.ID)
	return lockTime, err
}

func (s *Store) RecordLoginSuccess(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), userID)
	return err
}

func (s *Store) CreateSession(ctx context.Context, userID string) (string, time.Time, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	expires := now.Add(sessionLifetime)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`, hash[:], userID, expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (s *Store) UserForSession(ctx context.Context, token string) (User, error) {
	hash := sha256.Sum256([]byte(token))
	var userID, expires string
	if err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, hash[:]).Scan(&userID, &expires); err != nil {
		return User{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !time.Now().UTC().Before(expiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash[:])
		return User{}, errors.New("session expired")
	}
	stored, err := s.UserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	if stored.ManualLocked || (stored.LockedUntil != nil && time.Now().UTC().Before(*stored.LockedUntil)) {
		return User{}, errors.New("account locked")
	}
	return stored.User, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash[:])
	return err
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *Store) UpdateUserAdmin(ctx context.Context, userID string, admin bool) error {
	var super bool
	if err := s.db.QueryRowContext(ctx, `SELECT is_super_admin FROM users WHERE id = ?`, userID).Scan(&super); err != nil {
		return err
	}
	if super && !admin {
		return errors.New("默认超级管理员的管理员身份不可取消")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?`, admin, time.Now().UTC().Format(time.RFC3339Nano), userID)
	if err == nil {
		err = s.RevokeUserSessions(ctx, userID)
	}
	return err
}

func (s *Store) SetUserLocked(ctx context.Context, userID string, locked bool) error {
	var super bool
	if err := s.db.QueryRowContext(ctx, `SELECT is_super_admin FROM users WHERE id = ?`, userID).Scan(&super); err != nil {
		return err
	}
	if super && locked {
		return errors.New("默认超级管理员不可锁定")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET manual_locked = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, locked, time.Now().UTC().Format(time.RFC3339Nano), userID)
	if err == nil && locked {
		err = s.RevokeUserSessions(ctx, userID)
	}
	return err
}

func (s *Store) ChangeUserPassword(ctx context.Context, userID, password string) error {
	salt, hash, iterations, err := newPasswordHash(password)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE users SET password_salt = ?, password_hash = ?, password_iterations = ?, failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`, salt, hash, iterations, time.Now().UTC().Format(time.RFC3339Nano), userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("用户不存在")
	}
	return s.RevokeUserSessions(ctx, userID)
}

func cookieSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}
