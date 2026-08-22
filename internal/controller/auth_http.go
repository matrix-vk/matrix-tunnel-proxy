package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func (a *App) authStatus(w http.ResponseWriter, r *http.Request) {
	siteName, err := a.store.SiteName(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	databaseReady, err := a.store.DatabaseInitialized(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	exists, err := a.store.SuperAdminExists(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	response := map[string]any{"needsDatabaseSetup": !databaseReady, "needsSetup": !exists, "siteName": siteName}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if user, err := a.store.UserForSession(r.Context(), cookie.Value); err == nil {
			response["user"] = user
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) setupDatabase(w http.ResponseWriter, r *http.Request) {
	exists, err := a.store.SuperAdminExists(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if exists {
		writeError(w, http.StatusConflict, errors.New("系统已经初始化"))
		return
	}
	if err := a.store.InitializeDatabase(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *App) setupSuperAdmin(w http.ResponseWriter, r *http.Request) {
	ready, err := a.store.DatabaseInitialized(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ready {
		writeError(w, http.StatusPreconditionRequired, errors.New("请先初始化 SQLite 数据库"))
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SiteName string `json:"siteName"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := a.store.CreateInitialSuperAdminWithSiteName(r.Context(), request.Username, request.Password, request.SiteName)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := a.startSession(w, r, user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := a.store.UserByUsername(r.Context(), request.Username)
	if errors.Is(err, sql.ErrNoRows) {
		_ = pbkdf2SHA256([]byte(request.Password), []byte("matrix-dummy-salt"), passwordIterations)
		writeError(w, http.StatusUnauthorized, errors.New("用户名或密码错误"))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	if user.ManualLocked {
		writeError(w, http.StatusLocked, errors.New("账号已被锁定，请联系超级管理员"))
		return
	}
	if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
		writeJSON(w, http.StatusLocked, map[string]any{"error": "登录失败次数过多，账号已锁定 10 分钟", "lockedUntil": user.LockedUntil})
		return
	}
	if !verifyPassword(user, request.Password) {
		lockedUntil, failureErr := a.store.RecordLoginFailure(r.Context(), user)
		if failureErr != nil {
			writeError(w, http.StatusInternalServerError, failureErr)
			return
		}
		if !lockedUntil.IsZero() {
			writeJSON(w, http.StatusLocked, map[string]any{"error": "连续登录错误 5 次，账号已锁定 10 分钟", "lockedUntil": lockedUntil})
			return
		}
		writeError(w, http.StatusUnauthorized, errors.New("用户名或密码错误"))
		return
	}
	if err := a.store.RecordLoginSuccess(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	user.FailedAttempts = 0
	user.LockedUntil = nil
	if err := a.startSession(w, r, user.User); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user.User})
}

func (a *App) startSession(w http.ResponseWriter, r *http.Request, user User) error {
	token, expires, err := a.store.CreateSession(r.Context(), user.ID)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/", Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: cookieSecure(r), SameSite: http.SameSiteStrictMode})
	return nil
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("请先登录"))
			return
		}
		user, err := a.store.UserForSession(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("登录已失效，请重新登录"))
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthenticatedUser(r.Context(), user)))
	})
}

func (a *App) authMe(w http.ResponseWriter, r *http.Request) {
	user, _ := authenticatedUser(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		_ = a.store.DeleteSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: cookieSecure(r), SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	user, _ := authenticatedUser(r.Context())
	var request struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	stored, err := a.store.UserByID(r.Context(), user.ID)
	if err != nil || !verifyPassword(stored, request.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, errors.New("当前密码错误"))
		return
	}
	if err := a.store.ChangeUserPassword(r.Context(), user.ID, request.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func requireSuperAdmin(r *http.Request) (User, error) {
	user, ok := authenticatedUser(r.Context())
	if !ok || !user.IsSuperAdmin {
		return User{}, errors.New("只有超级管理员可以管理用户")
	}
	return user, nil
}

func (a *App) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, err := requireSuperAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	if _, err := requireSuperAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	user, err := a.store.CreateUser(r.Context(), request.Username, request.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request) {
	if _, err := requireSuperAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	var request struct {
		Password *string `json:"password"`
		IsAdmin  *bool   `json:"isAdmin"`
		Locked   *bool   `json:"locked"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	userID := r.PathValue("userId")
	if request.IsAdmin != nil {
		if err := a.store.UpdateUserAdmin(r.Context(), userID, *request.IsAdmin); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if request.Locked != nil {
		if err := a.store.SetUserLocked(r.Context(), userID, *request.Locked); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if request.Password != nil {
		if err := a.store.ChangeUserPassword(r.Context(), userID, *request.Password); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	updated, err := a.store.UserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("用户不存在"))
		return
	}
	writeJSON(w, http.StatusOK, updated.User)
}

func decodeJSON(r *http.Request, target any) error {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return errors.New("请求内容格式错误")
	}
	return nil
}

func (a *App) authorizeServer(w http.ResponseWriter, r *http.Request) bool {
	user, ok := authenticatedUser(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("请先登录"))
		return false
	}
	allowed, err := a.store.CanAccessServer(r.Context(), r.PathValue("serverId"), user.ID, user.IsAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}
	if !allowed {
		writeError(w, http.StatusNotFound, errors.New("服务器端不存在"))
		return false
	}
	return true
}
