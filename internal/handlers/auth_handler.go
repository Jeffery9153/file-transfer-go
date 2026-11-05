package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"chuan/internal/auth"
)

const (
	// SessionCookieName 会话 Cookie 名
	SessionCookieName = "chuan_session"
	// maxAuthBody 认证接口请求体上限，正常请求只有几百字节
	maxAuthBody = 16 << 10
)

type authPayload struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	RecoveryCode string `json:"recoveryCode"`
	NewPassword  string `json:"newPassword"`
}

// AuthStatusHandler 返回账号是否已初始化、当前请求是否已登录。
// 该接口必须在免鉴权白名单内，前端靠它决定进登录页还是首页。
func (h *Handler) AuthStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := h.authService.Status()

	// 未登录时不回传用户名，避免匿名探测账号名
	resp := map[string]interface{}{
		"success":     true,
		"initialized": status.Initialized,
		"loggedIn":    false,
	}
	if name, ok := h.currentUser(r); ok {
		resp["loggedIn"] = true
		resp["username"] = name
	}

	writeJSON(w, http.StatusOK, resp)
}

// AuthSetupHandler 首次初始化账号，成功后自动登录并返回一次性找回码。
func (h *Handler) AuthSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, failResp("方法不允许"))
		return
	}

	var body authPayload
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, failResp("请求格式错误"))
		return
	}

	code, token, err := h.authService.Init(body.Username, body.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAlreadyInitialized):
			writeJSON(w, http.StatusConflict, failResp(err.Error()))
		case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrWeakPassword):
			writeJSON(w, http.StatusBadRequest, failResp(err.Error()))
		default:
			log.Printf("初始化账号失败: %v", err)
			writeJSON(w, http.StatusInternalServerError, failResp("初始化失败，请查看服务端日志"))
		}
		return
	}

	h.setSessionCookie(w, r, token)
	log.Printf("账号初始化成功: %s", body.Username)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"username":     strings.TrimSpace(body.Username),
		"recoveryCode": code,
		"message":      "账号创建成功，请立即保存找回码",
	})
}

// AuthLoginHandler 账号密码登录。
func (h *Handler) AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, failResp("方法不允许"))
		return
	}

	var body authPayload
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, failResp("请求格式错误"))
		return
	}

	token, err := h.authService.Login(body.Username, body.Password, clientKey(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTooManyAttempts):
			writeJSON(w, http.StatusTooManyRequests, failResp(err.Error()))
		case errors.Is(err, auth.ErrNotInitialized):
			writeJSON(w, http.StatusBadRequest, failResp("账号尚未初始化，请先完成首次设置"))
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeJSON(w, http.StatusUnauthorized, failResp(err.Error()))
		default:
			log.Printf("登录失败: %v", err)
			writeJSON(w, http.StatusInternalServerError, failResp("登录失败，请重试"))
		}
		return
	}

	h.setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": strings.TrimSpace(body.Username),
	})
}

// AuthLogoutHandler 退出登录，清除会话 Cookie。
func (h *Handler) AuthLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, failResp("方法不允许"))
		return
	}
	h.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// AuthResetHandler 凭找回码重置密码，成功后旧码作废并返回新码。
func (h *Handler) AuthResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, failResp("方法不允许"))
		return
	}

	var body authPayload
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, failResp("请求格式错误"))
		return
	}

	newCode, token, err := h.authService.ResetByRecoveryCode(body.RecoveryCode, body.NewPassword, clientKey(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTooManyAttempts):
			writeJSON(w, http.StatusTooManyRequests, failResp(err.Error()))
		case errors.Is(err, auth.ErrInvalidRecoveryCode):
			writeJSON(w, http.StatusUnauthorized, failResp(err.Error()))
		case errors.Is(err, auth.ErrWeakPassword):
			writeJSON(w, http.StatusBadRequest, failResp(err.Error()))
		case errors.Is(err, auth.ErrNotInitialized):
			writeJSON(w, http.StatusBadRequest, failResp("账号尚未初始化，请先完成首次设置"))
		default:
			log.Printf("重置密码失败: %v", err)
			writeJSON(w, http.StatusInternalServerError, failResp("重置失败，请重试"))
		}
		return
	}

	h.setSessionCookie(w, r, token)
	log.Printf("账号密码已通过找回码重置")

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"recoveryCode": newCode,
		"message":      "密码已重置，旧的找回码已失效，请保存新的找回码",
	})
}

// currentUser 从 Cookie 中解析当前登录用户。
func (h *Handler) currentUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", false
	}
	return h.authService.VerifySession(cookie.Value)
}

// setSessionCookie 下发会话 Cookie。
// HttpOnly 阻断 XSS 读取，SameSite=Lax 兼顾站内跳转与 CSRF 防护。
func (h *Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.SessionTTL().Seconds()),
		Expires:  time.Now().Add(auth.SessionTTL()),
	})
}

// clearSessionCookie 清除会话 Cookie。
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// isSecureRequest 判断当前请求是否走 HTTPS（含反向代理场景）。
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.EqualFold(strings.TrimSpace(strings.Split(proto, ",")[0]), "https")
	}
	return false
}

// clientKey 用于限速的来源标识，优先取反向代理透传的真实 IP。
func clientKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return strings.TrimSpace(rip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// decodeJSONBody 限制大小并严格解析 JSON。
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}
	// 确保请求体只有一个 JSON 对象
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("请求体包含多余内容")
	}
	return nil
}

// writeJSON 统一 JSON 响应输出。
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("写入响应失败: %v", err)
	}
}

// failResp 构造失败响应体，与项目既有 success/message 风格保持一致。
func failResp(msg string) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"message": msg,
	}
}
