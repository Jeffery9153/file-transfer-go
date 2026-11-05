package handlers

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// publicPrefixes 免鉴权路径前缀（登录相关接口、登录页、前端静态资源）。
var publicPrefixes = []string{
	"/api/auth/",
	"/login",
	"/_next/",
	"/favicon",
}

// publicStaticExts 静态资源扩展名，未登录也要能加载，否则登录页样式脚本全挂。
// 注意不要放行 .html：首页 HTML 必须走鉴权，否则可被直接绕过。
var publicStaticExts = map[string]bool{
	".js":          true,
	".mjs":         true,
	".css":         true,
	".map":         true,
	".png":         true,
	".jpg":         true,
	".jpeg":        true,
	".gif":         true,
	".svg":         true,
	".ico":         true,
	".webp":        true,
	".woff":        true,
	".woff2":       true,
	".ttf":         true,
	".txt":         true,
	".webmanifest": true,
}

// isPublicPath 判断请求是否无需登录。
func isPublicPath(p string) bool {
	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	if publicStaticExts[strings.ToLower(path.Ext(p))] {
		return true
	}
	// Next 静态导出的根级资源目录
	if strings.HasPrefix(p, "/assets/") || strings.HasPrefix(p, "/static/") {
		return true
	}
	return false
}

// RequireAuth 全站鉴权中间件：
//   - 接口/WebSocket 未登录返回 401，前端据此跳转
//   - 页面请求未登录 302 到 /login，并带上原路径便于登录后回跳
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path

		if isPublicPath(p) {
			next.ServeHTTP(w, r)
			return
		}

		if _, ok := h.currentUser(r); ok {
			next.ServeHTTP(w, r)
			return
		}

		// 接口与 WebSocket：返回 401，让前端自行处理
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/ws/") {
			writeJSON(w, http.StatusUnauthorized, failResp("未登录或会话已过期"))
			return
		}

		target := "/login"
		if p != "" && p != "/" {
			target += "?next=" + url.QueryEscape(p)
		}
		http.Redirect(w, r, target, http.StatusFound)
	})
}
