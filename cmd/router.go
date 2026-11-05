package main

import (
	"fmt"
	"net/http"

	"chuan/internal/auth"
	"chuan/internal/handlers"
	"chuan/internal/web"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// setupRouter 设置路由和中间件
func setupRouter(config *Config) (http.Handler, error) {
	// 初始化账号服务（读取 data 目录下的账号数据与会话密钥）
	authService, err := auth.NewService(config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("初始化账号服务失败: %w", err)
	}

	// 初始化处理器
	h := handlers.NewHandler(authService)

	router := chi.NewRouter()

	// 设置中间件
	setupMiddleware(router)

	// 全站鉴权：未登录访问页面会跳转 /login，访问接口返回 401
	// 必须在注册路由前 Use，chi 要求中间件先于路由定义
	router.Use(h.RequireAuth)

	// 设置API路由
	setupAPIRoutes(router, h)

	// 设置前端路由
	router.Handle("/*", web.CreateFrontendHandler())

	return router, nil
}

// setupMiddleware 设置中间件
func setupMiddleware(r *chi.Mux) {
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))

	// CORS 配置
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
}

// setupAPIRoutes 设置API路由
func setupAPIRoutes(r *chi.Mux, h *handlers.Handler) {
	// 账号相关接口（在鉴权白名单内）
	r.Route("/api/auth", func(r chi.Router) {
		r.Get("/status", h.AuthStatusHandler)
		r.Post("/setup", h.AuthSetupHandler)
		r.Post("/login", h.AuthLoginHandler)
		r.Post("/logout", h.AuthLogoutHandler)
		r.Post("/reset", h.AuthResetHandler)
	})

	// WebRTC信令WebSocket路由
	r.Get("/api/ws/webrtc", h.HandleWebRTCWebSocket)
	r.Get("/ws/webrtc", h.HandleWebRTCWebSocket)

	// WebSocket 数据中继路由（P2P降级方案）
	r.Get("/api/ws/relay", h.HandleRelayWebSocket)
	r.Get("/ws/relay", h.HandleRelayWebSocket)

	// WebRTC房间API
	r.Post("/api/create-room", h.CreateRoomHandler)
	r.Get("/api/room-info", h.WebRTCRoomStatusHandler)
	r.Get("/api/webrtc-room-status", h.WebRTCRoomStatusHandler)
}
