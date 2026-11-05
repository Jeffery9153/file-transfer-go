package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"chuan/internal/auth"
	"chuan/internal/services"
)

type Handler struct {
	webrtcService *services.WebRTCService
	relayService  *services.RelayService
	authService   *auth.Service
}

func NewHandler(authService *auth.Service) *Handler {
	webrtcService := services.NewWebRTCService()
	return &Handler{
		webrtcService: webrtcService,
		relayService:  services.NewRelayService(webrtcService),
		authService:   authService,
	}
}

// HandleRelayWebSocket 处理数据中继WebSocket连接（P2P失败时的降级方案）
func (h *Handler) HandleRelayWebSocket(w http.ResponseWriter, r *http.Request) {
	h.relayService.HandleRelayWebSocket(w, r)
}

// HandleWebRTCWebSocket 处理WebRTC信令WebSocket连接
func (h *Handler) HandleWebRTCWebSocket(w http.ResponseWriter, r *http.Request) {
	h.webrtcService.HandleWebSocket(w, r)
}

// CreateRoomHandler 创建房间API - 简化版本，不处理无用参数
func (h *Handler) CreateRoomHandler(w http.ResponseWriter, r *http.Request) {
	// 设置响应为JSON格式
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "方法不允许",
		})
		return
	}

	// 创建新房间（忽略请求体中的无用参数）
	code := h.webrtcService.CreateNewRoom()
	log.Printf("创建房间成功: %s", code)

	// 构建响应
	response := map[string]interface{}{
		"success": true,
		"code":    code,
		"message": "房间创建成功",
	}

	json.NewEncoder(w).Encode(response)
}

// WebRTCRoomStatusHandler WebRTC房间状态API
func (h *Handler) WebRTCRoomStatusHandler(w http.ResponseWriter, r *http.Request) {
	// 设置响应为JSON格式
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "方法不允许",
		})
		return
	}

	// 从查询参数获取房间代码
	code := r.URL.Query().Get("code")
	if code == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "缺少房间代码",
		})
		return
	}

	// 获取房间状态
	status := h.webrtcService.GetRoomStatus(code)

	json.NewEncoder(w).Encode(status)
}

// GetRoomStatusHandler 获取房间状态API
func (h *Handler) GetRoomStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "方法不允许",
		})
		return
	}

	// 获取房间码
	code := r.URL.Query().Get("code")
	if code == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "房间码不能为空",
		})
		return
	}

	// 获取房间状态
	status := h.webrtcService.GetRoomStatus(code)
	json.NewEncoder(w).Encode(status)
}
