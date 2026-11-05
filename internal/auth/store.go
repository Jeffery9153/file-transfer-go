package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// authFileName 账号数据文件名
	authFileName = "auth.json"
	// secretFileName 会话签名密钥文件名
	secretFileName = "secret.key"

	authFileMode   = 0o600
	authDirMode    = 0o750
	secretKeyBytes = 32
	currentVersion = 1
)

// ErrNotInitialized 账号尚未初始化
var ErrNotInitialized = errors.New("账号尚未初始化")

// User 单用户模型下的唯一账号记录
type User struct {
	Username          string    `json:"username"`
	PasswordHash      string    `json:"password_hash"`
	RecoveryHash      string    `json:"recovery_hash"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	PasswordUpdatedAt time.Time `json:"password_updated_at"`
}

// authFile 落盘结构。保留 version 便于以后迁移。
type authFile struct {
	Version int   `json:"version"`
	User    *User `json:"user,omitempty"`
}

// Store 负责账号数据的读写，所有写入都是原子替换，避免断电导致文件损坏。
type Store struct {
	mu   sync.RWMutex
	path string
	data authFile
}

// NewStore 打开（或初始化）dataDir 下的账号存储。
func NewStore(dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	if err := os.MkdirAll(dataDir, authDirMode); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	s := &Store{
		path: filepath.Join(dataDir, authFileName),
		data: authFile{Version: currentVersion},
	}

	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// 首次启动，无需创建空文件，等真正初始化账号时再落盘
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("读取账号文件失败: %w", err)
	}

	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("解析账号文件失败（文件可能已损坏）: %w", err)
		}
	}
	if s.data.Version == 0 {
		s.data.Version = currentVersion
	}
	return s, nil
}

// Get 返回账号的只读副本，未初始化时返回 nil。
func (s *Store) Get() *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.User == nil {
		return nil
	}
	cp := *s.data.User
	return &cp
}

// Initialized 是否已完成首次初始化。
func (s *Store) Initialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.User != nil
}

// Create 仅在未初始化时创建账号，重复调用返回 ErrAlreadyInitialized。
func (s *Store) Create(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data.User != nil {
		return ErrAlreadyInitialized
	}
	s.data.Version = currentVersion
	s.data.User = u
	return s.persistLocked()
}

// Update 覆盖已有账号记录。
func (s *Store) Update(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data.User == nil {
		return ErrNotInitialized
	}
	s.data.Version = currentVersion
	s.data.User = u
	return s.persistLocked()
}

// persistLocked 原子写：临时文件 -> fsync -> rename。
// 调用方必须已持有写锁。
func (s *Store) persistLocked() error {
	payload, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化账号数据失败: %w", err)
	}
	return atomicWriteFile(s.path, payload)
}

// atomicWriteFile 同目录临时文件 + rename，保证不会读到半截内容。
func atomicWriteFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if err := tmp.Chmod(authFileMode); err != nil {
		cleanup()
		return fmt.Errorf("设置文件权限失败: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("同步临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("替换账号文件失败: %w", err)
	}
	return nil
}

// LoadOrCreateSecret 读取（不存在则生成）会话签名密钥。
// 密钥独立成文件，账号数据被重置时不会连带导致所有人掉线，
// 反过来删掉密钥等于让所有旧会话立即失效。
func LoadOrCreateSecret(dataDir string) ([]byte, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	if err := os.MkdirAll(dataDir, authDirMode); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	path := filepath.Join(dataDir, secretFileName)
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) >= secretKeyBytes {
		return raw[:secretKeyBytes], nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("读取密钥文件失败: %w", err)
	}

	secret := make([]byte, secretKeyBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %w", err)
	}
	if err := atomicWriteFile(path, secret); err != nil {
		return nil, err
	}
	return secret, nil
}
