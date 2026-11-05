package auth

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	// ErrAlreadyInitialized 账号已存在，不能重复初始化
	ErrAlreadyInitialized = errors.New("账号已初始化，请直接登录")
	// ErrInvalidCredentials 账号或密码错误
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	// ErrInvalidRecoveryCode 找回码无效
	ErrInvalidRecoveryCode = errors.New("找回码无效或已失效")
	// ErrTooManyAttempts 触发限速
	ErrTooManyAttempts = errors.New("尝试次数过多，请 3 分钟后再试")
	// ErrWeakPassword 密码不合规
	ErrWeakPassword = errors.New("密码长度需在 8~128 位之间")
	// ErrInvalidUsername 用户名不合规
	ErrInvalidUsername = errors.New("用户名需 2~32 位，仅允许字母、数字和 _ - . @")
)

const (
	minPasswordLen = 8
	maxPasswordLen = 128
	maxFails       = 5
	lockDuration   = 3 * time.Minute
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{2,32}$`)

// Service 账号业务层：初始化 / 登录 / 凭找回码重置 / 会话校验。
type Service struct {
	store   *Store
	secret  []byte
	limiter *loginLimiter

	// opMu 串行化初始化与重置这类"读-改-写"操作
	opMu sync.Mutex
}

// Status 对外暴露的账号状态
type Status struct {
	Initialized bool   `json:"initialized"`
	Username    string `json:"username,omitempty"`
}

// NewService 基于 dataDir 构建账号服务。
func NewService(dataDir string) (*Service, error) {
	store, err := NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	secret, err := LoadOrCreateSecret(dataDir)
	if err != nil {
		return nil, err
	}
	return &Service{
		store:   store,
		secret:  secret,
		limiter: newLoginLimiter(maxFails, lockDuration),
	}, nil
}

// Status 返回当前是否已初始化及用户名（不含任何敏感信息）。
func (s *Service) Status() Status {
	u := s.store.Get()
	if u == nil {
		return Status{Initialized: false}
	}
	return Status{Initialized: true, Username: u.Username}
}

// Init 首次初始化唯一账号，返回一次性展示的找回码和已签发的会话令牌。
// 只能在未初始化时调用。
func (s *Service) Init(username, password string) (recoveryCode, token string, err error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return "", "", ErrInvalidUsername
	}
	if err := validatePassword(password); err != nil {
		return "", "", err
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.store.Initialized() {
		return "", "", ErrAlreadyInitialized
	}

	pwHash, err := HashSecret(password)
	if err != nil {
		return "", "", err
	}
	code, err := GenerateRecoveryCode()
	if err != nil {
		return "", "", err
	}
	codeHash, err := HashSecret(NormalizeRecoveryCode(code))
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	user := &User{
		Username:          username,
		PasswordHash:      pwHash,
		RecoveryHash:      codeHash,
		CreatedAt:         now,
		UpdatedAt:         now,
		PasswordUpdatedAt: now,
	}
	if err := s.store.Create(user); err != nil {
		if errors.Is(err, ErrAlreadyInitialized) {
			return "", "", ErrAlreadyInitialized
		}
		return "", "", err
	}

	token, err = IssueSessionToken(s.secret, username, sessionTTL)
	if err != nil {
		return "", "", err
	}
	return code, token, nil
}

// Login 校验用户名密码并签发会话令牌。clientKey 用于失败限速（一般是客户端 IP）。
func (s *Service) Login(username, password, clientKey string) (string, error) {
	if s.limiter.Blocked(clientKey) {
		return "", ErrTooManyAttempts
	}

	user := s.store.Get()
	if user == nil {
		s.limiter.Fail(clientKey)
		return "", ErrNotInitialized
	}

	username = strings.TrimSpace(username)

	// 即使用户名对不上也照常做一次哈希校验，避免通过响应时间判断用户名
	okUser := subtleEqual(username, user.Username)
	okPass := VerifySecret(password, user.PasswordHash)

	if !okUser || !okPass {
		s.limiter.Fail(clientKey)
		return "", ErrInvalidCredentials
	}

	token, err := IssueSessionToken(s.secret, user.Username, sessionTTL)
	if err != nil {
		return "", err
	}
	s.limiter.Reset(clientKey)
	return token, nil
}

// ResetByRecoveryCode 用找回码重置密码。
// 成功后旧的找回码立即作废，并下发新的找回码（一次性 + 自动轮换）。
func (s *Service) ResetByRecoveryCode(recoveryCode, newPassword, clientKey string) (newRecoveryCode, token string, err error) {
	if s.limiter.Blocked("reset:" + clientKey) {
		return "", "", ErrTooManyAttempts
	}
	if err := validatePassword(newPassword); err != nil {
		return "", "", err
	}

	normalized := NormalizeRecoveryCode(recoveryCode)
	if normalized == "" {
		s.limiter.Fail("reset:" + clientKey)
		return "", "", ErrInvalidRecoveryCode
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	user := s.store.Get()
	if user == nil {
		return "", "", ErrNotInitialized
	}
	if !VerifySecret(normalized, user.RecoveryHash) {
		s.limiter.Fail("reset:" + clientKey)
		return "", "", ErrInvalidRecoveryCode
	}

	pwHash, err := HashSecret(newPassword)
	if err != nil {
		return "", "", err
	}
	code, err := GenerateRecoveryCode()
	if err != nil {
		return "", "", err
	}
	codeHash, err := HashSecret(NormalizeRecoveryCode(code))
	if err != nil {
		return "", "", err
	}

	now := time.Now().UTC()
	user.PasswordHash = pwHash
	user.RecoveryHash = codeHash
	user.UpdatedAt = now
	user.PasswordUpdatedAt = now

	if err := s.store.Update(user); err != nil {
		return "", "", err
	}

	token, err = IssueSessionToken(s.secret, user.Username, sessionTTL)
	if err != nil {
		return "", "", err
	}
	s.limiter.Reset("reset:" + clientKey)
	return code, token, nil
}

// VerifySession 校验会话令牌，返回用户名。
func (s *Service) VerifySession(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	username, ok := ParseSessionToken(s.secret, token)
	if !ok {
		return "", false
	}
	user := s.store.Get()
	if user == nil || user.Username != username {
		return "", false
	}
	return username, true
}

// validatePassword 基本强度校验：长度 + 不能全空白。
func validatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < minPasswordLen || n > maxPasswordLen {
		return ErrWeakPassword
	}
	if strings.TrimSpace(pw) == "" {
		return ErrWeakPassword
	}
	return nil
}

// subtleEqual 常量时间字符串比较，避免时序侧信道。
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		// 长度不同也走一遍比较，保持耗时稳定
		_ = subtleConstantCompare(a, b)
		return false
	}
	return subtleConstantCompare(a, b)
}

// loginLimiter 简单的按来源限速，防止在线暴力破解。
type loginLimiter struct {
	mu       sync.Mutex
	records  map[string]*attemptRecord
	maxFails int
	lockFor  time.Duration
}

type attemptRecord struct {
	fails int
	until time.Time
	last  time.Time
}

func newLoginLimiter(maxFails int, lockFor time.Duration) *loginLimiter {
	return &loginLimiter{
		records:  make(map[string]*attemptRecord),
		maxFails: maxFails,
		lockFor:  lockFor,
	}
}

// Blocked 当前来源是否处于锁定窗口内。
func (l *loginLimiter) Blocked(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.records[key]
	if !ok {
		return false
	}
	// until 为零值表示尚未触发锁定，不能当作"已过期"清掉记录
	if !rec.until.IsZero() && time.Now().After(rec.until) {
		delete(l.records, key)
		return false
	}
	return rec.fails >= l.maxFails
}

// Fail 记录一次失败，达到阈值后开始锁定。
func (l *loginLimiter) Fail(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked()

	rec, ok := l.records[key]
	if !ok {
		rec = &attemptRecord{}
		l.records[key] = rec
	}
	rec.fails++
	rec.last = time.Now()
	if rec.fails >= l.maxFails {
		rec.until = time.Now().Add(l.lockFor)
	}
}

// Reset 登录成功后清除该来源的失败记录。
func (l *loginLimiter) Reset(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, key)
}

// gcLocked 清理长时间不活跃的记录，避免 map 无限增长。
func (l *loginLimiter) gcLocked() {
	if len(l.records) < 512 {
		return
	}
	cutoff := time.Now().Add(-30 * time.Minute)
	for k, rec := range l.records {
		if rec.last.Before(cutoff) && time.Now().After(rec.until) {
			delete(l.records, k)
		}
	}
}
