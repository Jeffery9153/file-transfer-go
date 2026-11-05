package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPBKDF2KnownVectors 用公开测试向量验证自实现 PBKDF2-HMAC-SHA256 的正确性。
// P="password" S="salt" dkLen=32
func TestPBKDF2KnownVectors(t *testing.T) {
	cases := []struct {
		iterations int
		want       string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}

	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), c.iterations, 32))
		if got != c.want {
			t.Errorf("iterations=%d 结果错误\n got=%s\nwant=%s", c.iterations, got, c.want)
		}
	}
}

func TestHashAndVerifySecret(t *testing.T) {
	encoded, err := HashSecret("correct horse battery")
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	if !strings.HasPrefix(encoded, hashPrefix+"$") {
		t.Fatalf("哈希格式不符合预期: %s", encoded)
	}
	if !VerifySecret("correct horse battery", encoded) {
		t.Error("正确密码应当校验通过")
	}
	if VerifySecret("wrong password", encoded) {
		t.Error("错误密码不应校验通过")
	}
	if VerifySecret("correct horse battery", "garbage") {
		t.Error("非法哈希串不应校验通过")
	}

	// 同一密码两次哈希必须因随机盐而不同
	encoded2, _ := HashSecret("correct horse battery")
	if encoded == encoded2 {
		t.Error("随机盐未生效，两次哈希结果相同")
	}
}

func TestRecoveryCodeFormatAndNormalize(t *testing.T) {
	code, err := GenerateRecoveryCode()
	if err != nil {
		t.Fatalf("生成找回码失败: %v", err)
	}

	groups := strings.Split(code, "-")
	if len(groups) != 6 {
		t.Fatalf("找回码应为 6 组，实际 %d 组: %s", len(groups), code)
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Errorf("每组应为 4 字符，实际 %q", g)
		}
		for _, r := range g {
			if !strings.ContainsRune(crockfordAlphabet, r) {
				t.Errorf("找回码出现非法字符 %q", r)
			}
		}
	}

	// 归一化：小写、空格、易混字符
	lower := strings.ToLower(code)
	withSpaces := strings.ReplaceAll(lower, "-", " ")
	if NormalizeRecoveryCode(withSpaces) != NormalizeRecoveryCode(code) {
		t.Error("小写与空格应被归一化到同一结果")
	}
	if NormalizeRecoveryCode("io-l") != "10"+"1" {
		t.Errorf("O->0, I/L->1 映射失败: %q", NormalizeRecoveryCode("io-l"))
	}
}

func TestSessionToken(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	token, err := IssueSessionToken(secret, "admin", time.Hour)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if name, ok := ParseSessionToken(secret, token); !ok || name != "admin" {
		t.Errorf("正常令牌校验失败: name=%q ok=%v", name, ok)
	}

	// 篡改载荷
	if _, ok := ParseSessionToken(secret, "x"+token); ok {
		t.Error("被篡改的令牌不应通过")
	}
	// 换密钥
	if _, ok := ParseSessionToken([]byte("ffffffffffffffffffffffffffffffff"), token); ok {
		t.Error("使用错误密钥不应通过")
	}
	// 过期
	expired, _ := IssueSessionToken(secret, "admin", -time.Second)
	if _, ok := ParseSessionToken(secret, expired); ok {
		t.Error("过期令牌不应通过")
	}
}

func TestServiceFullFlow(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService(dir)
	if err != nil {
		t.Fatalf("初始化服务失败: %v", err)
	}

	if svc.Status().Initialized {
		t.Fatal("新目录不应处于已初始化状态")
	}

	// 首次初始化
	code, token, err := svc.Init("admin", "password123")
	if err != nil {
		t.Fatalf("初始化账号失败: %v", err)
	}
	if code == "" || token == "" {
		t.Fatal("初始化应同时返回找回码与会话令牌")
	}
	if name, ok := svc.VerifySession(token); !ok || name != "admin" {
		t.Fatalf("初始化后会话应立即有效: %q %v", name, ok)
	}

	// 重复初始化必须失败
	if _, _, err := svc.Init("other", "password123"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("重复初始化应返回 ErrAlreadyInitialized，实际 %v", err)
	}

	// 参数校验
	if _, _, err := svc.Init("a", "password123"); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("过短用户名应被拒绝，实际 %v", err)
	}

	// 错误密码
	if _, err := svc.Login("admin", "wrong-password", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("错误密码应返回 ErrInvalidCredentials，实际 %v", err)
	}

	// 正确登录
	loginToken, err := svc.Login("admin", "password123", "1.1.1.1")
	if err != nil {
		t.Fatalf("正确密码登录失败: %v", err)
	}
	if _, ok := svc.VerifySession(loginToken); !ok {
		t.Error("登录令牌应有效")
	}

	// 用错误找回码重置
	if _, _, err := svc.ResetByRecoveryCode("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF", "newpassword", "2.2.2.2"); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Errorf("错误找回码应被拒绝，实际 %v", err)
	}

	// 用正确找回码重置（大小写与空格不影响）
	messy := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	newCode, resetToken, err := svc.ResetByRecoveryCode(messy, "newpassword", "2.2.2.2")
	if err != nil {
		t.Fatalf("正确找回码重置失败: %v", err)
	}
	if newCode == code {
		t.Error("重置后必须下发新的找回码")
	}
	if _, ok := svc.VerifySession(resetToken); !ok {
		t.Error("重置后应自动登录")
	}

	// 旧码作废
	if _, _, err := svc.ResetByRecoveryCode(code, "anotherpass", "3.3.3.3"); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Errorf("旧找回码应已作废，实际 %v", err)
	}

	// 新密码可用、旧密码失效
	if _, err := svc.Login("admin", "newpassword", "4.4.4.4"); err != nil {
		t.Errorf("新密码应可登录: %v", err)
	}
	if _, err := svc.Login("admin", "password123", "4.4.4.4"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("旧密码应失效，实际 %v", err)
	}

	// 数据持久化：重启服务后账号与找回码仍可用
	svc2, err := NewService(dir)
	if err != nil {
		t.Fatalf("重新加载服务失败: %v", err)
	}
	if !svc2.Status().Initialized || svc2.Status().Username != "admin" {
		t.Error("重启后账号状态丢失")
	}
	if _, err := svc2.Login("admin", "newpassword", "5.5.5.5"); err != nil {
		t.Errorf("重启后新密码应仍可登录: %v", err)
	}
	if _, _, err := svc2.ResetByRecoveryCode(newCode, "thirdpassword", "6.6.6.6"); err != nil {
		t.Errorf("重启后新找回码应仍可用: %v", err)
	}
}

func TestLoginRateLimit(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService(dir)
	if err != nil {
		t.Fatalf("初始化服务失败: %v", err)
	}
	if _, _, err := svc.Init("admin", "password123"); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	key := "9.9.9.9"
	for i := 0; i < maxFails; i++ {
		if _, err := svc.Login("admin", "bad-password", key); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("第 %d 次失败应返回凭证错误，实际 %v", i+1, err)
		}
	}
	if _, err := svc.Login("admin", "password123", key); !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("达到阈值后应锁定，实际 %v", err)
	}

	// 其他来源不受影响
	if _, err := svc.Login("admin", "password123", "8.8.8.8"); err != nil {
		t.Errorf("其他 IP 不应受影响: %v", err)
	}
}

func TestStoreAtomicWriteAndPermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("创建存储失败: %v", err)
	}
	now := time.Now().UTC()
	if err := store.Create(&User{
		Username:          "admin",
		PasswordHash:      "h",
		RecoveryHash:      "r",
		CreatedAt:         now,
		UpdatedAt:         now,
		PasswordUpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建账号失败: %v", err)
	}

	path := filepath.Join(dir, authFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("账号文件未生成: %v", err)
	}
	if perm := info.Mode().Perm(); perm != authFileMode {
		t.Errorf("账号文件权限应为 %o，实际 %o", authFileMode, perm)
	}
	// 不应残留临时文件
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("残留临时文件: %s", e.Name())
		}
	}
}
