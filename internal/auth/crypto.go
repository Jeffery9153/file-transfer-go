package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// pbkdf2Iterations OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限附近取值，
	// 在 Apple Silicon 上单次校验约 60~90ms，可接受。
	pbkdf2Iterations = 210000
	saltLen          = 16
	derivedKeyLen    = 32

	// 找回码：15 字节熵 -> 24 个 base32 字符 -> 6 组 4 字符
	recoveryCodeEntropy = 15
	recoveryCodeGroup   = 4

	// 会话令牌有效期
	sessionTTL = 7 * 24 * time.Hour

	// 归档算法标识，便于后续升级迭代轮数而不破坏老数据
	hashPrefix = "pbkdf2-sha256"
)

// crockfordAlphabet 去掉了 I/L/O/U，避免手抄找回码时混淆。
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var recoveryEncoding = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

var (
	// ErrInvalidHash 哈希串格式不合法
	ErrInvalidHash = errors.New("密码哈希格式不合法")
	// ErrEmptyPassword 空密码
	ErrEmptyPassword = errors.New("密码不能为空")
)

// pbkdf2SHA256 按 RFC 2898 实现 PBKDF2-HMAC-SHA256。
// 不引入 golang.org/x/crypto，保持项目零额外依赖。
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	derived := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		// U1 = PRF(password, salt || INT_32_BE(block))
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		u = prf.Sum(u[:0])

		// T = U1
		t := make([]byte, hashLen)
		copy(t, u)

		// T = U1 XOR U2 XOR ... XOR Uc
		for n := 2; n <= iterations; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		derived = append(derived, t...)
	}

	return derived[:keyLen]
}

// HashSecret 把明文（密码或找回码）转换成可持久化的哈希串。
// 格式：pbkdf2-sha256$<迭代次数>$<base64salt>$<base64hash>
func HashSecret(plain string) (string, error) {
	if plain == "" {
		return "", ErrEmptyPassword
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成随机盐失败: %w", err)
	}

	dk := pbkdf2SHA256([]byte(plain), salt, pbkdf2Iterations, derivedKeyLen)

	return fmt.Sprintf("%s$%d$%s$%s",
		hashPrefix,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifySecret 校验明文是否与哈希串匹配，使用常量时间比较。
func VerifySecret(plain, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}

	got := pbkdf2SHA256([]byte(plain), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateRecoveryCode 生成一次性的账号找回码，形如 A7K2-9XQP-M4RT-8ZNV-3C6H-WQ2D。
// 返回的是用于展示给用户的明文，落库时必须先 HashSecret。
func GenerateRecoveryCode() (string, error) {
	raw := make([]byte, recoveryCodeEntropy)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成找回码失败: %w", err)
	}

	encoded := recoveryEncoding.EncodeToString(raw)

	var groups []string
	for i := 0; i < len(encoded); i += recoveryCodeGroup {
		end := i + recoveryCodeGroup
		if end > len(encoded) {
			end = len(encoded)
		}
		groups = append(groups, encoded[i:end])
	}
	return strings.Join(groups, "-"), nil
}

// NormalizeRecoveryCode 归一化用户输入的找回码：
// 去除空白与连字符、统一大写、按 Crockford 规则把易混字符映射回标准字符。
func NormalizeRecoveryCode(in string) string {
	var b strings.Builder
	b.Grow(len(in))

	for _, r := range strings.ToUpper(in) {
		switch r {
		case ' ', '\t', '\n', '\r', '-', '_':
			continue
		case 'I', 'L':
			b.WriteRune('1')
		case 'O':
			b.WriteRune('0')
		case 'U':
			// U 不在字母表内，按 Crockford 规范视为非法，直接丢弃以免误判
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RandomToken 生成 n 字节熵的 URL 安全随机串。
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// sessionClaims 会话令牌载荷
type sessionClaims struct {
	Username string `json:"u"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Nonce    string `json:"n"`
}

// signPayload 用 HMAC-SHA256 对载荷签名
func signPayload(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

// IssueSessionToken 签发会话令牌，格式 <base64url(payload)>.<base64url(sig)>
func IssueSessionToken(secret []byte, username string, ttl time.Duration) (string, error) {
	nonce, err := RandomToken(12)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := sessionClaims{
		Username: username,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
		Nonce:    nonce,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	sigPart := base64.RawURLEncoding.EncodeToString(signPayload(secret, []byte(payloadPart)))

	return payloadPart + "." + sigPart, nil
}

// ParseSessionToken 校验签名与有效期，返回用户名。
func ParseSessionToken(secret []byte, token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", false
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	expected := signPayload(secret, []byte(parts[0]))
	if !hmac.Equal(sig, expected) {
		return "", false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}

	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Expires <= time.Now().Unix() {
		return "", false
	}
	if claims.Username == "" {
		return "", false
	}
	return claims.Username, true
}

// SessionTTL 暴露令牌有效期给上层设置 Cookie MaxAge
func SessionTTL() time.Duration { return sessionTTL }

// subtleConstantCompare 先哈希再常量时间比较，规避长度差异带来的时序信息。
func subtleConstantCompare(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
