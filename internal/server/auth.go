package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// PBKDF2 parameters. SHA-256 + 600k iterations follows the current OWASP
// recommendation (2023+); bcrypt / scrypt / argon2 are deliberately NOT
// used because they are not FIPS 140-3 approved key-derivation functions
// — fipscan's own catalog flags them.
//
// NIST SP 800-132 specifies PBKDF2 as the approved password-based KDF.
const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32 // 256 bits
	pbkdf2SaltLen    = 16
	hashScheme       = "pbkdf2-sha256"
)

// HashPassword derives a PBKDF2-HMAC-SHA256 hash from password and
// formats it for storage / config:
//
//	pbkdf2-sha256$<iterations>$<base64-salt>$<base64-hash>
//
// All FIPS-approved primitives (HMAC-SHA-256, crypto/rand source seeded
// by the OS).
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s",
		hashScheme, pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword constant-time-compares password against a stored hash
// in the format produced by HashPassword.
func VerifyPassword(stored, password string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false, fmt.Errorf("unsupported hash format")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false, fmt.Errorf("invalid iteration count")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("invalid hash: %w", err)
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// basicAuth wraps h. If passwordHash is empty, the wrapper is a no-op
// (caller has already enforced that this only happens when listening on
// localhost). Otherwise every request must carry valid HTTP Basic
// credentials.
//
// The username defaults to "admin"; the password (after PBKDF2 verify)
// must match the configured hash.
func basicAuth(username, passwordHash string, h http.Handler) http.Handler {
	if passwordHash == "" {
		return h
	}
	if username == "" {
		username = "admin"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			unauthorized(w)
			return
		}
		// Username compared in constant time too, to avoid leaking length.
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(username)) == 1
		passOK, _ := VerifyPassword(passwordHash, p)
		if !userOK || !passOK {
			unauthorized(w)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="fipscan", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
