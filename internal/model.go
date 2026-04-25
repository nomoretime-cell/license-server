package internal

import (
	"encoding/json"
	"time"
)

// --- Request / Response ---

type LicenseRequest struct {
	Payload   json.RawMessage `json:"payload"`
	ValidDays int             `json:"valid_days"`
}

type LicenseEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type LicenseFile struct {
	Version   int             `json:"version"`
	Payload   json.RawMessage `json:"payload"`
	IssuedAt  time.Time       `json:"issued_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Signature string          `json:"signature"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	Operator  string    `json:"operator"`
	Payload   string    `json:"payload"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	ClientIP  string    `json:"client_ip"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// --- Config ---

type Config struct {
	ListenAddr     string       `json:"listen_addr"`
	PrivateKeyPath string       `json:"private_key_path"`
	TLSCertPath    string       `json:"tls_cert_path"`
	TLSKeyPath     string       `json:"tls_key_path"`
	IPWhitelist    []string     `json:"ip_whitelist"`
	JWTSecret      string       `json:"jwt_secret"`
	JWTExpireHours int          `json:"jwt_expire_hours"`
	DBDriver       string       `json:"db_driver"`
	DBDSN          string       `json:"db_dsn"`
	Users          []UserConfig `json:"users"`
}

type UserConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
