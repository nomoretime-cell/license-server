package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	keyMgr      *KeyManager
	audit       *AuditStore
	ipWhitelist map[string]bool
	jwtSecret   []byte
	jwtExpHrs   int
	users       map[string]string // username -> bcrypt hash
}

func NewServer(cfg *Config, keyMgr *KeyManager, audit *AuditStore) *Server {
	wl := make(map[string]bool, len(cfg.IPWhitelist))
	for _, ip := range cfg.IPWhitelist {
		wl[ip] = true
	}

	users := make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("hash password for %s: %v", u.Username, err)
		}
		users[u.Username] = string(h)
	}

	return &Server{
		keyMgr:      keyMgr,
		audit:       audit,
		ipWhitelist: wl,
		jwtSecret:   []byte(cfg.JWTSecret),
		jwtExpHrs:   cfg.JWTExpireHours,
		users:       users,
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":443"
	}
	if cfg.JWTExpireHours == 0 {
		cfg.JWTExpireHours = 8
	}
	if cfg.DBDriver == "" {
		cfg.DBDriver = "sqlite"
	}
	if cfg.DBDSN == "" {
		cfg.DBDSN = "audit.db"
	}
	return &cfg, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.Handle("/api/v1/login", s.withIPWhitelist(http.HandlerFunc(s.handleLogin)))
	mux.Handle("/api/v1/license/issue", s.withIPWhitelist(s.withJWTAuth(http.HandlerFunc(s.handleIssueLicense))))
	mux.Handle("/api/v1/license/audit", s.withIPWhitelist(s.withJWTAuth(http.HandlerFunc(s.handleGetAuditLogs))))
	return mux
}

// ==================== Middleware ====================

func (s *Server) withIPWhitelist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.ipWhitelist) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ip := extractIP(r)
		if !s.ipWhitelist[ip] {
			writeJSON(w, http.StatusForbidden, APIResponse{Code: http.StatusForbidden, Message: "IP not allowed: " + ip})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withJWTAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, APIResponse{Code: http.StatusUnauthorized, Message: "missing or invalid authorization header"})
			return
		}
		token, err := jwt.Parse(strings.TrimPrefix(auth, "Bearer "), func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, APIResponse{Code: http.StatusUnauthorized, Message: "invalid or expired token"})
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, APIResponse{Code: http.StatusUnauthorized, Message: "invalid token claims"})
			return
		}
		username, _ := claims["sub"].(string)
		r.Header.Set("X-Operator", username)
		next.ServeHTTP(w, r)
	})
}

// ==================== Handlers ====================

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, APIResponse{Code: http.StatusOK, Message: "healthy"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: http.StatusMethodNotAllowed, Message: "method not allowed"})
		return
	}
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Code: http.StatusBadRequest, Message: "invalid request body"})
		return
	}
	hash, ok := s.users[req.Username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, APIResponse{Code: http.StatusUnauthorized, Message: "invalid username or password"})
		return
	}

	expiresAt := time.Now().Add(time.Duration(s.jwtExpHrs) * time.Hour)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username, "exp": expiresAt.Unix(), "iat": time.Now().Unix(),
	}).SignedString(s.jwtSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Code: http.StatusInternalServerError, Message: "generate token failed"})
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Code: http.StatusOK, Message: "ok", Data: LoginResponse{Token: token, ExpiresAt: expiresAt}})
}

func (s *Server) handleIssueLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: http.StatusMethodNotAllowed, Message: "method not allowed"})
		return
	}
	var req LicenseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Code: http.StatusBadRequest, Message: "invalid request body"})
		return
	}
	if len(req.Payload) == 0 || string(req.Payload) == "null" {
		writeJSON(w, http.StatusBadRequest, APIResponse{Code: http.StatusBadRequest, Message: "payload is required"})
		return
	}
	if req.ValidDays <= 0 {
		req.ValidDays = 3650
	}

	// Normalize payload: unmarshal+remarshal to get sorted keys + compact format,
	// ensuring deterministic bytes across languages (Go, Python, C, ...).
	var payloadObj interface{}
	if err := json.Unmarshal(req.Payload, &payloadObj); err != nil {
		writeJSON(w, http.StatusBadRequest, APIResponse{Code: http.StatusBadRequest, Message: "invalid payload JSON"})
		return
	}
	normalizedPayload, _ := json.Marshal(payloadObj)
	req.Payload = json.RawMessage(normalizedPayload)

	now := time.Now().UTC()
	issuedAt := now.Format(time.RFC3339)
	expiresAt := now.AddDate(0, 0, req.ValidDays).Format(time.RFC3339)

	// Build envelope as sorted-key map for deterministic cross-language verification
	envelopeMap := map[string]interface{}{
		"expires_at": expiresAt,
		"issued_at":  issuedAt,
		"payload":    req.Payload,
	}
	envelopeBytes, _ := json.Marshal(envelopeMap)

	sig, err := s.keyMgr.Sign(envelopeBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Code: http.StatusInternalServerError, Message: "sign failed"})
		return
	}

	operator := r.Header.Get("X-Operator")
	clientIP := extractIP(r)

	issuedTime, _ := time.Parse(time.RFC3339, issuedAt)
	expiresTime, _ := time.Parse(time.RFC3339, expiresAt)

	if err := s.audit.Insert(AuditLog{
		Operator:  operator,
		Payload:   string(req.Payload),
		IssuedAt:  issuedTime,
		ExpiresAt: expiresTime,
		ClientIP:  clientIP,
	}); err != nil {
		log.Printf("[ERROR] audit insert: %v", err)
	}

	log.Printf("[AUDIT] operator=%s ip=%s payload=%s expires=%s",
		operator, clientIP, string(req.Payload), expiresAt)

	lic := &LicenseFile{
		Payload:   req.Payload,
		IssuedAt:  issuedTime,
		ExpiresAt: expiresTime,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	writeJSON(w, http.StatusOK, APIResponse{Code: http.StatusOK, Message: "license issued", Data: lic})
}

func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, APIResponse{Code: http.StatusMethodNotAllowed, Message: "method not allowed"})
		return
	}
	logs, err := s.audit.List()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIResponse{Code: http.StatusInternalServerError, Message: "query audit logs failed"})
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Code: http.StatusOK, Message: "ok", Data: logs})
}

// ==================== Helpers ====================

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
