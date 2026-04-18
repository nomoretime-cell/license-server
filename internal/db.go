package internal

import (
	"database/sql"
	"fmt"
	"time"
)

// AuditStore abstracts audit log persistence.
// Uses database/sql so switching from SQLite to MySQL/PostgreSQL
// only requires changing the driver and DSN — no code changes needed.
type AuditStore struct {
	db *sql.DB
}

func NewAuditStore(driverName, dsn string) (*AuditStore, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS audit_logs (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		operator   TEXT NOT NULL,
		payload    TEXT NOT NULL,
		issued_at  TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		client_ip  TEXT NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &AuditStore{db: db}, nil
}

func (s *AuditStore) Insert(log AuditLog) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_logs (operator, payload, issued_at, expires_at, client_ip)
		 VALUES (?, ?, ?, ?, ?)`,
		log.Operator, log.Payload,
		log.IssuedAt.Format(time.RFC3339), log.ExpiresAt.Format(time.RFC3339), log.ClientIP,
	)
	return err
}

func (s *AuditStore) List() ([]AuditLog, error) {
	rows, err := s.db.Query(
		`SELECT id, operator, payload, issued_at, expires_at, client_ip
		 FROM audit_logs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		var issuedStr, expiresStr string
		if err := rows.Scan(&l.ID, &l.Operator, &l.Payload,
			&issuedStr, &expiresStr, &l.ClientIP); err != nil {
			return nil, err
		}
		l.IssuedAt, _ = time.Parse(time.RFC3339, issuedStr)
		l.ExpiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func (s *AuditStore) Close() error {
	return s.db.Close()
}
