package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists registry enrollments and blinded accumulator entries.
type Store struct {
	db *sql.DB
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "brr.db"))
	if err != nil {
		return nil, err
	}
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS registries (
    registry_prefix TEXT PRIMARY KEY,
    issuer_aid TEXT NOT NULL,
    issuer_pubkey_b64 TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_sync_seq INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS accumulator_entries (
    registry_prefix TEXT NOT NULL,
    blinded_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    inserted_at TEXT NOT NULL,
    PRIMARY KEY (registry_prefix, blinded_id)
);
CREATE TABLE IF NOT EXISTS anchor_log (
    anchor_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    anchor_time TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    note TEXT
);
`)
	return err
}

type Registry struct {
	Prefix       string
	IssuerAID    string
	IssuerPubB64 string
	LastSyncSeq  int
	Status       string
}

func (s *Store) Enroll(prefix, issuerAID, issuerPubB64 string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO registries (registry_prefix, issuer_aid, issuer_pubkey_b64, enrolled_at, status)
		VALUES (?, ?, ?, ?, 'active')
		ON CONFLICT(registry_prefix) DO UPDATE SET
			issuer_aid=excluded.issuer_aid,
			issuer_pubkey_b64=excluded.issuer_pubkey_b64,
			status='active'`,
		prefix, issuerAID, issuerPubB64, now)
	return err
}

func (s *Store) GetRegistry(prefix string) (*Registry, error) {
	var r Registry
	err := s.db.QueryRow(`
		SELECT registry_prefix, issuer_aid, issuer_pubkey_b64, last_sync_seq, status
		FROM registries WHERE registry_prefix=?`, prefix).
		Scan(&r.Prefix, &r.IssuerAID, &r.IssuerPubB64, &r.LastSyncSeq, &r.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) InsertEvent(prefix, blindedID, eventType string, seq int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if eventType == "rev" {
		_, err = tx.Exec(`
			INSERT INTO accumulator_entries (registry_prefix, blinded_id, event_type, sequence_number, inserted_at)
			VALUES (?, ?, 'revoked', ?, ?)
			ON CONFLICT(registry_prefix, blinded_id) DO UPDATE SET
				event_type='revoked', sequence_number=excluded.sequence_number, inserted_at=excluded.inserted_at`,
			prefix, blindedID, seq, now)
	} else {
		// iss events recorded for sync audit; revocation check uses revoked set only.
		_, err = tx.Exec(`
			INSERT INTO accumulator_entries (registry_prefix, blinded_id, event_type, sequence_number, inserted_at)
			VALUES (?, ?, 'issued', ?, ?)
			ON CONFLICT(registry_prefix, blinded_id) DO UPDATE SET
				event_type=CASE WHEN accumulator_entries.event_type='revoked' THEN 'revoked' ELSE 'issued' END,
				sequence_number=excluded.sequence_number`,
			prefix, blindedID, seq, now)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE registries SET last_sync_seq=? WHERE registry_prefix=? AND last_sync_seq < ?`,
		seq, prefix, seq)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokedIDs(prefix string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT blinded_id FROM accumulator_entries
		WHERE registry_prefix=? AND event_type='revoked' ORDER BY blinded_id`, prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Store) RecordAnchor(root string, enabled bool) error {
	id := fmt.Sprintf("anchor-%d", time.Now().UnixNano())
	note := "BLOCKED: blockchain anchoring disabled — local log only"
	if enabled {
		note = "BLOCKED: on-chain TX not implemented"
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO anchor_log (anchor_id, merkle_root, anchor_time, enabled, note)
		VALUES (?, ?, ?, ?, ?)`,
		id, root, time.Now().UTC().Format(time.RFC3339), en, note)
	return err
}

func (s *Store) LatestAnchor() (map[string]interface{}, error) {
	var root, at string
	var enabled int
	var note string
	err := s.db.QueryRow(`
		SELECT merkle_root, anchor_time, enabled, note FROM anchor_log
		ORDER BY anchor_time DESC LIMIT 1`).Scan(&root, &at, &enabled, &note)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"merkle_root": root, "anchor_time": at,
		"anchoring_enabled": enabled == 1, "note": note,
	}, nil
}