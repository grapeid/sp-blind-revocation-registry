package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// A database written before enrolments were proven gains issuer_kel, and its
// registries read back with none, which is how they are told apart.
func TestARegistryEnrolledBeforeKeyLogsReadsAsUnproven(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "brr.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE registries (
		registry_prefix TEXT PRIMARY KEY, issuer_aid TEXT NOT NULL, issuer_pubkey_b64 TEXT NOT NULL,
		enrolled_at TEXT NOT NULL, last_sync_seq INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active');
		INSERT INTO registries VALUES ('EREG', 'EOLD', 'key', 'then', 0, 'active')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reg, err := st.GetRegistry("EREG")
	if err != nil || reg == nil {
		t.Fatalf("the old registry did not read back: %v", err)
	}
	if reg.IssuerKEL != "" {
		t.Fatalf("an old registry read back with a key log: %q", reg.IssuerKEL)
	}
}

// An enrolled registry is never replaced by enrolling it again, and its issuer
// moves only from the key it holds.
func TestAnEnrolledRegistryIsNotOverwritten(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Enroll("EREG", "EALICE", "alice-key", "alice-kel"); err != nil {
		t.Fatal(err)
	}
	if err := st.Enroll("EREG", "EMALLORY", "mallory-key", "mallory-kel"); !errors.Is(err, ErrChanged) {
		t.Fatalf("a second enrolment gave %v", err)
	}
	if err := st.ReplaceIssuer("EREG", "not-the-held-key", "EALICE", "new-key", "kel2"); !errors.Is(err, ErrChanged) {
		t.Fatalf("a replacement from a key not held gave %v", err)
	}
	reg, _ := st.GetRegistry("EREG")
	if reg.IssuerAID != "EALICE" || reg.IssuerPubB64 != "alice-key" {
		t.Fatalf("the registry changed hands: %+v", reg)
	}
}
