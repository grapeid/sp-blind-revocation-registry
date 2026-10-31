package brrtest

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/api"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
	"github.com/grapeid/sp-common/sign"
)

// NewServer starts an in-process BRR for integration tests. It checks
// everything the deployed service checks: an enrolment carries the issuer's
// key event log and the registry's inception, and every request is signed.
func NewServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	id, err := sign.LoadOrCreateIdentity(filepath.Join(dir, "brr-id", "brr_identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(api.New(st, id).Router())
}
