package brrtest

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/api"
	"github.com/grapeid/sp-blind-revocation-registry/internal/signer"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
)

// NewServer starts an in-process BRR for integration tests (sets BRR_DEV_SKIP_SIG).
func NewServer(t *testing.T) *httptest.Server {
	t.Helper()
	os.Setenv("BRR_DEV_SKIP_SIG", "true")
	t.Cleanup(func() { os.Unsetenv("BRR_DEV_SKIP_SIG") })

	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	id, err := signer.LoadOrCreate(filepath.Join(dir, "brr-id"))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(api.New(st, id).Router())
}