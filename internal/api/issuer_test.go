package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
	"github.com/grapeid/sp-blind-revocation-registry/internal/testissuer"
	"github.com/grapeid/sp-common/sign"
)

// issuer wraps testissuer.Issuer so a test reads as the requests it sends.
type issuer struct {
	*testissuer.Issuer
	t *testing.T
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	is, err := testissuer.New()
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{Issuer: is, t: t}
}

func (is *issuer) rotate() {
	if err := is.Rotate(); err != nil {
		is.t.Fatal(err)
	}
}

func (is *issuer) kel() string {
	kel, err := is.KEL()
	if err != nil {
		is.t.Fatal(err)
	}
	return kel
}

func (is *issuer) registry() (prefix, inception string) {
	prefix, inception, err := is.Registry()
	if err != nil {
		is.t.Fatal(err)
	}
	return prefix, inception
}

func (is *issuer) sign(fields map[string]any) string {
	sig, err := is.Sign(fields)
	if err != nil {
		is.t.Fatal(err)
	}
	return sig
}

func (is *issuer) enrolment(prefix, inception string) map[string]any {
	req, err := is.Enrolment(prefix, inception)
	if err != nil {
		is.t.Fatal(err)
	}
	return req
}

func (is *issuer) event(prefix, blindedID, eventType, seq string) map[string]any {
	n, err := strconv.Atoi(seq)
	if err != nil {
		is.t.Fatal(err)
	}
	ev, err := is.Event(prefix, blindedID, eventType, n)
	if err != nil {
		is.t.Fatal(err)
	}
	return ev
}

func newRegistry(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := sign.LoadOrCreateIdentity(filepath.Join(dir, "id", "brr_identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, id).Router(), st
}

func send(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
	return w
}

func mustSend(t *testing.T, h http.Handler, path string, body any) {
	t.Helper()
	if w := send(t, h, path, body); w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
}
