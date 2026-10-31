package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/blind"
)

// An issuer enrolls a registry, issues and revokes a credential, and a
// verifier finds the revocation in a bulk proof.
func TestBRRSteelThread(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	blinded := blind.BlindedID("EAcredSteelThread123456789012345678901234", "registry-salt-private-acdc-attr")
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, blinded, "iss", "1"))
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, blinded, "rev", "2"))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/registry/"+prefix+"/bulk-proof?bucket_hint="+blinded, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("bulk-proof %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Proof struct {
			RevokedIDs []string `json:"revoked_ids"`
		} `json:"proof"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, id := range resp.Proof.RevokedIDs {
		if id == blinded {
			return
		}
	}
	t.Fatalf("revoked blinded id not in bulk proof: %v", resp.Proof.RevokedIDs)
}
