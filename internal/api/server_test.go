package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/blind"
	"github.com/grapeid/sp-blind-revocation-registry/internal/signer"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
)

func TestBRRSteelThread(t *testing.T) {
	os.Setenv("BRR_DEV_SKIP_SIG", "true")
	defer os.Unsetenv("BRR_DEV_SKIP_SIG")

	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, id)
	router := srv.Router()

	prefix := "ERegSteel1"
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(nil)
	issuerAID := "EissuerTest"
	issuerPubB64 := base64.StdEncoding.EncodeToString(issuerPub)

	enrollBody, _ := json.Marshal(map[string]string{
		"registry_prefix": prefix, "issuer_aid": issuerAID,
		"issuer_public_key_b64": issuerPubB64, "signature": "dev",
	})
	req := httptest.NewRequest(http.MethodPost, "/registry/enroll", bytes.NewReader(enrollBody))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll %d: %s", rec.Code, rec.Body.String())
	}

	credSAID := "EAcredSteelThread123456789012345678901234"
	salt := "registry-salt-private-acdc-attr"
	blinded := blind.BlindedID(credSAID, salt)

	push := func(eventType string, seq int) {
		evBody, _ := json.Marshal(map[string]interface{}{
			"blinded_id": blinded, "event_type": eventType, "sequence_number": seq, "signature": "dev",
		})
		r := httptest.NewRequest(http.MethodPost, "/registry/"+prefix+"/event", bytes.NewReader(evBody))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("event %s %d: %s", eventType, w.Code, w.Body.String())
		}
	}
	push("iss", 1)
	push("rev", 2)

	bulkReq := httptest.NewRequest(http.MethodGet, "/registry/"+prefix+"/bulk-proof?bucket_hint="+blinded, nil)
	bulkRec := httptest.NewRecorder()
	router.ServeHTTP(bulkRec, bulkReq)
	if bulkRec.Code != http.StatusOK {
		t.Fatalf("bulk-proof %d: %s", bulkRec.Code, bulkRec.Body.String())
	}
	var bulkResp struct {
		Proof struct {
			RevokedIDs []string `json:"revoked_ids"`
		} `json:"proof"`
	}
	if err := json.Unmarshal(bulkRec.Body.Bytes(), &bulkResp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range bulkResp.Proof.RevokedIDs {
		if id == blinded {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked blinded id not in bulk proof: %v", bulkResp.Proof.RevokedIDs)
	}
	_ = issuerPriv
}