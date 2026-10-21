package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/grapeid/sp-blind-revocation-registry/internal/anchor"
	"github.com/grapeid/sp-blind-revocation-registry/internal/merkle"
	"github.com/grapeid/sp-blind-revocation-registry/internal/signer"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
)

const ProtocolVersion = "1.0"

type Server struct {
	Store    *store.Store
	Identity *signer.Identity
}

func New(st *store.Store, id *signer.Identity) *Server {
	return &Server{Store: st, Identity: id}
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Logger, middleware.Recoverer)

	r.Get("/health", s.handleHealth)
	r.Get("/.well-known/brr-service.json", s.handleDescriptor)
	r.Get("/anchor/latest", s.handleAnchorLatest)
	r.Get("/anchor/history", s.handleAnchorHistory)

	r.Post("/registry/enroll", s.handleEnroll)
	r.Post("/registry/{prefix}/event", s.handleEvent)
	r.Get("/registry/{prefix}/bulk-proof", s.handleBulkProof)
	r.Get("/registry/{prefix}/proof/{blinded_id}", s.handleSingleProof)

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"status": "active", "service": "blind-revocation-registry",
		"brr_aid": s.Identity.AID, "protocol_version": ProtocolVersion,
	})
}

func (s *Server) handleDescriptor(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"brr_aid":              s.Identity.AID,
		"protocol_version":     ProtocolVersion,
		"anchoring_enabled":    anchor.Enabled(),
		"anchoring_chains":     []string{},
		"bulk_proofs_supported": true,
		"min_bucket_leaves":    merkle.MinBucketLeaves,
		"rate_limits":          map[string]int{"bulk_proofs_per_minute": 1000},
	})
}

type enrollRequest struct {
	RegistryPrefix   string `json:"registry_prefix"`
	IssuerAID        string `json:"issuer_aid"`
	IssuerPubKeyB64  string `json:"issuer_public_key_b64"`
	Signature        string `json:"signature"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.RegistryPrefix == "" || req.IssuerAID == "" || req.IssuerPubKeyB64 == "" {
		writeErr(w, http.StatusBadRequest, "registry_prefix, issuer_aid, issuer_public_key_b64 required")
		return
	}
	if err := s.verifyIssuerSig(req.IssuerPubKeyB64, req.Signature, enrollCanonical(req)); err != nil {
		if os.Getenv("BRR_DEV_SKIP_SIG") != "true" {
			writeErr(w, http.StatusUnauthorized, "issuer signature invalid")
			return
		}
	}
	if err := s.Store.Enroll(req.RegistryPrefix, req.IssuerAID, req.IssuerPubKeyB64); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, _ := json.Marshal(map[string]string{
		"registry_prefix": req.RegistryPrefix, "status": "enrolled",
	})
	sig := s.Identity.Sign(body)
	jsonOK(w, map[string]interface{}{
		"ok": true, "registry_prefix": req.RegistryPrefix,
		"confirmation": body, "brr_signature": sig, "signed_by": s.Identity.AID,
	})
}

type eventRequest struct {
	BlindedID      string `json:"blinded_id"`
	EventType      string `json:"event_type"`
	SequenceNumber int    `json:"sequence_number"`
	Signature      string `json:"signature"`
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	prefix := chi.URLParam(r, "prefix")
	reg, err := s.Store.GetRegistry(prefix)
	if err != nil || reg == nil {
		writeErr(w, http.StatusNotFound, "registry not enrolled")
		return
	}
	var req eventRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.BlindedID == "" || (req.EventType != "iss" && req.EventType != "rev") {
		writeErr(w, http.StatusBadRequest, "blinded_id and event_type (iss|rev) required")
		return
	}
	if err := s.verifyIssuerSig(reg.IssuerPubB64, req.Signature, eventCanonical(prefix, req)); err != nil {
		if os.Getenv("BRR_DEV_SKIP_SIG") != "true" {
			writeErr(w, http.StatusUnauthorized, "issuer signature invalid")
			return
		}
	}
	if err := s.Store.InsertEvent(prefix, req.BlindedID, req.EventType, req.SequenceNumber); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	revoked, _ := s.Store.RevokedIDs(prefix)
	tree := merkle.NewTree(revoked)
	root := tree.Root()
	if anchor.Enabled() {
		_ = s.Store.RecordAnchor(encodeRoot(root), true)
	}
	jsonOK(w, map[string]interface{}{
		"ok": true, "merkle_root": encodeRoot(root),
		"event_type": req.EventType, "sequence_number": req.SequenceNumber,
	})
}

func (s *Server) handleBulkProof(w http.ResponseWriter, r *http.Request) {
	prefix := chi.URLParam(r, "prefix")
	hint := r.URL.Query().Get("bucket_hint")
	reg, err := s.Store.GetRegistry(prefix)
	if err != nil || reg == nil {
		writeErr(w, http.StatusNotFound, "registry not enrolled")
		return
	}
	revoked, err := s.Store.RevokedIDs(prefix)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tree := merkle.NewTree(revoked)
	target := hint
	if target == "" && len(revoked) > 0 {
		target = revoked[0]
	}
	if target == "" {
		target = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	proof := tree.BulkProofFor(target)
	proof.RegistryPrefix = prefix
	payload, _ := json.Marshal(proof)
	sig := s.Identity.Sign(payload)
	jsonOK(w, map[string]interface{}{
		"proof": proof, "brr_signature": sig, "signed_by": s.Identity.AID,
		"issued_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleSingleProof(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-BRR-Privacy-Warning", "non-private — use bulk-proof for verifier pipeline")
	prefix := chi.URLParam(r, "prefix")
	blindedID := chi.URLParam(r, "blinded_id")
	revoked, err := s.Store.RevokedIDs(prefix)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	revokedFlag := merkle.IsRevoked(blindedID, revoked)
	jsonOK(w, map[string]interface{}{
		"registry_prefix": prefix, "blinded_id": blindedID,
		"revoked": revokedFlag, "warning": "utility endpoint only — verifiers must use bulk-proof",
	})
}

func (s *Server) handleAnchorLatest(w http.ResponseWriter, r *http.Request) {
	if !anchor.Enabled() {
		jsonOK(w, map[string]interface{}{
			"anchoring_enabled": false,
			"note": "anchoring not enabled — registry tamper-evident via KERI receipts",
		})
		return
	}
	rec, err := s.Store.LatestAnchor()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		jsonOK(w, map[string]interface{}{"anchoring_enabled": true, "anchors": []interface{}{}})
		return
	}
	jsonOK(w, rec)
}

func (s *Server) handleAnchorHistory(w http.ResponseWriter, r *http.Request) {
	s.handleAnchorLatest(w, r)
}

func (s *Server) verifyIssuerSig(pubB64, sigB64 string, payload []byte) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return err
	}
	return signer.Verify(ed25519.PublicKey(pub), payload, sigB64)
}

func enrollCanonical(req enrollRequest) []byte {
	b, _ := json.Marshal(map[string]string{
		"registry_prefix": req.RegistryPrefix,
		"issuer_aid":      req.IssuerAID,
		"issuer_public_key_b64": req.IssuerPubKeyB64,
	})
	return b
}

func eventCanonical(prefix string, req eventRequest) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"registry_prefix": prefix,
		"blinded_id":      req.BlindedID,
		"event_type":      req.EventType,
		"sequence_number": req.SequenceNumber,
	})
	return b
}

func encodeRoot(root [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range root {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}