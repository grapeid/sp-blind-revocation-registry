package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-blind-revocation-registry/internal/anchor"
	"github.com/grapeid/sp-blind-revocation-registry/internal/merkle"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
	"github.com/grapeid/sp-common/decode"
	"github.com/grapeid/sp-common/sign"
	"github.com/grapeid/sp-common/verify"
)

const ProtocolVersion = "1.0"

type Server struct {
	Store    *store.Store
	Identity *sign.Identity
	// Verifier binds an issuer's key to its identifier. Always the key event
	// log check: there is no setting that turns it off, because whoever
	// enrolls a registry can revoke every credential in it.
	Verifier verify.KeyLog
}

func New(st *store.Store, id *sign.Identity) *Server {
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
		"brr_aid":               s.Identity.AID,
		"protocol_version":      ProtocolVersion,
		"anchoring_enabled":     anchor.Enabled(),
		"anchoring_chains":      []string{},
		"bulk_proofs_supported": true,
		"min_bucket_leaves":     merkle.MinBucketLeaves,
		"rate_limits":           map[string]int{"bulk_proofs_per_minute": 1000},
	})
}

type enrollRequest struct {
	RegistryPrefix  string `json:"registry_prefix"`
	IssuerAID       string `json:"issuer_aid"`
	IssuerPubKeyB64 string `json:"issuer_public_key_b64"`
	// KEL is the issuer's signed key event log, a CESR stream in base64url.
	// It is what binds the key to the issuer: anybody can make a key and sign
	// with it, and only the issuer's own log says which key speaks for it.
	KEL string `json:"kel"`
	// RegistryInception is the registry's inception event (vcp), in base64url.
	// A registry's prefix is the digest of that event, and the event names its
	// issuer, so it is what binds the prefix to the issuer.
	RegistryInception string `json:"registry_inception"`
	Signature         string `json:"signature"`
}

// maxInceptionBytes bounds a registry inception. One is a few hundred bytes;
// this leaves room for a long list of backers.
const maxInceptionBytes = 16 * 1024

// handleEnroll binds a registry to its issuer, and its issuer to a key.
//
// Whoever holds the enrolled key can revoke every credential in the registry,
// so the enrolment has to prove three things, and a signature proves only the
// first:
//
//   - the caller holds the key presented (the request's signature);
//   - the key is the issuer's current signing key (the issuer's key event log,
//     checked in process by sp-common's verify);
//   - the registry is the issuer's (its inception event digests to the prefix
//     and names the issuer).
//
// A registry already enrolled keeps its issuer. Its key and log change only
// on a log that extends the one held. Anything else is refused, never overwritten, which is how a
// registry used to be taken over by anybody who enrolled it again with a key
// of their own.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.RegistryPrefix == "" || req.IssuerAID == "" || req.IssuerPubKeyB64 == "" ||
		req.KEL == "" || req.RegistryInception == "" {
		writeErr(w, http.StatusBadRequest,
			"registry_prefix, issuer_aid, issuer_public_key_b64, kel and registry_inception required")
		return
	}
	presented, err := decode.Ed25519Key(req.IssuerPubKeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "issuer_public_key_b64: "+err.Error())
		return
	}
	canonical, err := enrollCanonical(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// First: the caller holds the key.
	if err := sign.VerifyEd25519(req.IssuerPubKeyB64, req.Signature, canonical); err != nil {
		writeErr(w, http.StatusUnauthorized, "issuer signature invalid: "+err.Error())
		return
	}
	// Second: the registry is the issuer's.
	if err := registryOf(req.RegistryInception, req.RegistryPrefix, req.IssuerAID); err != nil {
		writeErr(w, http.StatusForbidden, "could not confirm this registry belongs to that issuer: "+err.Error())
		return
	}
	// Third: the key is the issuer's.
	if result := s.Verifier.Verify(req.IssuerAID, req.KEL, req.IssuerPubKeyB64); !result.Verified {
		writeErr(w, http.StatusForbidden, "could not confirm this key belongs to that issuer: "+result.Reason)
		return
	}

	key := base64.StdEncoding.EncodeToString(presented)
	existing, err := s.Store.GetRegistry(req.RegistryPrefix)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not look up the registry")
		return
	}
	switch {
	case existing == nil:
		err = s.Store.Enroll(req.RegistryPrefix, req.IssuerAID, key, req.KEL)
	case existing.IssuerKEL == "":
		// Enrolled before enrolments were proven, so nothing ever showed the
		// key held was the issuer's. The issuer the registry's own inception
		// names, proving its current key, outranks that claim.
		log.Printf("[brr] registry %s: an unproven enrolment by %q replaced by its issuer %q",
			req.RegistryPrefix, existing.IssuerAID, req.IssuerAID)
		err = s.Store.ReplaceIssuer(req.RegistryPrefix, existing.IssuerPubB64, existing.IssuerKEL,
			req.IssuerAID, key, req.KEL)
	case existing.IssuerAID != req.IssuerAID:
		// Cannot happen while the inception binds the prefix, and is refused
		// rather than trusted to stay impossible.
		writeErr(w, http.StatusConflict, "this registry is enrolled to another issuer")
		return
	default:
		switch compareLogs(req.KEL, existing.IssuerKEL) {
		case logsSame, logBehind:
			// The log held already holds every event presented. Nothing
			// to store if the key is the one held; a key the held log has
			// since rotated away from is refused.
			if !sameKey(existing.IssuerPubB64, presented) {
				writeErr(w, http.StatusConflict,
					"this registry is enrolled with a newer key event log, which names a different key")
				return
			}
		case logExtends:
			// A newer log: it extends the one held. It names the presented
			// key (checked above), so if the issuer rotated the key moves
			// with it and the old one stops working.
			err = s.Store.ReplaceIssuer(req.RegistryPrefix, existing.IssuerPubB64, existing.IssuerKEL,
				req.IssuerAID, key, req.KEL)
		default:
			// Neither log extends the other: the issuer's keys have signed
			// two histories.
			// Storing nothing and answering with a signed receipt would
			// tell the caller its log was taken when it was not.
			writeErr(w, http.StatusConflict,
				"the key event log presented forks from the one this registry holds")
			return
		}
	}
	if errors.Is(err, store.ErrChanged) {
		writeErr(w, http.StatusConflict, "the registry changed while enrolling; try again")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not enroll the registry")
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

// registryOf checks that a registry inception digests to prefix and names
// issuer as the identity that governs it.
func registryOf(inceptionB64, prefix, issuer string) error {
	if len(inceptionB64) > base64.RawURLEncoding.EncodedLen(maxInceptionBytes)+4 {
		return fmt.Errorf("the registry inception is larger than %d bytes", maxInceptionBytes)
	}
	raw, err := decode.Base64(inceptionB64)
	if err != nil {
		return fmt.Errorf("the registry inception is not base64: %w", err)
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		return err
	}
	if ev.Ilk != "vcp" {
		return fmt.Errorf("a %s event is not a registry inception", ev.Ilk)
	}
	if ev.SAID != prefix {
		return fmt.Errorf("the registry inception founds %s, not %s", ev.SAID, prefix)
	}
	named, err := issuerNamedBy(raw)
	if err != nil {
		return err
	}
	if named != issuer {
		return fmt.Errorf("the registry's issuer is %s, not %s", named, issuer)
	}
	return nil
}

// issuerNamedBy reads the "ii" field of an event, by its exact name.
//
// Unmarshalling into a struct tagged "ii" would also take "II" or "iI", the
// last one winning, so an event carrying both "ii" and "II" would name one
// issuer to any KERI reader and another here. keri-go has already refused a
// field that appears twice under one exact name; a map matches names exactly,
// so the field read here is the field every other reader sees.
func issuerNamedBy(raw []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", fmt.Errorf("the registry inception does not parse: %w", err)
	}
	var issuer string
	if err := json.Unmarshal(fields["ii"], &issuer); err != nil || issuer == "" {
		return "", fmt.Errorf("the registry inception names no issuer")
	}
	return issuer, nil
}

// sameKey compares keys as bytes: the same key in two base64 alphabets is the
// same key.
func sameKey(storedB64 string, presented ed25519.PublicKey) bool {
	held, err := decode.Ed25519Key(storedB64)
	return err == nil && held.Equal(presented)
}

// logRelation is how a presented key event log stands to the one held.
type logRelation int

const (
	logForks   logRelation = iota // neither holds the other
	logsSame                      // the same events
	logExtends                    // every held event, and more after them
	logBehind                     // the held log has every presented event, and more
)

// compareLogs reports how a presented key event log stands to the one held,
// by relayproto's rule: every held event, in order, compared as keri-go reads
// them (sequence number, type and SAID), so a log that gained a receipt or
// was re-serialised still extends the one it came from.
func compareLogs(presentedB64, heldB64 string) logRelation {
	presentedRaw, err := decode.Base64(presentedB64)
	if err != nil {
		return logForks
	}
	heldRaw, err := decode.Base64(heldB64)
	if err != nil {
		return logForks
	}
	ahead := relayproto.LogExtends(presentedRaw, heldRaw)
	behind := relayproto.LogExtends(heldRaw, presentedRaw)
	switch {
	case ahead && behind:
		return logsSame
	case ahead:
		return logExtends
	case behind:
		return logBehind
	}
	return logForks
}

type eventRequest struct {
	BlindedID string `json:"blinded_id"`
	EventType string `json:"event_type"`
	// SequenceNumber is a decimal string: every signed field is a string
	// (the Identity Agent's ADR-049).
	SequenceNumber string `json:"sequence_number"`
	Signature      string `json:"signature"`
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	prefix := chi.URLParam(r, "prefix")
	reg, err := s.Store.GetRegistry(prefix)
	if err != nil || reg == nil {
		writeErr(w, http.StatusNotFound, "registry not enrolled")
		return
	}
	// A registry enrolled before enrolments were proven holds a key nothing
	// showed was its issuer's, so it takes no events until its issuer enrols
	// again with its key event log and the registry's inception.
	if reg.IssuerKEL == "" {
		writeErr(w, http.StatusForbidden,
			"this registry was enrolled without proof of its issuer; enroll it again with kel and registry_inception")
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
	seq, err := strconv.Atoi(req.SequenceNumber)
	if err != nil || seq < 0 {
		writeErr(w, http.StatusBadRequest, "sequence_number is a decimal string")
		return
	}
	canonical, err := eventCanonical(prefix, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sign.VerifyEd25519(reg.IssuerPubB64, req.Signature, canonical); err != nil {
		writeErr(w, http.StatusUnauthorized, "issuer signature invalid: "+err.Error())
		return
	}
	if err := s.Store.InsertEvent(prefix, req.BlindedID, req.EventType, seq); err != nil {
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
		"event_type": req.EventType, "sequence_number": seq,
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
			"note":              "anchoring not enabled — registry tamper-evident via KERI receipts",
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

// enrollCanonical and eventCanonical are the bytes an issuer signs: the one
// form every service-provider request is signed in (the Identity Agent's
// ADR-049), from relayproto.CanonicalBody. The registry prefix of an event is
// in its path and is signed too, so an event cannot be replayed into another
// registry.
func enrollCanonical(req enrollRequest) ([]byte, error) {
	return relayproto.CanonicalBody(map[string]any{
		"registry_prefix":       req.RegistryPrefix,
		"issuer_aid":            req.IssuerAID,
		"issuer_public_key_b64": req.IssuerPubKeyB64,
		"kel":                   req.KEL,
		"registry_inception":    req.RegistryInception,
	})
}

func eventCanonical(prefix string, req eventRequest) ([]byte, error) {
	return relayproto.CanonicalBody(map[string]any{
		"registry_prefix": prefix,
		"blinded_id":      req.BlindedID,
		"event_type":      req.EventType,
		"sequence_number": req.SequenceNumber,
	})
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
