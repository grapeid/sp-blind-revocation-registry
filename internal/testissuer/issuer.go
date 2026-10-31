// Package testissuer makes a real KERI issuer for exercising a registry: a
// self-addressing identifier with its signed key event log, the keys it can
// rotate to, and registries it founds. The tests and cmd/live-verify use it;
// the service never does.
package testissuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	keri "github.com/grapeid/keri-go"
	"github.com/grapeid/sp-common/decode"
)

type Issuer struct {
	AID      string
	current  *keri.SoftwareSigner
	next     *keri.SoftwareSigner
	lastSAID string
	sn       int
	messages [][]byte
}

// New makes an issuer with one signing key and a commitment to the next.
func New() (*Issuer, error) {
	cur, err := keri.GenerateSigner(true)
	if err != nil {
		return nil, err
	}
	nxt, err := keri.GenerateSigner(true)
	if err != nil {
		return nil, err
	}
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		return nil, err
	}
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		return nil, err
	}
	parsed, err := keri.ParseEvent(ev)
	if err != nil {
		return nil, err
	}
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		return nil, err
	}
	return &Issuer{AID: parsed.Identifier, current: cur, next: nxt, lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}, nil
}

// Rotate moves to the committed next key and commits to a new one.
func (is *Issuer) Rotate() error {
	newNext, err := keri.GenerateSigner(true)
	if err != nil {
		return err
	}
	pub, _ := is.next.PublicKey()
	npub, _ := newNext.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		return err
	}
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: is.AID, Keys: []string{pub}, PriorSAID: is.lastSAID, SN: is.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		return err
	}
	signed, err := keri.SignEvent(ev, is.next)
	if err != nil {
		return err
	}
	parsed, err := keri.ParseEvent(ev)
	if err != nil {
		return err
	}
	is.sn++
	is.lastSAID = parsed.SAID
	is.current, is.next = is.next, newNext
	is.messages = append(is.messages, signed.Message)
	return nil
}

// KEL is the issuer's signed key event log, a CESR stream in base64url.
func (is *Issuer) KEL() (string, error) {
	out, err := keri.ExportKEL(is.messages)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// PublicKey is the issuer's current signing key.
func (is *Issuer) PublicKey() ed25519.PublicKey {
	q, _ := is.current.PublicKey()
	pub, _, _ := decode.Ed25519KeyQB64(q)
	return pub
}

// PublicKeyB64 is the current signing key in padded standard base64.
func (is *Issuer) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(is.PublicKey())
}

// Registry founds a registry governed by this issuer, returning its prefix
// and its inception event in base64url.
func (is *Issuer) Registry() (prefix, inception string, err error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	raw, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: is.AID, Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		return "", "", err
	}
	ev, err := keri.VerifyTELEvent(raw)
	if err != nil {
		return "", "", err
	}
	return ev.SAID, base64.RawURLEncoding.EncodeToString(raw), nil
}

// Sign signs fields in the one form every service-provider request uses,
// with the current key, in base64url.
func (is *Issuer) Sign(fields map[string]any) (string, error) {
	body, err := relayproto.CanonicalBody(fields)
	if err != nil {
		return "", err
	}
	sig, err := is.current.Sign(body)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Enrolment is a complete, signed enrolment of a registry this issuer founded.
func (is *Issuer) Enrolment(prefix, inception string) (map[string]any, error) {
	kel, err := is.KEL()
	if err != nil {
		return nil, err
	}
	req := map[string]any{
		"registry_prefix": prefix, "issuer_aid": is.AID, "issuer_public_key_b64": is.PublicKeyB64(),
		"kel": kel, "registry_inception": inception,
	}
	if req["signature"], err = is.Sign(req); err != nil {
		return nil, err
	}
	return req, nil
}

// Event is a signed iss or rev event for a blinded id in prefix. The prefix
// travels in the path and is signed with the body.
func (is *Issuer) Event(prefix, blindedID, eventType string, seq int) (map[string]any, error) {
	sn := fmt.Sprint(seq)
	sig, err := is.Sign(map[string]any{"registry_prefix": prefix, "blinded_id": blindedID, "event_type": eventType, "sequence_number": sn})
	if err != nil {
		return nil, err
	}
	return map[string]any{"blinded_id": blindedID, "event_type": eventType, "sequence_number": sn, "signature": sig}, nil
}
