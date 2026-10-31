// Command live-verify runs the whole flow against a deployed registry: a new
// issuer enrolls a new registry, issues and revokes a credential, then fetches
// a bulk proof and checks the revocation is in it and signed by the registry.
//
//	go run ./cmd/live-verify https://your-brr.example
//
// Each run makes a throwaway issuer and registry, so it leaves one registry
// behind on the deployment.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grapeid/sp-blind-revocation-registry/internal/blind"
	"github.com/grapeid/sp-blind-revocation-registry/internal/testissuer"
	"github.com/grapeid/sp-common/decode"
)

var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: live-verify <registry base URL>")
		os.Exit(2)
	}
	if err := run(strings.TrimRight(os.Args[1], "/")); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL", err)
		os.Exit(1)
	}
	fmt.Println("PASS: enrolled, issued, revoked, and found the revocation in a signed bulk proof")
}

func run(base string) error {
	is, err := testissuer.New()
	if err != nil {
		return err
	}
	prefix, inception, err := is.Registry()
	if err != nil {
		return err
	}
	enrol, err := is.Enrolment(prefix, inception)
	if err != nil {
		return err
	}
	if err := post(base+"/registry/enroll", enrol); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	fmt.Println("OK enroll", prefix)

	blinded := blind.BlindedID("EAcredLiveVerify"+prefix[:16], "registry-salt-live-verify")
	for seq, eventType := range []string{"iss", "rev"} {
		ev, err := is.Event(prefix, blinded, eventType, seq+1)
		if err != nil {
			return err
		}
		if err := post(base+"/registry/"+prefix+"/event", ev); err != nil {
			return fmt.Errorf("event %s: %w", eventType, err)
		}
		fmt.Println("OK event", eventType)
	}

	resp, err := client.Get(base + "/registry/" + prefix + "/bulk-proof?bucket_hint=" + blinded)
	if err != nil {
		return fmt.Errorf("bulk-proof: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bulk-proof: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Proof        json.RawMessage `json:"proof"`
		BRRSignature string          `json:"brr_signature"`
		SignedBy     string          `json:"signed_by"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("bulk-proof: %w", err)
	}
	var proof struct {
		RevokedIDs []string `json:"revoked_ids"`
	}
	if err := json.Unmarshal(out.Proof, &proof); err != nil {
		return fmt.Errorf("bulk-proof: %w", err)
	}
	found := false
	for _, id := range proof.RevokedIDs {
		found = found || id == blinded
	}
	if !found {
		return fmt.Errorf("bulk-proof: the revoked id is not in revoked_ids")
	}
	// The registry's identifier is its verifying key, so the proof is
	// checked with nothing but what came with it.
	key, _, err := decode.Ed25519KeyQB64(out.SignedBy)
	if err != nil {
		return fmt.Errorf("bulk-proof: signed_by %q is not a key identifier: %w", out.SignedBy, err)
	}
	sig, err := decode.Ed25519Signature(out.BRRSignature)
	if err != nil {
		return fmt.Errorf("bulk-proof: %w", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, out.Proof); err != nil {
		return err
	}
	if !ed25519.Verify(key, compact.Bytes(), sig) {
		return fmt.Errorf("bulk-proof: the registry's signature over the proof does not verify")
	}
	fmt.Println("OK bulk-proof, signed by", out.SignedBy)
	return nil
}

func post(url string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%d %s", resp.StatusCode, msg)
	}
	return nil
}
