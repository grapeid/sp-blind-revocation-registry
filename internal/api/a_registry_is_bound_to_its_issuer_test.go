package api

import (
	"net/http"
	"testing"
)

// The takeover this exists for. Enrolling again used to replace the issuer's
// key with whatever the request carried, so anybody could enroll somebody
// else's registry with a key of their own, sign for it, and revoke every
// credential in it.
func TestAnotherIssuerCannotTakeOverARegistry(t *testing.T) {
	h, _ := newRegistry(t)
	alice, mallory := newIssuer(t), newIssuer(t)
	prefix, inception := alice.registry()
	mustSend(t, h, "/registry/enroll", alice.enrolment(prefix, inception))

	// Mallory is a genuine identity with a genuine log, enrolling Alice's
	// registry under Mallory's own identifier.
	if w := send(t, h, "/registry/enroll", mallory.enrolment(prefix, inception)); w.Code == http.StatusOK {
		t.Fatal("another issuer re-enrolled the registry")
	}
	// Under Alice's identifier, with Mallory's key and log.
	claim := mallory.enrolment(prefix, inception)
	claim["issuer_aid"] = alice.AID
	claim["signature"] = mallory.sign(withoutSignature(claim))
	if w := send(t, h, "/registry/enroll", claim); w.Code == http.StatusOK {
		t.Fatal("a key from another identity's log enrolled as the issuer")
	}
	// Under Alice's identifier, with Alice's log and Mallory's key.
	claim["kel"] = alice.kel()
	claim["signature"] = mallory.sign(withoutSignature(claim))
	if w := send(t, h, "/registry/enroll", claim); w.Code == http.StatusOK {
		t.Fatal("a key the issuer's log does not name enrolled")
	}
	// Whatever was tried, Mallory cannot revoke here and Alice still can.
	if w := send(t, h, "/registry/"+prefix+"/event", mallory.event(prefix, "b1", "rev", "1")); w.Code == http.StatusOK {
		t.Fatal("Mallory revoked a credential in Alice's registry")
	}
	mustSend(t, h, "/registry/"+prefix+"/event", alice.event(prefix, "b2", "rev", "2"))
}

// Enrolling first is not owning. A registry's prefix is the digest of its
// inception event, which names its issuer, so nobody but that issuer can
// enroll it, early or late.
func TestARegistryCanOnlyBeEnrolledByTheIssuerItNames(t *testing.T) {
	h, _ := newRegistry(t)
	alice, mallory := newIssuer(t), newIssuer(t)
	prefix, inception := alice.registry()
	if w := send(t, h, "/registry/enroll", mallory.enrolment(prefix, inception)); w.Code != http.StatusForbidden {
		t.Fatalf("another issuer enrolled the registry first: %d", w.Code)
	}
	// Mallory's own inception does not found Alice's prefix.
	_, malloryInception := mallory.registry()
	if w := send(t, h, "/registry/enroll", mallory.enrolment(prefix, malloryInception)); w.Code != http.StatusForbidden {
		t.Fatalf("an inception for another registry was accepted: %d", w.Code)
	}
	mustSend(t, h, "/registry/enroll", alice.enrolment(prefix, inception))
}

// An enrolment with no key event log has nothing to check its key against.
func TestAnEnrolmentWithoutAKeyLogIsRefused(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	req := is.enrolment(prefix, inception)
	delete(req, "kel")
	req["signature"] = is.sign(withoutSignature(req))
	if w := send(t, h, "/registry/enroll", req); w.Code == http.StatusOK {
		t.Fatal("enrolled without a key event log")
	}
}

// An issuer that rotates keeps its registry: the newer log extends the one
// held and names the new key. The old key stops working at once.
func TestAnIssuerThatRotatesKeepsItsRegistry(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	old := is.event(prefix, "b1", "rev", "1")

	is.rotate()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	if w := send(t, h, "/registry/"+prefix+"/event", old); w.Code != http.StatusUnauthorized {
		t.Fatalf("an event signed by the rotated-away key gave %d", w.Code)
	}
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, "b2", "rev", "2"))
}

// The same enrolment again is the same registry.
func TestEnrollingAgainWithTheSameKeyIsAccepted(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
}

// A registry enrolled before enrolments were proven holds a key nothing
// showed was its issuer's. The issuer its inception names, proving its key,
// takes it over from that claim; nobody else can.
func TestAnUnprovenEnrolmentGivesWayToTheRegistrysIssuer(t *testing.T) {
	h, st := newRegistry(t)
	alice, mallory := newIssuer(t), newIssuer(t)
	prefix, inception := alice.registry()
	if err := st.Enroll(prefix, "Esquatter", mallory.PublicKeyB64(), ""); err != nil {
		t.Fatal(err)
	}
	// Until then, the unproven key cannot push anything.
	if w := send(t, h, "/registry/"+prefix+"/event", mallory.event(prefix, "b0", "rev", "1")); w.Code != http.StatusForbidden {
		t.Fatalf("an unproven enrolment's key pushed an event: %d", w.Code)
	}
	if w := send(t, h, "/registry/enroll", mallory.enrolment(prefix, inception)); w.Code == http.StatusOK {
		t.Fatal("the squatter proved a registry that is not theirs")
	}
	mustSend(t, h, "/registry/enroll", alice.enrolment(prefix, inception))
	if w := send(t, h, "/registry/"+prefix+"/event", mallory.event(prefix, "b1", "rev", "1")); w.Code != http.StatusUnauthorized {
		t.Fatalf("the squatter's key still revokes: %d", w.Code)
	}
}

func withoutSignature(req map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range req {
		if k != "signature" {
			out[k] = v
		}
	}
	return out
}
