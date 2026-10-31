package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// An issuer's events are checked over the one signing form (the Identity
// Agent's ADR-049), with the sequence number a decimal string and the registry
// prefix from the path signed too.
func TestAnIssuerSignsInTheOneForm(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, "b1", "rev", "3"))
	// The same event signed for another registry is not accepted here.
	if w := send(t, h, "/registry/"+prefix+"/event", is.event("EOTHER", "b2", "rev", "4")); w.Code != http.StatusUnauthorized {
		t.Fatalf("an event signed for another registry gave %d", w.Code)
	}
}

// The form does not escape HTML characters, where Go's default JSON writer
// does, so a value containing them shows which form the registry checks.
func TestAnEventWithHTMLCharactersVerifies(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, "a<b>&c", "rev", "1"))
}

// A key of the wrong length is refused. It used to return no error from the
// signature check, which read as verified.
func TestAnIssuerKeyOfTheWrongLengthIsRefused(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	req := is.enrolment(prefix, inception)
	req["issuer_public_key_b64"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
	if w := send(t, h, "/registry/enroll", req); w.Code == http.StatusOK {
		t.Fatal("a 31-byte key enrolled")
	}
}

// An event's signature has one string per base64 alphabet. 64 bytes leave 4
// bits in the last character that carry nothing, and the registry's own
// decoder read all sixteen values of them as the same signature.
func TestAnEventSignatureInASecondSpellingIsRefused(t *testing.T) {
	h, _ := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	ev := is.event(prefix, "b1", "rev", "1")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sig := ev["signature"].(string)
	last := sig[len(sig)-1]
	ev["signature"] = sig[:len(sig)-1] + string(alphabet[strings.IndexByte(alphabet, last)^1])
	if w := send(t, h, "/registry/"+prefix+"/event", ev); w.Code != http.StatusUnauthorized {
		t.Fatalf("a second spelling of an event's signature gave %d", w.Code)
	}
}
