package api

import "testing"

// A struct tagged "ii" also matches "II" case-insensitively, so an event with
// both fields would name one issuer to a KERI reader and another here.
func TestTheIssuerIsReadByItsExactFieldName(t *testing.T) {
	got, err := issuerNamedBy([]byte(`{"t":"vcp","ii":"EREAL","II":"EOTHER"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got != "EREAL" {
		t.Fatalf("read the issuer as %q from a differently-cased field, not EREAL", got)
	}
	for _, raw := range []string{`{"t":"vcp","II":"EOTHER"}`, `{"t":"vcp","ii":""}`, `{"t":"vcp","ii":7}`} {
		if got, err := issuerNamedBy([]byte(raw)); err == nil {
			t.Errorf("%s named issuer %q", raw, got)
		}
	}
}
