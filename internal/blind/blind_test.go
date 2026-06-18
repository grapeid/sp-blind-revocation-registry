package blind

import "testing"

func TestBlindedIDDeterministic(t *testing.T) {
	a := BlindedID("EAcred1", "salt-abc")
	b := BlindedID("EAcred1", "salt-abc")
	if a != b || len(a) != 64 {
		t.Fatalf("blinded id: %s", a)
	}
	if BlindedID("EAcred1", "salt-xyz") == a {
		t.Fatal("different salts must differ")
	}
}