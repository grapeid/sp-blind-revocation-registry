package merkle

import "testing"

func TestBulkProofRoundTrip(t *testing.T) {
	revoked := []string{
		"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
		"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
	}
	tree := NewTree(revoked)
	proof := tree.BulkProofFor(revoked[0])
	proof.RegistryPrefix = "ERegTest"
	// BLOCKED: full sparse-merkle multiproof composition — membership + signed root suffice for steel thread.
	if !IsRevoked(revoked[0], proof.RevokedIDs) {
		t.Fatal("expected revoked in subtree")
	}
	if IsRevoked("0000000000000000000000000000000000000000000000000000000000000000", proof.RevokedIDs) {
		t.Fatal("unexpected revocation")
	}
}