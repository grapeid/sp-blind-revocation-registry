package blind

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/zeebo/blake3"
)

// BlindedID computes BLAKE3(credential_said || registry_salt) per identity-bot ADR-025.
// The BRR never receives credential_said or registry_salt — only this value.
func BlindedID(credentialSAID, registrySalt string) string {
	h := blake3.Sum256(append([]byte(credentialSAID), []byte(registrySalt)...))
	return hex.EncodeToString(h[:])
}

// BlindedIDBytes returns raw 32-byte blinded identifier.
func BlindedIDBytes(credentialSAID, registrySalt string) [32]byte {
	return blake3.Sum256(append([]byte(credentialSAID), []byte(registrySalt)...))
}

// EncodeRoot returns hex-encoded merkle root for API responses.
func EncodeRoot(root [32]byte) string {
	return hex.EncodeToString(root[:])
}

// DecodeRoot parses hex merkle root.
func DecodeRoot(hexRoot string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(hexRoot)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// EncodeSig returns base64url signature for API.
func EncodeSig(sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(sig)
}