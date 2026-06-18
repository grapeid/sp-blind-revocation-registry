package anchor

import "os"

// Enabled reports whether blockchain anchoring is on (optional per M36 Refinement 2).
func Enabled() bool {
	return os.Getenv("BRR_ANCHORING_ENABLED") == "true"
}