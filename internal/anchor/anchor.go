package anchor

import "os"

// Enabled reports whether blockchain anchoring is on. Anchoring is optional and off by default.
func Enabled() bool {
	return os.Getenv("BRR_ANCHORING_ENABLED") == "true"
}