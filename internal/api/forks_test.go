package api

import (
	"net/http"
	"testing"

	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
)

func (is *issuer) interact() {
	if err := is.Interact(); err != nil {
		is.t.Fatal(err)
	}
}

func (is *issuer) fork() *issuer {
	return &issuer{Issuer: is.Fork(), t: is.t}
}

func heldLog(t *testing.T, st *store.Store, prefix string) string {
	t.Helper()
	reg, err := st.GetRegistry(prefix)
	if err != nil || reg == nil {
		t.Fatalf("registry %s: %v", prefix, err)
	}
	return reg.IssuerKEL
}

// The same key with a log that forks from the one held. It used to answer 200
// with a signed receipt and store nothing, so the caller was told its log was
// taken when it was not.
func TestALogThatForksFromTheOneHeldIsRefused(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	other := is.fork()
	is.interact()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	other.interact()

	w := send(t, h, "/registry/enroll", other.enrolment(prefix, inception))
	if w.Code != http.StatusConflict {
		t.Fatalf("a forked log with the same key gave %d %s, want 409", w.Code, w.Body.String())
	}
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the registry no longer holds the log it held")
	}
}

// An older copy of the log held, with the same key, is the same registry: the
// enrolment is accepted and the newer log is kept.
func TestAnOlderLogWithTheSameKeyIsAcceptedAndChangesNothing(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	older := is.fork()
	is.interact()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	mustSend(t, h, "/registry/enroll", older.enrolment(prefix, inception))
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("an older log replaced the newer one")
	}
}

// Two rotations from one state are two histories signed by the same
// pre-committed key; the registry keeps the one it has and refuses the other,
// whichever key it names. A recovery supersedes interaction events, never a
// rotation.
func TestASecondRotationFromTheSameStateIsRefused(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	other := is.fork()
	is.rotate()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	other.rotate()
	if w := send(t, h, "/registry/enroll", other.enrolment(prefix, inception)); w.Code != http.StatusConflict {
		t.Fatalf("a second rotation from the same state gave %d, want 409", w.Code)
	}

	// Nor a rotation after interactions the held log does not have, when the
	// held log rotated first.
	is.interact()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	other.interact()
	other.rotate()
	if w := send(t, h, "/registry/enroll", other.enrolment(prefix, inception)); w.Code != http.StatusConflict {
		t.Fatalf("a log that rewrites a held rotation gave %d, want 409", w.Code)
	}
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the registry no longer holds the log it held")
	}
}

// A held rotation is not undone by a rotation that forks before an
// interaction preceding it. Whoever holds the key the issuer rotated to can
// sign another rotation from the earlier state, and its first differing event
// is a rotation, but the held events it would replace include a rotation.
func TestARotationAfterAnInteractionIsNotSuperseded(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	other := is.fork()
	is.interact()
	is.rotate()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	other.rotate()
	if w := send(t, h, "/registry/enroll", other.enrolment(prefix, inception)); w.Code != http.StatusConflict {
		t.Fatalf("a rotation that would replace a held rotation gave %d, want 409", w.Code)
	}
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the registry no longer holds the log it held")
	}
}
