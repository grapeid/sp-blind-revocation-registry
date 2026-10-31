package api

import (
	"net/http"
	"testing"
)

// The recovery this exists for. Whoever took the issuer's current key can
// append interaction events, and the registry follows them, because they
// extend the log it holds. The issuer recovers as KERI recovers: it rotates
// to its pre-committed next key from before those events. That rotation forks
// from the held log, so the registry used to refuse it and stay with whoever
// had the key.
func TestARecoveryRotationSupersedesInteractionEvents(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	thief := is.fork()
	thief.interact()
	thief.interact()
	mustSend(t, h, "/registry/enroll", thief.enrolment(prefix, inception))

	is.rotate() // at sn 1, below the held log's tip at sn 2
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the recovery was accepted and not stored")
	}
	// The taken key stops working at once, and the issuer's new key works.
	if w := send(t, h, "/registry/"+prefix+"/event", thief.event(prefix, "b1", "rev", "1")); w.Code != http.StatusUnauthorized {
		t.Fatalf("the taken key still revokes after the recovery: %d", w.Code)
	}
	mustSend(t, h, "/registry/"+prefix+"/event", is.event(prefix, "b2", "rev", "2"))

	// The thief's log, longer or not, does not win the registry back: its
	// first event past the fork is an interaction, which recovers nothing.
	thief.interact()
	if w := send(t, h, "/registry/enroll", thief.enrolment(prefix, inception)); w.Code != http.StatusConflict {
		t.Fatalf("the superseded log took the registry back: %d", w.Code)
	}
}

// A recovery can fork after interaction events that are the issuer's own,
// superseding only those that follow.
func TestARecoveryCanKeepTheInteractionsBeforeIt(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	is.interact()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	thief := is.fork()
	thief.interact()
	mustSend(t, h, "/registry/enroll", thief.enrolment(prefix, inception))

	is.rotate() // at sn 2, the held log's tip
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the recovery was not stored")
	}
}

// Only the pre-committed next key recovers. Whoever took the current key
// cannot rotate from before their own events to shake off somebody else, or
// to undo the issuer's recovery, because a rotation must name the key the log
// committed to, and keri-go refuses the log whole.
func TestOnlyThePreCommittedKeyRecovers(t *testing.T) {
	h, st := newRegistry(t)
	is := newIssuer(t)
	prefix, inception := is.registry()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	stolen, err := is.StealCurrentKey()
	if err != nil {
		t.Fatal(err)
	}
	thief := &issuer{Issuer: stolen, t: t}
	is.interact()
	mustSend(t, h, "/registry/enroll", is.enrolment(prefix, inception))

	thief.rotate()
	if w := send(t, h, "/registry/enroll", thief.enrolment(prefix, inception)); w.Code != http.StatusForbidden {
		t.Fatalf("a rotation to a key the log never committed to gave %d %s, want 403", w.Code, w.Body.String())
	}
	if heldLog(t, st, prefix) != is.kel() {
		t.Fatal("the registry no longer holds the issuer's log")
	}
}
