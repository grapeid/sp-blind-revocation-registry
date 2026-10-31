# Blind Revocation Registry (BRR)

A service that lets a verifier check whether a credential has been revoked without
the registry learning which credential is being checked, or whose it is.

An Identity Agent that issues credentials pushes its revocations here; an Identity
Agent that verifies credentials fetches proofs from here and decides locally. The
registry only ever sees opaque hashes.

This is one operator's implementation of an open protocol. Grape ID runs this code;
anybody may run the same code, or write their own implementation of the protocol.

## The protocol

The client side, and the protocol it speaks, are specified in the Identity Agent
project's
[ADR-025: Blind Revocation Registry Client](https://github.com/LF-Decentralized-Trust-labs/identity-bot/blob/main/docs/adr/025-blind-revocation-registry-client.md).
In short:

- **Blinded entries only.** The issuer pushes `BLAKE3(credential_SAID || registry_salt)`.
  The salt is a private attribute of the credential and is never sent to the registry.
- **Herd-private queries.** A verifier fetches a bulk proof for a whole bucket of
  blinded ids (at least 100 leaves) and checks revocation locally, so the registry
  cannot tell which credential it cares about.
- **The operator cannot lie, only be unreachable.** Every proof is a sparse Merkle
  subtree whose root the registry signs with its own key. A forged "valid" fails
  verification.
- **Blockchain anchoring is optional** and off by default.

## API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/registry/enroll` | An issuer enrolls a registry, proving the registry and the key are its own (signed) |
| POST | `/registry/{prefix}/event` | Push a blinded `iss` or `rev` event (signed) |
| GET | `/registry/{prefix}/bulk-proof?bucket_hint=…` | Herd-private signed subtree — what verifiers use |
| GET | `/registry/{prefix}/proof/{blinded_id}` | Single-entry lookup. Reveals what is being checked, so verifiers must not use it |
| GET | `/anchor/latest`, `/anchor/history` | Latest anchoring record |
| GET | `/.well-known/brr-service.json` | Service descriptor: signing identity, protocol version, limits |
| GET | `/health` | Liveness |

**Signed requests.** An issuer signs enrolments and events with Ed25519 in the one
form every service-provider request uses, set by the Identity Agent's ADR-049:
string fields of printable ASCII, keys sorted, no whitespace, no HTML escaping, the
`signature` field left out. So `sequence_number` is a decimal string
(`"sequence_number": "3"`). An event's signature also covers the registry prefix
from its path, so it cannot be replayed into another registry. The form is tested
against the published vectors in the Identity Agent's `relayproto` module.
Keys and signatures are read by sp-common's strict decoder: qb64, or raw base64 in
any alphabet, each with one string per value.

**Enrolment is proven, not trusted.** Whoever holds a registry's enrolled key can
revoke every credential in it, so an enrolment carries, besides its signature:

- `kel`: the issuer's signed key event log (a CESR stream, base64url). The registry
  checks it in process with keri-go, through sp-common's `verify`: it must derive
  `issuer_aid` and name `issuer_public_key_b64` as the current signing key.
- `registry_inception`: the registry's inception event (`vcp`, base64url). It must
  digest to `registry_prefix` and name `issuer_aid` as its issuer, so nobody else
  can enroll the registry first.

Both are signed with the rest of the request. An enrolled registry keeps its
issuer. Its key changes only when the issuer rotates: enrolling again with a newer
log that extends the one held and names the new key. Anything else is refused. A
registry enrolled before enrolments were proven takes no events until its issuer
enrolls it again, and then gives way to the issuer its inception names.

The registry's own identifier (`brr_aid`, `signed_by`) is non-transferable (code
`B`): it is the key its proofs are signed with, so a verifier needs nothing else
to check one.

## Running it

The service is Go, storing its data in SQLite under `BRR_DATA_DIR`.

```bash
go run ./cmd/brr          # listens on http://0.0.0.0:8093
go test ./...

docker build -t brr .
docker run -p 8093:8093 -v brr-data:/data brr
```

## Configuration

| Variable | Meaning |
|---|---|
| `PORT`, `HOST` | Listen address. `PORT` defaults to `8093`, `HOST` to `0.0.0.0` |
| `BRR_DATA_DIR` | Where data and the service signing identity are kept (default `./data`) |
| `BRR_ANCHORING_ENABLED` | `true` turns on anchoring records. Off by default |

Nothing turns the issuer checks off.

**Keep the service signing identity stable.** Verifiers check proofs against it. If
it changes, every previously signed proof stops verifying. It lives in
`BRR_DATA_DIR`, so put that on a disk that survives a restart.

## Checking a deployment

```bash
go run ./cmd/live-verify https://your-brr.example
```

This runs the whole flow against a live registry: a new KERI issuer founds and
enrolls a registry, issues and revokes a credential, then fetches a bulk proof and
checks the revocation is in it and signed by the registry's identifier. It leaves
one throwaway registry behind on each run.

## Known gaps

- Anchoring records are kept locally; nothing is broadcast to a chain.
- A key event log is checked on its own, with no witness receipts and no sense of
  how recent it is. So a key the issuer has rotated away from, presented with the
  log from before the rotation, still proves itself. Whoever holds such a key can
  enroll an issuer's registry that is not yet enrolled, until the issuer enrolls
  again with its newer log, which then wins.
- A registry's key moves only on a log that extends the one held. Whoever holds the
  current key can therefore extend the held log with events of their own, and a
  recovery rotation that forks from them will not move the registry.
- Revocations pushed under a registry enrolled before enrolments were proven stay
  in it. Nobody can tell them apart from the issuer's own.

## Licence, security, contributing

Apache 2.0 — see [LICENSE](LICENSE). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md). Contributions need a DCO sign-off — see
[CONTRIBUTING.md](CONTRIBUTING.md).
