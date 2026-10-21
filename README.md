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
| POST | `/registry/enroll` | An issuer enrolls a registry prefix and its public key (signed) |
| POST | `/registry/{prefix}/event` | Push a blinded `iss` or `rev` event (signed) |
| GET | `/registry/{prefix}/bulk-proof?bucket_hint=…` | Herd-private signed subtree — what verifiers use |
| GET | `/registry/{prefix}/proof/{blinded_id}` | Single-entry lookup. Reveals what is being checked, so verifiers must not use it |
| GET | `/anchor/latest`, `/anchor/history` | Latest anchoring record |
| GET | `/.well-known/brr-service.json` | Service descriptor: signing identity, protocol version, limits |
| GET | `/health` | Liveness |

## Two implementations

The repository holds the same service in two runtimes, sharing one API and
byte-identical hashing (golden tests in both check this).

| | Go | Node.js |
|---|---|---|
| Source | `cmd/brr`, `internal/` | `src/` |
| Storage | SQLite in `BRR_DATA_DIR` | PostgreSQL via `DATABASE_URL` |
| Default port | 8093 | 5000 |
| Container | `Dockerfile` | — |

### Go

```bash
go run ./cmd/brr          # listens on http://0.0.0.0:8093
go test ./...

docker build -t brr .
docker run -p 8093:8093 -v brr-data:/data brr
```

### Node.js

```bash
npm ci
npm test
npm run build
DATABASE_URL=postgres://user:pass@localhost/brr \
BRR_SERVICE_IDENTITY_JSON="$(node scripts/generate-identity.mjs)" \
npm start
```

## Configuration

| Variable | Applies to | Meaning |
|---|---|---|
| `PORT`, `HOST` | both | Listen address. `HOST` defaults to `0.0.0.0` |
| `BRR_DATA_DIR` | both | Where data and the service signing identity are kept (default `./data`) |
| `DATABASE_URL` | Node.js | PostgreSQL connection string (required) |
| `BRR_SERVICE_IDENTITY_JSON` | Node.js | The service signing identity, from `scripts/generate-identity.mjs`. Without it a new identity is generated in `BRR_DATA_DIR` |
| `BRR_ANCHORING_ENABLED` | both | `true` turns on anchoring records. Off by default |
| `BRR_DEV_SKIP_SIG` | both | `true` skips issuer signature checks. **Testing only — never in production** |

**Keep the service signing identity stable.** Verifiers check proofs against it. If
it changes, every previously signed proof stops verifying. On a platform whose disk
does not survive a restart, supply it through `BRR_SERVICE_IDENTITY_JSON` from your
secret manager rather than letting the service generate one.

## Checking a deployment

```bash
node scripts/live-verify.mjs https://your-brr.example
```

This runs the whole flow against a live registry: enroll, issue, revoke, then fetch
a bulk proof and check the revocation is in it and signed. It creates a new
throwaway registry prefix on each run.

## Known gaps

- Enrollment is not yet checked against the issuer's KERI key event log; the
  service trusts the public key in the enrollment request.
- Anchoring records are kept locally; nothing is broadcast to a chain.

## Licence, security, contributing

Apache 2.0 — see [LICENSE](LICENSE). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md). Contributions need a DCO sign-off — see
[CONTRIBUTING.md](CONTRIBUTING.md).
