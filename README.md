# Blind Revocation Registry (BRR)

Standalone M36 service — herd-private credential revocation checks without issuer contact.

## Protocol

- Issuer pushes **blinded** entries only: `BLAKE3(credential_said || registry_salt)`
- Registry salt is a **private ACDC attribute** — never sent to the BRR
- Verifiers fetch **bulk subtree proofs** and finalize revocation locally
- Blockchain anchoring is **optional** (`BRR_ANCHORING_ENABLED=true`); off by default

## Run locally

```bash
go run ./cmd/brr
# default http://0.0.0.0:8093
```

## API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/registry/enroll` | Issuer enrolls registry |
| POST | `/registry/{prefix}/event` | Push blinded `iss`/`rev` event |
| GET | `/registry/{prefix}/bulk-proof` | Herd-privacy subtree (C9 path) |
| GET | `/registry/{prefix}/proof/{blinded_id}` | Utility only — **not** for verify pipeline |
| GET | `/.well-known/brr-service.json` | Service descriptor |
| GET | `/health` | Liveness |

## Tests

```bash
go test ./...
```

## BLOCKED

- Production deploy at `brr.grapeid.org`
- KERI `vcp` enrollment validation against issuer KEL (IF9)
- On-chain blockchain anchoring TX broadcast
- Full keripy TEL driver integration (identity-bot side)