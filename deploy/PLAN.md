# Deploy adaptation plan — sp-blind-revocation-registry

## Decision

| Target | Path | Runtime |
|--------|------|---------|
| Docker / Linux VPS | repo root (`go run ./cmd/brr`) | Go + SQLite |
| Replit Autoscale | `deploy/replit/` | Node.js + PostgreSQL |

## Task status

| Task | Est. effort | Risk | Status |
|------|-------------|------|--------|
| Scaffold + `.replit` | 30 min | Low | Done |
| BLAKE3 blinded ID parity | 1 hr | Medium | Done (golden test) |
| Sparse Merkle tree port | 4–8 hrs | **Highest** | Done |
| PostgreSQL store | 1–2 hrs | Low | Done |
| Fastify API (8 routes) | 2–3 hrs | Low | Done |
| Replit publish | 30 min–2 hrs | High | **Replit Agent** |

## Highest-risk item: sparse Merkle tree

The `internal/merkle/smt.go` sparse Merkle implementation is the largest port. Errors break bulk-proof verification (C9 herd privacy).

**Mitigation:** Port line-for-line; `merkle.test.ts` + `blind.test.ts` locked to Go steel-thread vectors.

## Replit Agent

See [`deploy/replit/REPLIT_AGENT_SETUP.md`](replit/REPLIT_AGENT_SETUP.md).