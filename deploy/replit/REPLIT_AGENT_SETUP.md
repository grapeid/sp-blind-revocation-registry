# Replit Agent Setup — Blind Revocation Registry (BRR)

This guide mirrors the **successful** `sp-witness-watcher` Autoscale deploy at `witness.grapeid.org`.

## What you are deploying

- **Service:** M36 Blind Revocation Registry
- **Runtime:** Node.js 20 + TypeScript (Fastify)
- **Database:** Replit PostgreSQL (`DATABASE_URL` auto-injected)
- **Target domain:** `brr.grapeid.org` (custom CNAME after publish)

## Step 1 — Sync from GitHub

Import or pull `grapeid/sp-blind-revocation-registry` on branch `main`.

Node.js implementation lives in **`deploy/replit/`**. Go reference implementation stays at repo root.

## Step 2 — Hoist to workspace root (recommended — proven on witness-watcher)

Witness-watcher published successfully after Replit hoisted the Node app to the **workspace root** (`package.json`, `src/`, `.replit` at top level).

**Do this if publish fails with wrong working directory or missing `package.json`:**

1. Copy `deploy/replit/package.json`, `tsconfig.json`, `vitest.config.ts`, `src/`, `scripts/` to workspace root.
2. Replace root `.replit` with `deploy/replit/.replit` contents (uses `npm run build` / `node dist/index.js` without `cd`).
3. Run `npm install && npm run build` from workspace root.
4. Verify Preview: `GET /health` returns `{ status: "active", service: "blind-revocation-registry", ... }`.

## Step 3 — Enable PostgreSQL

1. Open **Replit Database** tool → create / attach **SQL Database**.
2. Confirm `DATABASE_URL` appears in Secrets (dev and production).

**Do not use SQLite** — published filesystem is ephemeral.

## Step 4 — Stable BRR service identity (required)

Generate once locally:

```bash
node deploy/replit/scripts/generate-identity.mjs
```

Set output as Secret **`BRR_SERVICE_IDENTITY_JSON`** (single-line JSON) in **Tools → Secrets**.

This secret is available identically in dev and published Autoscale (`process.env.BRR_SERVICE_IDENTITY_JSON`). **Never regenerate in production** — new AID breaks signed proof chains.

## Step 5 — Startup order (critical for health check)

`src/index.ts` already implements the witness-watcher fix:

1. Create pool (lazy — no `SELECT 1` ping)
2. `app.listen()` **first** → `/health` answers within 5 seconds
3. `store.migrate()` runs **after** listen in background

**Do not** add eager DB ping or migrate-before-listen — Neon cold start causes publish failure.

## Step 6 — Publish Autoscale

In **Publishing** pane:

| Setting | Value |
|---------|-------|
| Deployment type | **Autoscale** |
| Build | `npm run build` (from directory with `package.json`) |
| Run | `node dist/index.js` |
| Port | `5000` → external `80` |
| Health | `/health` (automatic) |

Production Secrets required:

- `DATABASE_URL` (from SQL Database)
- `BRR_SERVICE_IDENTITY_JSON`

Optional:

- `BRR_ANCHORING_ENABLED=false` (default off)
- `BRR_DEV_SKIP_SIG=true` (dev only — skips issuer sig verify)

## Step 7 — Custom domain

After publish succeeds:

1. **Publishing → Custom Domains** → add `brr.grapeid.org`
2. DNS: CNAME `brr.grapeid.org` → `<repl-slug>.<owner>.replit.app`
3. TLS is automatic

## API surface (unchanged from Go)

| Method | Path |
|--------|------|
| GET | `/health` |
| GET | `/.well-known/brr-service.json` |
| POST | `/registry/enroll` |
| POST | `/registry/{prefix}/event` |
| GET | `/registry/{prefix}/bulk-proof` |
| GET | `/registry/{prefix}/proof/{blinded_id}` |
| GET | `/anchor/latest` |
| GET | `/anchor/history` |

## Verify after publish

```bash
curl https://brr.grapeid.org/health
curl https://brr.grapeid.org/.well-known/brr-service.json
```

## Crypto libraries (no KERI framework)

- `@noble/hashes` — BLAKE3 (blinded IDs + sparse Merkle tree)
- `@noble/curves` — Ed25519 (BRR + issuer signatures)
- `pg` — PostgreSQL

Golden tests in `src/blind.test.ts` verify byte-parity with Go.