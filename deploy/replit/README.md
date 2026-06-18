# Blind Revocation Registry — Replit (Node.js / Autoscale)

JavaScript/TypeScript implementation of M36 BRR for **Replit Autoscale**. Canonical Go + SQLite remains at repo root.

## Quick start (Replit Agent)

Read **`REPLIT_AGENT_SETUP.md`** first — it documents the exact steps that worked for `sp-witness-watcher`.

## Local dev

```bash
cd deploy/replit
npm install
DATABASE_URL=postgres://... npm run dev
```

## Test

```bash
npm test
```

## Secrets

| Name | Purpose |
|------|---------|
| `DATABASE_URL` | Replit PostgreSQL (auto) |
| `BRR_SERVICE_IDENTITY_JSON` | Stable BRR service AID (generate once) |