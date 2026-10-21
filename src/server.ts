import Fastify, { type FastifyInstance } from 'fastify';
import { anchoringEnabled } from './anchor.js';
import { marshalSorted } from './json-canonical.js';
import { encode32, isRevoked, marshalProofForSigning, MerkleTree, MIN_BUCKET_LEAVES } from './merkle.js';
import { sign, verify, type ServiceIdentity } from './signer.js';
import type { BrrStore } from './store.js';

const PROTOCOL_VERSION = '1.0';

export interface AppContext {
  store: BrrStore;
  identity: ServiceIdentity;
}

export function buildServer(ctx: AppContext): FastifyInstance {
  const app = Fastify({ logger: true });

  app.get('/health', async () => ({
    status: 'active',
    service: 'blind-revocation-registry',
    brr_aid: ctx.identity.aid,
    protocol_version: PROTOCOL_VERSION,
    runtime: 'nodejs',
  }));

  app.get('/.well-known/brr-service.json', async () => ({
    brr_aid: ctx.identity.aid,
    protocol_version: PROTOCOL_VERSION,
    anchoring_enabled: anchoringEnabled(),
    anchoring_chains: [],
    bulk_proofs_supported: true,
    min_bucket_leaves: MIN_BUCKET_LEAVES,
    rate_limits: { bulk_proofs_per_minute: 1000 },
  }));

  app.get('/anchor/latest', async () => handleAnchorLatest(ctx));
  app.get('/anchor/history', async () => handleAnchorLatest(ctx));

  app.post<{
    Body: {
      registry_prefix?: string;
      issuer_aid?: string;
      issuer_public_key_b64?: string;
      signature?: string;
    };
  }>('/registry/enroll', async (req, reply) => {
    const { registry_prefix, issuer_aid, issuer_public_key_b64, signature } = req.body ?? {};
    if (!registry_prefix || !issuer_aid || !issuer_public_key_b64) {
      return reply.code(400).send({ error: 'registry_prefix, issuer_aid, issuer_public_key_b64 required' });
    }
    const canonical = marshalSorted({
      registry_prefix,
      issuer_aid,
      issuer_public_key_b64,
    });
    if (
      !verifyIssuerSig(issuer_public_key_b64, signature ?? '', canonical) &&
      process.env.BRR_DEV_SKIP_SIG !== 'true'
    ) {
      return reply.code(401).send({ error: 'issuer signature invalid' });
    }
    await ctx.store.enroll(registry_prefix, issuer_aid, issuer_public_key_b64);
    const confirmation = marshalSorted({ registry_prefix, status: 'enrolled' });
    return {
      ok: true,
      registry_prefix,
      confirmation: JSON.parse(confirmation),
      brr_signature: sign(ctx.identity, new TextEncoder().encode(confirmation)),
      signed_by: ctx.identity.aid,
    };
  });

  app.post<{
    Params: { prefix: string };
    Body: {
      blinded_id?: string;
      event_type?: string;
      sequence_number?: number;
      signature?: string;
    };
  }>('/registry/:prefix/event', async (req, reply) => {
    const prefix = req.params.prefix;
    const reg = await ctx.store.getRegistry(prefix);
    if (!reg) return reply.code(404).send({ error: 'registry not enrolled' });

    const { blinded_id, event_type, sequence_number = 0, signature } = req.body ?? {};
    if (!blinded_id || (event_type !== 'iss' && event_type !== 'rev')) {
      return reply.code(400).send({ error: 'blinded_id and event_type (iss|rev) required' });
    }
    const canonical = marshalSorted({
      registry_prefix: prefix,
      blinded_id,
      event_type,
      sequence_number,
    });
    if (
      !verifyIssuerSig(reg.issuerPubB64, signature ?? '', canonical) &&
      process.env.BRR_DEV_SKIP_SIG !== 'true'
    ) {
      return reply.code(401).send({ error: 'issuer signature invalid' });
    }
    await ctx.store.insertEvent(prefix, blinded_id, event_type, sequence_number);
    const revoked = await ctx.store.revokedIds(prefix);
    const tree = new MerkleTree(revoked);
    const root = tree.root();
    if (anchoringEnabled()) {
      await ctx.store.recordAnchor(encode32(root), true);
    }
    return {
      ok: true,
      merkle_root: encode32(root),
      event_type,
      sequence_number,
    };
  });

  app.get<{ Params: { prefix: string }; Querystring: { bucket_hint?: string } }>(
    '/registry/:prefix/bulk-proof',
    async (req, reply) => {
      const prefix = req.params.prefix;
      const reg = await ctx.store.getRegistry(prefix);
      if (!reg) return reply.code(404).send({ error: 'registry not enrolled' });

      const revoked = await ctx.store.revokedIds(prefix);
      const tree = new MerkleTree(revoked);
      let target = req.query.bucket_hint ?? '';
      if (!target && revoked.length > 0) target = revoked[0];
      if (!target) target = '0'.repeat(64);

      const proof = tree.bulkProofFor(target);
      proof.registry_prefix = prefix;
      const payload = marshalProofForSigning(proof);
      return {
        proof,
        brr_signature: sign(ctx.identity, new TextEncoder().encode(payload)),
        signed_by: ctx.identity.aid,
        issued_at: new Date().toISOString(),
      };
    },
  );

  app.get<{ Params: { prefix: string; blinded_id: string } }>(
    '/registry/:prefix/proof/:blinded_id',
    async (req, reply) => {
      reply.header('X-BRR-Privacy-Warning', 'non-private — use bulk-proof for verifier pipeline');
      const revoked = await ctx.store.revokedIds(req.params.prefix);
      return {
        registry_prefix: req.params.prefix,
        blinded_id: req.params.blinded_id,
        revoked: isRevoked(req.params.blinded_id, revoked),
        warning: 'utility endpoint only — verifiers must use bulk-proof',
      };
    },
  );

  return app;
}

async function handleAnchorLatest(ctx: AppContext) {
  if (!anchoringEnabled()) {
    return {
      anchoring_enabled: false,
      note: 'anchoring not enabled — registry tamper-evident via KERI receipts',
    };
  }
  const rec = await ctx.store.latestAnchor();
  if (!rec) return { anchoring_enabled: true, anchors: [] };
  return rec;
}

function verifyIssuerSig(pubB64: string, sigB64: string, payload: string): boolean {
  try {
    const pub = Buffer.from(pubB64, 'base64');
    if (pub.length !== 32) return false;
    return verify(pub, new TextEncoder().encode(payload), sigB64);
  } catch {
    return false;
  }
}