#!/usr/bin/env node
/**
 * Live BRR steel-thread: enroll → iss → rev → bulk-proof
 * Usage: node scripts/live-verify.mjs [baseUrl]
 * Default baseUrl: https://brr.grapeid.org
 */
import { ed25519 } from '@noble/curves/ed25519';
import { blake3 } from '@noble/hashes/blake3';

const BRR = process.argv[2] ?? 'https://brr.grapeid.org';
const PREFIX = 'ERegLiveVerify' + Date.now().toString(36);

function marshalSorted(obj) {
  const sort = (v) => {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map(sort);
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sort(v[k]);
    return out;
  };
  return JSON.stringify(sort(obj));
}

function b64url(sig) {
  return Buffer.from(sig)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function blindedId(said, salt) {
  return Buffer.from(blake3(new TextEncoder().encode(said + salt))).toString('hex');
}

const priv = ed25519.utils.randomPrivateKey();
const pub = ed25519.getPublicKey(priv);
const issuerAid = 'EissuerLiveVerify';
const issuerPubB64 = Buffer.from(pub).toString('base64');

async function post(path, body) {
  const res = await fetch(BRR + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function get(path) {
  const res = await fetch(BRR + path);
  return { status: res.status, json: await res.json() };
}

const enrollCanon = marshalSorted({
  registry_prefix: PREFIX,
  issuer_aid: issuerAid,
  issuer_public_key_b64: issuerPubB64,
});
const enrollSig = b64url(ed25519.sign(new TextEncoder().encode(enrollCanon), priv));
const enroll = await post('/registry/enroll', {
  registry_prefix: PREFIX,
  issuer_aid: issuerAid,
  issuer_public_key_b64: issuerPubB64,
  signature: enrollSig,
});
if (enroll.status !== 200) {
  console.error('FAIL enroll', enroll.status, enroll.json);
  process.exit(1);
}
console.log('OK enroll', PREFIX);

const blinded = blindedId('EAcredLiveVerifySteelThread12345678901', 'registry-salt-live-verify-test');

async function pushEvent(eventType, seq) {
  const canon = marshalSorted({
    registry_prefix: PREFIX,
    blinded_id: blinded,
    event_type: eventType,
    sequence_number: seq,
  });
  const sig = b64url(ed25519.sign(new TextEncoder().encode(canon), priv));
  const r = await post(`/registry/${PREFIX}/event`, {
    blinded_id: blinded,
    event_type: eventType,
    sequence_number: seq,
    signature: sig,
  });
  if (r.status !== 200) {
    console.error(`FAIL event ${eventType}`, r.status, r.json);
    process.exit(1);
  }
  console.log(`OK event ${eventType}`, r.json.merkle_root?.slice(0, 16) + '...');
}

await pushEvent('iss', 1);
await pushEvent('rev', 2);

const bulk = await get(`/registry/${PREFIX}/bulk-proof?bucket_hint=${blinded}`);
if (bulk.status !== 200) {
  console.error('FAIL bulk-proof', bulk.status, bulk.json);
  process.exit(1);
}
const found = bulk.json.proof?.revoked_ids?.includes(blinded);
if (!found || !bulk.json.brr_signature) {
  console.error('FAIL bulk-proof content', bulk.json);
  process.exit(1);
}
console.log('OK bulk-proof — blinded id in revoked_ids, brr_signature present');
console.log('PASS — BRR live steel thread');