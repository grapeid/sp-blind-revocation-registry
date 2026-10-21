#!/usr/bin/env node
/** Generate a BRR_SERVICE_IDENTITY_JSON value (the service signing identity) to store in your secret manager. */
import { ed25519 } from '@noble/curves/ed25519';

const priv = ed25519.utils.randomPrivateKey();
const pub = ed25519.getPublicKey(priv);
const aid =
  'E' +
  Buffer.from(pub)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
    .slice(0, 43);

console.log(
  JSON.stringify({
    aid,
    public_key_b64: Buffer.from(pub).toString('base64'),
    private_seed_b64: Buffer.from(priv).toString('base64'),
  }),
);