import { ed25519 } from '@noble/curves/ed25519';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface ServiceIdentity {
  aid: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

interface IdentityFile {
  aid: string;
  public_key_b64: string;
  private_seed_b64: string;
}

export async function loadOrCreateIdentity(dataDir: string): Promise<ServiceIdentity> {
  const envJson = process.env.BRR_SERVICE_IDENTITY_JSON;
  if (envJson) {
    return parseIdentityFile(JSON.parse(envJson) as IdentityFile);
  }

  await mkdir(dataDir, { recursive: true, mode: 0o755 });
  const path = join(dataDir, 'brr_identity.json');
  try {
    const raw = await readFile(path, 'utf8');
    return parseIdentityFile(JSON.parse(raw) as IdentityFile);
  } catch {
    // generate below
  }

  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const aid = 'E' + base64Url(pub).slice(0, 43);
  const out: IdentityFile = {
    aid,
    public_key_b64: Buffer.from(pub).toString('base64'),
    private_seed_b64: Buffer.from(priv).toString('base64'),
  };
  await writeFile(path, JSON.stringify(out, null, 2), { mode: 0o600 });
  return { aid, publicKey: pub, privateKey: priv };
}

function parseIdentityFile(raw: IdentityFile): ServiceIdentity {
  const pub = Buffer.from(raw.public_key_b64, 'base64');
  const seed = Buffer.from(raw.private_seed_b64, 'base64');
  if (pub.length !== 32 || seed.length !== 32) {
    throw new Error('invalid BRR service identity key material');
  }
  const priv = new Uint8Array(seed);
  const derivedPub = ed25519.getPublicKey(priv);
  if (Buffer.compare(Buffer.from(derivedPub), pub) !== 0) {
    throw new Error('BRR service identity public key does not match seed');
  }
  return { aid: raw.aid, publicKey: derivedPub, privateKey: priv };
}

export function sign(identity: ServiceIdentity, payload: Uint8Array): string {
  return base64Url(ed25519.sign(payload, identity.privateKey));
}

export function verify(pub: Uint8Array, payload: Uint8Array, sigB64: string): boolean {
  try {
    const sig = base64UrlDecode(sigB64);
    return ed25519.verify(sig, payload, pub);
  } catch {
    return false;
  }
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(b64, 'base64');
}