import { blake3 } from '@noble/hashes/blake3';

/** BLAKE3(credential_said || registry_salt) — hex-encoded 32 bytes. */
export function blindedId(credentialSaid: string, registrySalt: string): string {
  const input = new TextEncoder().encode(credentialSaid + registrySalt);
  const h = blake3(input);
  return Buffer.from(h).toString('hex');
}