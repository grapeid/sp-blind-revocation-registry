import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { canonicalBody } from './canonical-body.js';

// The published vectors live in the Identity Agent's relayproto module, which
// the Go build of this service already requires. Reading them from there means
// this implementation is held to the same file, not a copy of it.
function vectors(): { vectors: { name: string; fields: Record<string, string>; canonical: string }[]; refused: { name: string; fields: Record<string, unknown> }[] } | null {
  try {
    const dir = execFileSync('go', ['list', '-m', '-f', '{{.Dir}}',
      'github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto'], { encoding: 'utf8' }).trim();
    return JSON.parse(readFileSync(join(dir, 'signing-vectors.json'), 'utf8'));
  } catch {
    return null;
  }
}

describe('the one signing form', () => {
  const set = vectors();

  it.skipIf(set === null)('produces every published vector', () => {
    for (const v of set!.vectors) {
      expect(canonicalBody(v.fields), v.name).toBe(v.canonical);
    }
  });

  it.skipIf(set === null)('refuses every input the form refuses', () => {
    for (const r of set!.refused) {
      expect(() => canonicalBody(r.fields), r.name).toThrow();
    }
  });

  // The vector file's own fields happen to be written in sorted order, so a
  // missing sort would pass them; this input is not.
  it('sorts keys by byte value whatever order they arrive in', () => {
    expect(canonicalBody({ b: '2', a: '1', _: 'u', A: 'U' })).toBe('{"A":"U","_":"u","a":"1","b":"2"}');
  });

  it('does not escape HTML characters or slashes', () => {
    expect(canonicalBody({ q: 'a<b>&c', u: 'https://x/y', signature: 'x' })).toBe('{"q":"a<b>&c","u":"https://x/y"}');
  });
});
