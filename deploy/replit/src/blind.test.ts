import { describe, expect, it } from 'vitest';
import { blindedId } from './blind.js';

/** From Go steel-thread test log (TestBRRSteelThread). */
const STEEL_THREAD_BLINDED =
  '71693b6490e91563d3df524f152f19305aa381958d7dccba0ca338f339a9fa82';

describe('blindedId', () => {
  it('matches Go BLAKE3(credential_said || registry_salt)', () => {
    const id = blindedId(
      'EAcredSteelThread123456789012345678901234',
      'registry-salt-private-acdc-attr',
    );
    expect(id).toBe(STEEL_THREAD_BLINDED);
    expect(id).toHaveLength(64);
  });

  it('is deterministic', () => {
    expect(blindedId('EAcred1', 'salt-abc')).toBe(blindedId('EAcred1', 'salt-abc'));
    expect(blindedId('EAcred1', 'salt-xyz')).not.toBe(blindedId('EAcred1', 'salt-abc'));
  });
});