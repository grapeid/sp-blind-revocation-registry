import { describe, expect, it } from 'vitest';
import { isRevoked, MerkleTree } from './merkle.js';

describe('MerkleTree', () => {
  it('includes revoked id in bulk proof bucket', () => {
    const revoked = [
      'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
      'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    ];
    const tree = new MerkleTree(revoked);
    const proof = tree.bulkProofFor(revoked[0]);
    expect(isRevoked(revoked[0], proof.revoked_ids)).toBe(true);
    expect(
      isRevoked('0000000000000000000000000000000000000000000000000000000000000000', proof.revoked_ids),
    ).toBe(false);
  });
});