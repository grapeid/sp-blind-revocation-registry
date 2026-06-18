import { blake3 } from '@noble/hashes/blake3';

export const TREE_DEPTH = 32;
export const MIN_BUCKET_LEAVES = 100;
export const BUCKET_DEPTH = 7;

type Hash32 = Uint8Array;

const zeroHashes: Hash32[] = [];

function initZeroHashes(): void {
  if (zeroHashes.length > 0) return;
  zeroHashes[0] = blake3(new TextEncoder().encode('brr:empty:0'));
  for (let i = 1; i <= TREE_DEPTH; i++) {
    zeroHashes[i] = nodeHash(zeroHashes[i - 1], zeroHashes[i - 1]);
  }
}

function leafHash(blindedIdHex: string): Hash32 {
  const prefix = new TextEncoder().encode('brr:leaf:');
  const body = new TextEncoder().encode(blindedIdHex);
  const buf = new Uint8Array(prefix.length + body.length);
  buf.set(prefix);
  buf.set(body, prefix.length);
  return blake3(buf);
}

function nodeHash(left: Hash32, right: Hash32): Hash32 {
  const buf = new Uint8Array(64);
  buf.set(left, 0);
  buf.set(right, 32);
  return blake3(buf);
}

function leafIndex(blindedIdHex: string): bigint {
  initZeroHashes();
  const h = leafHash(blindedIdHex);
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const raw = view.getBigUint64(0, false);
  const mask = (1n << BigInt(TREE_DEPTH)) - 1n;
  return raw & mask;
}

function bucketIndex(leafIdx: bigint): bigint {
  return leafIdx >> BigInt(TREE_DEPTH - BUCKET_DEPTH);
}

export interface BulkProof {
  registry_prefix?: string;
  merkle_root: string;
  bucket_index: number;
  bucket_start: number;
  bucket_end: number;
  revoked_ids: string[];
  subtree_root: string;
  siblings: string[];
}

export class MerkleTree {
  private readonly entries = new Map<bigint, string>();

  constructor(revoked: string[]) {
    initZeroHashes();
    for (const id of revoked) {
      this.entries.set(leafIndex(id), id);
    }
  }

  private hasEntryInSubtree(prefix: bigint, depth: number): boolean {
    const shift = BigInt(TREE_DEPTH - depth);
    const bucket = prefix >> shift;
    for (const idx of this.entries.keys()) {
      if (idx >> shift === bucket) return true;
    }
    return false;
  }

  root(): Hash32 {
    if (this.entries.size === 0) return zeroHashes[TREE_DEPTH];
    return this.compute(0n, 0);
  }

  private compute(prefix: bigint, depth: number): Hash32 {
    if (depth === TREE_DEPTH) {
      const id = this.entries.get(prefix);
      if (id !== undefined) return leafHash(id);
      return zeroHashes[0];
    }
    const shift = TREE_DEPTH - depth - 1;
    const leftPrefix = prefix;
    const rightPrefix = prefix | (1n << BigInt(shift));
    const leftEmpty = !this.hasEntryInSubtree(leftPrefix, depth + 1);
    const rightEmpty = !this.hasEntryInSubtree(rightPrefix, depth + 1);
    if (leftEmpty && rightEmpty) return zeroHashes[TREE_DEPTH - depth];
    const left = leftEmpty ? zeroHashes[TREE_DEPTH - depth - 1] : this.compute(leftPrefix, depth + 1);
    const right = rightEmpty ? zeroHashes[TREE_DEPTH - depth - 1] : this.compute(rightPrefix, depth + 1);
    return nodeHash(left, right);
  }

  bulkProofFor(blindedIdHex: string): BulkProof {
    const idx = leafIndex(blindedIdHex);
    const bucket = bucketIndex(idx);
    const start = bucket << BigInt(TREE_DEPTH - BUCKET_DEPTH);
    const end = start + (1n << BigInt(TREE_DEPTH - BUCKET_DEPTH));

    const revoked: string[] = [];
    for (let i = start; i < end; i++) {
      const id = this.entries.get(i);
      if (id !== undefined) revoked.push(id);
    }
    revoked.sort();

    const subDepth = TREE_DEPTH - BUCKET_DEPTH;
    const subRoot = this.compute(start, subDepth);
    const siblings = this.siblingsForBucket(start, subDepth);

    return {
      merkle_root: encode32(this.root()),
      bucket_index: Number(bucket),
      bucket_start: Number(start),
      bucket_end: Number(end),
      revoked_ids: revoked,
      subtree_root: encode32(subRoot),
      siblings,
    };
  }

  private siblingsForBucket(start: bigint, depth: number): string[] {
    const siblings: string[] = [];
    let prefix = start;
    for (let d = depth; d > 0; d--) {
      const shift = TREE_DEPTH - d;
      const sibPrefix = prefix ^ (1n << BigInt(shift));
      siblings.push(encode32(this.compute(sibPrefix, d)));
      prefix >>= 1n;
    }
    return siblings;
  }
}

export function isRevoked(blindedIdHex: string, revoked: string[]): boolean {
  return revoked.includes(blindedIdHex);
}

/** Matches Go json.Marshal field order on BulkProof struct. */
export function marshalProofForSigning(proof: BulkProof): string {
  return JSON.stringify({
    registry_prefix: proof.registry_prefix ?? '',
    merkle_root: proof.merkle_root,
    bucket_index: proof.bucket_index,
    bucket_start: proof.bucket_start,
    bucket_end: proof.bucket_end,
    revoked_ids: proof.revoked_ids,
    subtree_root: proof.subtree_root,
    siblings: proof.siblings,
  });
}

export function encode32(bytes: Hash32): string {
  return Buffer.from(bytes).toString('hex');
}