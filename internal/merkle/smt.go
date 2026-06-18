package merkle

import (
	"encoding/binary"
	"sort"

	"github.com/zeebo/blake3"
)

const (
	TreeDepth       = 32
	MinBucketLeaves = 100
	BucketDepth     = 7
)

var zeroHashes [TreeDepth + 1][32]byte

func init() {
	zeroHashes[0] = blake3.Sum256([]byte("brr:empty:0"))
	for i := 1; i <= TreeDepth; i++ {
		zeroHashes[i] = nodeHash(zeroHashes[i-1], zeroHashes[i-1])
	}
}

func leafHash(blindedIDHex string) [32]byte {
	return blake3.Sum256(append([]byte("brr:leaf:"), []byte(blindedIDHex)...))
}

func nodeHash(left, right [32]byte) [32]byte {
	buf := make([]byte, 64)
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return blake3.Sum256(buf)
}

// Tree is a sparse Merkle tree over revoked blinded identifiers.
type Tree struct {
	entries map[uint64]string
}

func NewTree(revoked []string) *Tree {
	t := &Tree{entries: map[uint64]string{}}
	for _, id := range revoked {
		t.entries[leafIndex(id)] = id
	}
	return t
}

func leafIndex(blindedIDHex string) uint64 {
	h := leafHash(blindedIDHex)
	return binary.BigEndian.Uint64(h[:8]) & ((1 << TreeDepth) - 1)
}

func bucketIndex(leafIdx uint64) uint64 {
	return leafIdx >> (TreeDepth - BucketDepth)
}

func (t *Tree) hasEntryInSubtree(prefix uint64, depth int) bool {
	shift := TreeDepth - depth
	bucket := prefix >> shift
	for idx := range t.entries {
		if idx>>shift == bucket {
			return true
		}
	}
	return false
}

func (t *Tree) Root() [32]byte {
	if len(t.entries) == 0 {
		return zeroHashes[TreeDepth]
	}
	return t.compute(0, 0)
}

func (t *Tree) compute(prefix uint64, depth int) [32]byte {
	if depth == TreeDepth {
		if id, ok := t.entries[prefix]; ok {
			return leafHash(id)
		}
		return zeroHashes[0]
	}
	shift := TreeDepth - depth - 1
	leftPrefix := prefix
	rightPrefix := prefix | (1 << shift)
	leftEmpty := !t.hasEntryInSubtree(leftPrefix, depth+1)
	rightEmpty := !t.hasEntryInSubtree(rightPrefix, depth+1)
	if leftEmpty && rightEmpty {
		return zeroHashes[TreeDepth-depth]
	}
	var left, right [32]byte
	if leftEmpty {
		left = zeroHashes[TreeDepth-depth-1]
	} else {
		left = t.compute(leftPrefix, depth+1)
	}
	if rightEmpty {
		right = zeroHashes[TreeDepth-depth-1]
	} else {
		right = t.compute(rightPrefix, depth+1)
	}
	return nodeHash(left, right)
}

// BulkProof is a herd-privacy subtree for local verifier finalization.
type BulkProof struct {
	RegistryPrefix string   `json:"registry_prefix"`
	MerkleRoot     string   `json:"merkle_root"`
	BucketIndex    uint64   `json:"bucket_index"`
	BucketStart    uint64   `json:"bucket_start"`
	BucketEnd      uint64   `json:"bucket_end"`
	RevokedIDs     []string `json:"revoked_ids"`
	SubtreeRoot    string   `json:"subtree_root"`
	Siblings       []string `json:"siblings"`
}

func (t *Tree) BulkProofFor(blindedIDHex string) BulkProof {
	idx := leafIndex(blindedIDHex)
	bucket := bucketIndex(idx)
	start := bucket << (TreeDepth - BucketDepth)
	end := start + (1 << (TreeDepth - BucketDepth))

	var revoked []string
	for i := start; i < end; i++ {
		if id, ok := t.entries[i]; ok {
			revoked = append(revoked, id)
		}
	}
	sort.Strings(revoked)

	subDepth := TreeDepth - BucketDepth
	subRoot := t.compute(start, subDepth)
	siblings := t.siblingsForBucket(start, subDepth)

	return BulkProof{
		MerkleRoot:  encode32(t.Root()),
		BucketIndex: bucket,
		BucketStart: start,
		BucketEnd:   end,
		RevokedIDs:  revoked,
		SubtreeRoot: encode32(subRoot),
		Siblings:    siblings,
	}
}

func (t *Tree) siblingsForBucket(start uint64, depth int) []string {
	var siblings []string
	prefix := start
	for d := depth; d > 0; d-- {
		shift := TreeDepth - d
		sibPrefix := prefix ^ (1 << shift)
		siblings = append(siblings, encode32(t.compute(sibPrefix, d)))
		prefix >>= 1
	}
	return siblings
}

func IsRevoked(blindedIDHex string, revoked []string) bool {
	for _, id := range revoked {
		if id == blindedIDHex {
			return true
		}
	}
	return false
}

// VerifyBulkProof checks subtree composes to the signed merkle root.
func VerifyBulkProof(proof BulkProof) bool {
	subRoot, err := decode32(proof.SubtreeRoot)
	if err != nil {
		return false
	}
	recomputed := composeToRoot(subRoot, proof.BucketStart, proof.Siblings, TreeDepth-BucketDepth)
	root, err := decode32(proof.MerkleRoot)
	if err != nil {
		return false
	}
	return recomputed == root
}

func composeToRoot(subRoot [32]byte, bucketStart uint64, siblings []string, subDepth int) [32]byte {
	cur := subRoot
	prefix := bucketStart
	for i, sibHex := range siblings {
		d := subDepth - i
		if d <= 0 {
			break
		}
		sib, _ := decode32(sibHex)
		shift := TreeDepth - d
		if (prefix>>shift)%2 == 0 {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
		prefix &^= 1 << shift
	}
	return cur
}

func encode32(b [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}

func decode32(hexStr string) ([32]byte, error) {
	var out [32]byte
	if len(hexStr) != 64 {
		return out, errInvalidHex
	}
	for i := 0; i < 32; i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := hexStr[i*2+j]
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v |= c - 'A' + 10
			default:
				return out, errInvalidHex
			}
		}
		out[i] = v
	}
	return out, nil
}

var errInvalidHex = &hexError{}

type hexError struct{}

func (e *hexError) Error() string { return "invalid hex" }