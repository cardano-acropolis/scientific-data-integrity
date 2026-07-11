"""Hashing primitives: content hashes and a Merkle tree over data blocks.

Blake2b-256 is the on-chain identifier (Cardano-native, cheap); SHA-256 is
emitted alongside for interoperability with tools outside the Cardano world.

The Merkle tree is domain-separated (distinct leaf/node prefixes) to prevent
second-preimage attacks that swap an internal node for a leaf.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_LEAF = b"\x00"
_NODE = b"\x01"


def blake2b_256(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _leaf_hash(block: bytes) -> bytes:
    return hashlib.blake2b(_LEAF + block, digest_size=32).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.blake2b(_NODE + left + right, digest_size=32).digest()


@dataclass
class MerkleResult:
    root: str  # hex
    leaf_count: int


def merkle_root(blocks: list[bytes]) -> MerkleResult:
    """Merkle root over ``blocks``. Odd levels duplicate the last node."""
    if not blocks:
        # Well-defined empty-tree root: hash of the empty leaf.
        return MerkleResult(root=_leaf_hash(b"").hex(), leaf_count=0)

    level = [_leaf_hash(b) for b in blocks]
    leaf_count = len(level)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return MerkleResult(root=level[0].hex(), leaf_count=leaf_count)


def chunk(data: bytes, size: int) -> list[bytes]:
    """Split ``data`` into ``size``-byte blocks (last block may be shorter)."""
    if size <= 0:
        raise ValueError("chunk size must be positive")
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]
