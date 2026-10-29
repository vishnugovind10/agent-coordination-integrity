"""RFC 9162-style domain-separated Merkle inclusion proofs for small audit bundles."""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    """Largest power of two strictly smaller than size."""
    return 1 << ((size - 1).bit_length() - 1)


def root_hash(items: list[bytes]) -> bytes:
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return leaf_hash(items[0])
    split = _split(len(items))
    return node_hash(root_hash(items[:split]), root_hash(items[split:]))


def inclusion_proof(items: list[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(items):
        raise IndexError("leaf index is outside the tree")
    if len(items) == 1:
        return []
    split = _split(len(items))
    if index < split:
        return inclusion_proof(items[:split], index) + [root_hash(items[split:])]
    return inclusion_proof(items[split:], index - split) + [root_hash(items[:split])]


def verify_inclusion(
    data: bytes, index: int, size: int, proof: list[bytes], expected_root: bytes
) -> bool:
    if size < 1 or not 0 <= index < size:
        return False
    cursor = 0

    def reconstruct(offset: int, count: int) -> bytes:
        nonlocal cursor
        if count == 1:
            return leaf_hash(data)
        split = _split(count)
        if offset < split:
            left = reconstruct(offset, split)
            if cursor >= len(proof):
                raise ValueError("short inclusion proof")
            right = proof[cursor]
            cursor += 1
            return node_hash(left, right)
        right = reconstruct(offset - split, count - split)
        if cursor >= len(proof):
            raise ValueError("short inclusion proof")
        left = proof[cursor]
        cursor += 1
        return node_hash(left, right)

    try:
        return reconstruct(index, size) == expected_root and cursor == len(proof)
    except ValueError:
        return False
