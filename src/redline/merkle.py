from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, TypedDict

from redline.canonical import hash_obj

GENESIS_MERKLE_ROOT = "sha256:genesis"


class MerkleProofStep(TypedDict):
    side: Literal["left", "right"]
    hash: str


def merkle_root(leaves: Sequence[Any]) -> str:
    """Return a deterministic binary Merkle root over canonical leaf values."""
    if not leaves:
        return GENESIS_MERKLE_ROOT
    level = [_leaf_hash(leaf) for leaf in leaves]
    while len(level) > 1:
        level = _parent_level(level)
    return level[0]


def merkle_proof(leaves: Sequence[Any], index: int) -> list[MerkleProofStep]:
    if index < 0 or index >= len(leaves):
        raise IndexError("merkle proof index out of range")
    proof: list[MerkleProofStep] = []
    cursor = index
    level = [_leaf_hash(leaf) for leaf in leaves]
    while len(level) > 1:
        sibling_index = cursor - 1 if cursor % 2 else cursor + 1
        if sibling_index >= len(level):
            sibling_index = cursor
        proof.append(
            {
                "side": "left" if sibling_index < cursor else "right",
                "hash": level[sibling_index],
            }
        )
        cursor //= 2
        level = _parent_level(level)
    return proof


def verify_inclusion(
    leaf: Any,
    index: int,
    proof: Sequence[MerkleProofStep],
    root: str,
    *,
    leaf_count: int | None = None,
) -> bool:
    if index < 0:
        return False
    if leaf_count is not None and (leaf_count <= 0 or index >= leaf_count):
        return False
    current = _leaf_hash(leaf)
    cursor = index
    level_width = leaf_count
    try:
        for step in proof:
            side = step["side"]
            sibling_hash = step["hash"]
            if side == "left":
                if cursor % 2 == 0:
                    return False
                current = _node_hash(sibling_hash, current)
            elif side == "right":
                if cursor % 2 == 1:
                    return False
                if level_width is not None and cursor + 1 >= level_width and sibling_hash != current:
                    return False
                current = _node_hash(current, sibling_hash)
            else:
                return False
            cursor //= 2
            if level_width is not None:
                level_width = (level_width + 1) // 2
    except (KeyError, TypeError):
        return False
    return current == root


def _parent_level(level: Sequence[str]) -> list[str]:
    parents: list[str] = []
    for offset in range(0, len(level), 2):
        left = level[offset]
        right = level[offset + 1] if offset + 1 < len(level) else left
        parents.append(_node_hash(left, right))
    return parents


def _leaf_hash(leaf: Any) -> str:
    return hash_obj({"merkle": "leaf", "value": leaf})


def _node_hash(left: str, right: str) -> str:
    return hash_obj({"merkle": "node", "left": left, "right": right})
