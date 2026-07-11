"""Merkle-batched anchoring — amortize on-chain cost across many manifests.

Instead of one anchoring transaction per dataset, many signed manifests are
batched: their ``manifest_id``s are the leaves of a Merkle tree, the single
**root** is anchored once, and each manifest keeps a compact **inclusion
proof** back to that root. Per-dataset on-chain cost trends to zero while every
dataset remains independently verifiable (the OpenTimestamps pattern).

A batch leaf is the raw 32 bytes of a manifest_id (``bytes.fromhex``), so proof
verification uses ``hashing.verify_merkle_proof`` with the same bytes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import hashing, keys, manifest as manifest_mod
from .anchor import AnchorBackend, AnchorReceipt, METADATA_LABEL


@dataclass
class Batch:
    root: str
    leaf_count: int
    manifest_ids: list[str]
    proofs: list[list[dict]]


def build_batch(manifest_ids: list[str]) -> Batch:
    if not manifest_ids:
        raise ValueError("cannot batch zero manifests")
    leaves = [bytes.fromhex(m) for m in manifest_ids]
    root = hashing.merkle_root(leaves).root
    proofs = [hashing.merkle_proof(leaves, i) for i in range(len(leaves))]
    return Batch(root=root, leaf_count=len(leaves), manifest_ids=list(manifest_ids), proofs=proofs)


def build_batch_metadata(batch: Batch, *, signer_sk_hex: str | None = None) -> dict:
    """On-chain payload for a batch root (Cardano metadata shape).

    Optionally signs the root so the batch has an accountable submitter.
    """
    payload = {
        "std": "sdi-0.1",
        "typ": "batch",
        "id": batch.root,  # the anchored commitment id
        "n": batch.leaf_count,
    }
    if signer_sk_hex:
        payload["pk"] = keys.public_from_private(signer_sk_hex)
        payload["sig"] = keys.sign(signer_sk_hex, bytes.fromhex(batch.root))
    return {str(METADATA_LABEL): payload}


def anchor_batch(
    backend: AnchorBackend, batch: Batch, *, signer_sk_hex: str | None = None
) -> AnchorReceipt:
    """Anchor the batch root once via any backend."""
    metadata = build_batch_metadata(batch, signer_sk_hex=signer_sk_hex)
    return backend.anchor_commitment(batch.root, metadata)


def attach_anchor_block(
    manifest: dict, batch: Batch, index: int, receipt: AnchorReceipt
) -> dict:
    """Return ``manifest`` with a batch ``anchor`` block (its inclusion proof)."""
    signed = dict(manifest)
    signed["anchor"] = {
        "backend": f"batch:{receipt.backend}",
        "reference": receipt.reference,  # where the root is anchored
        "timestamp": receipt.timestamp,
        "batch": {
            "root": batch.root,
            "index": index,
            "leaf_count": batch.leaf_count,
            "proof": batch.proofs[index],
        },
    }
    return signed


def flush_manifests(
    signed_manifests: list[dict],
    backend: AnchorBackend,
    out_dir: str,
    *,
    signer_sk_hex: str | None = None,
) -> tuple[Batch, AnchorReceipt, list[tuple[str, str]]]:
    """Batch already-signed manifests, anchor the root once, write each out.

    Returns ``(batch, receipt, [(file_name, manifest_path), ...])``.
    """
    ids = [m["signature"]["manifest_id"] for m in signed_manifests]
    batch = build_batch(ids)
    receipt = anchor_batch(backend, batch, signer_sk_hex=signer_sk_hex)

    os.makedirs(out_dir, exist_ok=True)
    outputs: list[tuple[str, str]] = []
    for index, m in enumerate(signed_manifests):
        final = attach_anchor_block(m, batch, index, receipt)
        name = m["file"]["name"]
        out_path = os.path.join(out_dir, f"{name}.manifest.json")
        with open(out_path, "w") as fh:
            fh.write(manifest_mod.dumps(final))
        outputs.append((name, out_path))
    return batch, receipt, outputs


def commit_files_as_batch(
    paths: list[str],
    sk_hex: str,
    backend: AnchorBackend,
    out_dir: str,
    *,
    sign_root: bool = True,
) -> tuple[Batch, AnchorReceipt, list[tuple[str, str]]]:
    """One-shot: hash + sign each file, then batch-anchor them together."""
    signed = [manifest_mod.sign(manifest_mod.build(p), sk_hex) for p in paths]
    return flush_manifests(
        signed, backend, out_dir, signer_sk_hex=sk_hex if sign_root else None
    )


def verify_inclusion(manifest: dict) -> tuple[bool, str]:
    """Verify a manifest's inclusion proof resolves to its batch root."""
    anchor = manifest.get("anchor", {})
    batch = anchor.get("batch")
    if not batch:
        return False, "no batch inclusion proof"
    mid = manifest.get("signature", {}).get("manifest_id")
    if not mid:
        return False, "no manifest_id to prove"
    ok = hashing.verify_merkle_proof(
        bytes.fromhex(mid), batch["index"], batch["proof"], batch["root"]
    )
    return (ok, "ok" if ok else "inclusion proof does not resolve to batch root")
