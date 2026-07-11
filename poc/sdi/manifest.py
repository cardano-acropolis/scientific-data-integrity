"""Build, canonicalize, sign, and verify provenance manifests.

The manifest is the signed record of *what was acquired*. Its canonical form
(sorted keys, no whitespace) is hashed to a ``manifest_id`` — the single value
anchored on-chain. Signing covers everything except the ``signature`` block.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__, fcs as fcs_mod, hashing, keys

FIXED_CHUNK_BYTES = 65536


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build(path: str, *, now: datetime | None = None) -> dict:
    """Hash a file (FCS-aware) and return an unsigned manifest dict."""
    with open(path, "rb") as fh:
        raw = fh.read()

    now = now or datetime.now(timezone.utc)
    manifest: dict = {
        "sdi_version": __version__,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file": {
            "name": path.rsplit("/", 1)[-1],
            "size_bytes": len(raw),
            "blake2b_256": hashing.blake2b_256(raw),
            "sha256": hashing.sha256(raw),
        },
    }

    is_fcs = raw[:3] == b"FCS"
    if is_fcs:
        parsed = fcs_mod.parse(raw)
        if parsed.event_rows:
            blocks = parsed.event_rows
            method = "per-event-row"
        else:
            blocks = hashing.chunk(parsed.data_bytes, FIXED_CHUNK_BYTES)
            method = "fixed-chunk-fallback"
        merkle = hashing.merkle_root(blocks)
        manifest["fcs"] = {
            "version": parsed.version,
            "par": parsed.par,
            "tot": parsed.tot,
            "text_blake2b_256": hashing.blake2b_256(parsed.text_bytes),
            "keywords": {
                k: parsed.keywords[k]
                for k in fcs_mod.MIFLOWCYT_KEYS
                if k in parsed.keywords
            },
        }
        manifest["data_commitment"] = {
            "algo": "merkle-blake2b-256",
            "method": method,
            "leaf_count": merkle.leaf_count,
            "root": merkle.root,
        }
    else:
        # Non-FCS input: still commit to the content via a Merkle tree of chunks.
        merkle = hashing.merkle_root(hashing.chunk(raw, FIXED_CHUNK_BYTES))
        manifest["data_commitment"] = {
            "algo": "merkle-blake2b-256",
            "method": "fixed-chunk-fallback",
            "leaf_count": merkle.leaf_count,
            "root": merkle.root,
        }
    return manifest


# Keys attached after signing; excluded from the signed payload.
_UNSIGNED_KEYS = ("signature", "anchor")


def manifest_id(manifest: dict) -> str:
    """Blake2b-256 over the canonical acquisition record.

    Excludes the ``signature`` block and the ``anchor`` block: the signature
    commits to *what was acquired*, while the anchor reference is only known
    after signing.
    """
    payload = {k: v for k, v in manifest.items() if k not in _UNSIGNED_KEYS}
    return hashing.blake2b_256(_canonical(payload))


def sign(manifest: dict, sk_hex: str) -> dict:
    """Return a copy of ``manifest`` with a ``signature`` block attached."""
    mid = manifest_id(manifest)
    signed = dict(manifest)
    signed["signature"] = {
        "alg": "ed25519",
        "public_key": keys.public_from_private(sk_hex),
        "manifest_id": mid,
        "sig": keys.sign(sk_hex, bytes.fromhex(mid)),
    }
    return signed


def verify_signature(manifest: dict) -> tuple[bool, str]:
    """Check the manifest_id recomputes and the signature is valid."""
    sig = manifest.get("signature")
    if not sig:
        return False, "no signature block"
    recomputed = manifest_id(manifest)
    if recomputed != sig.get("manifest_id"):
        return False, "manifest_id mismatch (content was altered)"
    ok = keys.verify(sig["public_key"], bytes.fromhex(recomputed), sig["sig"])
    return (ok, "ok" if ok else "invalid signature")


def dumps(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True)
