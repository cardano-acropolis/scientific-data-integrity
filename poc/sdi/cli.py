"""Command-line interface for the Scientific Data Integrity PoC.

    sdi keygen      --out keys/lab
    sdi make-sample --out examples/sample.fcs
    sdi commit  <file> --key keys/lab.sk --backend local  --out manifest.json
    sdi verify  manifest.json --file <file> --backend local

``commit`` runs the full pipeline: hash -> manifest -> sign -> anchor.
``verify`` recomputes the hash, checks the signature, and confirms the anchor.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, anchor as anchor_mod, keys, manifest as manifest_mod
from . import fcs as fcs_mod


def _load(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def cmd_keygen(args) -> int:
    sk_hex, vk_hex = keys.generate()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(f"{args.out}.sk", "w") as fh:
        fh.write(sk_hex + "\n")
    os.chmod(f"{args.out}.sk", 0o600)
    with open(f"{args.out}.vk", "w") as fh:
        fh.write(vk_hex + "\n")
    print(f"wrote {args.out}.sk (keep secret) and {args.out}.vk")
    print(f"public key: {vk_hex}")
    return 0


def cmd_make_sample(args) -> int:
    import math

    params = ["FSC-A", "SSC-A", "FL1-A", "FL2-A"]
    events = [
        [
            1000 + 50 * math.sin(i / 7.0),
            800 + 40 * math.cos(i / 5.0),
            float(i % 512),
            float((i * 3) % 1024),
        ]
        for i in range(args.events)
    ]
    raw = fcs_mod.build_fcs_3_1(
        params=params,
        events=events,
        extra_keywords={
            "$CYT": "Demo Cytometer",
            "$CYTSN": "SN-DEMO-0001",
            "$DATE": "10-JUL-2026",
            "$OP": "pseudonymous-operator",
            "$SRC": "synthetic sample",
        },
    )
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(raw)
    print(f"wrote {args.out} ({len(raw)} bytes, {args.events} events, {len(params)} params)")
    return 0


def _backend_from_args(args):
    return anchor_mod.get_backend(
        args.backend,
        directory=getattr(args, "anchor_dir", "anchors"),
        network=getattr(args, "network", "preprod"),
    )


def cmd_commit(args) -> int:
    with open(args.key) as fh:
        sk_hex = fh.read().strip()

    manifest = manifest_mod.build(args.file)
    signed = manifest_mod.sign(manifest, sk_hex)

    backend = _backend_from_args(args)
    try:
        receipt = backend.anchor(signed)
    except RuntimeError as exc:
        print(f"anchor failed ({backend.name}): {exc}", file=sys.stderr)
        return 2

    signed["anchor"] = {
        "backend": receipt.backend,
        "reference": receipt.reference,
        "timestamp": receipt.timestamp,
        "detail": receipt.detail,
    }

    with open(args.out, "w") as fh:
        fh.write(manifest_mod.dumps(signed))

    print(f"manifest_id: {signed['signature']['manifest_id']}")
    print(f"anchored via {receipt.backend} -> {receipt.reference}")
    print(f"wrote {args.out}")
    return 0


def cmd_verify(args) -> int:
    manifest = _load(args.manifest)
    failures = []

    # 1) signature + manifest_id integrity
    sig_ok, sig_msg = manifest_mod.verify_signature(manifest)
    print(f"[{'ok' if sig_ok else 'FAIL'}] signature: {sig_msg}")
    if not sig_ok:
        failures.append("signature")

    # 2) file content matches the committed hashes
    if args.file:
        rebuilt = manifest_mod.build(args.file)
        same_file = rebuilt["file"]["blake2b_256"] == manifest["file"]["blake2b_256"]
        same_data = rebuilt.get("data_commitment", {}).get("root") == manifest.get(
            "data_commitment", {}
        ).get("root")
        print(f"[{'ok' if same_file else 'FAIL'}] file hash matches committed value")
        print(f"[{'ok' if same_data else 'FAIL'}] data Merkle root matches committed value")
        if not same_file:
            failures.append("file-hash")
        if not same_data:
            failures.append("data-root")

    # 3) anchor confirms the manifest_id
    anchor_info = manifest.get("anchor")
    if anchor_info:
        backend = anchor_mod.get_backend(
            anchor_info["backend"] if anchor_info["backend"] != "cardano-blockfrost"
            else "cardano",
            directory=getattr(args, "anchor_dir", "anchors"),
            network=getattr(args, "network", "preprod"),
        )
        mid = manifest["signature"]["manifest_id"]
        ok, detail = backend.confirm(mid, anchor_info["reference"])
        print(f"[{'ok' if ok else 'FAIL'}] anchor confirmed ({backend.name}): {detail}")
        if not ok:
            failures.append("anchor")

    if failures:
        print(f"\nVERIFICATION FAILED: {', '.join(failures)}")
        return 1
    print("\nVERIFICATION PASSED")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sdi", description=__doc__)
    p.add_argument("--version", action="version", version=f"sdi {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    g.add_argument("--out", default="keys/lab", help="output path prefix")
    g.set_defaults(func=cmd_keygen)

    s = sub.add_parser("make-sample", help="write a synthetic FCS 3.1 file")
    s.add_argument("--out", default="examples/sample.fcs")
    s.add_argument("--events", type=int, default=1000)
    s.set_defaults(func=cmd_make_sample)

    c = sub.add_parser("commit", help="hash, sign, and anchor a data file")
    c.add_argument("file")
    c.add_argument("--key", required=True, help="path to a .sk signing key")
    c.add_argument("--backend", default="local", choices=["local", "cardano"])
    c.add_argument("--out", default="manifest.json")
    c.add_argument("--anchor-dir", default="anchors")
    c.add_argument("--network", default="preprod")
    c.set_defaults(func=cmd_commit)

    v = sub.add_parser("verify", help="verify a manifest against a file and anchor")
    v.add_argument("manifest")
    v.add_argument("--file", help="the data file to re-hash and compare")
    v.add_argument("--anchor-dir", default="anchors")
    v.add_argument("--network", default="preprod")
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
