"""End-to-end and tamper-detection tests for the PoC pipeline.

Run: ``python -m pytest`` (or ``python poc/tests/test_end_to_end.py``).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sdi import anchor, fcs, hashing, keys, manifest  # noqa: E402


def _sample(tmp_path, events=200) -> str:
    raw = fcs.build_fcs_3_1(
        params=["FSC-A", "SSC-A", "FL1-A"],
        events=[[float(i), float(i * 2), float(i % 7)] for i in range(events)],
        extra_keywords={"$CYT": "Test", "$OP": "op"},
    )
    path = os.path.join(tmp_path, "sample.fcs")
    with open(path, "wb") as fh:
        fh.write(raw)
    return path


def test_fcs_roundtrip_parses_segments(tmp_path):
    path = _sample(tmp_path, events=50)
    with open(path, "rb") as fh:
        parsed = fcs.parse(fh.read())
    assert parsed.version == "FCS3.1"
    assert parsed.par == 3
    assert parsed.tot == 50
    assert parsed.row_method == "per-event-row"
    assert len(parsed.event_rows) == 50
    assert parsed.keywords["$CYT"] == "Test"


def test_merkle_is_deterministic_and_order_sensitive():
    a = [b"one", b"two", b"three"]
    assert hashing.merkle_root(a).root == hashing.merkle_root(list(a)).root
    assert hashing.merkle_root(a).root != hashing.merkle_root(a[::-1]).root


def test_sign_verify_and_tamper_detection(tmp_path):
    path = _sample(tmp_path)
    sk, _ = keys.generate()
    m = manifest.build(path)
    signed = manifest.sign(m, sk)

    ok, msg = manifest.verify_signature(signed)
    assert ok, msg

    # Tamper with committed content -> manifest_id recompute must diverge.
    signed["file"]["size_bytes"] += 1
    ok, msg = manifest.verify_signature(signed)
    assert not ok and "mismatch" in msg


def test_full_pipeline_local_anchor(tmp_path):
    path = _sample(tmp_path)
    sk, _ = keys.generate()
    signed = manifest.sign(manifest.build(path), sk)

    backend = anchor.LocalAnchor(directory=os.path.join(tmp_path, "anchors"))
    receipt = backend.anchor(signed)
    mid = signed["signature"]["manifest_id"]
    assert receipt.manifest_id == mid

    ok, detail = backend.confirm(mid, receipt.reference)
    assert ok, detail


def test_verify_catches_data_edit(tmp_path):
    path = _sample(tmp_path)
    sk, _ = keys.generate()
    committed = manifest.build(path)

    # Flip one byte in the DATA segment; the Merkle root must change.
    with open(path, "rb") as fh:
        raw = bytearray(fh.read())
    raw[-1] ^= 0xFF
    with open(path, "wb") as fh:
        fh.write(raw)

    rebuilt = manifest.build(path)
    assert rebuilt["data_commitment"]["root"] != committed["data_commitment"]["root"]


def test_metadata_shape_fits_cardano_limits(tmp_path):
    path = _sample(tmp_path)
    sk, _ = keys.generate()
    signed = manifest.sign(manifest.build(path), sk)
    meta = anchor.build_metadata(signed)[str(anchor.METADATA_LABEL)]
    assert len(meta["id"]) == 64
    assert all(len(chunk) <= 64 for chunk in meta["sig"])


if __name__ == "__main__":
    import tempfile

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            with tempfile.TemporaryDirectory() as td:
                try:
                    fn(td) if fn.__code__.co_argcount else fn()
                    print(f"[ok]   {name}")
                except Exception as exc:  # noqa: BLE001
                    failures += 1
                    print(f"[FAIL] {name}: {exc}")
    raise SystemExit(1 if failures else 0)
