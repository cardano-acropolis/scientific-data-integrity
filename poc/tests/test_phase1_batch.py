"""Phase 1: Merkle inclusion proofs, batched anchoring, and the folder watcher."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sdi import anchor, batch, daemon, fcs, hashing, keys, manifest  # noqa: E402


def _sample(path: str, tag: int) -> str:
    raw = fcs.build_fcs_3_1(
        params=["FSC-A", "SSC-A"],
        events=[[float(tag), float(i)] for i in range(20)],
        extra_keywords={"$OP": f"op{tag}"},
    )
    with open(path, "wb") as fh:
        fh.write(raw)
    return path


def test_merkle_proof_roundtrip_all_indices():
    for n in (1, 2, 3, 5, 8, 9):
        blocks = [f"leaf-{i}".encode() for i in range(n)]
        root = hashing.merkle_root(blocks).root
        for i in range(n):
            proof = hashing.merkle_proof(blocks, i)
            assert hashing.verify_merkle_proof(blocks[i], i, proof, root)


def test_merkle_proof_rejects_wrong_leaf():
    blocks = [b"a", b"b", b"c", b"d"]
    root = hashing.merkle_root(blocks).root
    proof = hashing.merkle_proof(blocks, 2)
    assert not hashing.verify_merkle_proof(b"not-c", 2, proof, root)


def test_build_batch_matches_standalone_root():
    ids = [hashing.blake2b_256(f"m{i}".encode()) for i in range(5)]
    b = batch.build_batch(ids)
    leaves = [bytes.fromhex(x) for x in ids]
    assert b.root == hashing.merkle_root(leaves).root
    assert b.leaf_count == 5


def test_commit_batch_end_to_end(tmp_path):
    files = [_sample(os.path.join(tmp_path, f"s{i}.fcs"), i) for i in range(5)]
    sk, _ = keys.generate()
    backend = anchor.LocalAnchor(directory=os.path.join(tmp_path, "anchors"))
    out_dir = os.path.join(tmp_path, "manifests")

    b, receipt, outputs = batch.commit_files_as_batch(files, sk, backend, out_dir)
    assert b.leaf_count == 5 and len(outputs) == 5

    # Exactly one anchor written for the whole batch.
    assert len(os.listdir(os.path.join(tmp_path, "anchors"))) == 1

    import json

    for i, (name, path) in enumerate(outputs):
        m = json.load(open(path))
        # signature intact
        ok, _ = manifest.verify_signature(m)
        assert ok
        # inclusion proof resolves to the batch root
        inc_ok, msg = batch.verify_inclusion(m)
        assert inc_ok, msg
        assert m["anchor"]["batch"]["root"] == b.root
        # anchor confirms the root, not the individual manifest_id
        c_ok, _ = backend.confirm(b.root, m["anchor"]["reference"])
        assert c_ok


def test_inclusion_proof_detects_tamper(tmp_path):
    files = [_sample(os.path.join(tmp_path, f"s{i}.fcs"), i) for i in range(4)]
    sk, _ = keys.generate()
    backend = anchor.LocalAnchor(directory=os.path.join(tmp_path, "anchors"))
    _, _, outputs = batch.commit_files_as_batch(
        files, sk, backend, os.path.join(tmp_path, "manifests")
    )
    import json

    m = json.load(open(outputs[0][1]))
    m["signature"]["manifest_id"] = "00" * 32  # forge a different id
    inc_ok, _ = batch.verify_inclusion(m)
    assert not inc_ok


def test_folder_watcher_emits_when_stable():
    clock = {"t": 0.0}
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        w = daemon.FolderWatcher(
            d, pattern="*.fcs", stable_seconds=2.0, clock=lambda: clock["t"]
        )
        # No files yet.
        assert w.poll_once() == []
        # A file appears (t=0): first sighting, not yet stable.
        _sample(os.path.join(d, "a.fcs"), 1)
        assert w.poll_once() == []
        # Still within the stable window.
        clock["t"] = 1.0
        assert w.poll_once() == []
        # Size unchanged for >= stable_seconds -> emitted once.
        clock["t"] = 3.0
        emitted = w.poll_once()
        assert emitted and emitted[0].endswith("a.fcs")
        # Not re-emitted.
        clock["t"] = 5.0
        assert w.poll_once() == []


def test_folder_watcher_waits_for_growing_file():
    clock = {"t": 0.0}
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "grow.fcs")
        w = daemon.FolderWatcher(d, stable_seconds=2.0, clock=lambda: clock["t"])
        with open(path, "wb") as fh:
            fh.write(b"x")
        assert w.poll_once() == []
        clock["t"] = 3.0
        with open(path, "ab") as fh:  # still growing at t=3 -> resets timer
            fh.write(b"y")
        assert w.poll_once() == []
        clock["t"] = 4.0  # only 1s since last change
        assert w.poll_once() == []
        clock["t"] = 5.5  # now stable for >= 2s
        assert w.poll_once() == [path]


def test_batcher_flushes_at_size(tmp_path):
    sk, _ = keys.generate()
    backend = anchor.LocalAnchor(directory=os.path.join(tmp_path, "anchors"))
    b = daemon.Batcher(
        backend, sk, os.path.join(tmp_path, "manifests"), batch_size=3
    )
    files = [_sample(os.path.join(tmp_path, f"s{i}.fcs"), i) for i in range(3)]
    assert b.add_file(files[0]) is None
    assert b.add_file(files[1]) is None
    result = b.add_file(files[2])  # third file triggers a flush
    assert result is not None
    batch_obj, _, outputs = result
    assert batch_obj.leaf_count == 3 and len(outputs) == 3
    assert b.pending_count() == 0


if __name__ == "__main__":
    import tempfile

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                if fn.__code__.co_argcount:
                    with tempfile.TemporaryDirectory() as td:
                        fn(td)
                else:
                    fn()
                print(f"[ok]   {name}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"[FAIL] {name}: {exc}")
    raise SystemExit(1 if failures else 0)
