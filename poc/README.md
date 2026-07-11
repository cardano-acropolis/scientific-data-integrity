# Scientific Data Integrity — Phase 0 proof-of-concept

A runnable spike of the Data Integrity pipeline from
[`../docs/data-integrity-technical-plan.md`](../docs/data-integrity-technical-plan.md):

```
hash  ->  provenance manifest  ->  Ed25519 signature  ->  anchor  ->  verify
```

Given a flow-cytometry `.fcs` file (or any file), it produces a signed
provenance manifest committing to the content, anchors the manifest's identifier
to a tamper-evident ledger, and later verifies that a file still matches its
commitment and that the anchor confirms it.

**What this proves — and what it doesn't.** The commitment gives **integrity**
(the file is unchanged), **time/priority** (the anchor's timestamp), and
**attribution** (the signing key). It does **not** prove the data came from a
genuine measurement — that is the Tier 2/3 (device attestation) problem in the
plan. This is *provenance*, not *proof of truth*.

## Install & run

Core pipeline needs only Python 3.9+. `cryptography` is used for Ed25519 when
available; otherwise a vendored pure-Python RFC 8032 implementation is used
automatically (keys and signatures are byte-compatible either way).

```bash
cd poc

# 1. Generate a pseudonymous lab signing key
python3 -m sdi keygen --out keys/lab

# 2. Make a synthetic FCS 3.1 file to play with (or bring your own .fcs)
python3 -m sdi make-sample --out examples/sample.fcs --events 1000

# 3. Commit: hash -> manifest -> sign -> anchor
python3 -m sdi commit examples/sample.fcs --key keys/lab.sk \
        --backend local --out manifest.json

# 4. Verify the file against its manifest and anchor
python3 -m sdi verify manifest.json --file examples/sample.fcs
#    -> VERIFICATION PASSED

# Tamper with a single byte and verification fails:
cp examples/sample.fcs bad.fcs
python3 - <<'PY'
d = bytearray(open("bad.fcs","rb").read()); d[-1] ^= 0xFF
open("bad.fcs","wb").write(d)
PY
python3 -m sdi verify manifest.json --file bad.fcs   # -> VERIFICATION FAILED
```

Run the tests:

```bash
python3 tests/test_end_to_end.py      # Phase 0: hash/sign/anchor/verify
python3 tests/test_phase1_batch.py    # Phase 1: Merkle proofs, batching, watcher
# or, if pytest is available: python -m pytest
```

## Batching and the watched-folder daemon (Phase 1)

One anchoring transaction per dataset is wasteful. **`commit-batch`** hashes and
signs many files, builds a Merkle tree over their `manifest_id`s, and anchors the
single **root** once — each manifest keeps a compact **inclusion proof** back to
that root, so per-dataset on-chain cost trends to zero while every dataset stays
independently verifiable.

```bash
python3 -m sdi commit-batch data/*.fcs --key keys/lab.sk \
        --backend local --out-dir manifests/
# -> one anchor for the whole batch; one manifest per file under manifests/

python3 -m sdi verify manifests/s3.fcs.manifest.json --file data/s3.fcs
# checks: signature, file hash, data root, batch inclusion proof, root anchor
```

**`watch`** is the install-anywhere capture path: it polls a directory (stdlib
only — no `watchdog` needed), commits each file once its size goes stable, and
flushes accumulated commits as a batch on a size or time trigger.

```bash
python3 -m sdi watch data/ --key keys/lab.sk --backend local \
        --out-dir manifests/ --pattern '*.fcs' \
        --batch-size 8 --batch-interval 30   # flush at 8 files or every 30s
```

## What's in the manifest

- **File hashes** — Blake2b-256 (the on-chain identifier; Cardano-native) and
  SHA-256 (interoperability).
- **FCS-aware commitment** — the TEXT (metadata) and DATA (events) segments are
  hashed separately, so a metadata edit is distinguishable from a data edit. The
  DATA segment is committed with a **Merkle tree over event rows** (domain-
  separated leaves/nodes), enabling streaming and partial verification of large
  files.
- **MIFlowCyt-relevant keywords** — instrument, serial, dates, operator, etc.,
  surfaced from the FCS TEXT segment.
- **Signature** — Ed25519 over the canonical manifest identifier.

The `manifest_id` (Blake2b-256 of the canonical, signature/anchor-excluded
manifest) is the single value anchored on-chain.

## Anchoring backends

| Backend | Flag | Needs | Notes |
|---|---|---|---|
| Local (default) | `--backend local` | nothing | Writes a receipt to `anchors/`. **Not a blockchain** — no distributed timestamp; for offline demos/tests. |
| Cardano | `--backend cardano` | `pycardano`, `BLOCKFROST_PROJECT_ID`, a funded **preprod** wallet (`CARDANO_PAYMENT_SKEY`) | Writes the commitment into Cardano transaction metadata (label 1667, placeholder pending CIP registration) on a testnet via Blockfrost. |

The Cardano path is fully wired but was **not exercised in this environment**
(no `pycardano`, no testnet funds, no Blockfrost key). To run it for real:

```bash
pip install pycardano blockfrost-python requests
export BLOCKFROST_PROJECT_ID=preprod...           # from blockfrost.io
export CARDANO_PAYMENT_SKEY=/path/to/payment.skey # funded preprod key
python3 -m sdi commit examples/sample.fcs --key keys/lab.sk --backend cardano --out manifest.json
python3 -m sdi verify manifest.json --file examples/sample.fcs   # confirms via Blockfrost
```

## Layout

```
sdi/
  fcs.py        minimal FCS 3.0/3.1 reader + synthetic-file builder
  hashing.py    Blake2b-256 / SHA-256, Merkle tree + inclusion proofs
  manifest.py   build / canonicalize / sign / verify the provenance manifest
  keys.py       Ed25519 (cryptography, with pure-Python RFC 8032 fallback)
  anchor.py     LocalAnchor + CardanoBlockfrostAnchor behind one interface
  batch.py      Merkle-batched anchoring + inclusion proofs
  daemon.py     watched-folder capture + batcher
  cli.py        keygen / make-sample / commit / commit-batch / watch / verify
tests/
  test_end_to_end.py       Phase 0
  test_phase1_batch.py     Phase 1
```

## Scope & next steps (per the plan)

Phases 0 and 1 are implemented here: the hash/sign/anchor/verify pipeline, the
watched-folder daemon, and Merkle-batched anchoring with inclusion proofs. Still
to come: a static verifier **web page**, FlowJo/instrument **integration**, NFT
minting (CIP-25/68), and the **attestation tiers** (TPM/TEE/instrument keys).
The `keys` and `anchor` seams are the extension points for those. The single
biggest gap is running the **Cardano** backend against real preprod — the code
path exists but has not been exercised on-chain (see above).

> Security note: the pure-Python Ed25519 fallback is a readable RFC 8032
> reference, not constant-time; production builds should use `cryptography`
> or an HSM/TEE-backed signer.
