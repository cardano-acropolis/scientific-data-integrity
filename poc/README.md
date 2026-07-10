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
python3 tests/test_end_to_end.py     # or: python -m pytest
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
  hashing.py    Blake2b-256 / SHA-256 and a domain-separated Merkle tree
  manifest.py   build / canonicalize / sign / verify the provenance manifest
  keys.py       Ed25519 (cryptography, with pure-Python RFC 8032 fallback)
  anchor.py     LocalAnchor + CardanoBlockfrostAnchor behind one interface
  cli.py        keygen / make-sample / commit / verify
tests/
  test_end_to_end.py
```

## Scope & next steps (per the plan)

This is Phase 0. It is intentionally small: no watched-folder daemon, no FlowJo
plugin, no NFT minting, no batching. Phase 1 adds the watched-folder agent,
Merkle-batched anchoring to amortize fees, and a verifier web page; later phases
add instrument integration and the attestation tiers. The `keys` and `anchor`
seams are the extension points for TPM/TEE/instrument keys and for the
Merkle-batch anchoring service.

> Security note: the pure-Python Ed25519 fallback is a readable RFC 8032
> reference, not constant-time; production builds should use `cryptography`
> or an HSM/TEE-backed signer.
