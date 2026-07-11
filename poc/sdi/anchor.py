"""Anchoring backends: commit a manifest_id to a tamper-evident ledger.

Two backends behind one interface:

* ``LocalAnchor`` — writes a signed-content receipt to disk. It is NOT a
  blockchain and provides no distributed timestamp; it exists so the full
  pipeline runs and is testable offline. Every receipt says so.
* ``CardanoBlockfrostAnchor`` — writes the commitment into Cardano transaction
  metadata on a testnet via Blockfrost. Requires ``pycardano``, a funded
  preprod wallet, and ``BLOCKFROST_PROJECT_ID``; it raises a clear error if any
  is missing, so the same CLI degrades gracefully where those aren't present.

Metadata label 1667 is a placeholder pending a CIP registration.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

METADATA_LABEL = 1667


def _chunk64(s: str) -> list[str]:
    """Cardano metadata strings cap at 64 bytes; split hex into <=64 chars."""
    return [s[i : i + 64] for i in range(0, len(s), 64)] or [""]


def build_metadata(manifest: dict) -> dict:
    """The on-chain payload for a signed manifest (Cardano metadata shape)."""
    sig = manifest["signature"]
    return {
        str(METADATA_LABEL): {
            "std": "sdi-0.1",
            "id": sig["manifest_id"],  # 64 hex chars — fits in one string
            "pk": sig["public_key"],
            "sig": _chunk64(sig["sig"]),  # 128 hex chars — two chunks
        }
    }


@dataclass
class AnchorReceipt:
    backend: str
    manifest_id: str
    reference: str  # tx hash (chain) or receipt path (local)
    timestamp: str
    detail: dict


class AnchorBackend(Protocol):
    name: str

    def anchor(self, manifest: dict) -> AnchorReceipt: ...

    def confirm(self, manifest_id: str, reference: str) -> tuple[bool, dict]: ...


class LocalAnchor:
    """Offline demo backend. Deterministic, no network, clearly not a chain."""

    name = "local"

    def __init__(self, directory: str = "anchors") -> None:
        self.directory = directory

    def anchor(self, manifest: dict) -> AnchorReceipt:
        os.makedirs(self.directory, exist_ok=True)
        mid = manifest["signature"]["manifest_id"]
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {
            "backend": self.name,
            "manifest_id": mid,
            "timestamp": ts,
            "metadata": build_metadata(manifest),
            "note": "LOCAL DEMO ANCHOR — not a blockchain; no distributed timestamp.",
        }
        path = os.path.join(self.directory, f"{mid}.anchor.json")
        with open(path, "w") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
        return AnchorReceipt(self.name, mid, path, ts, {"path": path})

    def confirm(self, manifest_id: str, reference: str) -> tuple[bool, dict]:
        try:
            with open(reference) as fh:
                record = json.load(fh)
        except OSError as exc:
            return False, {"error": str(exc)}
        ok = record.get("manifest_id") == manifest_id
        return ok, {"timestamp": record.get("timestamp"), "note": record.get("note")}


class CardanoBlockfrostAnchor:
    """Anchor into Cardano transaction metadata on a testnet via Blockfrost.

    Kept import-light: ``pycardano`` is imported lazily so the rest of the CLI
    works without it installed.
    """

    name = "cardano-blockfrost"

    def __init__(
        self,
        *,
        network: str = "preprod",
        project_id: str | None = None,
        payment_skey_path: str | None = None,
    ) -> None:
        self.network = network
        self.project_id = project_id or os.environ.get("BLOCKFROST_PROJECT_ID")
        self.payment_skey_path = payment_skey_path or os.environ.get("CARDANO_PAYMENT_SKEY")

    def _require(self):
        if not self.project_id:
            raise RuntimeError(
                "BLOCKFROST_PROJECT_ID is not set. Get a free preprod key at "
                "https://blockfrost.io and export it."
            )
        try:
            import pycardano  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "pycardano is not installed. `pip install pycardano blockfrost-python` "
                "to enable on-chain anchoring."
            ) from exc

    def anchor(self, manifest: dict) -> AnchorReceipt:
        self._require()
        from pycardano import (
            BlockFrostChainContext, Network, Metadata, AuxiliaryData,
            PaymentSigningKey, PaymentVerificationKey, Address, TransactionBuilder,
        )

        if not self.payment_skey_path:
            raise RuntimeError(
                "CARDANO_PAYMENT_SKEY is not set. Point it at a funded preprod "
                "payment signing key (cardano-cli / pycardano format)."
            )

        base_url = f"https://cardano-{self.network}.blockfrost.io/api"
        context = BlockFrostChainContext(self.project_id, base_url=base_url)
        net = Network.TESTNET

        skey = PaymentSigningKey.load(self.payment_skey_path)
        vkey = PaymentVerificationKey.from_signing_key(skey)
        address = Address(vkey.hash(), network=net)

        metadata = AuxiliaryData(Metadata(build_metadata(manifest)))
        builder = TransactionBuilder(context)
        builder.add_input_address(address)
        builder.auxiliary_data = metadata
        # Return change to self; a tiny self-payment carries the metadata tx.
        signed_tx = builder.build_and_sign([skey], change_address=address)
        context.submit_tx(signed_tx.to_cbor())

        tx_id = str(signed_tx.id)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        mid = manifest["signature"]["manifest_id"]
        return AnchorReceipt(
            self.name, mid, tx_id, ts,
            {"network": self.network, "tx": tx_id, "label": METADATA_LABEL},
        )

    def confirm(self, manifest_id: str, reference: str) -> tuple[bool, dict]:
        """Fetch tx metadata from Blockfrost and confirm the id is present."""
        import requests

        if not self.project_id:
            return False, {"error": "BLOCKFROST_PROJECT_ID not set"}
        base = f"https://cardano-{self.network}.blockfrost.io/api/v0"
        headers = {"project_id": self.project_id}
        try:
            meta = requests.get(
                f"{base}/txs/{reference}/metadata", headers=headers, timeout=30
            ).json()
            tx = requests.get(
                f"{base}/txs/{reference}", headers=headers, timeout=30
            ).json()
        except requests.RequestException as exc:
            return False, {"error": str(exc)}

        found = any(
            str(entry.get("label")) == str(METADATA_LABEL)
            and entry.get("json_metadata", {}).get("id") == manifest_id
            for entry in (meta if isinstance(meta, list) else [])
        )
        block_time = tx.get("block_time") if isinstance(tx, dict) else None
        return found, {"block_time": block_time, "tx": reference}


def get_backend(name: str, **kwargs) -> AnchorBackend:
    if name == "local":
        return LocalAnchor(**{k: v for k, v in kwargs.items() if k == "directory"})
    if name in ("cardano", "cardano-blockfrost"):
        return CardanoBlockfrostAnchor(
            **{k: v for k, v in kwargs.items()
               if k in ("network", "project_id", "payment_skey_path")}
        )
    raise ValueError(f"unknown anchor backend: {name}")
