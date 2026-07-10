"""Ed25519 keys for signing provenance manifests.

Prefers the ``cryptography`` library (fast, audited); falls back to a vendored
pure-Python RFC 8032 implementation so the PoC runs with no native
dependencies. Keys and signatures are byte-compatible between the two.

Pluggable by design: the manifest is signed through :func:`sign`, so a
TPM/TEE/HSM- or instrument-provisioned key (trust Tiers 2/3 in the plan) can
replace this software key without touching the manifest format.
"""

from __future__ import annotations

import os

try:  # Preferred backend.
    # Gate on _cffi_backend first: cryptography's Rust bindings import it, and a
    # missing backend otherwise aborts with a noisy pyo3 panic on stderr.
    import _cffi_backend  # noqa: F401

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    Ed25519PrivateKey.generate()  # probe: native bindings actually load
    _BACKEND = "cryptography"
except BaseException:  # noqa: BLE001 - pyo3 PanicException derives from BaseException
    # Covers ImportError and the pyo3 PanicException raised when the native
    # bindings can't load (missing _cffi_backend, etc.).
    from . import _ed25519_pure as _pure

    _BACKEND = "pure-python"


def backend() -> str:
    return _BACKEND


def generate() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex). Private key is a 32-byte seed."""
    if _BACKEND == "cryptography":
        sk = Ed25519PrivateKey.generate()
        return sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex()
    seed = os.urandom(32)
    return seed.hex(), _pure.secret_to_public(seed).hex()


def public_from_private(sk_hex: str) -> str:
    seed = bytes.fromhex(sk_hex)
    if _BACKEND == "cryptography":
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        return sk.public_key().public_bytes_raw().hex()
    return _pure.secret_to_public(seed).hex()


def sign(sk_hex: str, message: bytes) -> str:
    seed = bytes.fromhex(sk_hex)
    if _BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message).hex()
    return _pure.sign(seed, message).hex()


def verify(vk_hex: str, message: bytes, signature_hex: str) -> bool:
    pub = bytes.fromhex(vk_hex)
    sig = bytes.fromhex(signature_hex)
    if _BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
            return True
        except InvalidSignature:
            return False
    return _pure.verify(pub, message, sig)
