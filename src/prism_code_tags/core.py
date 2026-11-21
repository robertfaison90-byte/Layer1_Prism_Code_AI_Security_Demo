"""Minimal Ed25519 signature + SHA-256 content binding for arbitrary model files.

Verification is meaningful only when the caller independently trusts the supplied
public key. This module never deserializes a model artifact or contacts a network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class VerificationError(ValueError):
    """An artifact tag, trusted key, or signature failed validation."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def create_keypair(private_path: str | Path, public_path: str | Path) -> str:
    """Create a local unencrypted private key (mode 0600) and distributable public key.

    For production, use a managed signer/HSM instead of storing an unencrypted key.
    """
    private, public = Path(private_path), Path(public_path)
    if private.resolve() == public.resolve() or private.exists() or public.exists():
        raise FileExistsError("Both output paths must be different and not exist")
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_bytes = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(private_bytes)
        with public.open("xb") as stream:
            stream.write(public_bytes)
    except Exception:
        private.unlink(missing_ok=True)
        raise
    return _fingerprint(key.public_key())


def sign_artifact(artifact: str | Path, private_key: str | Path, *, model_name: str,
                  source_ref: str, metadata: Mapping[str, str] | None = None) -> dict:
    """Return a portable signed tag; caller stores the JSON next to the artifact."""
    file = Path(artifact)
    if not file.is_file() or not model_name or not source_ref:
        raise ValueError("Existing artifact, model_name and source_ref are required")
    fields = dict(metadata or {})
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in fields.items()):
        raise ValueError("Metadata keys and values must be strings")
    key = serialization.load_pem_private_key(Path(private_key).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    digest, size = _digest(file)
    payload = {
        "schema": "prism-code-tag/v1", "algorithm": "Ed25519+SHA-256",
        "artifact_sha256": digest, "artifact_size": size,
        "model_name": model_name, "source_ref": source_ref,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "metadata": fields, "key_fingerprint": _fingerprint(key.public_key()),
    }
    if len(_canonical(payload)) > 60000:
        raise ValueError("Tag metadata exceeds 60 KB")
    return {"payload": payload, "signature_base64": base64.b64encode(key.sign(_canonical(payload))).decode("ascii")}


def verify_artifact(artifact: str | Path, tag: Mapping, trusted_public_key: str | Path) -> dict:
    """Verify signature and content against an independently supplied trusted key.

    Returns the signed payload on success; raises VerificationError on failure.
    Does not load/execute the artifact or infer that the model is safe or accurate.
    """
    try:
        if set(tag) != {"payload", "signature_base64"}:
            raise VerificationError("Unexpected tag fields")
        payload = tag["payload"]
        required = {"schema", "algorithm", "artifact_sha256", "artifact_size", "model_name", "source_ref", "created_utc", "metadata", "key_fingerprint"}
        if not isinstance(payload, dict) or set(payload) != required:
            raise VerificationError("Invalid payload fields")
        if payload["schema"] != "prism-code-tag/v1" or payload["algorithm"] != "Ed25519+SHA-256":
            raise VerificationError("Unsupported tag format")
        if not isinstance(payload["metadata"], dict):
            raise VerificationError("Invalid metadata")
        if len(_canonical(tag)) > 65536:
            raise VerificationError("Tag too large")
        key = serialization.load_pem_public_key(Path(trusted_public_key).read_bytes())
        if not isinstance(key, Ed25519PublicKey) or payload["key_fingerprint"] != _fingerprint(key):
            raise VerificationError("Untrusted signer")
        signature = base64.b64decode(tag["signature_base64"], validate=True)
        key.verify(signature, _canonical(payload))
        actual_digest, actual_size = _digest(Path(artifact))
        if actual_digest != payload["artifact_sha256"] or actual_size != payload["artifact_size"]:
            raise VerificationError("Artifact changed since tagging")
        return payload
    except (InvalidSignature, OSError, ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError("Signature, tag, trusted key, or artifact invalid") from exc
