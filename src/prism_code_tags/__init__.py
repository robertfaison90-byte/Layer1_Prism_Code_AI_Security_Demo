"""Offline model-artifact provenance tags. Public API is in core."""
from .core import create_keypair, sign_artifact, verify_artifact, VerificationError

__all__ = ["create_keypair", "sign_artifact", "verify_artifact", "VerificationError"]
