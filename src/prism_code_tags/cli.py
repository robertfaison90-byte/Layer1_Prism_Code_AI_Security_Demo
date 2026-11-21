"""Command line interface for PRISM Code artifact tagging."""
import argparse
import json
import sys
from pathlib import Path

from .core import VerificationError, create_keypair, sign_artifact, verify_artifact


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="prism-tag", description="Tag and verify model files offline")
    sub = parser.add_subparsers(dest="command", required=True)
    key = sub.add_parser("keygen", help="Create local demo keypair; never commit private key")
    key.add_argument("--private", required=True)
    key.add_argument("--public", required=True)
    sign = sub.add_parser("sign", help="Sign content digest and provenance metadata")
    sign.add_argument("artifact")
    sign.add_argument("--private", required=True)
    sign.add_argument("--model-name", required=True)
    sign.add_argument("--source-ref", required=True, help="For example, reviewed Git commit or training run ID")
    sign.add_argument("--output", required=True)
    sign.add_argument("--metadata", action="append", default=[], metavar="KEY=VALUE")
    verify = sub.add_parser("verify", help="Verify using an independently trusted public key")
    verify.add_argument("artifact")
    verify.add_argument("--tag", required=True)
    verify.add_argument("--trusted-public-key", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            print(json.dumps({"key_fingerprint": create_keypair(args.private, args.public)}))
        elif args.command == "sign":
            if any("=" not in item or not item.split("=", 1)[0] for item in args.metadata):
                raise ValueError("Metadata must be KEY=VALUE")
            metadata = dict(item.split("=", 1) for item in args.metadata)
            result = sign_artifact(args.artifact, args.private, model_name=args.model_name,
                                   source_ref=args.source_ref, metadata=metadata)
            with Path(args.output).open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
            print(json.dumps({"tag": args.output, "key_fingerprint": result["payload"]["key_fingerprint"]}))
        else:
            payload = verify_artifact(args.artifact, json.loads(Path(args.tag).read_text(encoding="utf-8")), args.trusted_public_key)
            print(json.dumps({"verified": True, "model_name": payload["model_name"], "artifact_sha256": payload["artifact_sha256"]}))
        return 0
    except (VerificationError, OSError, ValueError) as exc:
        print(f"PRISM Code: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
