# PRISM Code Tags v0.1.0 — first public research release

Release page: https://github.com/robertfaison90-byte/Layer1_Prism_Code_AI_Security_Demo/releases/tag/PRISM_EVO_LEVEL1

Published Git tag: `PRISM_EVO_LEVEL1`. Python package version: `0.1.0`. The release tag currently uses a product-layer name rather than a semantic-version name. Source commit: `f1517620983e277c88059ef9d669193db6ce850e`.

PRISM Code Tags is the first public Python layer of PRISM EVO. It adds an Ed25519 signature over a canonical JSON envelope containing a SHA-256 digest and provenance fields for an exported model artifact. Verification checks the signature and the current file bytes against a **separately trusted** public key before the caller loads the file.

## Included

- Python 3.10+ package, `prism-tag` CLI (`keygen`, `sign`, `verify`), and Python API.
- A versioned tag with model name, source reference, timestamp, file digest, byte count, metadata, and signer-key fingerprint.
- Six automated tests: successful verification; changed file, changed metadata and wrong-key rejection; overwrite refusal; and owner-only demo private-key file mode.
- MIT license, quickstart, contribution instructions, and security policy.

## Get started

Clone this repository, then from its root run:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
printf 'toy-model-v1\n' > toy.model
prism-tag keygen --private demo.key --public demo.pub
prism-tag sign toy.model --private demo.key --model-name toy --source-ref git:reviewed-commit --metadata team=research --output toy.tag.json
prism-tag verify toy.model --tag toy.tag.json --trusted-public-key demo.pub
```

Never commit the generated private key. The local demo key is unencrypted; production deployments need managed signing keys and an independently distributed trust anchor. Verification must happen before any framework deserializes or executes an artifact. See [README](../README.md) and [SECURITY](../SECURITY.md) for the trust model.

## Scope and feedback

This release detects changed model bytes or signed metadata relative to a trusted key. It does not prove model accuracy, safety, training-data provenance, or that a signer should be trusted. No production security certification or signed GitHub release is claimed.

Machine learning engineers can share sanitized model workflow results and proposed integrations in [the feedback issue](https://github.com/robertfaison90-byte/Layer1_Prism_Code_AI_Security_Demo/issues/2).
