# PRISM Code Tags

**The first open-source layer of PRISM EVO.** A small Python library and command-line tool that attaches an Ed25519-signed provenance tag to **any model file** and verifies its SHA-256 digest before an engineer loads or distributes the file. Owned by Robert James Faison. MIT licensed. Research release v0.1.0.

**Release:** [PRISM Code Tags v0.1.0](https://github.com/robertfaison90-byte/Layer1_Prism_Code_AI_Security_Demo/releases/tag/PRISM_EVO_LEVEL1) (published tag: `PRISM_EVO_LEVEL1`). [Read the release notes](docs/RELEASE_NOTES_v0.1.0.md). Engineers can [share integration feedback](https://github.com/robertfaison90-byte/Layer1_Prism_Code_AI_Security_Demo/issues/2).

## What it is good for

- Make model files traceable to a named training run or reviewed source reference.
- Detect changed model bytes and changed signed metadata using a separately trusted public key.
- Add the same offline verification step to a scikit-learn, PyTorch, ONNX or R-exported artifact without requiring a particular model framework. The tool treats the model as bytes and never executes it.
- Give engineers a small, inspectable base to build their **own** model training, registry and policy integrations, with tests for tampering and wrong-key failure.

It does not certify accuracy, training data, authorship without a trusted key, runtime safety, privacy, or resistance to a malicious signer. It does not replace a model registry, Sigstore, or build attestation service.

## Install and local demonstration

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

The demo private key is unencrypted and created with mode 0600. **Never commit it.** Production signing needs a managed key service or HSM and an independently distributed trusted public key. Both toy model and tag are demonstration files. Verification must happen **before** deserializing a model. The caller must check that the signed `source_ref` is an approved run or commit; the tool checks that it has not changed, not whether its contents are truthful.

Python API:

```python
import json
from prism_code_tags import verify_artifact

verified = verify_artifact("model.onnx", json.load(open("model.tag.json")), "trusted-release.pub")
assert verified["source_ref"] == "git:approved-release-commit"
# Only then pass a trusted artifact to your framework's load method.
```

## What gets signed

The canonical JSON payload contains schema version, Ed25519+SHA-256 algorithm label, content digest and byte count, model name, source reference, UTC timestamp, string metadata, and the public-key fingerprint. A detached base64 signature is stored alongside it. The caller supplies the model file and independently trusted public key to `verify`. The tag never includes the model or private key. The wire format is documented by `src/prism_code_tags/core.py` and versioned as `prism-code-tag/v1`.

## Comparison with adjacent tools

| Tool | Core job | PRISM Code Tags' initial niche | Boundary |
|---|---|---|---|
| [Sigstore Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/) | Sign and verify blobs with richer identity/transparency workflows | Small offline model-specific metadata envelope and Python API | Cosign has stronger established identity and transparency infrastructure; use it for release provenance where appropriate |
| [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations) | Verify build provenance tied to CI | Tag a local model file and training reference before or outside CI | GitHub's attestation is better for CI build identity; they can be combined |
| [MLflow Model Registry](https://mlflow.org/docs/latest/model-registry/) | Track model versions, metadata, aliases and model signatures | Portable content signature checked with an explicit trusted key | An MLflow model signature describes input/output schema; do not confuse it with cryptographic signing |
| [DVC](https://doc.dvc.org/start) | Version data, models and pipelines through Git workflows | Independent signature over a particular exported artifact and provenance fields | DVC handles versioning and reproducibility at a broader workflow level |

The value proposition is an easy **verification hook** for a model workflow, not a claim to replace those systems or a proven performance advantage. The comparison uses official documentation, checked November 21, 2026.

## Roadmap

v0.1: local signing and verification, tests, MIT license. v0.2 proposal: integration examples for PyTorch/ONNX/scikit-learn and CI; explicit signer-key revocation and trust policy; signed release. v0.3 proposal: interoperable attestations, model registry adapter, R verification bridge. Later PRISM Guard supplies identities, policies, review and audit. Planned features require design review and tests before they become claims.

## License and community

MIT; see `LICENSE`. Contributions welcome via issues and reviewed pull requests. This repository contains only the public first-layer Python package. The private PRISM Guard prototype, research source records, model artifacts and customer information are not part of this release. See `CONTRIBUTING.md`, `SECURITY.md` and `docs/RELEASE_PROCESS.md`.
