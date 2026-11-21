# PRISM Code Tags release process

Repository: https://github.com/robertfaison90-byte/Layer1_Prism_Code_AI_Security_Demo

This repository publishes the open-source first layer: offline model-artifact signing and verification. The package version in `pyproject.toml` is `0.1.0`; a GitHub release/tag is a separate step and should only be created after the source commit and CI have been inspected.

1. Confirm the contributor has rights to submit all changed files under the repository MIT license.
2. Run `python -m pip install -e .` and `python -m unittest discover -s tests -v` in a clean Python 3.10+ environment. Review the CI result on the exact commit.
3. Inspect changed files for private keys, tokens, model weights, source correspondence, personal data and unreviewed dependencies. Never publish the separate PRISM Guard research kit here.
4. Test the CLI on a temporary toy file; verify that changing bytes or using a different trusted public key causes rejection.
5. Review key handling, dependency versions, release notes, and the explicit product limitations in the README and SECURITY policy.
6. Once the source commit passes review, create a version tag and release with the actual commit ID and a concise change log. Where appropriate, add a GitHub build attestation and verify it from an independent workflow.

This tool authenticates an artifact relative to an independently trusted public key. It does not certify model accuracy, safety or production deployment. A signed release, key revocation plan and independent security review are later milestones.
