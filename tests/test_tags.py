import copy
import tempfile
import unittest
from pathlib import Path

from prism_code_tags import VerificationError, create_keypair, sign_artifact, verify_artifact


class TagTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name)
        self.artifact = path / "toy.model"
        self.artifact.write_bytes(b"safe synthetic model bytes")
        self.private, self.public = path / "demo.key", path / "demo.pub"
        create_keypair(self.private, self.public)
        self.tag = sign_artifact(self.artifact, self.private, model_name="toy",
                                 source_ref="git:demo123", metadata={"purpose": "test"})

    def test_verify_and_metadata(self):
        self.assertEqual(verify_artifact(self.artifact, self.tag, self.public)["metadata"]["purpose"], "test")

    def test_modified_artifact_fails(self):
        self.artifact.write_bytes(self.artifact.read_bytes() + b"evil")
        with self.assertRaises(VerificationError):
            verify_artifact(self.artifact, self.tag, self.public)

    def test_modified_metadata_fails(self):
        changed = copy.deepcopy(self.tag)
        changed["payload"]["source_ref"] = "git:unreviewed"
        with self.assertRaises(VerificationError):
            verify_artifact(self.artifact, changed, self.public)

    def test_wrong_trusted_key_fails(self):
        path = Path(self.tmp.name)
        create_keypair(path / "other.key", path / "other.pub")
        with self.assertRaises(VerificationError):
            verify_artifact(self.artifact, self.tag, path / "other.pub")

    def test_keygen_refuses_overwrite(self):
        with self.assertRaises(FileExistsError):
            create_keypair(self.private, self.public)

    def test_private_key_owner_only(self):
        self.assertEqual(self.private.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
