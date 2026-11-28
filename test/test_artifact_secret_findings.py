import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("findings", Path(__file__).resolve().parents[1] / "scripts/check-artifact-secret-findings.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FindingTests(unittest.TestCase):
    def test_only_verified_manifest_digest_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            name = "agentic-workflow-chatgpt-v2026.1.1.zip"
            digest = hashlib.sha256(b"public skill").hexdigest()
            with zipfile.ZipFile(root / name, "w") as archive:
                archive.writestr("skills/api-key/SKILL.md", b"public skill")
                archive.writestr("assets/provenance.json", json.dumps({
                    "sha256": {"skills/api-key/SKILL.md": digest, "wrong": "0" * 64},
                    "secret": digest,
                }, indent=2))
            finding = {"RuleID": "generic-api-key", "File": f"/scan/{name}!assets/provenance.json", "StartLine": 3, "EndLine": 3}
            self.assertTrue(module.verified_digest_finding(finding, root))
            self.assertFalse(module.verified_digest_finding(dict(finding, RuleID="github-pat"), root))
            self.assertFalse(module.verified_digest_finding(dict(finding, File=f"/scan/{name}!other.json"), root))
            self.assertFalse(module.verified_digest_finding(dict(finding, StartLine=6, EndLine=6), root))
            self.assertFalse(module.verified_digest_finding(dict(finding, EndLine=4), root))
