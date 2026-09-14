import tomllib
import unittest
from pathlib import Path
from deep_tests.security_model import BoundaryViolation, normalize_relative_path, redact, validate_outbound_url
class CounterpartTipSecurityHardeningTests(unittest.TestCase):
    def test_mixed_and_double_encoded_parent_segments_fail_closed(self):
        for value in ("%2E%2E/secret","%2e%2E/secret","%252E%252E/secret","safe/%2E%2E/secret"):
            with self.assertRaises(BoundaryViolation): normalize_relative_path(value)
    def test_authority_confusion_urls_are_rejected(self):
        allowed={"api.example.test"}
        for value in ("//api.example.test/v1","https://api.example.test@attacker.invalid/v1","https://attacker.invalid/api.example.test"):
            with self.assertRaises(BoundaryViolation): validate_outbound_url(value,allowed)
    def test_redaction_is_idempotent_for_mixed_secret_shapes(self):
        gh="gh"+"p_"+"A"*32; lin="lin_"+"api_"+"B"*32; once=redact(f"Bearer opaque {gh} query={lin}"); self.assertEqual(once,redact(once)); self.assertNotIn(gh,once); self.assertNotIn(lin,once)
    def test_zed_pkg_runner_keeps_suite_and_verifier_coupled(self):
        script=tomllib.loads(Path(".zpkg.toml").read_text())["scripts"]["test"]; self.assertIn("unittest discover",script); self.assertIn("scripts/verify_repository.py",script)
if __name__ == "__main__": unittest.main()
