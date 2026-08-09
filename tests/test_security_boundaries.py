import random
import re
import unittest
from pathlib import Path

from deep_tests.security_model import (
    BoundaryViolation,
    Principal,
    ReplayWindow,
    authorize_read,
    normalize_relative_path,
    redact,
    sign,
    validate_outbound_url,
)


class SecurityBoundaryTests(unittest.TestCase):
    def test_path_traversal_corpus_is_rejected(self) -> None:
        traversal = [
            "../secret",
            "safe/../secret",
            "%2e%2e/secret",
            "%252e%252e/secret",
            "/absolute",
            "safe\\windows",
            "safe/%2e%2e/secret",
            "safe//double",
        ]
        for value in traversal:
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)
        self.assertEqual(normalize_relative_path("safe/nested/file.txt"), "safe/nested/file.txt")

    def test_ssrf_boundary_requires_exact_https_allowlist(self) -> None:
        allowed = {"api.example.test"}
        self.assertEqual(
            validate_outbound_url("https://api.example.test/v1", allowed),
            "https://api.example.test/v1",
        )
        for value in (
            "http://api.example.test/v1",
            "https://api.example.test.attacker.invalid/v1",
            "https://user@api.example.test/v1",
            "https://127.0.0.1/v1",
        ):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)

    def test_tenant_isolation_and_roles_fail_closed(self) -> None:
        authorize_read(Principal("tenant-a", frozenset({"reader"})), "tenant-a")
        with self.assertRaises(BoundaryViolation):
            authorize_read(Principal("tenant-a", frozenset({"reader"})), "tenant-b")
        with self.assertRaises(BoundaryViolation):
            authorize_read(Principal("tenant-a", frozenset({"writer"})), "tenant-a")

    def test_signature_tamper_replay_and_skew_are_rejected(self) -> None:
        secret = b"unit-test-secret"
        body = b"payload"
        now = 1_700_000_000
        signature = sign(secret, now, "nonce-1", body)
        window = ReplayWindow(max_skew_seconds=300)
        window.verify(secret, now, "nonce-1", body, signature, now=now)
        with self.assertRaises(BoundaryViolation):
            window.verify(secret, now, "nonce-1", body, signature, now=now)
        with self.assertRaises(BoundaryViolation):
            ReplayWindow().verify(secret, now, "nonce-2", b"tampered", signature, now=now)
        with self.assertRaises(BoundaryViolation):
            ReplayWindow(max_skew_seconds=10).verify(
                secret, now - 11, "nonce-3", body, sign(secret, now - 11, "nonce-3", body), now=now
            )

    def test_redaction_removes_token_and_bearer_shapes(self) -> None:
        github_shape = "gh" + "p_" + "A" * 32
        linear_shape = "lin_" + "api_" + "B" * 32
        value = f"Authorization: Bearer opaque {github_shape} {linear_shape}"
        result = redact(value)
        self.assertNotIn(github_shape, result)
        self.assertNotIn(linear_shape, result)
        self.assertNotIn("opaque", result)

    def test_workflow_actions_are_immutable_and_permissions_are_read_only(self) -> None:
        workflow = Path(".github/workflows/deep-tests.yml").read_text()
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request_target", workflow)
        uses = [line.split("uses:", 1)[1].strip() for line in workflow.splitlines() if "uses:" in line]
        self.assertGreaterEqual(len(uses), 2)
        for action in uses:
            self.assertRegex(action, re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$"))


if __name__ == "__main__":
    unittest.main()
