import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from deep_tests.hhm_boundaries import (
    AuthOutcome,
    AuthorityVerdict,
    BlePeerGate,
    HhmBoundaryViolation,
    PeerCertificate,
    PeerEnvelope,
    SharingConsent,
    UpdateManifest,
    VerifiedIdentity,
    audit_secret_paths,
    audit_sops_environment,
    authorize_product_identity,
    combine_dual_auth,
    validate_inert_component,
    validate_websocket_sizes,
    verify_peer_delivered_update,
    websocket_origin_matches_host,
)


FIXTURE = json.loads(
    Path("fixtures/hhm_security_cases.json").read_text(encoding="utf-8")
)


class SharedAuthBoundaryTests(unittest.TestCase):
    def test_anonymous_invalid_and_degraded_remain_distinct(self) -> None:
        for case in FIXTURE["auth_cases"]:
            with self.subTest(case=case):
                outcome = combine_dual_auth(
                    credential_present=case["credential_present"],
                    verdicts=(AuthorityVerdict(value) for value in case["verdicts"]),
                )
                self.assertEqual(outcome, AuthOutcome(case["outcome"]))

    def test_hhm_product_authorization_uses_the_exact_verified_tuple(self) -> None:
        allowed = {("supabase", "house-production", "resident-subject")}
        authorize_product_identity(
            VerifiedIdentity("supabase", "house-production", "resident-subject"),
            allowed,
        )
        for identity in (
            VerifiedIdentity("shared-auth", "house-production", "resident-subject"),
            VerifiedIdentity("supabase", "other-house", "resident-subject"),
            VerifiedIdentity("supabase", "house-production", "other-subject"),
        ):
            with self.subTest(identity=identity), self.assertRaises(HhmBoundaryViolation):
                authorize_product_identity(identity, allowed)

    def test_privileged_work_fails_closed_when_one_authority_cannot_decide(self) -> None:
        outcome = combine_dual_auth(
            credential_present=True,
            verdicts=(AuthorityVerdict.INVALID, AuthorityVerdict.UNAVAILABLE),
        )
        self.assertEqual(outcome, AuthOutcome.DEGRADED)
        self.assertNotEqual(outcome, AuthOutcome.AUTHENTICATED)


class BlePeerSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = FIXTURE["ble"]
        self.now = fixture["now"]
        self.payload = fixture["payload"].encode("utf-8")
        self.gate = BlePeerGate(
            local_installation_id=fixture["local_installation_id"],
            house_id=fixture["house_id"],
        )
        self.certificate = PeerCertificate(
            installation_id=fixture["peer_installation_id"],
            peer_key_id="peer-key-2026-08",
            house_id=fixture["house_id"],
            expires_at=self.now + 300,
            backend_signature_valid=True,
        )
        self.consent = SharingConsent(
            enabled=True,
            allowed_peer_installations=frozenset({fixture["peer_installation_id"]}),
            allowed_purposes=frozenset(fixture["allowed_purposes"]),
        )
        self.envelope = PeerEnvelope(
            protocol="hhm.ble-peer.v1",
            session_id="session-1",
            message_id="message-1",
            nonce="0123456789abcdef",
            sender_installation_id=fixture["peer_installation_id"],
            signing_key_id="peer-key-2026-08",
            recipient_installation_id=fixture["local_installation_id"],
            purpose="data_share",
            sequence=1,
            issued_at=self.now - 1,
            expires_at=self.now + 20,
            payload_digest=hashlib.sha256(self.payload).hexdigest(),
            sender_signature_valid=True,
        )

    def test_backend_certified_peer_with_explicit_consent_is_accepted(self) -> None:
        self.gate.accept(
            certificate=self.certificate,
            consent=self.consent,
            envelope=self.envelope,
            payload=self.payload,
            now=self.now,
        )

    def test_replay_and_out_of_order_messages_fail_closed(self) -> None:
        self.gate.accept(
            certificate=self.certificate,
            consent=self.consent,
            envelope=self.envelope,
            payload=self.payload,
            now=self.now,
        )
        with self.assertRaises(HhmBoundaryViolation):
            self.gate.accept(
                certificate=self.certificate,
                consent=self.consent,
                envelope=self.envelope,
                payload=self.payload,
                now=self.now,
            )
        reordered = replace(
            self.envelope,
            message_id="message-2",
            nonce="fedcba9876543210",
            sequence=1,
        )
        with self.assertRaises(HhmBoundaryViolation):
            self.gate.accept(
                certificate=self.certificate,
                consent=self.consent,
                envelope=reordered,
                payload=self.payload,
                now=self.now,
            )

    def test_proximity_alone_never_establishes_peer_trust(self) -> None:
        for certificate in (
            replace(self.certificate, backend_signature_valid=False),
            replace(self.certificate, revoked=True),
            replace(self.certificate, house_id="other-house"),
        ):
            with self.subTest(certificate=certificate), self.assertRaises(
                HhmBoundaryViolation
            ):
                self.gate.accept(
                    certificate=certificate,
                    consent=self.consent,
                    envelope=self.envelope,
                    payload=self.payload,
                    now=self.now,
                )

    def test_peer_messages_are_recipient_purpose_consent_and_credential_bound(self) -> None:
        variants = [
            replace(self.envelope, recipient_installation_id="another-installation"),
            replace(self.envelope, signing_key_id="unbound-peer-key"),
            replace(self.envelope, purpose=FIXTURE["ble"]["forbidden_purposes"][0]),
            replace(self.envelope, contains_credential=True),
            replace(self.envelope, sender_signature_valid=False),
            replace(self.envelope, payload_digest="0" * 64),
            replace(self.envelope, issued_at=self.now + 1),
            replace(self.envelope, expires_at=self.now),
        ]
        for envelope in variants:
            with self.subTest(envelope=envelope), self.assertRaises(HhmBoundaryViolation):
                self.gate.accept(
                    certificate=self.certificate,
                    consent=self.consent,
                    envelope=envelope,
                    payload=self.payload,
                    now=self.now,
                )
        with self.assertRaises(HhmBoundaryViolation):
            self.gate.accept(
                certificate=self.certificate,
                consent=replace(self.consent, enabled=False),
                envelope=self.envelope,
                payload=self.payload,
                now=self.now,
            )

    def test_peer_transport_cannot_authorize_an_app_update(self) -> None:
        update = b"synthetic signed application artifact"
        manifest = UpdateManifest(
            application_id="hhm-flutter",
            platform="android-arm64",
            channel="stable",
            version=42,
            payload_size=len(update),
            payload_digest=hashlib.sha256(update).hexdigest(),
            canonical_release_signature_valid=True,
        )
        verify_peer_delivered_update(
            manifest,
            update,
            expected_application_id="hhm-flutter",
            expected_platform="android-arm64",
            expected_channel="stable",
            installed_version=41,
        )
        invalid_manifests = (
            replace(manifest, version=41),
            replace(manifest, canonical_release_signature_valid=False),
            replace(manifest, application_id="hhm-desktop-app.rs"),
            replace(manifest, platform="macos-arm64"),
            replace(manifest, channel="development"),
            replace(manifest, payload_digest="0" * 64),
        )
        for invalid in invalid_manifests:
            with self.subTest(manifest=invalid), self.assertRaises(HhmBoundaryViolation):
                verify_peer_delivered_update(
                    invalid,
                    update,
                    expected_application_id="hhm-flutter",
                    expected_platform="android-arm64",
                    expected_channel="stable",
                    installed_version=41,
                )

    def test_desktop_update_uses_the_same_canonical_release_boundary(self) -> None:
        update = b"synthetic desktop application artifact"
        manifest = UpdateManifest(
            application_id="hhm-desktop-app.rs",
            platform="linux-x86_64",
            channel="stable",
            version=8,
            payload_size=len(update),
            payload_digest=hashlib.sha256(update).hexdigest(),
            canonical_release_signature_valid=True,
        )
        verify_peer_delivered_update(
            manifest,
            update,
            expected_application_id="hhm-desktop-app.rs",
            expected_platform="linux-x86_64",
            expected_channel="stable",
            installed_version=7,
        )


class HtmlAndWebSocketBoundaryTests(unittest.TestCase):
    def test_component_is_inert_private_bounded_html(self) -> None:
        headers = FIXTURE["component_headers"]
        validate_inert_component(headers, "<article><h2>Safe</h2></article>")
        for body in (
            "<script>unsafe()</script>",
            "<img src=x onerror=unsafe()>",
            "<a href='javascript:unsafe()'>unsafe</a>",
            "x" * (64 * 1024 + 1),
        ):
            with self.subTest(body=body[:32]), self.assertRaises(HhmBoundaryViolation):
                validate_inert_component(headers, body)
        incomplete = dict(headers)
        del incomplete["content-security-policy"]
        with self.assertRaises(HhmBoundaryViolation):
            validate_inert_component(incomplete, "<p>Safe</p>")

    def test_websocket_origin_is_exact_and_single(self) -> None:
        for case in FIXTURE["websocket_origins"]:
            with self.subTest(case=case):
                self.assertEqual(
                    websocket_origin_matches_host(
                        host_headers=[case["host"]], origin_headers=[case["origin"]]
                    ),
                    case["accepted"],
                )
        self.assertFalse(
            websocket_origin_matches_host(
                host_headers=["example.test"],
                origin_headers=["https://example.test", "https://example.test"],
            )
        )

    def test_websocket_frame_and_message_sizes_are_bounded(self) -> None:
        validate_websocket_sizes(frame_bytes=8 * 1024, message_bytes=16 * 1024)
        for frame_bytes, message_bytes in (
            (8 * 1024 + 1, 16 * 1024),
            (8 * 1024, 16 * 1024 + 1),
            (1024, 512),
        ):
            with self.subTest(
                frame_bytes=frame_bytes, message_bytes=message_bytes
            ), self.assertRaises(HhmBoundaryViolation):
                validate_websocket_sizes(
                    frame_bytes=frame_bytes, message_bytes=message_bytes
                )


class EncryptedEnvironmentBoundaryTests(unittest.TestCase):
    def test_sops_ciphertext_requires_mac_and_multiple_age_recipients(self) -> None:
        lines = FIXTURE["sops_ciphertext_lines"]
        audit_sops_environment("\n".join(lines))
        plaintext = ["HHM_API_BASE_URL=https://api.example.test", *lines[1:]]
        with self.assertRaises(HhmBoundaryViolation):
            audit_sops_environment("\n".join(plaintext))
        one_recipient = [line for line in lines if "list_1" not in line]
        with self.assertRaises(HhmBoundaryViolation):
            audit_sops_environment("\n".join(one_recipient))
        missing_mac = [line for line in lines if not line.startswith("sops_mac=")]
        with self.assertRaises(HhmBoundaryViolation):
            audit_sops_environment("\n".join(missing_mac))

    def test_only_encrypted_or_public_example_paths_may_be_tracked(self) -> None:
        audit_secret_paths(("env/enc/dev.env.enc", "env/enc/prod.env.enc", ".env.example"))
        for path in (".env", "env/dec/dev.env", "keys.txt", "operator.agekey"):
            with self.subTest(path=path), self.assertRaises(HhmBoundaryViolation):
                audit_secret_paths((path,))


if __name__ == "__main__":
    unittest.main()
