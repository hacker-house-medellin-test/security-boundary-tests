import hashlib
import json
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deep_tests.hhm_boundaries import (
    AuthOutcome,
    AuthorityVerdict,
    BlePeerGate,
    HhmBoundaryViolation,
    NegotiatedPeerSession,
    PeerCertificate,
    PeerEnvelope,
    SharingConsent,
    SignedUpdateManifest,
    VerifiedIdentity,
    audit_secret_paths,
    audit_sops_environment,
    authorize_product_identity,
    combine_dual_auth,
    load_pinned_peer_contract,
    validate_handshake_material,
    validate_handshake_request,
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


class PinnedPeerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema, self.fixture, self.provenance = load_pinned_peer_contract(Path("."))
        self.now = datetime(2026, 8, 24, 18, 0, 30, tzinfo=timezone.utc)

    def test_exact_hhm_interfaces_revision_and_fixture_are_pinned(self) -> None:
        self.assertEqual(
            self.provenance["commit"],
            "f694bc9b58907db918f0449b5d04a5763f8fa745",
        )
        definitions = self.schema["$defs"]
        self.assertEqual(definitions["ProtocolVersion"]["const"], "hhm.p2p.v1")
        self.assertEqual(
            definitions["HandshakeResponse"]["allOf"][0]["then"]["properties"][
                "selected_capabilities"
            ]["minItems"],
            1,
        )
        self.assertEqual(
            definitions["SignedUpdateManifest"]["properties"]["app_id"]["enum"],
            ["hhm-flutter", "hhm-desktop-app.rs"],
        )
        validate_handshake_request(self.fixture["handshake_request"], now=self.now)
        session = validate_handshake_material(
            self.fixture["handshake_request"],
            self.fixture["handshake_response"],
            now=self.now,
            local_installation_id="desktop-installation",
            peer_installation_id="flutter-installation",
            requester_attestation_valid=True,
            responder_attestation_valid=True,
            transcript_signature_valid=True,
        )
        self.assertIsInstance(session, NegotiatedPeerSession)
        PeerEnvelope.from_wire(self.fixture["encrypted_envelope"])
        SignedUpdateManifest.from_wire(self.fixture["signed_update_manifest"])

    def test_accepted_and_rejected_handshake_material_are_distinct(self) -> None:
        accepted = validate_handshake_material(
            self.fixture["handshake_request"],
            self.fixture["handshake_response"],
            now=self.now,
            local_installation_id="desktop-installation",
            peer_installation_id="flutter-installation",
            requester_attestation_valid=True,
            responder_attestation_valid=True,
            transcript_signature_valid=True,
        )
        self.assertIsNotNone(accepted)
        rejected = {
            "protocol_version": "hhm.p2p.v1",
            "session_id": self.fixture["handshake_request"]["session_id"],
            "offer_id": self.fixture["handshake_request"]["offer_id"],
            "decision": "rejected",
            "selected_capabilities": [],
            "rejection_code": "consent_declined",
            "expires_at": self.fixture["handshake_request"]["expires_at"],
        }
        self.assertIsNone(
            validate_handshake_material(
                self.fixture["handshake_request"],
                rejected,
                now=self.now,
                local_installation_id="desktop-installation",
                peer_installation_id="flutter-installation",
                requester_attestation_valid=False,
                responder_attestation_valid=False,
                transcript_signature_valid=False,
            )
        )

    def test_handshake_request_rejects_malformed_or_expired_material(self) -> None:
        variants = []
        for field, value in (
            ("protocol_version", "hhm.p2p.v2"),
            ("challenge_nonce", "short"),
            ("ephemeral_public_key", "not+base64url"),
            ("device_key_id", "bad key id"),
            ("device_attestation", "A" * 63),
            ("requested_capabilities", []),
            ("requested_capabilities", ["resident_message", "resident_message"]),
            ("requested_capabilities", ["door_unlock"]),
            ("expires_at", "2026-08-24T18:00:29Z"),
        ):
            candidate = deepcopy(self.fixture["handshake_request"])
            candidate[field] = value
            variants.append(candidate)
        extra = deepcopy(self.fixture["handshake_request"])
        extra["bearer_token"] = "forbidden"
        variants.append(extra)
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(
                HhmBoundaryViolation
            ):
                validate_handshake_request(candidate, now=self.now)

    def test_accepted_handshake_requires_material_and_a_selected_capability(self) -> None:
        variants = []
        empty = deepcopy(self.fixture["handshake_response"])
        empty["selected_capabilities"] = []
        variants.append(empty)
        missing_signature = deepcopy(self.fixture["handshake_response"])
        del missing_signature["transcript_signature"]
        variants.append(missing_signature)
        unrequested = deepcopy(self.fixture["handshake_response"])
        unrequested["selected_capabilities"] = ["contact_card"]
        variants.append(unrequested)
        mismatch = deepcopy(self.fixture["handshake_response"])
        mismatch["session_id"] = "2f50b35a-e1fc-4bb2-a732-5701f144135a"
        variants.append(mismatch)
        for response in variants:
            with self.subTest(response=response), self.assertRaises(
                HhmBoundaryViolation
            ):
                validate_handshake_material(
                    self.fixture["handshake_request"],
                    response,
                    now=self.now,
                    local_installation_id="desktop-installation",
                    peer_installation_id="flutter-installation",
                    requester_attestation_valid=True,
                    responder_attestation_valid=True,
                    transcript_signature_valid=True,
                )
        with self.assertRaises(HhmBoundaryViolation):
            validate_handshake_material(
                self.fixture["handshake_request"],
                self.fixture["handshake_response"],
                now=self.now,
                local_installation_id="desktop-installation",
                peer_installation_id="flutter-installation",
                requester_attestation_valid=True,
                responder_attestation_valid=False,
                transcript_signature_valid=True,
            )

    def test_envelope_wire_bounds_accept_edges_and_reject_overflow(self) -> None:
        for field, value in (
            ("sequence", 0),
            ("sequence", 4294967295),
            ("nonce", "N" * 16),
            ("nonce", "N" * 64),
            ("ciphertext", "C"),
            ("ciphertext", "C" * 87384),
        ):
            candidate = deepcopy(self.fixture["encrypted_envelope"])
            candidate[field] = value
            PeerEnvelope.from_wire(candidate)
        for field, value in (
            ("sequence", -1),
            ("sequence", 4294967296),
            ("nonce", "N" * 15),
            ("nonce", "N" * 65),
            ("nonce", "invalid+nonce"),
            ("ciphertext", ""),
            ("ciphertext", "C" * 87385),
            ("payload_type", "hhm.door-unlock.v1"),
        ):
            candidate = deepcopy(self.fixture["encrypted_envelope"])
            candidate[field] = value
            with self.subTest(field=field, length=len(value) if isinstance(value, str) else value), self.assertRaises(
                HhmBoundaryViolation
            ):
                PeerEnvelope.from_wire(candidate)


class BlePeerSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        _, fixture, _ = load_pinned_peer_contract(Path("."))
        self.fixture = fixture
        self.now = datetime(2026, 8, 24, 18, 0, 30, tzinfo=timezone.utc)
        session = validate_handshake_material(
            fixture["handshake_request"],
            fixture["handshake_response"],
            now=self.now,
            local_installation_id="desktop-installation",
            peer_installation_id="flutter-installation",
            requester_attestation_valid=True,
            responder_attestation_valid=True,
            transcript_signature_valid=True,
        )
        assert session is not None
        self.session = session
        self.gate = BlePeerGate(
            local_installation_id="desktop-installation",
            house_id="house-medellin",
        )
        self.certificate = PeerCertificate(
            installation_id="flutter-installation",
            peer_key_id="device:example-1",
            house_id="house-medellin",
            expires_at=self.now + timedelta(minutes=10),
            backend_signature_valid=True,
        )
        self.consent = SharingConsent(
            enabled=True,
            allowed_peer_installations=frozenset({"flutter-installation"}),
            allowed_capabilities=frozenset({"resident_message", "update_manifest"}),
        )
        self.envelope = PeerEnvelope.from_wire(fixture["encrypted_envelope"])

    def test_backend_certified_peer_with_explicit_consent_is_accepted(self) -> None:
        self.gate.accept(
            certificate=self.certificate,
            consent=self.consent,
            session=self.session,
            envelope=self.envelope,
            now=self.now,
            aead_valid=True,
        )

    def test_replay_and_out_of_order_messages_fail_closed(self) -> None:
        self.gate.accept(
            certificate=self.certificate,
            consent=self.consent,
            session=self.session,
            envelope=self.envelope,
            now=self.now,
            aead_valid=True,
        )
        with self.assertRaises(HhmBoundaryViolation):
            self.gate.accept(
                certificate=self.certificate,
                consent=self.consent,
                session=self.session,
                envelope=self.envelope,
                now=self.now,
                aead_valid=True,
            )
        reordered = replace(
            self.envelope,
            message_id="08b3cd7d-c3fe-4ca0-9505-e3382ec352c4",
            nonce="fedcba9876543210fedcba",
            sequence=1,
        )
        with self.assertRaises(HhmBoundaryViolation):
            self.gate.accept(
                certificate=self.certificate,
                consent=self.consent,
                session=self.session,
                envelope=reordered,
                now=self.now,
                aead_valid=True,
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
                    session=self.session,
                    envelope=self.envelope,
                    now=self.now,
                    aead_valid=True,
                )

    def test_peer_messages_are_session_capability_and_credential_bound(self) -> None:
        variants = [
            replace(self.envelope, sender_key_id="device:unbound-key"),
            replace(self.envelope, session_id="2f50b35a-e1fc-4bb2-a732-5701f144135a"),
            replace(self.envelope, created_at=self.now + timedelta(seconds=1)),
            replace(self.envelope, expires_at=self.now),
            replace(
                self.envelope,
                created_at=self.now - timedelta(minutes=6),
                expires_at=self.now + timedelta(seconds=1),
            ),
        ]
        for envelope in variants:
            with self.subTest(envelope=envelope), self.assertRaises(HhmBoundaryViolation):
                self.gate.accept(
                    certificate=self.certificate,
                    consent=self.consent,
                    session=self.session,
                    envelope=envelope,
                    now=self.now,
                    aead_valid=True,
                )
        for consent, session, aead_valid, contains_credential in (
            (replace(self.consent, enabled=False), self.session, True, False),
            (
                replace(self.consent, allowed_capabilities=frozenset({"resident_message"})),
                self.session,
                True,
                False,
            ),
            (self.consent, replace(self.session, local_installation_id="other-installation"), True, False),
            (self.consent, self.session, False, False),
            (self.consent, self.session, True, True),
        ):
            with self.subTest(consent=consent, session=session), self.assertRaises(
                HhmBoundaryViolation
            ):
                self.gate.accept(
                    certificate=self.certificate,
                    consent=consent,
                    session=session,
                    envelope=self.envelope,
                    now=self.now,
                    aead_valid=aead_valid,
                    decrypted_payload_contains_credential=contains_credential,
                )

    def test_peer_transport_cannot_authorize_an_app_update(self) -> None:
        update = b"synthetic signed Flutter application artifact"
        wire = deepcopy(self.fixture["signed_update_manifest"])
        wire["artifact_size"] = len(update)
        wire["artifact_sha256"] = hashlib.sha256(update).hexdigest()
        manifest = SignedUpdateManifest.from_wire(wire)
        verify_peer_delivered_update(
            manifest,
            update,
            expected_app_id="hhm-flutter",
            expected_platform="android",
            expected_channel="stable",
            installed_version="1.2.2",
            installed_anti_rollback_counter=6,
            allowed_release_hosts={"releases.example.invalid"},
            canonical_release_signature_valid=True,
        )
        invalid_checks = (
            (replace(manifest, version="1.2.2"), True, {"releases.example.invalid"}),
            (replace(manifest, anti_rollback_counter=6), True, {"releases.example.invalid"}),
            (replace(manifest, artifact_sha256="0" * 64), True, {"releases.example.invalid"}),
            (replace(manifest, artifact_url="http://releases.example.invalid/app"), True, {"releases.example.invalid"}),
            (manifest, False, {"releases.example.invalid"}),
            (manifest, True, {"other.example.invalid"}),
        )
        for invalid, signature_valid, hosts in invalid_checks:
            with self.subTest(manifest=invalid), self.assertRaises(HhmBoundaryViolation):
                verify_peer_delivered_update(
                    invalid,
                    update,
                    expected_app_id="hhm-flutter",
                    expected_platform="android",
                    expected_channel="stable",
                    installed_version="1.2.2",
                    installed_anti_rollback_counter=6,
                    allowed_release_hosts=hosts,
                    canonical_release_signature_valid=signature_valid,
                )

    def test_update_manifest_wire_shape_requires_https_digest_and_exact_app_id(self) -> None:
        SignedUpdateManifest.from_wire(self.fixture["signed_update_manifest"])
        for field, value in (
            ("app_id", "hhm-desktop-app"),
            ("app_id", "hhm-desktop.rs"),
            ("artifact_url", "http://releases.example.invalid/app"),
            ("artifact_sha256", "A" * 64),
            ("artifact_sha256", "a" * 63),
            ("anti_rollback_counter", 0),
            ("artifact_size", 0),
            ("artifact_size", 2147483649),
            ("signature", "S" * 63),
            ("channel", "development"),
            ("version", "version-1"),
        ):
            wire = deepcopy(self.fixture["signed_update_manifest"])
            wire[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(
                HhmBoundaryViolation
            ):
                SignedUpdateManifest.from_wire(wire)

    def test_desktop_update_uses_the_same_canonical_release_boundary(self) -> None:
        update = b"synthetic desktop application artifact"
        wire = deepcopy(self.fixture["signed_update_manifest"])
        wire.update(
            {
                "app_id": "hhm-desktop-app.rs",
                "platform": "linux",
                "version": "2.0.0",
                "anti_rollback_counter": 9,
                "artifact_size": len(update),
                "artifact_sha256": hashlib.sha256(update).hexdigest(),
                "artifact_url": "https://releases.example.invalid/hhm-desktop-app.rs-2.0.0",
            }
        )
        manifest = SignedUpdateManifest.from_wire(wire)
        verify_peer_delivered_update(
            manifest,
            update,
            expected_app_id="hhm-desktop-app.rs",
            expected_platform="linux",
            expected_channel="stable",
            installed_version="1.9.9",
            installed_anti_rollback_counter=8,
            allowed_release_hosts={"releases.example.invalid"},
            canonical_release_signature_valid=True,
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
