from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


class HhmBoundaryViolation(ValueError):
    pass


class AuthorityVerdict(str, Enum):
    AUTHENTICATED = "authenticated"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


class AuthOutcome(str, Enum):
    AUTHENTICATED = "authenticated"
    ANONYMOUS = "anonymous"
    UNAUTHENTICATED = "unauthenticated"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class VerifiedIdentity:
    provider: str
    provider_tenant: str
    provider_subject: str

    @property
    def product_key(self) -> tuple[str, str, str]:
        return (self.provider, self.provider_tenant, self.provider_subject)


def combine_dual_auth(
    *, credential_present: bool, verdicts: Iterable[AuthorityVerdict]
) -> AuthOutcome:
    """Models the official guard result without reimplementing token validation."""

    results = tuple(verdicts)
    if not credential_present:
        return AuthOutcome.ANONYMOUS
    if AuthorityVerdict.AUTHENTICATED in results:
        return AuthOutcome.AUTHENTICATED
    if len(results) >= 2 and all(result is AuthorityVerdict.INVALID for result in results):
        return AuthOutcome.UNAUTHENTICATED
    return AuthOutcome.DEGRADED


def authorize_product_identity(
    identity: VerifiedIdentity,
    allowed_identities: set[tuple[str, str, str]],
) -> None:
    """HHM authorization uses only the exact verified provider identity tuple."""

    components = identity.product_key
    if any(
        not component
        or component != component.strip()
        or "|" in component
        or any(ord(character) < 32 or ord(character) == 127 for character in component)
        for component in components
    ):
        raise HhmBoundaryViolation("verified identity tuple is malformed")
    if components not in allowed_identities:
        raise HhmBoundaryViolation("identity is not authorized by HHM product policy")


@dataclass(frozen=True)
class PeerCertificate:
    installation_id: str
    peer_key_id: str
    house_id: str
    expires_at: datetime
    backend_signature_valid: bool
    revoked: bool = False


@dataclass(frozen=True)
class PeerEnvelope:
    protocol_version: str
    session_id: str
    message_id: str
    sequence: int
    payload_type: str
    nonce: str
    ciphertext: str
    sender_key_id: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> PeerEnvelope:
        required = {
            "protocol_version",
            "session_id",
            "message_id",
            "sequence",
            "payload_type",
            "nonce",
            "ciphertext",
            "sender_key_id",
            "created_at",
            "expires_at",
        }
        _require_exact_fields(value, required, "encrypted envelope")
        protocol_version = _bounded_string(value["protocol_version"], 1, 32, "protocol")
        if protocol_version != P2P_PROTOCOL:
            raise HhmBoundaryViolation("unsupported peer protocol")
        session_id = _canonical_uuid(value["session_id"], "session_id")
        message_id = _canonical_uuid(value["message_id"], "message_id")
        sequence = value["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 4294967295:
            raise HhmBoundaryViolation("envelope sequence is outside the schema boundary")
        payload_type = _bounded_string(value["payload_type"], 1, 64, "payload_type")
        if payload_type not in PAYLOAD_TYPES:
            raise HhmBoundaryViolation("unknown peer payload type")
        nonce = _base64url(value["nonce"], 16, 64, "nonce")
        ciphertext = _base64url(value["ciphertext"], 1, 87384, "ciphertext")
        sender_key_id = _key_id(value["sender_key_id"], "sender_key_id")
        return cls(
            protocol_version=protocol_version,
            session_id=session_id,
            message_id=message_id,
            sequence=sequence,
            payload_type=payload_type,
            nonce=nonce,
            ciphertext=ciphertext,
            sender_key_id=sender_key_id,
            created_at=_utc_timestamp(value["created_at"], "created_at"),
            expires_at=_utc_timestamp(value["expires_at"], "expires_at"),
        )


@dataclass(frozen=True)
class NegotiatedPeerSession:
    session_id: str
    local_installation_id: str
    peer_installation_id: str
    peer_key_id: str
    selected_capabilities: frozenset[str]
    expires_at: datetime


@dataclass(frozen=True)
class SharingConsent:
    enabled: bool
    allowed_peer_installations: frozenset[str]
    allowed_capabilities: frozenset[str]


P2P_PROTOCOL = "hhm.p2p.v1"
CAPABILITIES = frozenset(
    {"resident_message", "contact_card", "file_manifest", "update_manifest"}
)
PAYLOAD_TYPES = frozenset(
    {
        "hhm.resident-message.v1",
        "hhm.contact-card.v1",
        "hhm.file-manifest.v1",
        "hhm.update-manifest.v1",
        "hhm.receipt.v1",
    }
)
PAYLOAD_CAPABILITY = {
    "hhm.resident-message.v1": "resident_message",
    "hhm.contact-card.v1": "contact_card",
    "hhm.file-manifest.v1": "file_manifest",
    "hhm.update-manifest.v1": "update_manifest",
}
REJECTION_CODES = frozenset(
    {
        "consent_declined",
        "expired",
        "replayed",
        "attestation_invalid",
        "capability_denied",
        "rate_limited",
        "unsupported_version",
    }
)
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SEMVER = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def load_pinned_peer_contract(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    vendor = root / "vendor" / "hhm-interfaces"
    provenance = json.loads((vendor / "PROVENANCE.json").read_text(encoding="utf-8"))
    if (
        provenance.get("repository") != "hacker-house-medellin/hhm-interfaces"
        or provenance.get("commit") != "f694bc9b58907db918f0449b5d04a5763f8fa745"
    ):
        raise HhmBoundaryViolation("peer contract provenance is not pinned")
    contents: dict[str, dict[str, Any]] = {}
    expected_files = {
        "fixtures/peer-session.json": {
            "git_blob": "75df4f5435b67d278f8ea19286b192e8eca0cf10",
            "sha256": "cc8c94f006db484196645056878342eccb6ad39c6ec42a77928ff35c6bdc92d8",
        },
        "schemas/peer-session.json": {
            "git_blob": "94e72f5fbf65815f28ba718cabceb93ebf9b744c",
            "sha256": "2e9ab7864a1f3ac991dd76c43b2fec71ad075ba9ea760df1364e5119dde4a965",
        },
    }
    files = provenance.get("files")
    if not isinstance(files, dict) or files != expected_files:
        raise HhmBoundaryViolation("peer contract provenance inventory drifted")
    for relative_path, evidence in files.items():
        path = vendor / relative_path
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(digest, evidence["sha256"]):
            raise HhmBoundaryViolation(f"pinned peer contract digest mismatch: {relative_path}")
        contents[relative_path] = json.loads(raw)
    return (
        contents["schemas/peer-session.json"],
        contents["fixtures/peer-session.json"],
        provenance,
    )


def validate_handshake_request(value: Mapping[str, Any], *, now: datetime) -> None:
    required = {
        "protocol_version",
        "session_id",
        "offer_id",
        "challenge_nonce",
        "ephemeral_public_key",
        "device_key_id",
        "device_attestation",
        "requested_capabilities",
        "expires_at",
    }
    _require_exact_fields(value, required, "handshake request")
    if value["protocol_version"] != P2P_PROTOCOL:
        raise HhmBoundaryViolation("unsupported peer protocol")
    _canonical_uuid(value["session_id"], "session_id")
    _canonical_uuid(value["offer_id"], "offer_id")
    _base64url(value["challenge_nonce"], 22, 86, "challenge_nonce")
    _base64url(value["ephemeral_public_key"], 43, 86, "ephemeral_public_key")
    _key_id(value["device_key_id"], "device_key_id")
    _base64url(value["device_attestation"], 64, 4096, "device_attestation")
    _capability_set(value["requested_capabilities"], minimum=1)
    expires_at = _utc_timestamp(value["expires_at"], "expires_at")
    if expires_at <= now or expires_at - now > timedelta(seconds=60):
        raise HhmBoundaryViolation("handshake request expiry is outside app policy")


def validate_handshake_material(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    now: datetime,
    local_installation_id: str,
    peer_installation_id: str,
    requester_attestation_valid: bool,
    responder_attestation_valid: bool,
    transcript_signature_valid: bool,
) -> NegotiatedPeerSession | None:
    validate_handshake_request(request, now=now)
    if not isinstance(response, Mapping):
        raise HhmBoundaryViolation("handshake response is not an object")
    common = {
        "protocol_version",
        "session_id",
        "offer_id",
        "decision",
        "selected_capabilities",
        "expires_at",
    }
    decision = response.get("decision")
    if decision == "accepted":
        required = common | {
            "ephemeral_public_key",
            "device_key_id",
            "device_attestation",
            "transcript_signature",
        }
    elif decision == "rejected":
        required = common | {"rejection_code"}
    else:
        raise HhmBoundaryViolation("handshake decision is invalid")
    _require_exact_fields(response, required, "handshake response")
    if response["protocol_version"] != P2P_PROTOCOL:
        raise HhmBoundaryViolation("unsupported peer protocol")
    if response["session_id"] != request["session_id"] or response["offer_id"] != request["offer_id"]:
        raise HhmBoundaryViolation("handshake response is not transcript-bound")
    _canonical_uuid(response["session_id"], "session_id")
    _canonical_uuid(response["offer_id"], "offer_id")
    expires_at = _utc_timestamp(response["expires_at"], "expires_at")
    request_expiry = _utc_timestamp(request["expires_at"], "expires_at")
    if expires_at <= now or expires_at > request_expiry:
        raise HhmBoundaryViolation("handshake response expiry is not request-bound")
    selected = _capability_set(
        response["selected_capabilities"], minimum=1 if decision == "accepted" else 0
    )
    requested = _capability_set(request["requested_capabilities"], minimum=1)
    if not selected.issubset(requested):
        raise HhmBoundaryViolation("response selected an unrequested capability")
    if decision == "rejected":
        if selected or response["rejection_code"] not in REJECTION_CODES:
            raise HhmBoundaryViolation("rejected handshake material is invalid")
        return None
    _base64url(response["ephemeral_public_key"], 43, 86, "ephemeral_public_key")
    _key_id(response["device_key_id"], "device_key_id")
    _base64url(response["device_attestation"], 64, 4096, "device_attestation")
    _base64url(response["transcript_signature"], 64, 512, "transcript_signature")
    if not (
        requester_attestation_valid
        and responder_attestation_valid
        and transcript_signature_valid
    ):
        raise HhmBoundaryViolation("handshake cryptographic material did not verify")
    return NegotiatedPeerSession(
        session_id=str(request["session_id"]),
        local_installation_id=local_installation_id,
        peer_installation_id=peer_installation_id,
        peer_key_id=str(request["device_key_id"]),
        selected_capabilities=selected,
        expires_at=expires_at,
    )


class BlePeerGate:
    MAX_LIFETIME = timedelta(minutes=5)

    def __init__(self, *, local_installation_id: str, house_id: str) -> None:
        self._local_installation_id = local_installation_id
        self._house_id = house_id
        self._seen_nonces: set[tuple[str, str]] = set()
        self._seen_messages: set[tuple[str, str]] = set()
        self._last_sequence: dict[tuple[str, str], int] = {}

    def accept(
        self,
        *,
        certificate: PeerCertificate,
        consent: SharingConsent,
        session: NegotiatedPeerSession,
        envelope: PeerEnvelope,
        now: datetime,
        aead_valid: bool,
        decrypted_payload_contains_credential: bool = False,
    ) -> None:
        if not consent.enabled:
            raise HhmBoundaryViolation("peer sharing is not enabled")
        if (
            certificate.revoked
            or not certificate.backend_signature_valid
            or certificate.expires_at < now
            or certificate.house_id != self._house_id
            or certificate.installation_id != session.peer_installation_id
            or certificate.peer_key_id != session.peer_key_id
            or envelope.sender_key_id != session.peer_key_id
            or certificate.installation_id not in consent.allowed_peer_installations
        ):
            raise HhmBoundaryViolation("peer certificate is not trusted for this house")
        if (
            session.local_installation_id != self._local_installation_id
            or session.session_id != envelope.session_id
            or session.expires_at <= now
            or not aead_valid
            or decrypted_payload_contains_credential
        ):
            raise HhmBoundaryViolation("peer envelope violates the trust boundary")
        capability = PAYLOAD_CAPABILITY.get(envelope.payload_type)
        if capability is not None and (
            capability not in session.selected_capabilities
            or capability not in consent.allowed_capabilities
        ):
            raise HhmBoundaryViolation("peer payload capability was not negotiated")
        if (
            envelope.created_at > now
            or envelope.expires_at <= now
            or envelope.expires_at - envelope.created_at > self.MAX_LIFETIME
        ):
            raise HhmBoundaryViolation("peer envelope timing or size is invalid")

        nonce_key = (certificate.installation_id, envelope.nonce)
        message_key = (certificate.installation_id, envelope.message_id)
        sequence_key = (certificate.installation_id, envelope.session_id)
        if nonce_key in self._seen_nonces or message_key in self._seen_messages:
            raise HhmBoundaryViolation("peer message replay detected")
        if envelope.sequence <= self._last_sequence.get(sequence_key, -1):
            raise HhmBoundaryViolation("peer sequence replay or reordering detected")
        self._seen_nonces.add(nonce_key)
        self._seen_messages.add(message_key)
        self._last_sequence[sequence_key] = envelope.sequence


@dataclass(frozen=True)
class SignedUpdateManifest:
    schema: str
    app_id: str
    platform: str
    channel: str
    version: str
    anti_rollback_counter: int
    artifact_size: int
    artifact_sha256: str
    artifact_url: str
    signing_key_id: str
    signature: str
    published_at: datetime

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> SignedUpdateManifest:
        required = {
            "schema",
            "app_id",
            "platform",
            "channel",
            "version",
            "anti_rollback_counter",
            "artifact_size",
            "artifact_sha256",
            "artifact_url",
            "signing_key_id",
            "signature",
            "published_at",
        }
        _require_exact_fields(value, required, "signed update manifest")
        schema = _bounded_string(value["schema"], 1, 64, "schema")
        app_id = _bounded_string(value["app_id"], 1, 64, "app_id")
        platform = _bounded_string(value["platform"], 1, 32, "platform")
        channel = _bounded_string(value["channel"], 1, 16, "channel")
        version = _bounded_string(value["version"], 1, 128, "version")
        counter = value["anti_rollback_counter"]
        artifact_size = value["artifact_size"]
        artifact_sha256 = _bounded_string(value["artifact_sha256"], 64, 64, "artifact_sha256")
        artifact_url = _bounded_string(value["artifact_url"], 1, 4096, "artifact_url")
        if (
            schema != "hhm.update-manifest.v1"
            or app_id not in {"hhm-flutter", "hhm-desktop-app.rs"}
            or platform not in {"android", "ios", "linux", "macos", "windows", "web"}
            or channel not in {"stable", "beta"}
            or _SEMVER.fullmatch(version) is None
            or isinstance(counter, bool)
            or not isinstance(counter, int)
            or not 1 <= counter <= 9007199254740991
            or isinstance(artifact_size, bool)
            or not isinstance(artifact_size, int)
            or not 1 <= artifact_size <= 2147483648
            or _SHA256.fullmatch(artifact_sha256) is None
        ):
            raise HhmBoundaryViolation("signed update manifest violates the schema")
        parsed_url = urllib.parse.urlsplit(artifact_url)
        if parsed_url.scheme != "https" or not parsed_url.hostname:
            raise HhmBoundaryViolation("update artifact URL must use HTTPS")
        signing_key_id = _key_id(value["signing_key_id"], "signing_key_id")
        signature = _base64url(value["signature"], 64, 512, "signature")
        return cls(
            schema=schema,
            app_id=app_id,
            platform=platform,
            channel=channel,
            version=version,
            anti_rollback_counter=counter,
            artifact_size=artifact_size,
            artifact_sha256=artifact_sha256,
            artifact_url=artifact_url,
            signing_key_id=signing_key_id,
            signature=signature,
            published_at=_utc_timestamp(value["published_at"], "published_at"),
        )


def verify_peer_delivered_update(
    manifest: SignedUpdateManifest,
    artifact: bytes,
    *,
    expected_app_id: str,
    expected_platform: str,
    expected_channel: str,
    installed_version: str,
    installed_anti_rollback_counter: int,
    allowed_release_hosts: set[str],
    canonical_release_signature_valid: bool,
    maximum_payload_bytes: int = 256 * 1024 * 1024,
) -> None:
    """A BLE peer may transport an update but cannot authorize or sign it."""

    parsed_url = urllib.parse.urlsplit(manifest.artifact_url)
    if (
        manifest.app_id != expected_app_id
        or manifest.platform != expected_platform
        or manifest.channel != expected_channel
        or _semver_key(manifest.version) <= _semver_key(installed_version)
        or manifest.anti_rollback_counter <= installed_anti_rollback_counter
        or manifest.artifact_size != len(artifact)
        or manifest.artifact_size > maximum_payload_bytes
        or parsed_url.scheme != "https"
        or parsed_url.hostname not in allowed_release_hosts
        or parsed_url.username is not None
        or parsed_url.password is not None
        or bool(parsed_url.query)
        or bool(parsed_url.fragment)
        or not canonical_release_signature_valid
    ):
        raise HhmBoundaryViolation("update manifest is not authorized")
    digest = hashlib.sha256(artifact).hexdigest()
    if not hmac.compare_digest(manifest.artifact_sha256, digest):
        raise HhmBoundaryViolation("update payload digest mismatch")


def _require_exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise HhmBoundaryViolation(f"{label} fields do not match the wire contract")


def _bounded_string(value: Any, minimum: int, maximum: int, label: str) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise HhmBoundaryViolation(f"{label} is outside the string boundary")
    return value


def _base64url(value: Any, minimum: int, maximum: int, label: str) -> str:
    text = _bounded_string(value, minimum, maximum, label)
    if _BASE64URL.fullmatch(text) is None:
        raise HhmBoundaryViolation(f"{label} is not unpadded base64url")
    return text


def _key_id(value: Any, label: str) -> str:
    text = _bounded_string(value, 1, 128, label)
    if _KEY_ID.fullmatch(text) is None:
        raise HhmBoundaryViolation(f"{label} is malformed")
    return text


def _canonical_uuid(value: Any, label: str) -> str:
    text = _bounded_string(value, 36, 36, label)
    try:
        parsed = uuid.UUID(text)
    except ValueError as error:
        raise HhmBoundaryViolation(f"{label} is not a UUID") from error
    if str(parsed) != text:
        raise HhmBoundaryViolation(f"{label} is not canonical")
    return text


def _utc_timestamp(value: Any, label: str) -> datetime:
    text = _bounded_string(value, 20, 35, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise HhmBoundaryViolation(f"{label} is not an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise HhmBoundaryViolation(f"{label} must be UTC")
    return parsed.astimezone(timezone.utc)


def _capability_set(value: Any, *, minimum: int) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= 4
        or any(not isinstance(item, str) or item not in CAPABILITIES for item in value)
        or len(set(value)) != len(value)
    ):
        raise HhmBoundaryViolation("capability selection violates the schema")
    return frozenset(value)


def _semver_key(value: str) -> tuple[int, int, int, int, str]:
    matched = _SEMVER.fullmatch(value)
    if matched is None:
        raise HhmBoundaryViolation("version is not compatible semver")
    major, minor, patch, prerelease = matched.groups()
    return (int(major), int(minor), int(patch), 1 if prerelease is None else 0, prerelease or "")


def validate_inert_component(
    headers: Mapping[str, str], body: str, *, maximum_body_bytes: int = 64 * 1024
) -> None:
    normalized = {name.lower(): value for name, value in headers.items()}
    required = {
        "x-hhm-component-contract": "hhm.component.v1",
        "cache-control": "private, no-store",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
    }
    if any(normalized.get(name) != expected for name, expected in required.items()):
        raise HhmBoundaryViolation("component security headers are incomplete")
    if not normalized.get("content-type", "").lower().startswith("text/html"):
        raise HhmBoundaryViolation("component is not HTML")
    csp = normalized.get("content-security-policy", "")
    for directive in (
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "object-src 'none'",
        "sandbox",
    ):
        if directive not in csp:
            raise HhmBoundaryViolation("component CSP is not inert")
    if len(body.encode("utf-8")) > maximum_body_bytes:
        raise HhmBoundaryViolation("component body exceeds the client boundary")
    executable_markup = re.compile(
        r"(?is)<\s*(script|iframe|object|embed)\b|\bon[a-z]+\s*=|javascript\s*:"
    )
    if executable_markup.search(body):
        raise HhmBoundaryViolation("component contains executable markup")


def websocket_origin_matches_host(
    *, host_headers: Sequence[str], origin_headers: Sequence[str]
) -> bool:
    if len(host_headers) != 1 or len(origin_headers) != 1:
        return False
    host, origin = host_headers[0], origin_headers[0]
    if not host or "@" in host or origin == "null":
        return False
    try:
        host_uri = urllib.parse.urlsplit(f"//{host}")
        origin_uri = urllib.parse.urlsplit(origin)
        host_port = host_uri.port
        origin_port = origin_uri.port
    except ValueError:
        return False
    if (
        origin_uri.scheme.lower() not in {"http", "https"}
        or origin_uri.username is not None
        or origin_uri.password is not None
        or not host_uri.hostname
        or not origin_uri.hostname
        or origin_uri.path not in {"", "/"}
        or origin_uri.query
        or origin_uri.fragment
        or host_uri.hostname.lower() != origin_uri.hostname.lower()
    ):
        return False
    default_port = 80 if origin_uri.scheme.lower() == "http" else 443
    return (host_port or default_port) == (origin_port or default_port)


def validate_websocket_sizes(*, frame_bytes: int, message_bytes: int) -> None:
    if (
        frame_bytes < 0
        or message_bytes < 0
        or frame_bytes > 8 * 1024
        or message_bytes > 16 * 1024
        or frame_bytes > message_bytes
    ):
        raise HhmBoundaryViolation("WebSocket frame or message exceeds the boundary")


_ENCRYPTED_VALUE = re.compile(r"^ENC\[AES256_GCM,.+\]$")
_AGE_RECIPIENT = re.compile(r"^age1[a-z0-9]{20,}$")
_PRIVATE_KEY_MARKER = re.compile(r"BEGIN (?:AGE |[A-Z ]*)PRIVATE KEY")


def audit_sops_environment(content: str, *, minimum_recipients: int = 2) -> None:
    if _PRIVATE_KEY_MARKER.search(content):
        raise HhmBoundaryViolation("private key material is forbidden")
    recipients: set[str] = set()
    found_mac = False
    found_data = False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise HhmBoundaryViolation("encrypted dotenv line is malformed")
        name, value = stripped.split("=", 1)
        if name.startswith("sops_age__") and name.endswith("__map_recipient"):
            if not _AGE_RECIPIENT.fullmatch(value):
                raise HhmBoundaryViolation("SOPS age recipient is malformed")
            recipients.add(value)
        elif name == "sops_mac":
            if not _ENCRYPTED_VALUE.fullmatch(value):
                raise HhmBoundaryViolation("SOPS MAC is missing or plaintext")
            found_mac = True
        elif not name.startswith("sops_"):
            if not _ENCRYPTED_VALUE.fullmatch(value):
                raise HhmBoundaryViolation(f"{name} is not ciphertext")
            found_data = True
    if not found_data or not found_mac or len(recipients) < minimum_recipients:
        raise HhmBoundaryViolation("SOPS document is incomplete")


def audit_secret_paths(paths: Iterable[str]) -> None:
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        lowered = tuple(part.lower() for part in path.parts)
        if path.name == ".env.example":
            continue
        if path.name == ".env" or "dec" in lowered or path.suffix in {".agekey", ".key"}:
            raise HhmBoundaryViolation(f"plaintext secret path is tracked: {raw_path}")
        if path.name.lower() in {"keys.txt", "age-keys.txt"}:
            raise HhmBoundaryViolation(f"private key path is tracked: {raw_path}")
