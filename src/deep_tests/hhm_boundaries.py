from __future__ import annotations

import hashlib
import hmac
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Sequence


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
    expires_at: int
    backend_signature_valid: bool
    revoked: bool = False


@dataclass(frozen=True)
class PeerEnvelope:
    protocol: str
    session_id: str
    message_id: str
    nonce: str
    sender_installation_id: str
    signing_key_id: str
    recipient_installation_id: str
    purpose: str
    sequence: int
    issued_at: int
    expires_at: int
    payload_digest: str
    sender_signature_valid: bool
    contains_credential: bool = False


@dataclass(frozen=True)
class SharingConsent:
    enabled: bool
    allowed_peer_installations: frozenset[str]
    allowed_purposes: frozenset[str]


class BlePeerGate:
    PROTOCOL = "hhm.ble-peer.v1"
    MAX_MESSAGE_BYTES = 64 * 1024
    MAX_LIFETIME_SECONDS = 30
    SAFE_PURPOSES = frozenset({"trust_handshake", "data_share", "update_chunk"})

    def __init__(self, *, local_installation_id: str, house_id: str) -> None:
        self._local_installation_id = local_installation_id
        self._house_id = house_id
        self._seen_nonces: set[tuple[str, str]] = set()
        self._last_sequence: dict[tuple[str, str], int] = {}

    def accept(
        self,
        *,
        certificate: PeerCertificate,
        consent: SharingConsent,
        envelope: PeerEnvelope,
        payload: bytes,
        now: int,
    ) -> None:
        if not consent.enabled:
            raise HhmBoundaryViolation("peer sharing is not enabled")
        if (
            certificate.revoked
            or not certificate.backend_signature_valid
            or certificate.expires_at < now
            or certificate.house_id != self._house_id
            or certificate.installation_id != envelope.sender_installation_id
            or certificate.peer_key_id != envelope.signing_key_id
            or certificate.installation_id not in consent.allowed_peer_installations
        ):
            raise HhmBoundaryViolation("peer certificate is not trusted for this house")
        if (
            envelope.protocol != self.PROTOCOL
            or envelope.recipient_installation_id != self._local_installation_id
            or envelope.purpose not in self.SAFE_PURPOSES
            or envelope.purpose not in consent.allowed_purposes
            or envelope.contains_credential
            or not envelope.sender_signature_valid
        ):
            raise HhmBoundaryViolation("peer envelope violates the trust boundary")
        if (
            not envelope.session_id
            or not envelope.message_id
            or len(envelope.nonce) < 16
            or envelope.sequence < 1
            or envelope.issued_at > now
            or envelope.expires_at <= now
            or envelope.expires_at - envelope.issued_at > self.MAX_LIFETIME_SECONDS
            or len(payload) > self.MAX_MESSAGE_BYTES
        ):
            raise HhmBoundaryViolation("peer envelope timing or size is invalid")
        supplied_digest = hashlib.sha256(payload).hexdigest()
        if not hmac.compare_digest(envelope.payload_digest, supplied_digest):
            raise HhmBoundaryViolation("peer payload digest mismatch")

        nonce_key = (certificate.installation_id, envelope.nonce)
        sequence_key = (certificate.installation_id, envelope.session_id)
        if nonce_key in self._seen_nonces:
            raise HhmBoundaryViolation("peer nonce replay detected")
        if envelope.sequence <= self._last_sequence.get(sequence_key, 0):
            raise HhmBoundaryViolation("peer sequence replay or reordering detected")
        self._seen_nonces.add(nonce_key)
        self._last_sequence[sequence_key] = envelope.sequence


@dataclass(frozen=True)
class UpdateManifest:
    application_id: str
    platform: str
    channel: str
    version: int
    payload_size: int
    payload_digest: str
    canonical_release_signature_valid: bool


def verify_peer_delivered_update(
    manifest: UpdateManifest,
    payload: bytes,
    *,
    expected_application_id: str,
    expected_platform: str,
    expected_channel: str,
    installed_version: int,
    maximum_payload_bytes: int = 256 * 1024 * 1024,
) -> None:
    """A BLE peer may transport an update but cannot authorize or sign it."""

    if (
        manifest.application_id != expected_application_id
        or manifest.platform != expected_platform
        or manifest.channel != expected_channel
        or manifest.version <= installed_version
        or manifest.payload_size != len(payload)
        or manifest.payload_size <= 0
        or manifest.payload_size > maximum_payload_bytes
        or not manifest.canonical_release_signature_valid
    ):
        raise HhmBoundaryViolation("update manifest is not authorized")
    digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(manifest.payload_digest, digest):
        raise HhmBoundaryViolation("update payload digest mismatch")


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
