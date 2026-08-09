from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import PurePosixPath


class BoundaryViolation(ValueError):
    pass


def normalize_relative_path(value: str) -> str:
    decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    if not decoded or "\x00" in decoded or "\\" in decoded or decoded.startswith("/"):
        raise BoundaryViolation("path must be a non-empty relative POSIX path")
    parts = PurePosixPath(decoded).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise BoundaryViolation("path traversal segment is forbidden")
    normalized = "/".join(parts)
    if normalized != decoded:
        raise BoundaryViolation("path normalization changed the request")
    return normalized


def validate_outbound_url(value: str, allowed_hosts: set[str]) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BoundaryViolation("outbound URL must use HTTPS without user info")
    host = parsed.hostname.rstrip(".").lower()
    if host not in {item.rstrip(".").lower() for item in allowed_hosts}:
        raise BoundaryViolation("outbound host is not allowlisted")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        raise BoundaryViolation("non-public IP destinations are forbidden")
    if parsed.fragment:
        raise BoundaryViolation("fragments are not sent upstream")
    return urllib.parse.urlunsplit(parsed)


def redact(value: str) -> str:
    token_pattern = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}")
    bearer_pattern = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+")
    redacted = token_pattern.sub("[REDACTED]", value)
    return bearer_pattern.sub(r"\1[REDACTED]", redacted)


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    roles: frozenset[str]


def authorize_read(principal: Principal, resource_tenant_id: str) -> None:
    if principal.tenant_id != resource_tenant_id:
        raise BoundaryViolation("cross-tenant read is forbidden")
    if not ({"reader", "admin"} & principal.roles):
        raise BoundaryViolation("read role is required")


def sign(secret: bytes, timestamp: int, nonce: str, body: bytes) -> str:
    message = f"{timestamp}.{nonce}.".encode() + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@dataclass
class ReplayWindow:
    max_skew_seconds: int = 300
    seen: dict[str, int] = field(default_factory=dict)

    def verify(
        self,
        secret: bytes,
        timestamp: int,
        nonce: str,
        body: bytes,
        signature: str,
        now: int | None = None,
    ) -> None:
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > self.max_skew_seconds:
            raise BoundaryViolation("signature timestamp is outside the replay window")
        if nonce in self.seen:
            raise BoundaryViolation("nonce replay detected")
        expected = sign(secret, timestamp, nonce, body)
        if not hmac.compare_digest(expected, signature):
            raise BoundaryViolation("signature mismatch")
        self.seen[nonce] = timestamp
        cutoff = current - self.max_skew_seconds
        self.seen = {key: seen_at for key, seen_at in self.seen.items() if seen_at >= cutoff}
