from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from scanmaster.domain.scanners import TargetKind


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    value: str
    canonical: str

    @classmethod
    def parse(cls, value: str) -> Target:
        raw = value.strip()
        if not raw:
            raise ValueError("target must not be empty")
        if raw.startswith("api-spec:"):
            specification = raw.removeprefix("api-spec:").strip()
            if not specification:
                raise ValueError("API specification target must include a path or URL")
            return cls(TargetKind.API_SPECIFICATION, specification, specification)
        parsed = urlsplit(raw)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            host = parsed.hostname.lower()
            port = parsed.port
            default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
            authority = host if port is None or default_port else f"{host}:{port}"
            path = parsed.path or "/"
            canonical = urlunsplit((parsed.scheme.lower(), authority, path, parsed.query, ""))
            return cls(TargetKind.URL, raw, canonical)
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            if "/" in raw or any(character.isspace() for character in raw):
                raise ValueError(f"invalid target: {raw}") from None
            return cls(TargetKind.HOSTNAME, raw, raw.rstrip(".").lower())
        if network.prefixlen == network.max_prefixlen:
            return cls(TargetKind.IP_ADDRESS, raw, str(network.network_address))
        return cls(TargetKind.CIDR, raw, str(network))
