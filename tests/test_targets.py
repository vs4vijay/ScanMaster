import pytest

from scanmaster.domain.scanners import TargetKind
from scanmaster.domain.targets import Target


@pytest.mark.parametrize(
    ("value", "kind", "canonical"),
    [
        ("HTTPS://Example.COM:443/path#fragment", TargetKind.URL, "https://example.com/path"),
        ("Example.COM.", TargetKind.HOSTNAME, "example.com"),
        ("192.0.2.1", TargetKind.IP_ADDRESS, "192.0.2.1"),
        ("192.0.2.7/24", TargetKind.CIDR, "192.0.2.0/24"),
        ("api-spec:openapi.json", TargetKind.API_SPECIFICATION, "openapi.json"),
    ],
)
def test_target_canonicalization(value: str, kind: TargetKind, canonical: str) -> None:
    target = Target.parse(value)
    assert target.kind is kind
    assert target.canonical == canonical
