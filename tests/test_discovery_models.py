from src.discovery_models import DiscoverySourceResult


def test_discovery_source_result_stores_success() -> None:
    result = DiscoverySourceResult(
        source="crt.name",
        hostnames=["api.example.com", "mail.example.com"],
    )

    assert result.source == "crt.name"
    assert result.hostnames == [
        "api.example.com",
        "mail.example.com",
    ]
    assert result.error is None


def test_discovery_source_result_stores_error() -> None:
    result = DiscoverySourceResult(
        source="crt.sh",
        hostnames=[],
        error="Certificate discovery timed out.",
    )

    assert result.source == "crt.sh"
    assert result.hostnames == []
    assert result.error == "Certificate discovery timed out."