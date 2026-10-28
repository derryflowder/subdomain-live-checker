from src.crt_name import discover_from_crt_name
from src.discovery import discover_from_crtsh
from src.discovery_models import DiscoverySourceResult
from src.discovery_sources import discover_from_all_sources, get_discovery_sources


def test_get_discovery_sources_contains_crt_sources() -> None:
    sources = get_discovery_sources()

    assert discover_from_crtsh in sources
    assert discover_from_crt_name in sources


def test_discover_from_all_sources(monkeypatch) -> None:
    def fake_source_one(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_one",
            hostnames=["api.example.com"],
        )

    def fake_source_two(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_two",
            hostnames=["mail.example.com"],
        )

    monkeypatch.setattr(
        "src.discovery_sources.get_discovery_sources",
        lambda: [fake_source_one, fake_source_two],
    )

    hostnames, results = discover_from_all_sources("example.com")

    assert hostnames == [
        "api.example.com",
        "mail.example.com",
    ]
    assert len(results) == 2


def test_discover_from_all_sources_filters_invalid_hostnames(monkeypatch) -> None:
    def fake_source(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_one",
            hostnames=[
                "api.example.com",
                "example.com",
                "other.example.net",
                "*.example.com",
            ],
        )

    monkeypatch.setattr(
        "src.discovery_sources.get_discovery_sources",
        lambda: [fake_source],
    )

    hostnames, results = discover_from_all_sources("example.com")

    assert hostnames == ["api.example.com"]
    assert len(results) == 1

def test_discover_from_all_sources_limits_hostnames(monkeypatch) -> None:
    def fake_source(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_one",
            hostnames=[f"host{i}.example.com" for i in range(600)],
        )

    monkeypatch.setattr(
        "src.discovery_sources.get_discovery_sources",
        lambda: [fake_source],
    )

    hostnames, _ = discover_from_all_sources("example.com")

    assert len(hostnames) == 500
    assert set(hostnames).issubset(
        {f"host{i}.example.com" for i in range(600)}
    )