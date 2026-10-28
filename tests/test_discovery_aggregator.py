from src.discovery_aggregator import aggregate_discovery
from src.discovery_models import DiscoverySourceResult


def test_aggregate_discovery_merges_and_deduplicates() -> None:
    def source_one(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_one",
            hostnames=["api.example.com", "www.example.com"],
        )

    def source_two(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="source_two",
            hostnames=["www.example.com", "mail.example.com"],
        )

    hostnames, results = aggregate_discovery(
        "example.com",
        [source_one, source_two],
    )

    assert hostnames == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]
    assert len(results) == 2


def test_aggregate_discovery_continues_after_source_failure() -> None:
    def failing_source(domain: str) -> DiscoverySourceResult:
        raise RuntimeError("temporary failure")

    def working_source(domain: str) -> DiscoverySourceResult:
        return DiscoverySourceResult(
            source="working_source",
            hostnames=["api.example.com"],
        )

    hostnames, results = aggregate_discovery(
        "example.com",
        [failing_source, working_source],
    )

    assert hostnames == ["api.example.com"]
    assert len(results) == 2
    assert results[0].error == "temporary failure"
    assert results[1].error is None