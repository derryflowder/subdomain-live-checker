from collections.abc import Callable

from src.discovery_models import DiscoverySourceResult

DiscoveryFunction = Callable[[str], DiscoverySourceResult]


def aggregate_discovery(
    domain: str,
    sources: list[DiscoveryFunction],
) -> tuple[list[str], list[DiscoverySourceResult]]:
    """Run discovery sources independently and merge their hostnames."""
    results: list[DiscoverySourceResult] = []
    hostnames: set[str] = set()

    for source in sources:
        try:
            result = source(domain)
        except Exception as exc:
            result = DiscoverySourceResult(
                source=getattr(source, "__name__", "unknown"),
                hostnames=[],
                error=str(exc),
            )

        results.append(result)
        hostnames.update(result.hostnames)

    return sorted(hostnames), results
