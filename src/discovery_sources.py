from src.crt_name import discover_from_crt_name
from src.discovery import (
    discover_from_crtsh,
    filter_subdomains,
    limit_hostnames,
)
from src.discovery_aggregator import aggregate_discovery


def get_discovery_sources() -> list:
    """Return configured passive discovery sources."""
    return [
        discover_from_crtsh,
        discover_from_crt_name,
    ]


def discover_from_all_sources(
    domain: str,
):
    """Run all configured passive discovery sources."""
    hostnames, results = aggregate_discovery(
        domain,
        get_discovery_sources(),
    )

    hostnames = filter_subdomains(hostnames, domain)
    hostnames = limit_hostnames(hostnames)

    return hostnames, results