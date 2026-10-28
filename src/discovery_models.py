from dataclasses import dataclass


@dataclass(slots=True)
class DiscoverySourceResult:
    source: str
    hostnames: list[str]
    error: str | None = None