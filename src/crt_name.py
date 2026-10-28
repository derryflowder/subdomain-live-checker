import httpx

from src.discovery_models import DiscoverySourceResult

CRT_NAME_URL = "https://crt.name/v1/search"


class CrtNameDiscoveryError(Exception):
    """Raised when crt.name discovery fails."""


def fetch_crt_name_names(domain: str) -> list[str]:
    """Fetch subdomain names from the public crt.name index."""
    try:
        response = httpx.get(
            CRT_NAME_URL,
            params={"apex": domain},
            timeout=10.0,
        )

        if response.status_code >= 400:
            raise CrtNameDiscoveryError(
                f"crt.name returned HTTP {response.status_code}."
            )

    except httpx.TimeoutException as exc:
        raise CrtNameDiscoveryError(
            "crt.name discovery timed out."
        ) from exc
    except httpx.HTTPError as exc:
        raise CrtNameDiscoveryError(
            f"crt.name discovery failed: {exc}"
        ) from exc

    return [
        line.strip()
        for line in response.text.splitlines()
        if line.strip()
    ]

def discover_from_crt_name(domain: str) -> DiscoverySourceResult:
    """Run crt.name discovery and return a standardized result."""
    try:
        hostnames = fetch_crt_name_names(domain)
    except CrtNameDiscoveryError as exc:
        return DiscoverySourceResult(
            source="crt.name",
            hostnames=[],
            error=str(exc),
        )

    return DiscoverySourceResult(
        source="crt.name",
        hostnames=hostnames,
    )