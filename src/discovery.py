import httpx

from src.discovery_models import DiscoverySourceResult

CT_URL = "https://crt.sh/"
MAX_DISCOVERED_HOSTS = 500
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"


class DiscoveryError(Exception):
    """Raised when passive subdomain discovery fails."""


def normalize_hostname(hostname: str) -> str:
    """Normalize a discovered hostname."""
    return hostname.strip().lower().rstrip(".")


def unique_hostnames(hostnames: list[str]) -> list[str]:
    """Normalize hostnames and remove duplicates."""
    normalized = {normalize_hostname(hostname) for hostname in hostnames}
    return sorted(hostname for hostname in normalized if hostname)


def fetch_certificate_names(domain: str) -> list[str]:
    """Fetch certificate names for a domain from a public CT source."""
    try:
        response = httpx.get(
            CT_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=10.0,
        )

        if response.status_code >= 400:
            raise DiscoveryError(
                f"Certificate discovery returned HTTP {response.status_code}."
            )

        records = response.json()

    except httpx.TimeoutException as exc:
        raise DiscoveryError(
            "Certificate discovery timed out. The certificate source may be "
            "temporarily unavailable."
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise DiscoveryError(f"Certificate discovery failed: {exc}") from exc

    hostnames: list[str] = []

    for record in records:
        name_value = record.get("name_value", "")
        hostnames.extend(name_value.splitlines())

    return unique_hostnames(hostnames)


def discover_from_crtsh(domain: str) -> DiscoverySourceResult:
    """Run crt.sh discovery and return a standardized result."""
    try:
        hostnames = fetch_certificate_names(domain)
    except DiscoveryError as exc:
        return DiscoverySourceResult(
            source="crt.sh",
            hostnames=[],
            error=str(exc),
        )

    return DiscoverySourceResult(
        source="crt.sh",
        hostnames=hostnames,
    )

def filter_subdomains(hostnames: list[str], domain: str) -> list[str]:
    """Keep only valid subdomains of the target domain."""
    normalized_domain = normalize_hostname(domain)
    suffix = f".{normalized_domain}"

    return sorted(
        hostname
        for hostname in unique_hostnames(hostnames)
        if hostname.endswith(suffix)
        and hostname != normalized_domain
        and "*" not in hostname
    )

def limit_hostnames(hostnames: list[str]) -> list[str]:
    """Limit the number of discovered hostnames used by the checker."""
    return hostnames[:MAX_DISCOVERED_HOSTS]

def discover_subdomains(domain: str) -> list[str]:
    """Discover subdomains belonging to the target domain."""
    normalized_domain = normalize_hostname(domain)

    if not normalized_domain:
        raise ValueError("Domain must not be empty.")

    certificate_names = fetch_certificate_names(normalized_domain)

    return filter_subdomains(certificate_names, normalized_domain)
