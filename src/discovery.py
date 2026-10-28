import httpx

CT_URL = "https://crt.sh/"


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
        response.raise_for_status()
        records = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise DiscoveryError(f"Certificate discovery failed: {exc}") from exc

    hostnames: list[str] = []

    for record in records:
        name_value = record.get("name_value", "")
        hostnames.extend(name_value.splitlines())

    return unique_hostnames(hostnames)


def discover_subdomains(domain: str) -> list[str]:
    """Discover subdomains belonging to the target domain."""
    normalized_domain = normalize_hostname(domain)

    if not normalized_domain:
        raise ValueError("Domain must not be empty.")

    certificate_names = fetch_certificate_names(normalized_domain)

    suffix = f".{normalized_domain}"

    return sorted(
        hostname
        for hostname in certificate_names
        if hostname.endswith(suffix) and hostname != normalized_domain
    )
