import httpx

from src.discovery import (
    DiscoveryError,
    discover_subdomains,
    fetch_certificate_names,
    normalize_hostname,
    unique_hostnames,
)


def test_normalize_hostname() -> None:
    assert normalize_hostname("  WWW.Example.COM  ") == "www.example.com"


def test_normalize_hostname_removes_trailing_dot() -> None:
    assert normalize_hostname("api.example.com.") == "api.example.com"


def test_unique_hostnames_normalizes_and_removes_duplicates() -> None:
    hostnames = [
        "WWW.Example.COM",
        "api.example.com.",
        " api.example.com ",
        "mail.example.com",
        "",
    ]

    assert unique_hostnames(hostnames) == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]


def test_fetch_certificate_names(monkeypatch) -> None:
    payload = [
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "API.example.com.\nmail.example.com"},
    ]

    def fake_get(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            json=payload,
            request=httpx.Request("GET", "https://crt.sh/"),
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert fetch_certificate_names("example.com") == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]


def test_fetch_certificate_names_raises_discovery_error(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        request = httpx.Request("GET", "https://crt.sh/")
        return httpx.Response(status_code=503, request=request)

    monkeypatch.setattr(httpx, "get", fake_get)

    try:
        fetch_certificate_names("example.com")
    except DiscoveryError as exc:
        assert "Certificate discovery returned HTTP 503" in str(exc)
    else:
        raise AssertionError("DiscoveryError was not raised")


def test_fetch_certificate_names_handles_invalid_json(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        request = httpx.Request("GET", "https://crt.sh/")
        return httpx.Response(
            status_code=200,
            content=b"not-json",
            request=request,
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    try:
        fetch_certificate_names("example.com")
    except DiscoveryError as exc:
        assert "Certificate discovery failed" in str(exc)
    else:
        raise AssertionError("DiscoveryError was not raised")


def test_discover_subdomains_filters_to_target_domain(monkeypatch) -> None:
    def fake_fetch_certificate_names(domain: str) -> list[str]:
        assert domain == "example.com"
        return [
            "www.example.com",
            "api.example.com",
            "mail.example.com",
            "other-domain.com",
            "api.other-domain.com",
            "example.com",
        ]

    monkeypatch.setattr(
        "src.discovery.fetch_certificate_names",
        fake_fetch_certificate_names,
    )

    assert discover_subdomains("Example.COM.") == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]
