import httpx

from src.checker import check_subdomain, check_subdomains, classify_status, extract_title
from src.models import ResultStatus, SubdomainResult


def test_subdomain_result_stores_http_data() -> None:
    result = SubdomainResult(
        hostname="api.example.com",
        status_code=200,
        response_time_ms=143.7,
        final_url="https://api.example.com/",
        content_type="application/json",
        server="nginx",
        title="API",
    )

    assert result.hostname == "api.example.com"
    assert result.status_code == 200
    assert result.response_time_ms == 143.7
    assert result.final_url == "https://api.example.com/"
    assert result.content_type == "application/json"
    assert result.server == "nginx"
    assert result.title == "API"
    assert result.error is None


def test_subdomain_result_can_store_error() -> None:
    result = SubdomainResult(
        hostname="old.example.com",
        error="connection failed",
    )

    assert result.hostname == "old.example.com"
    assert result.status_code is None
    assert result.error == "connection failed"


def test_extract_title() -> None:
    html = "<html><head><title>Example Site</title></head></html>"

    assert extract_title(html) == "Example Site"


def test_extract_title_normalizes_whitespace() -> None:
    html = "<title>  Example   Site\n    </title>"

    assert extract_title(html) == "Example Site"


def test_extract_title_returns_none_when_missing() -> None:
    assert extract_title("<html><body>Hello</body></html>") is None


def test_check_subdomain_limits_html_for_title(monkeypatch) -> None:
    request = httpx.Request("GET", "https://example.com/")

    html = "A" * 65536 + "<title>Too Late</title>"

    response = httpx.Response(
        status_code=200,
        headers={"content-type": "text/html"},
        content=html.encode(),
        request=request,
    )

    def fake_get(*args, **kwargs):
        return response

    monkeypatch.setattr(httpx, "get", fake_get)

    result = check_subdomain("example.com")

    assert result.title is None


def test_check_subdomain_collects_http_data(monkeypatch) -> None:
    request = httpx.Request("GET", "https://api.example.com/")

    response = httpx.Response(
        status_code=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "server": "nginx",
        },
        content=b"<html><title>API</title></html>",
        request=request,
    )

    def fake_get(*args, **kwargs):
        return response

    monkeypatch.setattr(httpx, "get", fake_get)

    result = check_subdomain("api.example.com")

    assert result.hostname == "api.example.com"
    assert result.status_code == 200
    assert result.final_url == "https://api.example.com/"
    assert result.content_type == "text/html; charset=utf-8"
    assert result.server == "nginx"
    assert result.title == "API"
    assert result.response_time_ms is not None
    assert result.response_time_ms >= 0
    assert result.error is None


def test_check_subdomain_detects_redirect_history(monkeypatch) -> None:
    request = httpx.Request("GET", "https://www.example.com/")

    redirect_response = httpx.Response(
        status_code=301,
        headers={"location": "https://www.example.com/"},
        request=httpx.Request("GET", "https://example.com/"),
    )

    response = httpx.Response(
        status_code=200,
        headers={"content-type": "text/html"},
        content=b"<html><title>Example</title></html>",
        request=request,
        history=[redirect_response],
    )

    def fake_get(*args, **kwargs):
        return response

    monkeypatch.setattr(httpx, "get", fake_get)

    result = check_subdomain("example.com")

    assert result.status == ResultStatus.REDIRECT
    assert result.status_code == 200
    assert result.final_url == "https://www.example.com/"


def test_check_subdomain_handles_timeout(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        raise httpx.TimeoutException("request timed out")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = check_subdomain("slow.example.com")

    assert result.hostname == "slow.example.com"
    assert result.status_code is None
    assert result.error == "timeout"
    assert result.response_time_ms is not None


def test_check_subdomain_handles_connection_error(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        raise httpx.ConnectError("connection failed")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = check_subdomain("offline.example.com")

    assert result.hostname == "offline.example.com"
    assert result.status_code is None
    assert result.error == "connection error"
    assert result.response_time_ms is not None


def test_classify_status() -> None:
    assert classify_status(200) == ResultStatus.LIVE
    assert classify_status(204) == ResultStatus.LIVE
    assert classify_status(301) == ResultStatus.REDIRECT
    assert classify_status(302) == ResultStatus.REDIRECT
    assert classify_status(403) == ResultStatus.FORBIDDEN
    assert classify_status(404) == ResultStatus.NOT_FOUND
    assert classify_status(None, "timeout") == ResultStatus.TIMEOUT
    assert classify_status(None, "connection error") == ResultStatus.UNREACHABLE


def test_classify_status_handles_unknown_error() -> None:
    assert classify_status(None, "something else") == ResultStatus.ERROR


def test_check_subdomains_checks_hostnames_in_order(monkeypatch) -> None:
    checked_hostnames: list[str] = []

    def fake_check_subdomain(hostname: str) -> SubdomainResult:
        checked_hostnames.append(hostname)

        return SubdomainResult(
            hostname=hostname,
            status=ResultStatus.LIVE,
            status_code=200,
        )

    monkeypatch.setattr("src.checker.check_subdomain", fake_check_subdomain)

    hostnames = [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]

    results = check_subdomains(hostnames)

    assert checked_hostnames == hostnames
    assert [result.hostname for result in results] == hostnames
    assert all(result.status == ResultStatus.LIVE for result in results)

def test_check_subdomains_preserves_order(monkeypatch) -> None:
    from src.models import ResultStatus, SubdomainResult

    def fake_check(hostname: str) -> SubdomainResult:
        return SubdomainResult(
            hostname=hostname,
            status=ResultStatus.LIVE,
            status_code=200,
        )

    monkeypatch.setattr("src.checker.check_subdomain", fake_check)

    results = check_subdomains(
        ["a.example.com", "b.example.com", "c.example.com"]
    )

    assert [result.hostname for result in results] == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


def test_check_subdomains_empty_list() -> None:
    assert check_subdomains([]) == []