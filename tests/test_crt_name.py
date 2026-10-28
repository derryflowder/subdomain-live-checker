import httpx

from src.crt_name import CrtNameDiscoveryError, fetch_crt_name_names


def test_fetch_crt_name_names(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        return httpx.Response(
            status_code=200,
            text="example.com\napi.example.com\nmail.example.com\n",
            request=httpx.Request("GET", "https://crt.name/"),
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    assert fetch_crt_name_names("example.com") == [
        "example.com",
        "api.example.com",
        "mail.example.com",
    ]


def test_fetch_crt_name_names_handles_http_error(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        return httpx.Response(
            status_code=503,
            request=httpx.Request("GET", "https://crt.name/"),
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    try:
        fetch_crt_name_names("example.com")
    except CrtNameDiscoveryError as exc:
        assert "crt.name returned HTTP 503" in str(exc)
    else:
        raise AssertionError("CrtNameDiscoveryError was not raised")


def test_fetch_crt_name_names_handles_timeout(monkeypatch) -> None:
    def fake_get(*args, **kwargs):
        raise httpx.ReadTimeout("test timeout")

    monkeypatch.setattr(httpx, "get", fake_get)

    try:
        fetch_crt_name_names("example.com")
    except CrtNameDiscoveryError as exc:
        assert "crt.name discovery timed out" in str(exc)
    else:
        raise AssertionError("CrtNameDiscoveryError was not raised")