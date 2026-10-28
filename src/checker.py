import re
import time

import httpx

from src.models import ResultStatus, SubdomainResult

DEFAULT_TIMEOUT = 8.0
MAX_TITLE_LENGTH = 200
MAX_HTML_BYTES = 64 * 1024


def classify_status(
    status_code: int | None,
    error: str | None = None,
) -> ResultStatus:
    """Classify a checker result into a user-facing status."""
    if error == "timeout":
        return ResultStatus.TIMEOUT

    if error == "connection error":
        return ResultStatus.UNREACHABLE

    if error:
        return ResultStatus.ERROR

    if status_code is None:
        return ResultStatus.ERROR

    if 200 <= status_code < 300:
        return ResultStatus.LIVE

    if 300 <= status_code < 400:
        return ResultStatus.REDIRECT

    if status_code == 403:
        return ResultStatus.FORBIDDEN

    if status_code == 404:
        return ResultStatus.NOT_FOUND

    return ResultStatus.ERROR


def extract_title(html: str) -> str | None:
    """Extract the first HTML title."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)

    if not match:
        return None

    title = re.sub(r"\s+", " ", match.group(1)).strip()

    return title[:MAX_TITLE_LENGTH] or None


def check_subdomain(
    hostname: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> SubdomainResult:
    """Check a hostname over HTTPS and return structured response data."""
    url = f"https://{hostname}/"
    started_at = time.perf_counter()

    try:
        response = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
        )
    except httpx.TimeoutException:
        return SubdomainResult(
            hostname=hostname,
            status=classify_status(None, "timeout"),
            response_time_ms=_elapsed_ms(started_at),
            error="timeout",
        )
    except httpx.ConnectError:
        return SubdomainResult(
            hostname=hostname,
            status=classify_status(None, "connection error"),
            response_time_ms=_elapsed_ms(started_at),
            error="connection error",
        )
    except httpx.HTTPError as exc:
        return SubdomainResult(
            hostname=hostname,
            status=classify_status(None, f"HTTP error: {exc}"),
            response_time_ms=_elapsed_ms(started_at),
            error=f"HTTP error: {exc}",
        )

    response_time_ms = _elapsed_ms(started_at)

    return SubdomainResult(
        hostname=hostname,
        status=(
            ResultStatus.REDIRECT if response.history else classify_status(response.status_code)
        ),
        status_code=response.status_code,
        response_time_ms=response_time_ms,
        final_url=str(response.url),
        content_type=response.headers.get("content-type"),
        server=response.headers.get("server"),
        title=extract_title(response.text[:MAX_HTML_BYTES]),
    )


def _elapsed_ms(started_at: float) -> float:
    """Return elapsed time in milliseconds."""
    return round((time.perf_counter() - started_at) * 1000, 1)


def check_subdomains(hostnames: list[str]) -> list[SubdomainResult]:
    """Check a list of hostnames sequentially."""
    return [check_subdomain(hostname) for hostname in hostnames]
