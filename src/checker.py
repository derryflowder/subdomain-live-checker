import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from src.models import ResultStatus, SubdomainResult
from src.paths import (
    DEFAULT_PATHS_TIMEOUT,
    PATH_CHECKABLE_STATUSES,
    check_paths_for_result,
)
from src.techdetect import detect_technologies

DEFAULT_TIMEOUT = 8.0
MAX_TITLE_LENGTH = 200
MAX_HTML_BYTES = 64 * 1024

_RATE_LIMITER = threading.Semaphore(5)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; SubdomainLiveChecker/0.3.2; "
        "+https://github.com/)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

TAKEOVER_SIGNATURES = {
    "NoSuchBucket": "AWS S3 Bucket",
    "The specified bucket does not exist": "AWS S3 Bucket",
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "Heroku | No such app": "Heroku",
    "project not found": "GitLab Pages",
    "This domain is not configured": "Shopify",
    "404 Blog not found": "Tumblr",
}


def classify_status(
    status_code: int | None,
    error: str | None = None,
) -> ResultStatus:
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
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:MAX_TITLE_LENGTH] or None


def detect_takeover(html: str) -> str | None:
    sample = html.lower()
    for signature, service in TAKEOVER_SIGNATURES.items():
        if signature.lower() in sample:
            return service
    return None


def _build_timeout(timeout: float) -> httpx.Timeout:
    return httpx.Timeout(
        connect=timeout,
        read=timeout,
        write=timeout,
        pool=timeout,
    )


def _check_url(
    hostname: str,
    scheme: str,
    timeout: float,
    verify: bool,
) -> SubdomainResult:
    url = f"{scheme}://{hostname}/"

    with _RATE_LIMITER:
        started_at = time.perf_counter()

        try:
            with httpx.stream(
                "GET",
                url,
                timeout=_build_timeout(timeout),
                follow_redirects=True,
                headers=DEFAULT_HEADERS,
                verify=verify,
            ) as response:
                body = bytearray()

                for chunk in response.iter_bytes(chunk_size=8192):
                    remaining = MAX_HTML_BYTES - len(body)
                    if remaining <= 0:
                        break
                    body.extend(chunk[:remaining])

                    if len(body) >= MAX_HTML_BYTES:
                        break

                encoding = response.encoding or "utf-8"
                text_sample = body.decode(encoding, errors="replace")

                response_time_ms = _elapsed_ms(started_at)
                headers_snapshot = dict(response.headers)

                return SubdomainResult(
                    hostname=hostname,
                    status=(
                        ResultStatus.REDIRECT
                        if response.history
                        else classify_status(response.status_code)
                    ),
                    status_code=response.status_code,
                    response_time_ms=response_time_ms,
                    final_url=str(response.url),
                    content_type=response.headers.get("content-type"),
                    server=response.headers.get("server"),
                    title=extract_title(text_sample),
                    takeover=detect_takeover(text_sample),
                    technologies=detect_technologies(
                        text_sample, headers_snapshot
                    ),
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
        except Exception as exc:
            return SubdomainResult(
                hostname=hostname,
                status=ResultStatus.ERROR,
                response_time_ms=_elapsed_ms(started_at),
                error=f"Unexpected error: {exc}",
            )


def check_subdomain(
    hostname: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = True,
) -> SubdomainResult:
    result = _check_url(hostname, "https", timeout, verify)

    if result.error == "connection error":
        fallback = _check_url(hostname, "http", timeout, verify)
        if fallback.error != "connection error":
            return fallback

    return result


def _elapsed_ms(started_at: float) -> float:
    return round((time.perf_counter() - started_at) * 1000, 1)


ProgressCallback = Callable[[int, int], None]


def check_subdomains(
    hostnames: list[str],
    on_progress: ProgressCallback | None = None,
    max_workers: int = 20,
    paths: list[str] | None = None,
    verify: bool = True,
    paths_timeout: float = DEFAULT_PATHS_TIMEOUT,
) -> list[SubdomainResult]:
    if not hostnames:
        return []

    unique_hostnames = list(dict.fromkeys(hostnames))
    total = len(unique_hostnames)
    results_by_hostname: dict[str, SubdomainResult] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                check_subdomain, host, verify=verify
            ): host
            for host in unique_hostnames
        }
        for future in as_completed(futures):
            hostname = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = SubdomainResult(
                    hostname=hostname,
                    status=ResultStatus.ERROR,
                    error=f"Unexpected error: {exc}",
                )
            results_by_hostname[hostname] = result
            if on_progress:
                on_progress(len(results_by_hostname), total)

    ordered = [results_by_hostname[host] for host in unique_hostnames]

    if not paths:
        return ordered

    checkable = [r for r in ordered if r.status in PATH_CHECKABLE_STATUSES]
    if not checkable:
        return ordered

    phase_total = total + len(checkable)
    if on_progress:
        on_progress(total, phase_total)

    done = 0
    path_workers = min(10, len(checkable))

    with ThreadPoolExecutor(max_workers=path_workers) as executor:
        futures = {
            executor.submit(
                check_paths_for_result,
                r,
                paths,
                paths_timeout,
                verify,
            ): r
            for r in checkable
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass
            done += 1
            if on_progress:
                on_progress(total + done, phase_total)

    return ordered