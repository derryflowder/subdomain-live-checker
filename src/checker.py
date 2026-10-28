import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from src.models import ResultStatus, SubdomainResult

DEFAULT_TIMEOUT = 8.0
MAX_TITLE_LENGTH = 200
MAX_HTML_BYTES = 64 * 1024

TAKEOVER_SIGNATURES = {
    "NoSuchBucket": "AWS S3 Bucket",
    "The specified bucket does not exist": "AWS S3 Bucket",
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "Heroku | No such app": "Heroku",
    "project not found": "GitLab Pages",
    "This domain is not configured": "Shopify",
    "404 Blog not found": "Tumblr",
}

def classify_status(status_code: int | None, error: str | None = None) -> ResultStatus:
    if error == "timeout": return ResultStatus.TIMEOUT
    if error == "connection error": return ResultStatus.UNREACHABLE
    if error: return ResultStatus.ERROR
    if status_code is None: return ResultStatus.ERROR
    if 200 <= status_code < 300: return ResultStatus.LIVE
    if 300 <= status_code < 400: return ResultStatus.REDIRECT
    if status_code == 403: return ResultStatus.FORBIDDEN
    if status_code == 404: return ResultStatus.NOT_FOUND
    return ResultStatus.ERROR

def extract_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match: return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:MAX_TITLE_LENGTH] or None

def detect_takeover(html: str) -> str | None:
    sample = html[:MAX_HTML_BYTES].lower()
    for signature, service in TAKEOVER_SIGNATURES.items():
        if signature.lower() in sample:
            return service
    return None

def check_subdomain(hostname: str, timeout: float = DEFAULT_TIMEOUT) -> SubdomainResult:
    url = f"https://{hostname}/"
    started_at = time.perf_counter()

    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.TimeoutException:
        return SubdomainResult(hostname=hostname, status=classify_status(None, "timeout"), response_time_ms=_elapsed_ms(started_at), error="timeout")
    except httpx.ConnectError:
        return SubdomainResult(hostname=hostname, status=classify_status(None, "connection error"), response_time_ms=_elapsed_ms(started_at), error="connection error")
    except httpx.HTTPError as exc:
        return SubdomainResult(hostname=hostname, status=classify_status(None, f"HTTP error: {exc}"), response_time_ms=_elapsed_ms(started_at), error=f"HTTP error: {exc}")
    except Exception as exc:
        return SubdomainResult(hostname=hostname, status=ResultStatus.ERROR, response_time_ms=_elapsed_ms(started_at), error=f"Unexpected error: {exc}")

    response_time_ms = _elapsed_ms(started_at)
    text_sample = response.text[:MAX_HTML_BYTES]

    return SubdomainResult(
        hostname=hostname,
        status=(ResultStatus.REDIRECT if response.history else classify_status(response.status_code)),
        status_code=response.status_code,
        response_time_ms=response_time_ms,
        final_url=str(response.url),
        content_type=response.headers.get("content-type"),
        server=response.headers.get("server"),
        title=extract_title(text_sample),
        takeover=detect_takeover(text_sample)
    )

def _elapsed_ms(started_at: float) -> float:
    return round((time.perf_counter() - started_at) * 1000, 1)

ProgressCallback = Callable[[int, int], None]

def check_subdomains(hostnames: list[str], on_progress: ProgressCallback | None = None) -> list[SubdomainResult]:
    if not hostnames: return []
    
    unique_hostnames = list(dict.fromkeys(hostnames))
    total = len(unique_hostnames)
    results_by_hostname: dict[str, SubdomainResult] = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(check_subdomain, host): host for host in unique_hostnames}
        for future in as_completed(futures):
            hostname = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = SubdomainResult(hostname=hostname, status=ResultStatus.ERROR, error=f"Unexpected error: {exc}")
            results_by_hostname[hostname] = result
            if on_progress: on_progress(len(results_by_hostname), total)

    return [results_by_hostname[host] for host in unique_hostnames]